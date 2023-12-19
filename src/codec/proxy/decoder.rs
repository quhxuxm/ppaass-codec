use std::io::Read;

use bytes::{Buf, Bytes, BytesMut};
use flate2::read::GzDecoder;
use log::{error, trace};
use ppaass_crypto::{decrypt_with_aes, CryptoError, RsaCryptoFetcher};
use ppaass_protocol::message::proxy::{
    CloseTunnelCommand, EncodedProxyMessage, EncodedProxyMessagePayload, InitTunnelResult,
    ProxyMessage, ProxyMessagePayload, RelayData,
};
use ppaass_protocol::values::security::Encryption;

use crate::codec::{decode_header, DecodeStatus, HEADER_LENGTH};
use crate::error::CodecError;
use pretty_hex::*;
use tokio_util::codec::Decoder;

/// The decoder for proxy message
pub struct ProxyMessageDecoder<F>
where
    F: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: F,
    status: DecodeStatus,
}

impl<F> ProxyMessageDecoder<F>
where
    F: RsaCryptoFetcher,
{
    pub fn new(rsa_crypto_fetcher: F) -> Self {
        Self {
            rsa_crypto_fetcher,
            status: DecodeStatus::Head,
        }
    }
}

/// Decode the input bytes to proxy message
impl<F> Decoder for ProxyMessageDecoder<F>
where
    F: RsaCryptoFetcher,
{
    type Item = ProxyMessage;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.status {
            DecodeStatus::Head => {
                let (compressed, body_length) = match decode_header(src) {
                    Ok(None) => return Ok(None),
                    Ok(Some(header)) => header,
                    Err(e) => {
                        error!("Fail to decode input proxy message because of error: {e:?}");
                        return Err(e);
                    }
                };
                self.status = DecodeStatus::Data(compressed, body_length);
                Ok(None)
            }
            DecodeStatus::Data(compressed, body_length) => {
                if src.remaining() < body_length as usize {
                    trace!("Input proxy message is not enough to decode body, continue read, buffer remaining: {}, body length: {body_length}.",src.remaining());
                    src.reserve(body_length as usize);
                    return Ok(None);
                }
                trace!("Input proxy message has enough bytes to decode body, buffer remaining: {}, body length: {body_length}.",src.remaining(),);
                self.status = DecodeStatus::Data(compressed, body_length);
                let body_bytes = src.split_to(body_length as usize);
                trace!(
                    "Input proxy message body bytes(compressed={compressed}):\n\n{}\n\n",
                    pretty_hex(&body_bytes)
                );
                let encrypted_proxy_message: EncodedProxyMessage = if compressed {
                    let mut gzip_decoder = GzDecoder::new(body_bytes.reader());
                    let mut decompressed_bytes = Vec::new();
                    if let Err(e) = gzip_decoder.read_to_end(&mut decompressed_bytes) {
                        error!("Fail to decompress incoming proxy message bytes because of error: {e:?}");
                        return Err(CodecError::Io(e));
                    };
                    let decompressed_bytes = Bytes::from_iter(decompressed_bytes);
                    let encrypted_message: EncodedProxyMessage = decompressed_bytes.try_into()?;
                    encrypted_message
                } else {
                    trace!(
                        "Raw bytes will convert to PpaassMessage:\n{}\n",
                        pretty_hex::pretty_hex(&body_bytes)
                    );
                    body_bytes.freeze().try_into()?
                };
                trace!("Get decoded encrypted proxy message: {encrypted_proxy_message:?}");

                let EncodedProxyMessage {
                    message_id,
                    secure_info,
                    payload: encrypted_message_payload,
                } = encrypted_proxy_message;

                let proxy_message_payload = match &secure_info.encryption {
                    Encryption::Plain => match encrypted_message_payload {
                        EncodedProxyMessagePayload::InitTunnelResult(bytes) => {
                            let init_tunnel_result: InitTunnelResult = bytes.try_into()?;
                            ProxyMessagePayload::InitTunnelResult(init_tunnel_result)
                        }
                        EncodedProxyMessagePayload::RelayData(bytes) => {
                            let relay_data: RelayData = bytes.try_into()?;
                            ProxyMessagePayload::RelayData(relay_data)
                        }
                        EncodedProxyMessagePayload::CloseTunnelCommand(bytes) => {
                            let close_tunnel_command: CloseTunnelCommand = bytes.try_into()?;
                            ProxyMessagePayload::CloseTunnelCommand(close_tunnel_command)
                        }
                    },
                    Encryption::Aes(ref encryption_token) => {
                        let rsa_crypto = self
                            .rsa_crypto_fetcher
                            .fetch(&secure_info.user_token)?
                            .ok_or(CryptoError::Rsa(format!(
                                "Crypto for user: {} not found when decoding message",
                                secure_info.user_token
                            )))?;
                        let original_encryption_token =
                            Bytes::from(rsa_crypto.decrypt(encryption_token)?);

                        match encrypted_message_payload {
                            EncodedProxyMessagePayload::InitTunnelResult(bytes) => {
                                let mut encrypted_bytes = BytesMut::new();
                                encrypted_bytes.extend_from_slice(&bytes);
                                let decrypted_bytes = decrypt_with_aes(
                                    &original_encryption_token,
                                    &mut encrypted_bytes,
                                )?
                                .freeze();
                                let init_tunnel_result: InitTunnelResult =
                                    decrypted_bytes.try_into()?;
                                ProxyMessagePayload::InitTunnelResult(init_tunnel_result)
                            }
                            EncodedProxyMessagePayload::RelayData(bytes) => {
                                let mut encrypted_bytes = BytesMut::new();
                                encrypted_bytes.extend_from_slice(&bytes);
                                let decrypted_bytes = decrypt_with_aes(
                                    &original_encryption_token,
                                    &mut encrypted_bytes,
                                )?
                                .freeze();
                                let relay_data: RelayData = decrypted_bytes.try_into()?;
                                ProxyMessagePayload::RelayData(relay_data)
                            }
                            EncodedProxyMessagePayload::CloseTunnelCommand(bytes) => {
                                let mut encrypted_bytes = BytesMut::new();
                                encrypted_bytes.extend_from_slice(&bytes);
                                let decrypted_bytes = decrypt_with_aes(
                                    &original_encryption_token,
                                    &mut encrypted_bytes,
                                )?
                                .freeze();
                                let close_tunnel_command: CloseTunnelCommand =
                                    decrypted_bytes.try_into()?;
                                ProxyMessagePayload::CloseTunnelCommand(close_tunnel_command)
                            }
                        }
                    }
                };
                trace!("Get decoded decrypted proxy message: {proxy_message_payload:?}");
                self.status = DecodeStatus::Head;
                src.reserve(HEADER_LENGTH);
                let proxy_message = ProxyMessage {
                    message_id,
                    secure_info,
                    payload: proxy_message_payload,
                };
                Ok(Some(proxy_message))
            }
        }
    }
}
