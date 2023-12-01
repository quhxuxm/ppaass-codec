use std::io::Write;

use bytes::{BufMut, Bytes, BytesMut};
use flate2::{write::GzEncoder, Compression};
use log::trace;
use ppaass_crypto::{encrypt_with_aes, CryptoError, RsaCryptoFetcher};
use ppaass_protocol::message::proxy::{
    EncodedProxyMessage, EncodedProxyMessagePayload, ProxyMessage, ProxyMessagePayload,
};
use ppaass_protocol::values::security::{Encryption, SecureInfo};

use crate::codec::{COMPRESS_FLAG, MAGIC_FLAG, UNCOMPRESSED_FLAG};
use crate::error::EncoderError;

use tokio_util::codec::Encoder;

pub struct ProxyMessageEncoder<F>
where
    F: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: F,
    compress: bool,
}

impl<F> ProxyMessageEncoder<F>
where
    F: RsaCryptoFetcher,
{
    pub fn new(compress: bool, rsa_crypto_fetcher: F) -> Self {
        Self {
            rsa_crypto_fetcher,
            compress,
        }
    }
}

/// Encode the proxy message to bytes
impl<F> Encoder<ProxyMessage> for ProxyMessageEncoder<F>
where
    F: RsaCryptoFetcher,
{
    type Error = EncoderError;

    fn encode(
        &mut self,
        proxy_message: ProxyMessage,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        trace!("Encode proxy message to output: {:?}", proxy_message);
        dst.put(MAGIC_FLAG);
        if self.compress {
            dst.put_u8(COMPRESS_FLAG);
        } else {
            dst.put_u8(UNCOMPRESSED_FLAG);
        }
        let ProxyMessage {
            message_id,
            secure_info,
            tunnel,
            payload: original_message_payload,
        } = proxy_message;

        let encoded_proxy_message = match secure_info.encryption {
            Encryption::Plain => {
                let proxy_message_payload = match original_message_payload {
                    ProxyMessagePayload::InitTunnelResult(init_tunnel_result) => {
                        EncodedProxyMessagePayload::InitTunnelResult(init_tunnel_result.try_into()?)
                    }
                    ProxyMessagePayload::RelayData(relay_data) => {
                        EncodedProxyMessagePayload::RelayData(relay_data.try_into()?)
                    }
                    ProxyMessagePayload::CloseTunnelCommand(close_tunnel_command) => {
                        EncodedProxyMessagePayload::CloseTunnelCommand(
                            close_tunnel_command.try_into()?,
                        )
                    }
                };
                EncodedProxyMessage {
                    message_id,
                    secure_info,
                    tunnel,
                    payload: proxy_message_payload,
                }
            }
            Encryption::Aes(ref original_encryption_token) => {
                let rsa_crypto = self
                    .rsa_crypto_fetcher
                    .fetch(&secure_info.user_token)?
                    .ok_or(CryptoError::Rsa(format!(
                    "Crypto for user: {} not found when encoding message for tunnel: {tunnel:?}",
                    secure_info.user_token
                )))?;
                let encrypted_encryption_token =
                    Bytes::from(rsa_crypto.encrypt(original_encryption_token)?);
                let encrypted_secure_info = SecureInfo {
                    user_token: secure_info.user_token,
                    encryption: Encryption::Aes(encrypted_encryption_token),
                };
                let encrypted_proxy_message_payload = match original_message_payload {
                    ProxyMessagePayload::InitTunnelResult(init_tunnel_result) => {
                        let init_tunnel_result_bytes: Bytes = init_tunnel_result.try_into()?;
                        let mut init_tunnel_result_bytes_mut = BytesMut::new();
                        init_tunnel_result_bytes_mut.extend_from_slice(&init_tunnel_result_bytes);
                        let encrypted_init_tunnel_result_bytes = encrypt_with_aes(
                            original_encryption_token,
                            &mut init_tunnel_result_bytes_mut,
                        )?
                        .freeze();
                        EncodedProxyMessagePayload::InitTunnelResult(
                            encrypted_init_tunnel_result_bytes,
                        )
                    }
                    ProxyMessagePayload::RelayData(relay_data) => {
                        let relay_data_bytes: Bytes = relay_data.try_into()?;
                        let mut relay_data_bytes_mut = BytesMut::new();
                        relay_data_bytes_mut.extend_from_slice(&relay_data_bytes);
                        let encrypted_relay_data_bytes =
                            encrypt_with_aes(original_encryption_token, &mut relay_data_bytes_mut)?
                                .freeze();
                        EncodedProxyMessagePayload::RelayData(encrypted_relay_data_bytes)
                    }
                    ProxyMessagePayload::CloseTunnelCommand(close_tunnel_command) => {
                        let close_tunnel_command_bytes: Bytes = close_tunnel_command.try_into()?;
                        let mut close_tunnel_command_bytes_mut = BytesMut::new();
                        close_tunnel_command_bytes_mut
                            .extend_from_slice(&close_tunnel_command_bytes);
                        let encrypted_close_tunnel_command_bytes = encrypt_with_aes(
                            original_encryption_token,
                            &mut close_tunnel_command_bytes_mut,
                        )?
                        .freeze();
                        EncodedProxyMessagePayload::CloseTunnelCommand(
                            encrypted_close_tunnel_command_bytes,
                        )
                    }
                };
                EncodedProxyMessage {
                    message_id,
                    secure_info: encrypted_secure_info,
                    tunnel,
                    payload: encrypted_proxy_message_payload,
                }
            }
        };
        let bytes_framed: Bytes = encoded_proxy_message.try_into()?;
        let bytes_framed = if self.compress {
            let encoder_buf = BytesMut::new();
            let mut gzip_encoder = GzEncoder::new(encoder_buf.writer(), Compression::fast());
            gzip_encoder.write_all(&bytes_framed)?;
            gzip_encoder.finish()?.into_inner().freeze()
        } else {
            bytes_framed
        };
        dst.put_u64(bytes_framed.len() as u64);
        dst.put(bytes_framed.as_ref());
        Ok(())
    }
}
