use std::io::Read;

use bytes::{Buf, Bytes, BytesMut};
use flate2::read::GzDecoder;
use log::{error, trace};
use ppaass_crypto::{decrypt_with_aes, CryptoError, RsaCryptoFetcher};
use ppaass_protocol::message::agent::{
    AgentMessage, AgentMessagePayload, CloseTunnelCommand, EncodedAgentMessage,
    EncodedAgentMessagePayload, InitTunnelCommand, RelayData,
};
use ppaass_protocol::values::security::Encryption;

use crate::codec::{decode_header, DecodeStatus, HEADER_LENGTH};
use crate::error::CodecError;
use pretty_hex::*;
use tokio_util::codec::Decoder;

/// The decoder for agent message
pub struct AgentMessageDecoder<F>
where
    F: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: F,
    status: DecodeStatus,
}

impl<F> AgentMessageDecoder<F>
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

/// Decode the input bytes to agent message
impl<F> Decoder for AgentMessageDecoder<F>
where
    F: RsaCryptoFetcher,
{
    type Item = AgentMessage;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.status {
            DecodeStatus::Head => {
                let (compressed, body_length) = match decode_header(src) {
                    Ok(None) => return Ok(None),
                    Ok(Some(header)) => header,
                    Err(e) => {
                        error!("Fail to decode input agent message because of error: {e:?}");
                        return Err(e);
                    }
                };
                self.status = DecodeStatus::Data(compressed, body_length);
                Ok(None)
            }
            DecodeStatus::Data(compressed, body_length) => {
                if src.remaining() < body_length as usize {
                    trace!("Input agent message is not enough to decode body, continue read, buffer remaining: {}, body length: {body_length}.",src.remaining());
                    src.reserve(body_length as usize);
                    return Ok(None);
                }
                trace!("Input agent message has enough bytes to decode body, buffer remaining: {}, body length: {body_length}.",src.remaining(),);
                self.status = DecodeStatus::Data(compressed, body_length);
                let body_bytes = src.split_to(body_length as usize);
                trace!(
                    "Input agent message body bytes(compressed={compressed}):\n\n{}\n\n",
                    pretty_hex(&body_bytes)
                );
                let encrypted_agent_message: EncodedAgentMessage = if compressed {
                    let mut gzip_decoder = GzDecoder::new(body_bytes.reader());
                    let mut decompressed_bytes = Vec::new();
                    if let Err(e) = gzip_decoder.read_to_end(&mut decompressed_bytes) {
                        error!("Fail to decompress incoming agent message bytes because of error: {e:?}");
                        return Err(CodecError::Io(e));
                    };
                    let decompressed_bytes = Bytes::from_iter(decompressed_bytes);
                    decompressed_bytes.try_into()?
                } else {
                    trace!(
                        "Raw bytes will convert to PpaassMessage:\n{}\n",
                        pretty_hex::pretty_hex(&body_bytes)
                    );
                    body_bytes.freeze().try_into()?
                };
                trace!("Get decoded encrypted agent message: {encrypted_agent_message:?}");

                let EncodedAgentMessage {
                    message_id,
                    secure_info,
                    payload: encrypted_message_payload,
                } = encrypted_agent_message;

                let agent_message_payload = match &secure_info.encryption {
                    Encryption::Plain => match encrypted_message_payload {
                        EncodedAgentMessagePayload::InitTunnelCommand(bytes) => {
                            let init_tunnel_command: InitTunnelCommand = bytes.try_into()?;
                            AgentMessagePayload::InitTunnelCommand(init_tunnel_command)
                        }
                        EncodedAgentMessagePayload::RelayData(bytes) => {
                            let relay_data: RelayData = bytes.try_into()?;
                            AgentMessagePayload::RelayData(relay_data)
                        }
                        EncodedAgentMessagePayload::CloseTunnelCommand(bytes) => {
                            let close_tunnel_command: CloseTunnelCommand = bytes.try_into()?;
                            AgentMessagePayload::CloseTunnelCommand(close_tunnel_command)
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
                            EncodedAgentMessagePayload::InitTunnelCommand(bytes) => {
                                let mut encrypted_bytes = BytesMut::new();
                                encrypted_bytes.extend_from_slice(&bytes);
                                let decrypted_bytes = decrypt_with_aes(
                                    &original_encryption_token,
                                    &mut encrypted_bytes,
                                )?
                                .freeze();
                                let init_tunnel_command: InitTunnelCommand =
                                    decrypted_bytes.try_into()?;
                                AgentMessagePayload::InitTunnelCommand(init_tunnel_command)
                            }
                            EncodedAgentMessagePayload::RelayData(bytes) => {
                                let mut encrypted_bytes = BytesMut::new();
                                encrypted_bytes.extend_from_slice(&bytes);
                                let decrypted_bytes = decrypt_with_aes(
                                    &original_encryption_token,
                                    &mut encrypted_bytes,
                                )?
                                .freeze();
                                let relay_data: RelayData = decrypted_bytes.try_into()?;
                                AgentMessagePayload::RelayData(relay_data)
                            }
                            EncodedAgentMessagePayload::CloseTunnelCommand(bytes) => {
                                let mut encrypted_bytes = BytesMut::new();
                                encrypted_bytes.extend_from_slice(&bytes);
                                let decrypted_bytes = decrypt_with_aes(
                                    &original_encryption_token,
                                    &mut encrypted_bytes,
                                )?
                                .freeze();
                                let close_tunnel_command: CloseTunnelCommand =
                                    decrypted_bytes.try_into()?;
                                AgentMessagePayload::CloseTunnelCommand(close_tunnel_command)
                            }
                        }
                    }
                };
                trace!("Get decoded decrypted agent message: {agent_message_payload:?}");
                self.status = DecodeStatus::Head;
                src.reserve(HEADER_LENGTH);
                let agent_message = AgentMessage {
                    message_id,
                    secure_info,
                    payload: agent_message_payload,
                };
                Ok(Some(agent_message))
            }
        }
    }
}
