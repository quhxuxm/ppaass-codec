use std::io::{Read, Write};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use log::{error, trace};
use ppaass_crypto::{decrypt_with_aes, encrypt_with_aes, RsaCryptoFetcher};
use ppaass_protocol::message::{AgentMessage, Encryption, ProxyMessage};
use pretty_hex::*;
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    codec::{COMPRESS_FLAG, HEADER_LENGTH, PPAASS_FLAG, UNCOMPRESS_FLAG},
    DecoderError, EncoderError,
};

use super::DecodeStatus;

pub struct ProxyConnectionCodec<F>
where
    F: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: F,
    compress: bool,
    status: DecodeStatus,
}

impl<F> ProxyConnectionCodec<F>
where
    F: RsaCryptoFetcher,
{
    pub fn new(compress: bool, rsa_crypto_fetcher: F) -> Self {
        Self {
            rsa_crypto_fetcher,
            compress,
            status: DecodeStatus::Head,
        }
    }
}

/// Decode the input bytes buffer to ppaass message
impl<F> Decoder for ProxyConnectionCodec<F>
where
    F: RsaCryptoFetcher,
{
    type Item = ProxyMessage;
    type Error = DecoderError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (compressed, body_length) = match self.status {
            DecodeStatus::Head => {
                if src.len() < HEADER_LENGTH {
                    trace!(
                        "Input message is not enough to decode header, header length: {}",
                        src.len()
                    );
                    src.reserve(HEADER_LENGTH);
                    return Ok(None);
                }
                let ppaass_flag = src.split_to(PPAASS_FLAG.len());
                if !PPAASS_FLAG.eq(&ppaass_flag) {
                    return Err(DecoderError::Other(format!(
                        "The incoming message is not begin with {:?}",
                        PPAASS_FLAG
                    )));
                }
                let compressed = src.get_u8() == 1;
                let body_length = src.get_u64();
                src.reserve(body_length as usize);
                trace!("The body length of the input message is {}", body_length);
                self.status = DecodeStatus::Data(compressed, body_length);
                (compressed, body_length)
            }
            DecodeStatus::Data(compressed, body_length) => (compressed, body_length),
        };
        if src.remaining() < body_length as usize {
            trace!(
                "Input message is not enough to decode body, continue read, buffer remaining: {}, body length: {body_length}.",
                src.remaining(),
            );
            src.reserve(body_length as usize);
            return Ok(None);
        }
        trace!(
            "Input message has enough bytes to decode body, buffer remaining: {}, body length: {body_length}.",
            src.remaining(),
        );
        self.status = DecodeStatus::Data(compressed, body_length);
        let body_bytes = src.split_to(body_length as usize);
        trace!(
            "Input message body bytes(compressed={compressed}):\n\n{}\n\n",
            pretty_hex(&body_bytes)
        );
        let encrypted_proxy_message: ProxyMessage = if compressed {
            let mut gzip_decoder = GzDecoder::new(body_bytes.reader());
            let mut decompressed_bytes = Vec::new();
            if let Err(e) = gzip_decoder.read_to_end(&mut decompressed_bytes) {
                error!("Fail to decompress incoming message bytes because of error: {e:?}");
                return Err(DecoderError::Io(e));
            };
            let decompressed_bytes = Bytes::from_iter(decompressed_bytes);
            trace!(
                "Decompressed bytes will convert to PpaassMessage:\n{}\n",
                pretty_hex::pretty_hex(&decompressed_bytes)
            );
            let encrypted_message: ProxyMessage = decompressed_bytes.try_into()?;
            encrypted_message
        } else {
            trace!(
                "Raw bytes will convert to PpaassMessage:\n{}\n",
                pretty_hex::pretty_hex(&body_bytes)
            );
            body_bytes.freeze().try_into()?
        };

        let ProxyMessage {
            unique_id,
            user_token,
            encryption,
            payload: encrypted_proxy_message_payload,
            ..
        } = encrypted_proxy_message;

        let original_proxy_message_payload = match encryption {
            Encryption::Plain => encrypted_proxy_message_payload,
            Encryption::Aes(ref encryption_token) => {
                let rsa_crypto = self.rsa_crypto_fetcher.fetch(&user_token)?;
                let mut proxy_message_payload = BytesMut::new();
                proxy_message_payload.extend_from_slice(&encrypted_proxy_message_payload);
                let original_encryption_token = Bytes::from(rsa_crypto.decrypt(encryption_token)?);
                decrypt_with_aes(&original_encryption_token, &mut proxy_message_payload)?.freeze()
            }
        };

        self.status = DecodeStatus::Head;
        src.reserve(HEADER_LENGTH);

        let proxy_message_framed = ProxyMessage::new(
            unique_id,
            user_token,
            encryption,
            original_proxy_message_payload,
        );
        Ok(Some(proxy_message_framed))
    }
}

/// Encode the ppaass message to bytes buffer
impl<F> Encoder<AgentMessage> for ProxyConnectionCodec<F>
where
    F: RsaCryptoFetcher,
{
    type Error = EncoderError;

    fn encode(
        &mut self,
        original_agent_message: AgentMessage,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        trace!(
            "Encode message to output(decrypted): {:?}",
            original_agent_message
        );
        dst.put(PPAASS_FLAG);
        if self.compress {
            dst.put_u8(COMPRESS_FLAG);
        } else {
            dst.put_u8(UNCOMPRESS_FLAG);
        }
        let AgentMessage {
            unique_id,
            user_token,
            encryption,
            payload: original_agent_message_payload,
            ..
        } = original_agent_message;

        let (encrypted_agent_message_payload, encrypted_payload_encryption_type) = match encryption
        {
            Encryption::Plain => (original_agent_message_payload, Encryption::Plain),
            Encryption::Aes(ref original_token) => {
                let rsa_crypto = self.rsa_crypto_fetcher.fetch(&user_token)?;
                let encrypted_encryption_token = Bytes::from(rsa_crypto.encrypt(original_token)?);
                let mut original_agent_message_payload = {
                    let mut agent_message_payload = BytesMut::new();
                    agent_message_payload.extend_from_slice(&original_agent_message_payload);
                    agent_message_payload
                };

                let encrypted_agent_message_payload =
                    encrypt_with_aes(original_token, &mut original_agent_message_payload)?.freeze();
                (
                    encrypted_agent_message_payload,
                    Encryption::Aes(encrypted_encryption_token),
                )
            }
        };

        let agent_message = AgentMessage::new(
            unique_id,
            user_token,
            encrypted_payload_encryption_type,
            encrypted_agent_message_payload,
        );
        let bytes_framed: Bytes = agent_message.try_into()?;
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
