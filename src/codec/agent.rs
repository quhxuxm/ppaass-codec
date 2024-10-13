use super::DecodeStatus;
use crate::error::CodecError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use log::{error, trace};
use ppaass_crypto::crypto::{decrypt_with_aes, encrypt_with_aes, RsaCryptoFetcher};
use ppaass_crypto::error::CryptoError;
use ppaass_protocol::message::{Encryption, Packet};
use pretty_hex::*;
use std::{
    io::{Read, Write},
    mem::size_of,
};
use tokio_util::codec::{Decoder, Encoder};
const PPAASS_FLAG: &[u8] = "__PPAASS__".as_bytes();
const HEADER_LENGTH: usize = PPAASS_FLAG.len() + size_of::<u64>();

pub struct MessageEncoder<T>
where
    T: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: T,
}

impl<T> MessageEncoder<T>
where
    T: RsaCryptoFetcher,
{
    pub fn new(compress: bool, rsa_crypto_fetcher: T) -> Self {
        Self { rsa_crypto_fetcher }
    }
}

/// Encode the ppaass message to bytes buffer
impl<T> Encoder<Packet> for MessageEncoder<T>
where
    T: RsaCryptoFetcher,
{
    type Error = CodecError;

    fn encode(&mut self, original_message: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        trace!(
            "Encode message to output(decrypted): {:?}",
            original_message
        );
        dst.put(PPAASS_FLAG);
        let Packet {
            packet_id,
            user_token,
            encryption,
            payload,
        } = original_message;

        let rsa_crypto = self
            .rsa_crypto_fetcher
            .fetch(&user_token)?
            .ok_or(CryptoError::Other(format!(
                "Crypto not exist for user: {user_token}"
            )))?;

        let (encrypted_payload_bytes, encrypted_encryption) = match encryption {
            Encryption::Plain => (payload, Encryption::Plain),
            Encryption::Aes(ref original_aes_token) => {
                let rsa_encrypted_aes_token = Bytes::from(rsa_crypto.encrypt(original_aes_token)?);

                let mut original_payload_bytes: BytesMut = BytesMut::from_iter(payload);

                let aes_encrypted_payload_bytes =
                    encrypt_with_aes(original_aes_token, &mut original_payload_bytes)?.freeze();
                (
                    aes_encrypted_payload_bytes,
                    Encryption::Aes(rsa_encrypted_aes_token),
                )
            }
        };

        let packet = Packet::new(
            packet_id,
            user_token,
            encrypted_encryption,
            encrypted_payload_bytes,
        );
        let packet_bytes: Bytes = packet.try_into()?;
        let gz_encoder_buf = BytesMut::new();
        let mut gzip_encoder = GzEncoder::new(gz_encoder_buf.writer(), Compression::fast());
        gzip_encoder.write_all(&packet_bytes)?;
        let packet_bytes = gzip_encoder.finish()?.into_inner().freeze();
        let result_bytes_length = packet_bytes.len();
        dst.put_u64(result_bytes_length as u64);
        dst.put(packet_bytes.as_ref());
        Ok(())
    }
}

pub struct PacketDecoder<T>
where
    T: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: T,
    status: DecodeStatus,
    non_plain_original_encryption_token_cache: Option<Bytes>,
}

impl<T> PacketDecoder<T>
where
    T: RsaCryptoFetcher,
{
    pub fn new(rsa_crypto_fetcher: T) -> Self {
        Self {
            rsa_crypto_fetcher,
            status: DecodeStatus::Head,
            non_plain_original_encryption_token_cache: None,
        }
    }
}

/// Decode the input bytes buffer to ppaass message
impl<T> Decoder for PacketDecoder<T>
where
    T: RsaCryptoFetcher,
{
    type Item = Packet;
    type Error = CodecError;

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
                    return Err(CodecError::Other(format!(
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
        let encrypted_message: CodecPpaassMessage = if compressed {
            let mut gzip_decoder = GzDecoder::new(body_bytes.reader());
            let mut decompressed_bytes = Vec::new();
            if let Err(e) = gzip_decoder.read_to_end(&mut decompressed_bytes) {
                error!("Fail to decompress incoming message bytes because of error: {e:?}");
                return Err(CodecError::StdIo(e));
            };
            let decompressed_bytes = Bytes::from_iter(decompressed_bytes);
            trace!(
                "Decompressed bytes will convert to PpaassMessage:\n{}\n",
                pretty_hex::pretty_hex(&decompressed_bytes)
            );
            decompressed_bytes.try_into()?
        } else {
            trace!(
                "Raw bytes will convert to PpaassMessage:\n{}\n",
                pretty_hex::pretty_hex(&body_bytes)
            );
            body_bytes.freeze().try_into()?
        };

        let CodecPpaassMessage {
            message_id,
            user_token,
            encryption: payload_encryption,
            payload: encrypted_message_payload,
        } = encrypted_message;

        let rsa_crypto = self
            .rsa_crypto_fetcher
            .fetch(&user_token)?
            .ok_or(CryptoError::Other(format!(
                "Crypto not exist for user: {user_token}"
            )))?;

        let decrypt_payload_bytes = match payload_encryption {
            PpaassMessagePayloadEncryption::Plain => encrypted_message_payload,
            PpaassMessagePayloadEncryption::Aes(ref encryption_token) => {
                let original_encryption_token = match self.non_plain_original_encryption_token_cache
                {
                    None => {
                        let original_encryption_token =
                            Bytes::from(rsa_crypto.decrypt(encryption_token)?);
                        self.non_plain_original_encryption_token_cache =
                            Some(original_encryption_token.clone());
                        original_encryption_token
                    }
                    Some(ref token) => token.clone(),
                };
                let mut encrypted_message_payload = BytesMut::from_iter(encrypted_message_payload);
                decrypt_with_aes(&original_encryption_token, &mut encrypted_message_payload)?
                    .freeze()
            }
        };
        self.status = DecodeStatus::Head;
        src.reserve(HEADER_LENGTH);
        let message_framed = Packet::new(
            message_id,
            user_token,
            payload_encryption,
            decrypt_payload_bytes.try_into()?,
        );
        Ok(Some(message_framed))
    }
}
