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
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};
const PPAASS_FLAG: &[u8] = "__PPAASS__".as_bytes();
const HEADER_LENGTH: usize = PPAASS_FLAG.len() + size_of::<u64>();

pub struct MessageEncoder<T>
where
    T: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: T,
    length_delimited_codec: LengthDelimitedCodec,
}

impl<T> MessageEncoder<T>
where
    T: RsaCryptoFetcher,
{
    pub fn new(rsa_crypto_fetcher: T) -> Self {
        Self {
            rsa_crypto_fetcher,
            length_delimited_codec: LengthDelimitedCodec::new(),
        }
    }
}

/// Encode the ppaass message to bytes buffer
impl<T> Encoder<Packet> for MessageEncoder<T>
where
    T: RsaCryptoFetcher,
{
    type Error = CodecError;

    fn encode(&mut self, original_packet: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let Packet {
            packet_id,
            user_token,
            encryption,
            payload,
        } = original_packet;
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

        let packet_to_send = Packet::new(
            packet_id,
            user_token,
            encrypted_encryption,
            encrypted_payload_bytes,
        );
        let packet_bytes_to_send: Bytes = packet_to_send.try_into()?;
        let gz_encoder_buf = BytesMut::new();
        let mut gzip_encoder = GzEncoder::new(gz_encoder_buf.writer(), Compression::fast());
        gzip_encoder.write_all(&packet_bytes_to_send)?;
        let packet_bytes_to_send = gzip_encoder.finish()?.into_inner().freeze();
        self.length_delimited_codec
            .encode(packet_bytes_to_send, dst)?;
        Ok(())
    }
}

pub struct PacketDecoder<T>
where
    T: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: T,
    length_delimited_codec: LengthDelimitedCodec,
}

impl<T> PacketDecoder<T>
where
    T: RsaCryptoFetcher,
{
    pub fn new(rsa_crypto_fetcher: T) -> Self {
        Self {
            rsa_crypto_fetcher,
            length_delimited_codec: LengthDelimitedCodec::new(),
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
        let length_decode_result = self.length_delimited_codec.decode(src)?;
        let decompressed_packet: Packet = match length_decode_result {
            None => return Ok(None),
            Some(packet_bytes) => {
                let mut gzip_decoder = GzDecoder::new(packet_bytes.reader());
                let mut decompressed_packet_bytes = Vec::new();
                if let Err(e) = gzip_decoder.read_to_end(&mut decompressed_packet_bytes) {
                    error!("Fail to decompress incoming message bytes because of error: {e:?}");
                    return Err(CodecError::StdIo(e));
                };
                let decompressed_packet_bytes = Bytes::from_iter(decompressed_packet_bytes);
                decompressed_packet_bytes.try_into()?
            }
        };
        let decrypted_packed = match decompressed_packet.encryption() {
            Encryption::Plain => decompressed_packet,
            Encryption::Aes(rsa_encrypted_aes_token) => {
                let rsa_crypto = self
                    .rsa_crypto_fetcher
                    .fetch(decompressed_packet.user_token())?
                    .ok_or(CryptoError::Other(format!(
                        "Crypto not exist for user: {}",
                        decompressed_packet.user_token()
                    )))?;
                let decrypted_aes_token = Bytes::from(rsa_crypto.decrypt(rsa_encrypted_aes_token)?);
                let mut decrypted_payload_bytes =
                    BytesMut::from_iter(decompressed_packet.payload());
                decrypt_with_aes(&decrypted_aes_token, &mut decrypted_payload)?.freeze();
                todo!()
            }
        };

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
