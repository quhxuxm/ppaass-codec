use crate::error::CodecError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use ppaass_crypto::crypto::{decrypt_with_aes, encrypt_with_aes, RsaCryptoFetcher};
use ppaass_crypto::error::CryptoError;
use ppaass_protocol::message::{Encryption, Packet};
use std::io::{Read, Write};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};
use tracing::error;
struct PacketEncoder<'a, T>
where
    T: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: &'a T,
    length_delimited_codec: LengthDelimitedCodec,
}

impl<'a, T> PacketEncoder<'a, T>
where
    T: RsaCryptoFetcher,
{
    pub fn new(rsa_crypto_fetcher: &'a T) -> Self {
        Self {
            rsa_crypto_fetcher,
            length_delimited_codec: LengthDelimitedCodec::new(),
        }
    }
}

/// Encode the ppaass message to bytes buffer
impl<'a, T> Encoder<Packet> for PacketEncoder<'a, T>
where
    T: RsaCryptoFetcher,
{
    type Error = CodecError;

    fn encode(&mut self, original_packet: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let rsa_crypto = self
            .rsa_crypto_fetcher
            .fetch(original_packet.user_token())?
            .ok_or(CryptoError::Other(format!(
                "Crypto not exist for user: {}",
                original_packet.user_token()
            )))?;

        let (encrypted_payload_bytes, encrypted_encryption) = match original_packet.encryption() {
            Encryption::Plain => (original_packet.payload().to_vec(), Encryption::Plain),
            Encryption::Aes(ref original_aes_token) => {
                let rsa_encrypted_aes_token = Bytes::from(rsa_crypto.encrypt(original_aes_token)?);
                let mut original_payload_bytes: BytesMut =
                    BytesMut::from(original_packet.payload());
                let aes_encrypted_payload_bytes =
                    encrypt_with_aes(original_aes_token, &mut original_payload_bytes)?;
                (
                    aes_encrypted_payload_bytes.to_vec(),
                    Encryption::Aes(rsa_encrypted_aes_token),
                )
            }
        };

        let packet_to_send = Packet::new(
            original_packet.packet_id().to_owned(),
            original_packet.user_token().to_owned(),
            encrypted_encryption,
            encrypted_payload_bytes.into(),
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

struct PacketDecoder<'a, T>
where
    T: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: &'a T,
    length_delimited_codec: LengthDelimitedCodec,
}

impl<'a, T> PacketDecoder<'a, T>
where
    T: RsaCryptoFetcher,
{
    pub fn new(rsa_crypto_fetcher: &'a T) -> Self {
        Self {
            rsa_crypto_fetcher,
            length_delimited_codec: LengthDelimitedCodec::new(),
        }
    }
}

/// Decode the input bytes buffer to ppaass message
impl<'a, T> Decoder for PacketDecoder<'a, T>
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
                let decrypted_payload =
                    decrypt_with_aes(&decrypted_aes_token, &mut decrypted_payload_bytes)?.freeze();
                Packet::new(
                    decompressed_packet.packet_id().to_owned(),
                    decompressed_packet.user_token().to_owned(),
                    Encryption::Aes(decrypted_aes_token),
                    decrypted_payload,
                )
            }
        };
        Ok(Some(decrypted_packed))
    }
}

pub struct PacketCodec<'a, T>
where
    T: RsaCryptoFetcher,
{
    encoder: PacketEncoder<'a, T>,
    decoder: PacketDecoder<'a, T>,
}

impl<'a, T> PacketCodec<'a, T>
where
    T: RsaCryptoFetcher,
{
    pub fn new(rsa_crypto_fetcher: &'a T) -> Self {
        Self {
            encoder: PacketEncoder::new(&rsa_crypto_fetcher),
            decoder: PacketDecoder::new(&rsa_crypto_fetcher),
        }
    }
}
