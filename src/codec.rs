use crate::error::CodecError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use ppaass_crypto::crypto::{decrypt_with_aes, encrypt_with_aes, RsaCryptoFetcher};
use ppaass_crypto::error::CryptoError;
use ppaass_protocol::message::{PpaassPacket, PpaassPacketPayloadEncryption};
use std::io::{Read, Write};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};
use tracing::error;
struct PpaassPacketEncoder<'a, T>
where
    T: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: &'a T,
    length_delimited_codec: LengthDelimitedCodec,
}

impl<'a, T> PpaassPacketEncoder<'a, T>
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
impl<'a, T> Encoder<PpaassPacket> for PpaassPacketEncoder<'a, T>
where
    T: RsaCryptoFetcher,
{
    type Error = CodecError;

    fn encode(
        &mut self,
        original_packet: PpaassPacket,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let rsa_crypto = self
            .rsa_crypto_fetcher
            .fetch(original_packet.user_token())?
            .ok_or(CryptoError::Other(format!(
                "Crypto not exist for user: {}",
                original_packet.user_token()
            )))?;

        let (encrypted_payload_bytes, encrypted_encryption) = match original_packet.encryption() {
            PpaassPacketPayloadEncryption::Plain => (
                original_packet.payload().to_vec(),
                PpaassPacketPayloadEncryption::Plain,
            ),
            PpaassPacketPayloadEncryption::Aes(ref original_aes_token) => {
                let rsa_encrypted_aes_token = Bytes::from(rsa_crypto.encrypt(original_aes_token)?);
                let mut original_payload_bytes: BytesMut =
                    BytesMut::from(original_packet.payload());
                let aes_encrypted_payload_bytes =
                    encrypt_with_aes(original_aes_token, &mut original_payload_bytes)?;
                (
                    aes_encrypted_payload_bytes.to_vec(),
                    PpaassPacketPayloadEncryption::Aes(rsa_encrypted_aes_token),
                )
            }
        };

        let packet_to_send = PpaassPacket::new(
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

struct PpaassPacketDecoder<'a, T>
where
    T: RsaCryptoFetcher,
{
    rsa_crypto_fetcher: &'a T,
    length_delimited_codec: LengthDelimitedCodec,
}

impl<'a, T> PpaassPacketDecoder<'a, T>
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
impl<'a, T> Decoder for PpaassPacketDecoder<'a, T>
where
    T: RsaCryptoFetcher,
{
    type Item = PpaassPacket;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let length_decode_result = self.length_delimited_codec.decode(src)?;
        let decompressed_packet: PpaassPacket = match length_decode_result {
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
            PpaassPacketPayloadEncryption::Plain => decompressed_packet,
            PpaassPacketPayloadEncryption::Aes(rsa_encrypted_aes_token) => {
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
                PpaassPacket::new(
                    decompressed_packet.packet_id().to_owned(),
                    decompressed_packet.user_token().to_owned(),
                    PpaassPacketPayloadEncryption::Aes(decrypted_aes_token),
                    decrypted_payload,
                )
            }
        };
        Ok(Some(decrypted_packed))
    }
}

pub struct PpaassPacketCodec<'a, T>
where
    T: RsaCryptoFetcher,
{
    encoder: PpaassPacketEncoder<'a, T>,
    decoder: PpaassPacketDecoder<'a, T>,
}

impl<'a, T> PpaassPacketCodec<'a, T>
where
    T: RsaCryptoFetcher,
{
    pub fn new(rsa_crypto_fetcher: &'a T) -> Self {
        Self {
            encoder: PpaassPacketEncoder::new(&rsa_crypto_fetcher),
            decoder: PpaassPacketDecoder::new(&rsa_crypto_fetcher),
        }
    }
}

impl<'a, T> Encoder<PpaassPacket> for PpaassPacketCodec<'a, T>
where
    T: RsaCryptoFetcher,
{
    type Error = CodecError;
    fn encode(&mut self, item: PpaassPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encoder.encode(item, dst)
    }
}

impl<'a, T> Decoder for PpaassPacketCodec<'a, T>
where
    T: RsaCryptoFetcher,
{
    type Item = PpaassPacket;
    type Error = CodecError;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decoder.decode(src)
    }
}
