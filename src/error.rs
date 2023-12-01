use ppaass_crypto::CryptoError;
use ppaass_protocol::error::ProtocolError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncoderError {
    #[error("I/O error happen: {0:?}")]
    Io(#[from] std::io::Error),
    #[error("Protocol error happen: {0:?}")]
    Protocol(#[from] ProtocolError),
    #[error("Crypto error happen: {0:?}")]
    Crypto(#[from] CryptoError),
    #[error("Other error happen: {0:?}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum DecoderError {
    #[error("I/O error happen: {0:?}")]
    Io(#[from] std::io::Error),
    #[error("Protocol error happen: {0:?}")]
    Protocol(#[from] ProtocolError),
    #[error("Crypto error happen: {0:?}")]
    Crypto(#[from] CryptoError),
    #[error("Other error happen: {0:?}")]
    Other(String),
}
