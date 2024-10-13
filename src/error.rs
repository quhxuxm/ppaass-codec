use ppaass_crypto::error::CryptoError;
use ppaass_protocol::error::ProtocolError;
use thiserror::Error;
#[derive(Error, Debug)]
pub enum CodecError {
    #[error("Codec error happen because of io: {_0:?}")]
    StdIo(#[from] std::io::Error),
    #[error("Codec error happen because of protocol: {_0:?}")]
    Protocol(#[from] ProtocolError),
    #[error("Codec error happen because of crypto: {_0:?}")]
    Crypto(#[from] CryptoError),
    #[error("Bincode error: {_0:?}")]
    Bincode(#[from] bincode::Error),
    #[error("Codec error happen because of reason: {_0}")]
    Other(String),
}
