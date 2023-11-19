use std::{
    fmt::{Debug, Formatter},
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::{Sink, Stream};
use pin_project::pin_project;
use ppaass_crypto::{random_32_bytes, RsaCryptoFetcher};
use ppaass_protocol::message::WrapperMessage;
use std::fmt::Result as FmtResult;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::{ConnectionCodec, DecoderError, EncoderError};

#[non_exhaustive]
#[pin_project]
pub struct Connection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    #[pin]
    inner: Framed<T, ConnectionCodec<R>>,
    connection_id: String,
}

impl<T, R> Connection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub fn new(
        stream: T,
        rsa_crypto_fetcher: R,
        compress: bool,
        buffer_size: usize,
    ) -> Connection<T, R> {
        let _connection_codec = ConnectionCodec::new(compress, rsa_crypto_fetcher);
        let inner = Framed::with_capacity(stream, _connection_codec, buffer_size);
        Self {
            inner,
            connection_id: String::from_utf8_lossy(random_32_bytes().as_ref()).to_string(),
        }
    }

    pub fn get_connection_id(&self) -> &str {
        &self.connection_id
    }
}

impl<T, R> Debug for Connection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Connection")
            .field("connection_id", &self.connection_id)
            .field("inner", &"<OBJ>")
            .finish()
    }
}

impl<T, R> Sink<WrapperMessage> for Connection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    type Error = EncoderError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: WrapperMessage) -> Result<(), Self::Error> {
        let this = self.project();
        this.inner.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_close(cx)
    }
}

impl<T, R> Stream for Connection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    type Item = Result<WrapperMessage, DecoderError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.inner.poll_next(cx)
    }
}
