use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, Stream};
use pin_project::pin_project;
use ppaass_crypto::{random_16_bytes, RsaCryptoFetcher};
use ppaass_protocol::message::{AgentMessage, ProxyMessage};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::{proxy::ProxyConnectionCodec, DecoderError, EncoderError};

#[non_exhaustive]
#[pin_project]
pub struct ProxyConnection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    #[pin]
    inner: Framed<T, ProxyConnectionCodec<R>>,
    connection_id: String,
}

impl<T, R> ProxyConnection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub fn new(
        stream: T,
        rsa_crypto_fetcher: R,
        compress: bool,
        buffer_size: usize,
    ) -> ProxyConnection<T, R> {
        let proxy_connection_codec = ProxyConnectionCodec::new(compress, rsa_crypto_fetcher);
        let inner = Framed::with_capacity(stream, proxy_connection_codec, buffer_size);
        Self {
            inner,
            connection_id: String::from_utf8_lossy(random_16_bytes().as_ref()).to_string(),
        }
    }
}

impl<T, R> Sink<AgentMessage> for ProxyConnection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    type Error = EncoderError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: AgentMessage) -> Result<(), Self::Error> {
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

impl<T, R> Stream for ProxyConnection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    type Item = Result<ProxyMessage, DecoderError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.inner.poll_next(cx)
    }
}
