use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::{Sink, Stream};
use pin_project::pin_project;
use ppaass_crypto::{random_16_bytes, RsaCryptoFetcher};
use ppaass_protocol::message::{AgentMessage, ProxyMessage};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::{agent::AgentConnectionCodec, DecoderError, EncoderError};

#[non_exhaustive]
#[pin_project]
pub struct AgentConnection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    #[pin]
    inner: Framed<T, AgentConnectionCodec<R>>,
    connection_id: String,
}

impl<T, R> AgentConnection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub fn new(
        stream: T,
        rsa_crypto_fetcher: R,
        compress: bool,
        buffer_size: usize,
    ) -> AgentConnection<T, R> {
        let agent_connection_codec = AgentConnectionCodec::new(compress, rsa_crypto_fetcher);
        let inner = Framed::with_capacity(stream, agent_connection_codec, buffer_size);
        Self {
            inner,
            connection_id: String::from_utf8_lossy(random_16_bytes().as_ref()).to_string(),
        }
    }
}

impl<T, R> Sink<ProxyMessage> for AgentConnection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    type Error = EncoderError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: ProxyMessage) -> Result<(), Self::Error> {
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

impl<T, R> Stream for AgentConnection<T, R>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
{
    type Item = Result<AgentMessage, DecoderError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.inner.poll_next(cx)
    }
}
