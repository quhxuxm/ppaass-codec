use std::{
    fmt::{Debug, Display},
    pin::Pin,
    task::{Context, Poll},
};

use pin_project::pin_project;
use ppaass_crypto::{random_16_bytes, RsaCryptoFetcher};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::agent::AgentConnectionCodec;

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
            connection_id: random_16_bytes(),
        }
    }

    pub fn get_connection_id(&self) -> &I {
        &self.connection_id
    }
}

impl<T, R, I> Sink<PpaassProxyMessage> for PpaassAgentConnection<'_, T, R, I>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
    I: ToString + Send + Sync + Clone + Display + Debug + 'static,
{
    type Error = CommonError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: PpaassProxyMessage) -> Result<(), Self::Error> {
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

impl<T, R, I> Stream for PpaassAgentConnection<'_, T, R, I>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    R: RsaCryptoFetcher + Send + Sync + 'static,
    I: ToString + Send + Sync + Clone + Display + Debug + 'static,
{
    type Item = Result<PpaassAgentMessage, CommonError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.inner.poll_next(cx)
    }
}
