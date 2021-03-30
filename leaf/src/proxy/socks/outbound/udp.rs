use std::{
    io::{Error, ErrorKind, Result},
    net::SocketAddr,
    sync::Arc,
};

use async_socks5::{AddrKind, Auth, SocksDatagram};
use async_trait::async_trait;
use futures::future::TryFutureExt;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    app::dns_client::DnsClient,
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
        OutboundTransport, TcpConnector, UdpConnector, UdpOutboundHandler, UdpTransportType,
    },
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

impl TcpConnector for Handler {}
impl UdpConnector for Handler {}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn udp_connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Proxy(
            self.address.clone(),
            self.port,
            self.bind_addr,
        ))
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Packet
    }

    async fn handle_udp<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<OutboundTransport>,
    ) -> Result<Box<dyn OutboundDatagram>> {
        // TODO support chaining, this requires implementing our own socks5 client
        let stream = self
            .dial_tcp_stream(
                self.dns_client.clone(),
                &self.bind_addr,
                &self.address,
                &self.port,
            )
            .await?;
        let socket = self.create_udp_socket(&self.bind_addr).await?;
        let socket = SocksDatagram::associate(stream, socket, None::<Auth>, None::<AddrKind>)
            .map_err(|x| Error::new(ErrorKind::Other, x))
            .await?;
        Ok(Box::new(Datagram { socket }))
    }
}

pub struct Datagram<S> {
    pub socket: SocksDatagram<S>,
}

impl<S> OutboundDatagram for Datagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let rh = Arc::new(self.socket);
        let sh = rh.clone();
        (
            Box::new(DatagramRecvHalf(rh)),
            Box::new(DatagramSendHalf(sh)),
        )
    }
}

pub struct DatagramRecvHalf<S>(Arc<SocksDatagram<S>>);

#[async_trait]
impl<S> OutboundDatagramRecvHalf for DatagramRecvHalf<S>
where
    S: 'static + AsyncRead + AsyncWrite + Send + Unpin + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocksAddr)> {
        let (n, addr) = self
            .0
            .recv_from(buf)
            .map_err(|x| Error::new(ErrorKind::Other, x))
            .await?;
        match addr {
            AddrKind::Ip(addr) => Ok((n, SocksAddr::Ip(addr))),
            AddrKind::Domain(domain, port) => Ok((n, SocksAddr::Domain(domain, port))),
        }
    }
}

pub struct DatagramSendHalf<S>(Arc<SocksDatagram<S>>);

#[async_trait]
impl<S> OutboundDatagramSendHalf for DatagramSendHalf<S>
where
    S: 'static + AsyncRead + AsyncWrite + Send + Unpin + Sync,
{
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> Result<usize> {
        match target {
            SocksAddr::Ip(a) => {
                self.0
                    .send_to(buf, a.to_owned())
                    .map_ok(|_| buf.len())
                    .map_err(|x| Error::new(ErrorKind::Other, x))
                    .await
            }
            // FIXME for this, we need our own socks5 impl
            _ => Err(Error::new(
                ErrorKind::Other,
                "socks outbound does not support sending UDP packets to domain address",
            )),
        }
    }
}
