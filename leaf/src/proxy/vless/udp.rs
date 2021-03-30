use std::cmp::min;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::future::TryFutureExt;
use log::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use uuid::Uuid;

use crate::{
    app::dns_client::DnsClient,
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
        OutboundTransport, TcpConnector, UdpOutboundHandler, UdpTransportType,
    },
    session::{Session, SocksAddr, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

impl TcpConnector for Handler {}

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
        UdpTransportType::Stream
    }

    async fn handle_udp<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        let uuid = Uuid::parse_str(&self.uuid).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("parse uuid failed: {}", e))
        })?;
        let mut buf = BytesMut::new();
        buf.put_u8(0x0); // version
        buf.put_slice(uuid.as_bytes()); // uuid
        buf.put_u8(0x0); // addons
        buf.put_u8(0x02); // ucp command
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortFirst)?;

        let mut stream = if let Some(OutboundTransport::Stream(stream)) = transport {
            stream
        } else {
            self.dial_tcp_stream(
                self.dns_client.clone(),
                &self.bind_addr,
                &self.address,
                &self.port,
            )
            .await?
        };

        let destination = match &sess.destination {
            SocksAddr::Domain(domain, port) => {
                Some(SocksAddr::Domain(domain.to_owned(), port.to_owned()))
            }
            _ => None,
        };

        stream.write_all(&buf[..]).await?;
        Ok(Box::new(Datagram {
            stream,
            destination,
            head: Some(buf),
        }))
    }
}

pub struct Datagram<S> {
    stream: S,
    destination: Option<SocksAddr>,
    head: Option<BytesMut>,
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
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(DatagramRecvHalf(r, self.destination)),
            Box::new(DatagramSendHalf(w, self.head)),
        )
    }
}

pub struct DatagramRecvHalf<T>(ReadHalf<T>, Option<SocksAddr>);

#[async_trait]
impl<T> OutboundDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let mut buf2 = BytesMut::new();
        let addr = SocksAddr::read_from(&mut self.0, SocksAddrWireType::PortLast).await?;
        if self.1.is_some() {
            buf2.resize(1, 0);
            let _ = self.0.read_exact(&mut buf2).await?;
            if buf2[0] != 0x0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("invalid vless version: {}", buf2[0]),
                ));
            }

            // read addons
            buf2.resize(1, 0);
            let _ = self.0.read_exact(&mut buf2).await?;
            if buf2[0] != 0x0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("invalid vless version: {}", buf2[0]),
                ));
            }
        }

        buf2.resize(2, 0);
        let _ = self.0.read_exact(&mut buf2).await?;
        let payload_len = BigEndian::read_u16(&buf2);
        buf2.resize(payload_len as usize, 0);
        let _ = self.0.read_exact(&mut buf2).await?;
        let to_write = min(buf2.len(), buf.len());
        if to_write < buf2.len() {
            warn!(
                "trucated udp payload, buf size too small: {} < {}",
                buf.len(),
                buf2.len()
            );
        }
        buf[..to_write].copy_from_slice(&buf2[..to_write]);
        if self.1.is_some() {
            Ok((to_write, self.1.as_ref().unwrap().clone()))
        } else {
            Ok((to_write, addr))
        }
    }
}

pub struct DatagramSendHalf<T>(WriteHalf<T>, Option<BytesMut>);

#[async_trait]
impl<T> OutboundDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let mut data = BytesMut::new();
        target.write_buf(&mut data, SocksAddrWireType::PortLast)?;
        data.put_u16(buf.len() as u16);
        data.put_slice(buf);
        self.0.write_all(&data).map_ok(|_| buf.len()).await
    }
}
