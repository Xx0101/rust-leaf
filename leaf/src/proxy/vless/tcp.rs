use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    app::dns_client::DnsClient,
    proxy::{stream::SimpleProxyStream, OutboundConnect, ProxyStream, TcpConnector, TcpOutboundHandler},
    session::{Session, SocksAddrWireType},
};

use super::*;

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

impl TcpConnector for Handler {}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Proxy(
            self.address.clone(),
            self.port,
            self.bind_addr,
        ))
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        let uuid = Uuid::parse_str(&self.uuid).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("parse uuid failed: {}", e))
        })?;
        let mut buf = BytesMut::new();
        buf.put_u8(0x0); // version
        buf.put_slice(uuid.as_bytes()); // uuid
        buf.put_u8(0x0); // addons
        buf.put_u8(0x01); // tcp command
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortFirst)?;

        let mut stream = if let Some(stream) = stream {
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

        stream.write_all(&buf[..]).await?;
        let stream = VLessAuthStream::new(stream);
        Ok(Box::new(SimpleProxyStream(stream)))
    }
}
