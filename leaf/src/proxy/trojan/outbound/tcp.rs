use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};

use crate::{
    app::dns_client::DnsClient,
    proxy::{BufHeadProxyStream, OutboundConnect, ProxyStream, TcpConnector, TcpOutboundHandler},
    session::{Session, SocksAddrWireType},
};

use super::stream::*;

use shadowsocks::{
    relay::tcprelay::crypto_io::*,
    context::*,
    config::*,
    crypto::v1::*
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub password: String,
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
        let stream = if let Some(stream) = stream {
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
        let mut buf = BytesMut::new();
        let password = Sha224::digest(self.password.as_bytes());
        let password = hex::encode(&password[..]);
        buf.put_slice(password.as_bytes());
        buf.put_slice(b"\r\n");
        buf.put_u8(0x01); // tcp
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast)?;
        buf.put_slice(b"\r\n");

        let password = "123456";
        let method = CipherKind::AES_128_GCM;
        let mut enc_key = vec![0u8; method.key_len()].into_boxed_slice();
        openssl_bytes_to_key(password.as_bytes(), &mut enc_key);
        let stream = TrojanStream::new(stream, method, enc_key.as_ref()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("create shadowsocks stream failed: {}", e),
            )
        })?;
        // FIXME receive-only conns
        Ok(Box::new(BufHeadProxyStream::new(stream, buf.freeze())))
    }
}
