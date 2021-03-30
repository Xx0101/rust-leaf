use std::{
    convert::TryFrom,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    string::ToString,
};

use byteorder::{BigEndian, ByteOrder};
use bytes::BufMut;
use log::*;
use tokio::io::{AsyncRead, AsyncReadExt};

pub type StreamId = u16;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct DatagramSource {
    pub address: SocketAddr,
    pub stream_id: Option<StreamId>,
}

impl DatagramSource {
    pub fn new(address: SocketAddr, stream_id: Option<StreamId>) -> Self {
        DatagramSource { address, stream_id }
    }
}

impl std::fmt::Display for DatagramSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(id) = self.stream_id.as_ref() {
            write!(f, "{}(stream-{})", self.address, id)
        } else {
            write!(f, "{}", self.address)
        }
    }
}

pub struct Session {
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The socket address of the local socket of an inbound connection.
    pub local_addr: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: SocksAddr,
    /// The tag of the inbound handler this session initiated.
    pub inbound_tag: String,
    /// Optional stream ID for multiplexing transports.
    pub stream_id: Option<StreamId>,
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Session {
            source: self.source,
            local_addr: self.local_addr,
            destination: self.destination.clone(),
            inbound_tag: self.inbound_tag.clone(),
            stream_id: self.stream_id,
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Session {
            source: "0.0.0.0:0".parse().unwrap(),
            local_addr: "0.0.0.0:0".parse().unwrap(),
            destination: SocksAddr::empty_ipv4(),
            inbound_tag: "".to_string(),
            stream_id: None,
        }
    }
}

struct SocksAddrPortLastType;

impl SocksAddrPortLastType {
    const V4: u8 = 0x1;
    const V6: u8 = 0x4;
    const DOMAIN: u8 = 0x3;
}

struct SocksAddrPortFirstType;

impl SocksAddrPortFirstType {
    const V4: u8 = 0x1;
    const V6: u8 = 0x3;
    const DOMAIN: u8 = 0x2;
}

pub enum SocksAddrWireType {
    PortFirst,
    PortLast,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

const INSUFF_BYTES: &str = "insufficient bytes";

fn invalid_domain() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "invalid domain")
}

fn invalid_addr_type() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "invalid address type")
}

impl SocksAddr {
    pub fn empty_ipv4() -> Self {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        Self::from(addr)
    }

    pub fn must_ip(self) -> SocketAddr {
        match self {
            SocksAddr::Ip(a) => a,
            _ => {
                error!("assert SocksAddr as SocketAddr failed");
                panic!("");
            }
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(_addr) => 1 + 4 + 2,
                SocketAddr::V6(_addr) => 1 + 16 + 2,
            },
            Self::Domain(domain, _port) => 1 + 1 + domain.len() + 2,
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            SocksAddr::Ip(addr) => addr.port(),
            SocksAddr::Domain(_, port) => *port,
        }
    }

    pub fn is_domain(&self) -> bool {
        match self {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(_, _) => true,
        }
    }

    pub fn domain(&self) -> Option<&String> {
        if let SocksAddr::Domain(domain, _) = self {
            Some(domain)
        } else {
            None
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        if let SocksAddr::Ip(addr) = self {
            Some(addr.ip())
        } else {
            None
        }
    }

    pub fn host(&self) -> String {
        match self {
            SocksAddr::Ip(addr) => {
                let ip = addr.ip();
                ip.to_string()
            }
            SocksAddr::Domain(domain, _) => domain.to_owned(),
        }
    }

    /// Writes `self` into `buf`.
    pub fn write_buf<T: BufMut>(
        &self,
        buf: &mut T,
        addr_type: SocksAddrWireType,
    ) -> io::Result<()> {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(addr) => match addr_type {
                    SocksAddrWireType::PortLast => {
                        buf.put_u8(SocksAddrPortLastType::V4);
                        buf.put_slice(&addr.ip().octets());
                        buf.put_u16(addr.port());
                    }
                    SocksAddrWireType::PortFirst => {
                        buf.put_u16(addr.port());
                        buf.put_u8(SocksAddrPortFirstType::V4);
                        buf.put_slice(&addr.ip().octets());
                    }
                },
                SocketAddr::V6(addr) => match addr_type {
                    SocksAddrWireType::PortLast => {
                        buf.put_u8(SocksAddrPortLastType::V6);
                        buf.put_slice(&addr.ip().octets());
                        buf.put_u16(addr.port());
                    }
                    SocksAddrWireType::PortFirst => {
                        buf.put_u16(addr.port());
                        buf.put_u8(SocksAddrPortFirstType::V6);
                        buf.put_slice(&addr.ip().octets());
                    }
                },
            },
            Self::Domain(domain, port) => match addr_type {
                SocksAddrWireType::PortLast => {
                    buf.put_u8(SocksAddrPortLastType::DOMAIN);
                    buf.put_u8(domain.len() as u8);
                    buf.put_slice(domain.as_bytes());
                    buf.put_u16(*port);
                }
                SocksAddrWireType::PortFirst => {
                    buf.put_u16(*port);
                    buf.put_u8(SocksAddrPortFirstType::DOMAIN);
                    buf.put_u8(domain.len() as u8);
                    buf.put_slice(domain.as_bytes());
                }
            },
        }
        Ok(())
    }

    pub async fn read_from<T: AsyncRead + Unpin>(
        r: &mut T,
        addr_type: SocksAddrWireType,
    ) -> io::Result<Self> {
        match addr_type {
            SocksAddrWireType::PortLast => match r.read_u8().await? {
                SocksAddrPortLastType::V4 => {
                    let ip = Ipv4Addr::from(r.read_u32().await?);
                    let port = r.read_u16().await?;
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortLastType::V6 => {
                    let ip = Ipv6Addr::from(r.read_u128().await?);
                    let port = r.read_u16().await?;
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortLastType::DOMAIN => {
                    let domain_len = r.read_u8().await? as usize;
                    let mut buf = vec![0u8; domain_len];
                    let n = r.read_exact(&mut buf).await?;
                    debug_assert_eq!(domain_len, n);
                    let domain = String::from_utf8(buf).map_err(|_| invalid_domain())?;
                    let port = r.read_u16().await?;
                    Ok(Self::Domain(domain, port))
                }
                _ => Err(invalid_addr_type()),
            },
            SocksAddrWireType::PortFirst => match r.read_u8().await? {
                SocksAddrPortFirstType::V4 => {
                    let port = r.read_u16().await?;
                    let ip = Ipv4Addr::from(r.read_u32().await?);
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortFirstType::V6 => {
                    let port = r.read_u16().await?;
                    let ip = Ipv6Addr::from(r.read_u128().await?);
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortFirstType::DOMAIN => {
                    let port = r.read_u16().await?;
                    let domain_len = r.read_u8().await? as usize;
                    let mut buf = vec![0u8; domain_len];
                    let n = r.read_exact(&mut buf).await?;
                    debug_assert_eq!(domain_len, n);
                    let domain = String::from_utf8(buf).map_err(|_| invalid_domain())?;
                    Ok(Self::Domain(domain, port))
                }
                _ => Err(invalid_addr_type()),
            },
        }
    }
}

impl Clone for SocksAddr {
    fn clone(&self) -> Self {
        match self {
            SocksAddr::Ip(a) => Self::from(a.to_owned()),
            SocksAddr::Domain(domain, port) => Self::from((domain.to_owned(), *port)),
        }
    }
}

impl fmt::Display for SocksAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            SocksAddr::Ip(addr) => addr.to_string(),
            SocksAddr::Domain(domain, port) => format!("{}:{}", domain, port),
        };
        write!(f, "{}", s)
    }
}

impl From<(IpAddr, u16)> for SocksAddr {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for SocksAddr {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for SocksAddr {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(String, u16)> for SocksAddr {
    fn from((domain, port): (String, u16)) -> Self {
        Self::Domain(domain, port)
    }
}

impl From<(&'_ str, u16)> for SocksAddr {
    fn from((domain, port): (&'_ str, u16)) -> Self {
        Self::Domain(domain.to_owned(), port)
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<&SocketAddr> for SocksAddr {
    fn from(addr: &SocketAddr) -> Self {
        Self::Ip(addr.to_owned())
    }
}

impl From<SocketAddrV4> for SocksAddr {
    fn from(value: SocketAddrV4) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddrV6> for SocksAddr {
    fn from(value: SocketAddrV6) -> Self {
        Self::Ip(value.into())
    }
}

impl TryFrom<String> for SocksAddr {
    type Error = &'static str;

    fn try_from(addr: String) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 {
            return Err("invalid address");
        }
        if let Ok(port) = parts[1].parse::<u16>() {
            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                return Ok(Self::from((ip, port)));
            }
            if parts[0].len() > 0xff {
                return Err("domain too long");
            }
            Ok(Self::from((parts[0], port)))
        } else {
            Err("invalid port")
        }
    }
}

/// Tries to read `SocksAddr` from `&[u8]`.
impl TryFrom<(&[u8], SocksAddrWireType)> for SocksAddr {
    type Error = &'static str;

    fn try_from((buf, addr_type): (&[u8], SocksAddrWireType)) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(INSUFF_BYTES);
        }

        match addr_type {
            SocksAddrWireType::PortLast => match buf[0] {
                SocksAddrPortLastType::V4 => {
                    if buf.len() < 1 + 4 + 2 {
                        return Err(INSUFF_BYTES);
                    }
                    let mut ip_bytes = [0u8; 4];
                    (&mut ip_bytes).copy_from_slice(&buf[1..5]);
                    let ip = Ipv4Addr::from(ip_bytes);
                    let mut port_bytes = [0u8; 2];
                    (&mut port_bytes).copy_from_slice(&buf[5..7]);
                    let port = u16::from_be_bytes(port_bytes);
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortLastType::V6 => {
                    if buf.len() < 1 + 16 + 2 {
                        return Err(INSUFF_BYTES);
                    }
                    let mut ip_bytes = [0u8; 16];
                    (&mut ip_bytes).copy_from_slice(&buf[1..17]);
                    let ip = Ipv6Addr::from(ip_bytes);
                    let mut port_bytes = [0u8; 2];
                    (&mut port_bytes).copy_from_slice(&buf[17..19]);
                    let port = u16::from_be_bytes(port_bytes);
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortLastType::DOMAIN => {
                    if buf.is_empty() {
                        return Err(INSUFF_BYTES);
                    }
                    let domain_len = buf[1] as usize;
                    if buf.len() < 1 + domain_len + 2 {
                        return Err(INSUFF_BYTES);
                    }
                    let domain = String::from_utf8((&buf[2..domain_len + 2]).to_vec())
                        .map_err(|_| "invalid domain")?;
                    let mut port_bytes = [0u8; 2];
                    (&mut port_bytes).copy_from_slice(&buf[domain_len + 2..domain_len + 4]);
                    let port = u16::from_be_bytes(port_bytes);
                    Ok(Self::Domain(domain, port))
                }
                _ => Err("invalid address type"),
            },
            SocksAddrWireType::PortFirst => match buf[0] {
                SocksAddrPortFirstType::V4 => {
                    let buf = &buf[1..];
                    if buf.len() < 4 + 2 {
                        return Err(INSUFF_BYTES);
                    }
                    let port = BigEndian::read_u16(&buf[..2]);
                    let buf = &buf[2..];
                    let mut ip_bytes = [0u8; 4];
                    (&mut ip_bytes).copy_from_slice(&buf[..4]);
                    let ip = Ipv4Addr::from(ip_bytes);
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortFirstType::V6 => {
                    let buf = &buf[1..];
                    if buf.len() < 16 + 2 {
                        return Err(INSUFF_BYTES);
                    }
                    let port = BigEndian::read_u16(&buf[..2]);
                    let buf = &buf[2..];
                    let mut ip_bytes = [0u8; 16];
                    (&mut ip_bytes).copy_from_slice(&buf[..16]);
                    let ip = Ipv6Addr::from(ip_bytes);
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortFirstType::DOMAIN => {
                    let buf = &buf[1..];
                    if buf.len() < 3 {
                        return Err(INSUFF_BYTES);
                    }
                    let port = BigEndian::read_u16(&buf[..2]);
                    let buf = &buf[2..];
                    let domain_len = buf[0] as usize;
                    let buf = &buf[1..];
                    if buf.len() < domain_len {
                        return Err(INSUFF_BYTES);
                    }
                    let domain = String::from_utf8((&buf[..domain_len]).to_vec())
                        .map_err(|_| "invalid domain")?;
                    Ok(Self::Domain(domain, port))
                }
                _ => Err("invalid address type"),
            },
        }
    }
}
