use std::mem::MaybeUninit;
use std::{cmp::min, io, pin::Pin, slice};

use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{
    ready,
    task::{Context, Poll},
};
use log::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use shadowsocks::{
    relay::tcprelay::crypto_io::*,
    context::Context as sContext,
    config::*,
    crypto::v1::*
};

enum ReadState {
    WaitingSalt,
    WaitingLength,
    WaitingData(usize),
    PendingData(usize),
}

enum EncryptWriteState {
    AssemblePacket,
    Writing(usize),
}

pub struct TrojanStream<T> {
    inner: T,
    cipher: Cipher,
    enc: EncryptedWriter,
    read_buf: BytesMut,
    buffer: BytesMut,
    read_state: ReadState,
    state: EncryptWriteState,
    read_pos: usize,
}

impl<T> TrojanStream<T> {
    pub fn new(s: T, method: CipherKind, key: &[u8]) -> Result<Self> {
        let prev_len = method.salt_len();
        let context = sContext::new(ServerType::Local);
        let local_salt = loop {
            let mut salt = vec![0u8; prev_len];
            if prev_len > 0 {
                random_iv_or_salt(&mut salt);
            }

            if context.check_nonce_and_set(&salt) {
                // Salt exist, generate another one
                continue;
            }
            break salt;
        };
        debug!("[aead] key {}", key.len());
        let mut buffer = BytesMut::with_capacity(local_salt.len());
        buffer.put(local_salt.as_ref());
        debug!("[aead] salt {}", local_salt.len());

        Ok(TrojanStream {
            inner: s,
            cipher: Cipher::new(method, key, &local_salt),
            enc: EncryptedWriter::new(method, key, &local_salt),
            // never depend on these sizes, reserve when need
            read_buf: BytesMut::with_capacity(0x3fff + 0x20),
            buffer: buffer,

            read_state: ReadState::WaitingSalt,
            state: EncryptWriteState::AssemblePacket,
            read_pos: 0,
        })
    }
}

trait ReadExt {
    fn poll_read_exact(&mut self, cx: &mut Context, size: usize) -> Poll<io::Result<()>>;
}

fn early_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "early eof")
}

impl<T> ReadExt for TrojanStream<T>
    where
        T: AsyncRead + Unpin,
{
    // Read exactly `size` bytes into `read_buf`, starting from position 0.
    fn poll_read_exact(&mut self, cx: &mut Context, size: usize) -> Poll<io::Result<()>> {
        return Poll::Ready(Ok(()));
    }
}

pub fn crypto_err() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "crypto error")
}

impl<T> AsyncRead for TrojanStream<T>
    where
        T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub const MAX_PACKET_SIZE: usize = 0x3FFF;

impl<T> AsyncWrite for TrojanStream<T>
    where
        T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.len() > MAX_PACKET_SIZE {
            buf = &buf[..MAX_PACKET_SIZE];
        }
        loop {
            match self.state {
                EncryptWriteState::AssemblePacket => {
                    debug!("[stream buf] {}", buf.len());
                    let me = &mut *self;
                    // Step 1. Append Length
                    let length_size = 2 + me.cipher.tag_len();
                    me.buffer.reserve(length_size);

                    let mbuf = &mut me.buffer.chunk_mut()[..length_size];
                    let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };

                    me.buffer.put_u16(buf.len() as u16);
                    me.cipher.encrypt_packet(mbuf);
                    unsafe { me.buffer.advance_mut(me.cipher.tag_len()) };

                    // Step 2. Append data
                    let data_size = buf.len() + me.cipher.tag_len();
                    me.buffer.reserve(data_size);

                    let mbuf = &mut me.buffer.chunk_mut()[..data_size];
                    let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };

                    me.buffer.put_slice(buf);
                    me.cipher.encrypt_packet(mbuf);
                    unsafe { me.buffer.advance_mut(me.cipher.tag_len()) };

                    // Step 3. Write all
                    me.state = EncryptWriteState::Writing(0);
                }
                EncryptWriteState::Writing( pos ) => {
                    let me = &mut *self;
                    if pos < me.buffer.len() {
                        let n = ready!(Pin::new(&mut me.inner).poll_write(cx, &me.buffer[pos..]))?;
                        if n == 0 {
                            return Err(early_eof()).into();
                        }
                        debug!("[aead] write buf {}", pos);
                        me.state = EncryptWriteState::Writing(pos+n)
                    } else {
                        debug!("go to next chunk {}", pos);
                        // Reset state
                        me.state = EncryptWriteState::AssemblePacket;
                        me.buffer.clear();

                        return Ok(buf.len()).into();
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
