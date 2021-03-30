use std::{io, pin::Pin};
use std::mem::MaybeUninit;
use bytes::BytesMut;
use futures::{
    ready,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
enum ReadState {
    WaitingResponseHeader,
    Streaming,
}

pub struct VLessAuthStream<T> {
    inner: T,
    read_buf: BytesMut,
    read_state: ReadState,
    read_pos: usize,
}

impl<T> VLessAuthStream<T> {
    pub fn new(s: T) -> Self {
        VLessAuthStream {
            inner: s,
            read_buf: BytesMut::with_capacity(2),
            read_state: ReadState::WaitingResponseHeader,
            read_pos: 0,
        }
    }
}

trait ReadExt {
    fn poll_read_exact(&mut self, cx: &mut Context, size: usize) -> Poll<io::Result<()>>;
}

impl<T: AsyncRead + Unpin> ReadExt for VLessAuthStream<T> {
    fn poll_read_exact(&mut self, cx: &mut Context, size: usize) -> Poll<io::Result<()>> {
        self.read_buf.reserve(size);
        unsafe { self.read_buf.set_len(size) };
        loop {
            if self.read_pos < size {
                let dst = unsafe {
                    &mut *((&mut self.read_buf[self.read_pos..size]) as *mut _
                        as *mut [MaybeUninit<u8>])
                };
                let mut buf = ReadBuf::uninit(dst);
                let ptr = buf.filled().as_ptr();
                ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
                assert_eq!(ptr, buf.filled().as_ptr());
                if buf.filled().len() == 0 {
                    return Poll::Ready(Err(early_eof()));
                }
                self.read_pos += buf.filled().len();
            } else {
                assert!(self.read_pos == size);
                self.read_pos = 0;
                return Poll::Ready(Ok(()));
            }
        }
    }
}

fn early_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "early eof")
}

impl<T: AsyncRead + Unpin> AsyncRead for VLessAuthStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.read_state {
                ReadState::WaitingResponseHeader => {
                    let me = &mut *self;
                    ready!(me.poll_read_exact(cx, 2))?;
                    if me.read_buf[0] != 0x0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("invalid vless version: {}", me.read_buf[0]),
                        )));
                    }
                    if me.read_buf[1] != 0x0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("unsupport vless addons: {}", me.read_buf[1]),
                        )));
                    }

                    me.read_state = ReadState::Streaming;
                }
                ReadState::Streaming => {
                    return Pin::new(&mut self.inner).poll_read(cx, buf);
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for VLessAuthStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
