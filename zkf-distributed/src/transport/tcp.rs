//! TCP transport: blocking I/O over `std::net`.

use crate::error::DistributedError;
use crate::protocol::WireMessage;
use crate::transport::frame::{read_frame, write_frame};
use crate::transport::{Connection, Listener, Transport};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream};
use std::time::Duration;

/// TCP transport using standard library blocking sockets.
pub struct TcpTransport;

fn tcp_connect_timeout() -> Duration {
    std::env::var("ZKF_DISTRIBUTED_TCP_CONNECT_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(5))
}

impl TcpTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for TcpTransport {
    fn connect(&self, addr: SocketAddr) -> Result<Box<dyn Connection>, DistributedError> {
        let stream = TcpStream::connect_timeout(&addr, tcp_connect_timeout())
            .map_err(|e| DistributedError::Io(format!("TCP connect to {addr}: {e}")))?;
        stream.set_nodelay(true).ok();
        let remote = stream.peer_addr()?;
        Ok(Box::new(TcpConnection { stream, remote }))
    }

    fn listen(&self, addr: SocketAddr) -> Result<Box<dyn Listener>, DistributedError> {
        let listener = StdTcpListener::bind(addr)
            .map_err(|e| DistributedError::Io(format!("TCP bind {addr}: {e}")))?;
        let local = listener.local_addr()?;
        Ok(Box::new(TcpListener { listener, local }))
    }

    fn name(&self) -> &'static str {
        "tcp"
    }

    fn zero_copy(&self) -> bool {
        false
    }
}

// ─── TCP Connection ──────────────────────────────────────────────────────

struct TcpConnection {
    stream: TcpStream,
    remote: SocketAddr,
}

impl Connection for TcpConnection {
    fn send(&mut self, msg: &WireMessage) -> Result<(), DistributedError> {
        write_frame(&mut self.stream, msg)
    }

    fn recv(&mut self, timeout: Option<Duration>) -> Result<WireMessage, DistributedError> {
        self.stream.set_read_timeout(timeout)?;
        let result = read_frame(&mut self.stream);
        self.stream.set_read_timeout(None)?;
        result
    }

    fn send_raw(&mut self, data: &[u8]) -> Result<(), DistributedError> {
        // Send with length prefix for raw bulk data.
        let len = data.len() as u64;
        self.stream.write_all(&len.to_le_bytes())?;
        self.stream.write_all(data)?;
        self.stream.flush()?;
        Ok(())
    }

    fn recv_raw(
        &mut self,
        buf: &mut [u8],
        timeout: Option<Duration>,
    ) -> Result<usize, DistributedError> {
        self.stream.set_read_timeout(timeout)?;
        // Read length prefix first.
        let mut len_buf = [0u8; 8];
        self.stream.read_exact(&mut len_buf)?;
        let len = u64::from_le_bytes(len_buf) as usize;
        let read_len = len.min(buf.len());
        self.stream.read_exact(&mut buf[..read_len])?;
        self.stream.set_read_timeout(None)?;
        Ok(read_len)
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    fn close(&mut self) -> Result<(), DistributedError> {
        self.stream.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }
}

// ─── TCP Listener ────────────────────────────────────────────────────────

struct TcpListener {
    listener: StdTcpListener,
    local: SocketAddr,
}

impl Listener for TcpListener {
    fn accept(&mut self) -> Result<Box<dyn Connection>, DistributedError> {
        let (stream, remote) = self.listener.accept()?;
        stream.set_nodelay(true).ok();
        Ok(Box::new(TcpConnection { stream, remote }))
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_connect_timeout_defaults_to_five_seconds() {
        unsafe {
            std::env::remove_var("ZKF_DISTRIBUTED_TCP_CONNECT_TIMEOUT_MS");
        }
        assert_eq!(tcp_connect_timeout(), Duration::from_secs(5));
    }

    #[test]
    fn tcp_connect_timeout_honors_env_override() {
        unsafe {
            std::env::set_var("ZKF_DISTRIBUTED_TCP_CONNECT_TIMEOUT_MS", "75");
        }
        assert_eq!(tcp_connect_timeout(), Duration::from_millis(75));
        unsafe {
            std::env::remove_var("ZKF_DISTRIBUTED_TCP_CONNECT_TIMEOUT_MS");
        }
    }
}
