// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

//! Transport abstraction: traits for network connections and listeners.

pub mod frame;
pub mod rdma;
pub mod tcp;

use crate::config::TransportPreference;
use crate::error::DistributedError;
use crate::protocol::WireMessage;
use std::net::SocketAddr;
use std::time::Duration;

/// Network transport layer abstraction.
pub trait Transport: Send + Sync {
    /// Open a connection to the given address.
    fn connect(&self, addr: SocketAddr) -> Result<Box<dyn Connection>, DistributedError>;

    /// Start listening for inbound connections.
    fn listen(&self, addr: SocketAddr) -> Result<Box<dyn Listener>, DistributedError>;

    /// Name of this transport (e.g., "tcp", "rdma").
    fn name(&self) -> &'static str;

    /// Whether this transport supports zero-copy semantics.
    fn zero_copy(&self) -> bool;
}

/// An established bidirectional connection.
pub trait Connection: Send {
    /// Send a framed wire message.
    fn send(&mut self, msg: &WireMessage) -> Result<(), DistributedError>;

    /// Receive a framed wire message, with optional timeout.
    fn recv(&mut self, timeout: Option<Duration>) -> Result<WireMessage, DistributedError>;

    /// Send raw bytes (for bulk buffer transfer).
    fn send_raw(&mut self, data: &[u8]) -> Result<(), DistributedError>;

    /// Receive raw bytes into the provided buffer. Returns bytes read.
    fn recv_raw(
        &mut self,
        buf: &mut [u8],
        timeout: Option<Duration>,
    ) -> Result<usize, DistributedError>;

    /// Remote peer address.
    fn remote_addr(&self) -> SocketAddr;

    /// Close the connection.
    fn close(&mut self) -> Result<(), DistributedError>;
}

/// A listener accepting inbound connections.
pub trait Listener: Send {
    /// Accept the next inbound connection (blocking).
    fn accept(&mut self) -> Result<Box<dyn Connection>, DistributedError>;

    /// Local address we are bound to.
    fn local_addr(&self) -> SocketAddr;
}

pub struct ResolvedTransport {
    pub transport: Box<dyn Transport>,
    pub fallback_note: Option<String>,
}

pub fn create_transport(
    preference: TransportPreference,
) -> Result<ResolvedTransport, DistributedError> {
    match preference {
        TransportPreference::Tcp => Ok(ResolvedTransport {
            transport: Box::new(tcp::TcpTransport::new()),
            fallback_note: None,
        }),
        TransportPreference::PreferRdma => Ok(ResolvedTransport {
            transport: Box::new(tcp::TcpTransport::new()),
            fallback_note: Some(
                "RDMA transport is still experimental and unavailable in production builds; falling back to TCP"
                    .to_string(),
            ),
        }),
        TransportPreference::RdmaOnly => Err(DistributedError::Config(
            "RDMA-only transport is not available yet; use TCP or prefer-rdma for production distributed proving"
                .into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefer_rdma_falls_back_to_tcp() {
        let resolved = create_transport(TransportPreference::PreferRdma).unwrap();
        assert_eq!(resolved.transport.name(), "tcp");
        assert!(resolved.fallback_note.is_some());
    }

    #[test]
    fn rdma_only_fails_closed() {
        let err = create_transport(TransportPreference::RdmaOnly)
            .err()
            .expect("rdma-only should fail");
        assert!(err.to_string().contains("RDMA-only transport"));
    }
}
