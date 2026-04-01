//! Experimental RDMA transport guardrail.

use crate::error::DistributedError;
use crate::transport::{Connection, Listener, Transport};
use std::net::SocketAddr;

/// Fail-closed RDMA transport.
///
/// Production distributed proving currently uses TCP. RDMA is intentionally
/// rejected until there is a real implementation and kernel support.
pub struct ExperimentalRdmaTransport;

impl ExperimentalRdmaTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ExperimentalRdmaTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for ExperimentalRdmaTransport {
    fn connect(&self, _addr: SocketAddr) -> Result<Box<dyn Connection>, DistributedError> {
        Err(DistributedError::Config(
            "RDMA transport is experimental and not available in production builds".into(),
        ))
    }

    fn listen(&self, _addr: SocketAddr) -> Result<Box<dyn Listener>, DistributedError> {
        Err(DistributedError::Config(
            "RDMA transport is experimental and not available in production builds".into(),
        ))
    }

    fn name(&self) -> &'static str {
        "rdma-experimental"
    }

    fn zero_copy(&self) -> bool {
        false
    }
}
