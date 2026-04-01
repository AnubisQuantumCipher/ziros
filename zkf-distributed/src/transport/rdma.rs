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
