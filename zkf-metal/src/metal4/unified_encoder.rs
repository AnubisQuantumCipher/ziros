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

//! Metal 4-style command encoding helpers backed by the current command-buffer API.

use crate::async_dispatch::{GpuCompletion, GpuFuture, GpuWaitError, commit_and_wait};
use crate::device::{self, MetalContext};
use crate::metal4::is_metal4_available;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_metal::{MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder};

/// Configuration for the Metal 4 unified encoder.
#[derive(Debug, Clone, Copy)]
pub struct UnifiedEncoderConfig {
    /// Maximum number of compute-encoder passes to record into one command buffer.
    pub max_concurrent_dispatches: u32,
    /// Whether to prefer the secondary queue for parallel encoding.
    pub parallel_encoding: bool,
}

impl Default for UnifiedEncoderConfig {
    fn default() -> Self {
        Self {
            max_concurrent_dispatches: 8,
            parallel_encoding: true,
        }
    }
}

/// Host-gated wrapper around a single command buffer used as a unified encoder surface.
pub struct UnifiedEncoder {
    ctx: &'static MetalContext,
    config: UnifiedEncoderConfig,
    cmd: Retained<ProtocolObject<dyn MTLCommandBuffer>>,
    passes_encoded: u32,
}

impl UnifiedEncoder {
    pub fn new(config: UnifiedEncoderConfig) -> Result<Self, String> {
        if !is_metal4_available() {
            return Err("Metal 4 unified encoding is not available on this host".to_string());
        }
        let ctx = device::global_context()
            .ok_or_else(|| "Metal GPU unavailable on this host".to_string())?;
        let cmd = if config.parallel_encoding {
            ctx.secondary_command_buffer()
                .or_else(|| ctx.command_buffer())
        } else {
            ctx.command_buffer()
        }
        .ok_or_else(|| "failed to allocate Metal command buffer".to_string())?;

        Ok(Self {
            ctx,
            config,
            cmd,
            passes_encoded: 0,
        })
    }

    pub fn context(&self) -> &'static MetalContext {
        self.ctx
    }

    pub fn command_buffer(&self) -> &ProtocolObject<dyn MTLCommandBuffer> {
        &self.cmd
    }

    pub fn passes_encoded(&self) -> u32 {
        self.passes_encoded
    }

    pub fn with_compute_encoder<T>(
        &mut self,
        encode: impl FnOnce(&ProtocolObject<dyn MTLComputeCommandEncoder>) -> Result<T, String>,
    ) -> Result<T, String> {
        if self.passes_encoded >= self.config.max_concurrent_dispatches.max(1) {
            return Err(format!(
                "unified encoder pass budget exceeded (max={})",
                self.config.max_concurrent_dispatches.max(1)
            ));
        }
        let encoder = self
            .cmd
            .computeCommandEncoder()
            .ok_or_else(|| "failed to create Metal compute encoder".to_string())?;
        let result = encode(&encoder);
        encoder.endEncoding();
        if result.is_ok() {
            self.passes_encoded += 1;
        }
        result
    }

    pub fn commit(self) -> Result<GpuCompletion, GpuWaitError> {
        commit_and_wait(self.cmd, "metal4-unified")
    }

    pub fn commit_async(self) -> GpuFuture {
        GpuFuture::submit_labeled(self.cmd, "metal4-unified")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unified_encoder_default_budget_is_nonzero() {
        let config = UnifiedEncoderConfig::default();
        assert!(config.max_concurrent_dispatches >= 1);
    }
}
