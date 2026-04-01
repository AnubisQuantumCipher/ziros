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

//! Optional LZ4 per-chunk compression for buffer transfers.

/// Compress a chunk using LZ4.
pub fn compress_chunk(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

/// Decompress an LZ4-compressed chunk.
pub fn decompress_chunk(compressed: &[u8]) -> Result<Vec<u8>, String> {
    lz4_flex::decompress_size_prepended(compressed)
        .map_err(|e| format!("LZ4 decompression failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_compression() {
        let data = vec![42u8; 4096];
        let compressed = compress_chunk(&data);
        let decompressed = decompress_chunk(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn compression_reduces_size_for_repetitive_data() {
        let data = vec![0u8; 1024 * 1024]; // 1 MiB of zeros
        let compressed = compress_chunk(&data);
        assert!(compressed.len() < data.len() / 10);
    }

    #[test]
    fn empty_data_roundtrip() {
        let data = Vec::new();
        let compressed = compress_chunk(&data);
        let decompressed = decompress_chunk(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }
}
