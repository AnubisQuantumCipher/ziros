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
