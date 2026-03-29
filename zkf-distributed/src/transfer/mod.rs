//! Buffer transfer manager: chunked send/recv with integrity checking.

pub mod compression;

use crate::config::{ClusterConfig, IntegrityAlgorithm};
use crate::error::DistributedError;
use crate::identity::PeerId;
use crate::protocol::{
    MessageBody, TransferAckMsg, TransferChunkMsg, TransferCompleteMsg, TransferRequestMsg,
    WireMessage,
};
use crate::swarm_transport_core;
use crate::transport::Connection;
use std::time::{Duration, Instant};

/// Manages chunked buffer transfers with integrity checking and optional compression.
pub struct BufferTransferManager {
    chunk_size: usize,
    compress: bool,
    integrity: IntegrityAlgorithm,
}

impl BufferTransferManager {
    pub fn new(config: &ClusterConfig) -> Self {
        Self {
            chunk_size: config.transfer_chunk_bytes,
            compress: config.compress_transfers,
            integrity: config.integrity_algorithm,
        }
    }

    /// Send a buffer to a remote peer, chunk by chunk.
    pub fn send_buffer(
        &self,
        conn: &mut dyn Connection,
        sender_id: &PeerId,
        job_id: &str,
        slot: u32,
        data: &[u8],
        sequence: &mut u64,
    ) -> Result<TransferStats, DistributedError> {
        let start = Instant::now();
        let total_bytes = data.len();
        let chunk_count = total_bytes.div_ceil(self.chunk_size);
        let chunk_count = chunk_count.max(1) as u32;

        // Send transfer request.
        let request = WireMessage {
            version: 1,
            sender: sender_id.clone(),
            sequence: *sequence,
            body: MessageBody::TransferRequest(TransferRequestMsg {
                job_id: job_id.into(),
                slot,
                total_bytes,
                chunk_count,
                compressed: self.compress,
            }),
        };
        *sequence += 1;
        conn.send(&request)?;

        // Send chunks.
        let mut total_compressed = 0usize;

        for i in 0..chunk_count {
            let start_offset = i as usize * self.chunk_size;
            let end_offset = (start_offset + self.chunk_size).min(total_bytes);
            let chunk_data = &data[start_offset..end_offset];

            let (wire_data, digest) = if self.compress {
                let compressed = compression::compress_chunk(chunk_data);
                total_compressed += compressed.len();
                let dig = self.compute_digest(&compressed);
                (compressed, dig)
            } else {
                total_compressed += chunk_data.len();
                let dig = self.compute_digest(chunk_data);
                (chunk_data.to_vec(), dig)
            };

            let chunk_msg = WireMessage {
                version: 1,
                sender: sender_id.clone(),
                sequence: *sequence,
                body: MessageBody::TransferChunk(TransferChunkMsg {
                    job_id: job_id.into(),
                    slot,
                    chunk_index: i,
                    data: wire_data,
                    digest,
                }),
            };
            *sequence += 1;
            conn.send(&chunk_msg)?;
        }

        // Send completion with full digest.
        let total_digest = self.compute_digest(data);
        let complete = WireMessage {
            version: 1,
            sender: sender_id.clone(),
            sequence: *sequence,
            body: MessageBody::TransferComplete(TransferCompleteMsg {
                job_id: job_id.into(),
                slot,
                total_digest,
            }),
        };
        *sequence += 1;
        conn.send(&complete)?;

        // Wait for ack.
        let ack = conn.recv(Some(Duration::from_secs(30)))?;
        match ack.body {
            MessageBody::TransferAck(ref a) if a.accepted => {}
            MessageBody::TransferAck(ref a) => {
                return Err(DistributedError::TransferFailed {
                    slot,
                    reason: a.reason.clone().unwrap_or_else(|| "rejected".into()),
                });
            }
            _ => {
                return Err(DistributedError::TransferFailed {
                    slot,
                    reason: "unexpected response to transfer".into(),
                });
            }
        }

        let elapsed = start.elapsed();
        let throughput_gbps = if elapsed.as_secs_f64() > 0.0 {
            (total_bytes as f64 * 8.0) / (elapsed.as_secs_f64() * 1e9)
        } else {
            0.0
        };

        Ok(TransferStats {
            total_bytes,
            compressed_bytes: if self.compress {
                Some(total_compressed)
            } else {
                None
            },
            wall_time: elapsed,
            throughput_gbps,
        })
    }

    /// Receive a buffer from a remote peer, chunk by chunk.
    pub fn recv_buffer(
        &self,
        conn: &mut dyn Connection,
        receiver_id: &PeerId,
        request: &TransferRequestMsg,
        sequence: &mut u64,
    ) -> Result<(Vec<u8>, TransferStats), DistributedError> {
        let start = Instant::now();
        let mut assembled = vec![0u8; request.total_bytes];
        let mut cursor = 0usize;
        let mut total_compressed = 0usize;

        for _ in 0..request.chunk_count {
            let msg = conn.recv(Some(Duration::from_secs(30)))?;
            match msg.body {
                MessageBody::TransferChunk(chunk) => {
                    // Verify chunk digest.
                    let expected_digest = self.compute_digest(&chunk.data);
                    if !swarm_transport_core::integrity_digest_matches(
                        self.integrity,
                        &chunk.data,
                        &chunk.digest,
                    ) {
                        return Err(DistributedError::IntegrityFailed {
                            slot: request.slot,
                            expected: hex_encode(&expected_digest),
                            actual: hex_encode(&chunk.digest),
                        });
                    }

                    total_compressed += chunk.data.len();

                    let plain_data = if request.compressed {
                        compression::decompress_chunk(&chunk.data).map_err(|e| {
                            DistributedError::TransferFailed {
                                slot: request.slot,
                                reason: e,
                            }
                        })?
                    } else {
                        chunk.data
                    };

                    let end = (cursor + plain_data.len()).min(assembled.len());
                    let copy_len = end - cursor;
                    assembled[cursor..end].copy_from_slice(&plain_data[..copy_len]);
                    cursor = end;
                }
                _ => {
                    return Err(DistributedError::TransferFailed {
                        slot: request.slot,
                        reason: "expected TransferChunk".into(),
                    });
                }
            }
        }

        // Receive completion and verify full digest.
        let complete_msg = conn.recv(Some(Duration::from_secs(30)))?;
        match complete_msg.body {
            MessageBody::TransferComplete(ref tc) => {
                let local_digest = self.compute_digest(&assembled[..cursor]);
                if !swarm_transport_core::integrity_digest_matches(
                    self.integrity,
                    &assembled[..cursor],
                    &tc.total_digest,
                ) {
                    // Send rejection ack.
                    let nack = WireMessage {
                        version: 1,
                        sender: receiver_id.clone(),
                        sequence: *sequence,
                        body: MessageBody::TransferAck(TransferAckMsg {
                            job_id: request.job_id.clone(),
                            slot: request.slot,
                            accepted: false,
                            reason: Some("full digest mismatch".into()),
                        }),
                    };
                    *sequence += 1;
                    conn.send(&nack)?;

                    return Err(DistributedError::IntegrityFailed {
                        slot: request.slot,
                        expected: hex_encode(&tc.total_digest),
                        actual: hex_encode(&local_digest),
                    });
                }
            }
            _ => {
                return Err(DistributedError::TransferFailed {
                    slot: request.slot,
                    reason: "expected TransferComplete".into(),
                });
            }
        }

        // Send acceptance ack.
        let ack = WireMessage {
            version: 1,
            sender: receiver_id.clone(),
            sequence: *sequence,
            body: MessageBody::TransferAck(TransferAckMsg {
                job_id: request.job_id.clone(),
                slot: request.slot,
                accepted: true,
                reason: None,
            }),
        };
        *sequence += 1;
        conn.send(&ack)?;

        let elapsed = start.elapsed();
        let throughput_gbps = if elapsed.as_secs_f64() > 0.0 {
            (request.total_bytes as f64 * 8.0) / (elapsed.as_secs_f64() * 1e9)
        } else {
            0.0
        };

        Ok((
            assembled,
            TransferStats {
                total_bytes: request.total_bytes,
                compressed_bytes: if request.compressed {
                    Some(total_compressed)
                } else {
                    None
                },
                wall_time: elapsed,
                throughput_gbps,
            },
        ))
    }

    fn compute_digest(&self, data: &[u8]) -> Vec<u8> {
        compute_integrity_digest(self.integrity, data)
    }
}

/// Transfer statistics for a single buffer slot.
#[derive(Debug, Clone)]
pub struct TransferStats {
    pub total_bytes: usize,
    pub compressed_bytes: Option<usize>,
    pub wall_time: Duration,
    pub throughput_gbps: f64,
}

pub(crate) fn compute_integrity_digest(algorithm: IntegrityAlgorithm, data: &[u8]) -> Vec<u8> {
    swarm_transport_core::integrity_digest(algorithm, data)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn integrity_digests_detect_single_byte_corruption(
            payload in prop::collection::vec(any::<u8>(), 1..17),
            flip_index in any::<usize>(),
        ) {
            let mut tampered = payload.clone();
            let index = flip_index % tampered.len();
            tampered[index] ^= 0x01;

            prop_assert_ne!(
                compute_integrity_digest(IntegrityAlgorithm::Fnv, &payload),
                compute_integrity_digest(IntegrityAlgorithm::Fnv, &tampered),
            );
            prop_assert_ne!(
                compute_integrity_digest(IntegrityAlgorithm::Sha256, &payload),
                compute_integrity_digest(IntegrityAlgorithm::Sha256, &tampered),
            );
        }
    }
}
