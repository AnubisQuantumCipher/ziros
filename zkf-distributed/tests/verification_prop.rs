use proptest::prelude::*;
use std::io::Cursor;
use zkf_distributed::identity::{PeerId, PressureLevel};
use zkf_distributed::protocol::{HeartbeatMsg, MessageBody, WireMessage};
use zkf_distributed::transfer::compression::{compress_chunk, decompress_chunk};
use zkf_distributed::transport::frame::{read_frame, write_frame};

proptest! {
    #[test]
    fn framed_wire_messages_roundtrip(
        version in 1u32..8,
        sequence in any::<u64>(),
        active_subgraph_count in any::<u32>(),
        current_buffer_bytes in any::<u64>(),
    ) {
        let message = WireMessage {
            version,
            sender: PeerId("prop-node".to_string()),
            sequence,
            body: MessageBody::Heartbeat(HeartbeatMsg {
                pressure: PressureLevel::Normal,
                active_subgraph_count,
                current_buffer_bytes,
                encrypted_threat_gossip_supported: false,
                threat_epoch_id: None,
                threat_epoch_public_key: None,
                threat_digests: Vec::new(),
                activation_level: None,
                intelligence_root: None,
                local_pressure: None,
                network_pressure: None,
                encrypted_threat_payload: None,
                signature_bundle: None,
            }),
        };

        let mut bytes = Vec::new();
        write_frame(&mut bytes, &message).expect("write frame");
        let decoded = read_frame(&mut Cursor::new(bytes)).expect("read frame");

        prop_assert_eq!(decoded.version, version);
        prop_assert_eq!(decoded.sequence, sequence);
        match decoded.body {
            MessageBody::Heartbeat(heartbeat) => {
                prop_assert_eq!(heartbeat.active_subgraph_count, active_subgraph_count);
                prop_assert_eq!(heartbeat.current_buffer_bytes, current_buffer_bytes);
            }
            other => prop_assert!(false, "expected heartbeat, got {other:?}"),
        }
    }

    #[test]
    fn lz4_chunks_roundtrip_small_payloads(payload in prop::collection::vec(any::<u8>(), 0..16)) {
        let compressed = compress_chunk(&payload);
        let decompressed = decompress_chunk(&compressed).expect("lz4 roundtrip");
        prop_assert_eq!(decompressed, payload);
    }

    #[test]
    fn oversized_frames_fail_closed(trailing in prop::collection::vec(any::<u8>(), 0..8)) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&trailing);

        let err = read_frame(&mut Cursor::new(bytes)).expect_err("oversized frame must fail");
        match err {
            zkf_distributed::error::DistributedError::Serialization(message) => {
                prop_assert!(message.contains("frame too large"));
            }
            other => prop_assert!(false, "expected serialization error, got {other:?}"),
        }
    }
}
