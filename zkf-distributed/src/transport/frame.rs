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

//! Length-delimited wire framing: [4 bytes LE u32 len][postcard payload].

use crate::error::DistributedError;
use crate::protocol::WireMessage;
use crate::swarm_transport_core;
use std::io::{Read, Write};

/// Maximum frame size: 256 MiB. Prevents accidental allocation of huge buffers.
pub const MAX_FRAME_SIZE: u32 = 256 * 1024 * 1024;

pub(crate) fn write_frame_payload<W: Write>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), DistributedError> {
    let len = payload.len() as u32;
    if !swarm_transport_core::frame_length_valid(len, MAX_FRAME_SIZE) {
        return Err(DistributedError::Serialization(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

pub(crate) fn read_frame_payload<R: Read>(reader: &mut R) -> Result<Vec<u8>, DistributedError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);

    if !swarm_transport_core::frame_length_valid(len, MAX_FRAME_SIZE) {
        return Err(DistributedError::Serialization(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

/// Write a framed wire message to a writer.
pub fn write_frame<W: Write>(writer: &mut W, msg: &WireMessage) -> Result<(), DistributedError> {
    let payload =
        postcard::to_allocvec(msg).map_err(|e| DistributedError::Serialization(e.to_string()))?;
    write_frame_payload(writer, &payload)
}

/// Read a framed wire message from a reader.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<WireMessage, DistributedError> {
    let payload = read_frame_payload(reader)?;
    postcard::from_bytes(&payload).map_err(|e| DistributedError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PeerId;
    use crate::identity::PressureLevel;
    use crate::protocol::{HeartbeatMsg, MessageBody};
    use std::io::Cursor;

    #[test]
    fn roundtrip_frame() {
        let msg = WireMessage {
            version: 1,
            sender: PeerId("test".into()),
            sequence: 42,
            body: MessageBody::Heartbeat(HeartbeatMsg {
                pressure: PressureLevel::Normal,
                active_subgraph_count: 0,
                current_buffer_bytes: 0,
                encrypted_threat_gossip_supported: false,
                threat_epoch_id: None,
                threat_epoch_public_key: None,
                threat_epoch_ml_kem_public_key: None,
                threat_digests: Vec::new(),
                activation_level: None,
                intelligence_root: None,
                local_pressure: None,
                network_pressure: None,
                encrypted_threat_payload: None,
                signature_bundle: None,
            }),
        };

        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = read_frame(&mut cursor).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.sender.0, "test");
        assert_eq!(decoded.sequence, 42);
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut buf = Vec::new();
        let huge_len = MAX_FRAME_SIZE + 1;
        buf.extend_from_slice(&huge_len.to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]); // some junk payload

        let mut cursor = Cursor::new(&buf);
        let result = read_frame(&mut cursor);
        assert!(result.is_err());
    }
}
