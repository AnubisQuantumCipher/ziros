use crate::error::DistributedError;
use crate::protocol::{AttestationChainMsg, SubgraphTraceEntry};
use crate::swarm::identity::{LocalPeerIdentity, PublicKeyBundle, SignatureBundle};
use crate::swarm_memory_core;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_runtime::swarm::SwarmConfig;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmMemoryEntry {
    pub sequence_id: i64,
    pub entry_kind: String,
    pub signer_peer_id: String,
    pub recorded_unix_ms: u128,
    pub previous_hash: String,
    pub entry_hash: String,
    pub payload_json: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemorySnapshot {
    pub intelligence_root: String,
    pub chain_head: String,
    pub exported_unix_ms: u128,
    pub signer_peer_id: String,
    #[serde(with = "base64_bytes")]
    pub compressed_payload: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "base64_bytes")]
    pub signature: Vec<u8>,
    #[serde(default)]
    pub signature_bundle: Option<SignatureBundle>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotFileRecord {
    pub relative_path: String,
    pub contents: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyArchaeologyMatch {
    pub sequence_id: i64,
    pub entry_kind: String,
    pub entry_hash: String,
}

pub fn output_digest(
    output_data: &[(u32, Vec<u8>)],
    named_outputs: &[(String, Vec<u8>)],
) -> [u8; 32] {
    swarm_memory_core::output_digest(output_data, named_outputs)
}

pub fn trace_digest(trace_entries: &[SubgraphTraceEntry]) -> [u8; 32] {
    swarm_memory_core::trace_digest(trace_entries)
}

pub fn attestation_signing_bytes(
    job_id: &str,
    partition_id: u32,
    output_digest: [u8; 32],
    trace_digest: [u8; 32],
    activation_level: Option<u8>,
) -> Vec<u8> {
    swarm_memory_core::attestation_signing_bytes(
        job_id,
        partition_id,
        output_digest,
        trace_digest,
        activation_level,
    )
}

pub fn persist_attestation_chain(
    config: &SwarmConfig,
    chain: &AttestationChainMsg,
) -> Result<PathBuf, DistributedError> {
    let dir = attestation_dir(config);
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}-{}.json", chain.job_id, chain.partition_id));
    let bytes = serde_json::to_vec_pretty(chain)
        .map_err(|err| DistributedError::Serialization(err.to_string()))?;
    fs::write(&path, bytes)?;

    let signer_peer_id = chain
        .attestations
        .first()
        .map(|attestation| attestation.signer_peer_id.clone())
        .unwrap_or_else(|| "system".to_string());
    let signature = chain
        .attestations
        .first()
        .map(|attestation| attestation.signature.clone())
        .unwrap_or_default();
    let payload = serde_json::to_value(chain).unwrap_or(Value::Null);
    let _ = append_memory_entry(
        config,
        "attestation-chain",
        &signer_peer_id,
        &signature,
        &payload,
    )?;

    Ok(path)
}

pub fn load_attestation_chains(
    config: &SwarmConfig,
) -> Result<Vec<AttestationChainMsg>, DistributedError> {
    read_json_entries(&attestation_dir(config))
}

pub fn append_memory_entry(
    config: &SwarmConfig,
    entry_kind: &str,
    signer_peer_id: &str,
    signature: &[u8],
    payload: &Value,
) -> Result<SwarmMemoryEntry, DistributedError> {
    let conn = open_memory_db(config)?;
    append_memory_entry_with_conn(&conn, entry_kind, signer_peer_id, signature, payload)
}

pub fn load_memory_entries(
    config: &SwarmConfig,
) -> Result<Vec<SwarmMemoryEntry>, DistributedError> {
    let conn = open_memory_db(config)?;
    let mut stmt = conn
        .prepare(
            "SELECT sequence_id, entry_kind, signer_peer_id, recorded_unix_ms, previous_hash, entry_hash, payload_json, signature
             FROM swarm_memory_log
             ORDER BY sequence_id ASC",
        )
        .map_err(|err| DistributedError::Io(err.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(SwarmMemoryEntry {
                sequence_id: row.get(0)?,
                entry_kind: row.get(1)?,
                signer_peer_id: row.get(2)?,
                recorded_unix_ms: row.get::<_, i64>(3)? as u128,
                previous_hash: row.get(4)?,
                entry_hash: row.get(5)?,
                payload_json: row.get(6)?,
                signature: row.get(7)?,
            })
        })
        .map_err(|err| DistributedError::Io(err.to_string()))?;
    let mut entries = Vec::new();
    for row in rows {
        entries.push(row.map_err(|err| DistributedError::Io(err.to_string()))?);
    }
    Ok(entries)
}

pub fn verify_memory_chain(config: &SwarmConfig) -> Result<bool, DistributedError> {
    let entries = load_memory_entries(config)?;
    let mut previous_hash = String::from("GENESIS");
    for entry in entries {
        if entry.previous_hash != previous_hash {
            return Ok(false);
        }
        let recomputed = memory_entry_hash(
            &entry.entry_kind,
            &entry.signer_peer_id,
            entry.recorded_unix_ms,
            &entry.previous_hash,
            entry.payload_json.as_bytes(),
            &entry.signature,
        );
        if recomputed != entry.entry_hash {
            return Ok(false);
        }
        previous_hash = entry.entry_hash;
    }
    Ok(true)
}

pub fn memory_chain_head(config: &SwarmConfig) -> Result<String, DistributedError> {
    Ok(load_memory_entries(config)?
        .last()
        .map(|entry| entry.entry_hash.clone())
        .unwrap_or_else(|| "GENESIS".to_string()))
}

pub fn current_intelligence_root(config: &SwarmConfig) -> Result<String, DistributedError> {
    for entry in load_memory_entries(config)?.into_iter().rev() {
        let Ok(payload) = serde_json::from_str::<Value>(&entry.payload_json) else {
            continue;
        };
        if let Some(root) = payload.get("intelligence_root").and_then(Value::as_str) {
            return Ok(root.to_string());
        }
    }
    Ok(hex_string(&Sha256::digest(b"empty-intelligence")))
}

pub fn persist_threat_intelligence_outcome(
    config: &SwarmConfig,
    entry_kind: &str,
    signer_peer_id: &str,
    signature: &[u8],
    intelligence_root: &str,
    payload: &Value,
) -> Result<SwarmMemoryEntry, DistributedError> {
    let payload = serde_json::json!({
        "intelligence_root": intelligence_root,
        "payload": payload,
    });
    append_memory_entry(config, entry_kind, signer_peer_id, signature, &payload)
}

pub fn export_memory_snapshot_signed(
    config: &SwarmConfig,
    signer: &LocalPeerIdentity,
) -> Result<MemorySnapshot, DistributedError> {
    let intelligence_root = current_intelligence_root(config)?;
    let chain_head = memory_chain_head(config)?;
    let payload = serde_json::json!({
        "entries": load_memory_entries(config)?,
        "attestations": load_attestation_chains(config)?,
        "rules": snapshot_directory_entries(&config.rules_path)?,
        "baselines": snapshot_directory_entries(&config.swarm_root().join("baselines"))?,
        "reputation": snapshot_directory_entries(&config.reputation_log_path)?,
    });
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|err| DistributedError::Serialization(err.to_string()))?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&payload_bytes)
        .map_err(|err| DistributedError::Io(err.to_string()))?;
    let compressed_payload = encoder
        .finish()
        .map_err(|err| DistributedError::Io(err.to_string()))?;
    let mut snapshot = MemorySnapshot {
        intelligence_root,
        chain_head,
        exported_unix_ms: unix_time_now_ms(),
        signer_peer_id: signer.stable_peer_id().0,
        compressed_payload,
        signature: Vec::new(),
        signature_bundle: None,
    };
    let signature_bundle = signer.sign_bundle(&snapshot_signing_bytes(&snapshot));
    snapshot.signature = signature_bundle.ed25519.clone();
    snapshot.signature_bundle = Some(signature_bundle);
    Ok(snapshot)
}

pub fn import_memory_snapshot_verified(
    config: &SwarmConfig,
    snapshot: &MemorySnapshot,
    legacy_public_key: &[u8],
    public_key_bundle: Option<&PublicKeyBundle>,
) -> Result<(), DistributedError> {
    let signing_bytes = snapshot_signing_bytes(snapshot);
    let signature_valid = match snapshot.signature_bundle.as_ref() {
        Some(signature_bundle) => zkf_core::verify_signed_message(
            legacy_public_key,
            public_key_bundle,
            &signing_bytes,
            &snapshot.signature,
            Some(signature_bundle),
            b"zkf-swarm",
        ),
        None => LocalPeerIdentity::verify(legacy_public_key, &signing_bytes, &snapshot.signature),
    };
    if !signature_valid {
        return Err(DistributedError::HandshakeFailed {
            peer_id: snapshot.signer_peer_id.clone(),
            reason: "memory snapshot signature verification failed".to_string(),
        });
    }

    let payload = decode_snapshot_payload(&snapshot.compressed_payload)?;
    let entries = payload
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let attestations = payload
        .get("attestations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rules = payload
        .get("rules")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let baselines = payload
        .get("baselines")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let reputation = payload
        .get("reputation")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));

    let conn = open_memory_db(config)?;
    conn.execute("DELETE FROM swarm_memory_log", [])
        .map_err(|err| DistributedError::Io(err.to_string()))?;
    for entry in entries {
        let parsed: SwarmMemoryEntry = serde_json::from_value(entry)
            .map_err(|err| DistributedError::Serialization(err.to_string()))?;
        conn.execute(
            "INSERT INTO swarm_memory_log
             (sequence_id, entry_kind, signer_peer_id, recorded_unix_ms, previous_hash, entry_hash, payload_json, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                parsed.sequence_id,
                parsed.entry_kind,
                parsed.signer_peer_id,
                parsed.recorded_unix_ms as i64,
                parsed.previous_hash,
                parsed.entry_hash,
                parsed.payload_json,
                parsed.signature,
            ],
        )
        .map_err(|err| DistributedError::Io(err.to_string()))?;
    }

    fs::create_dir_all(attestation_dir(config))?;
    for attestation in attestations {
        let parsed: AttestationChainMsg = serde_json::from_value(attestation)
            .map_err(|err| DistributedError::Serialization(err.to_string()))?;
        let path =
            attestation_dir(config).join(format!("{}-{}.json", parsed.job_id, parsed.partition_id));
        fs::write(
            path,
            serde_json::to_vec_pretty(&parsed)
                .map_err(|err| DistributedError::Serialization(err.to_string()))?,
        )?;
    }
    restore_snapshot_directory_entries(&config.rules_path, rules)?;
    restore_snapshot_directory_entries(&config.swarm_root().join("baselines"), baselines)?;
    restore_snapshot_directory_entries(&config.reputation_log_path, reputation)?;
    if memory_chain_head(config)? != snapshot.chain_head {
        return Err(DistributedError::Config(
            "imported snapshot did not preserve the exported memory chain head".to_string(),
        ));
    }
    if current_intelligence_root(config)? != snapshot.intelligence_root {
        return Err(DistributedError::Config(
            "imported snapshot did not preserve the exported intelligence root".to_string(),
        ));
    }
    Ok(())
}

pub fn anomaly_archaeology_scan(
    config: &SwarmConfig,
    stage_key_hash: u64,
    kind: &str,
) -> Result<Vec<AnomalyArchaeologyMatch>, DistributedError> {
    let mut matches = Vec::new();
    for entry in load_memory_entries(config)? {
        let Ok(payload) = serde_json::from_str::<Value>(&entry.payload_json) else {
            continue;
        };
        if payload_matches_archeology(&payload, stage_key_hash, kind) {
            matches.push(AnomalyArchaeologyMatch {
                sequence_id: entry.sequence_id,
                entry_kind: entry.entry_kind,
                entry_hash: entry.entry_hash,
            });
        }
    }
    Ok(matches)
}

pub fn snapshot_signing_bytes(snapshot: &MemorySnapshot) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(snapshot.intelligence_root.as_bytes());
    bytes.extend_from_slice(snapshot.chain_head.as_bytes());
    bytes.extend_from_slice(&snapshot.exported_unix_ms.to_le_bytes());
    bytes.extend_from_slice(snapshot.signer_peer_id.as_bytes());
    bytes.extend_from_slice(&(snapshot.compressed_payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&snapshot.compressed_payload);
    bytes
}

fn open_memory_db(config: &SwarmConfig) -> Result<Connection, DistributedError> {
    let path = memory_db_path(config);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path).map_err(|err| DistributedError::Io(err.to_string()))?;
    ensure_memory_schema(&conn)?;
    Ok(conn)
}

fn ensure_memory_schema(conn: &Connection) -> Result<(), DistributedError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS swarm_memory_log (
            sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_kind TEXT NOT NULL,
            signer_peer_id TEXT NOT NULL,
            recorded_unix_ms INTEGER NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            signature BLOB NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_swarm_memory_log_entry_hash ON swarm_memory_log(entry_hash);",
    )
    .map_err(|err| DistributedError::Io(err.to_string()))
}

fn append_memory_entry_with_conn(
    conn: &Connection,
    entry_kind: &str,
    signer_peer_id: &str,
    signature: &[u8],
    payload: &Value,
) -> Result<SwarmMemoryEntry, DistributedError> {
    let payload_json = serde_json::to_string(payload)
        .map_err(|err| DistributedError::Serialization(err.to_string()))?;
    let previous_hash = conn
        .query_row(
            "SELECT entry_hash FROM swarm_memory_log ORDER BY sequence_id DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap_or_else(|_| "GENESIS".to_string());
    let recorded_unix_ms = unix_time_now_ms();
    let entry_hash = memory_entry_hash(
        entry_kind,
        signer_peer_id,
        recorded_unix_ms,
        &previous_hash,
        payload_json.as_bytes(),
        signature,
    );
    conn.execute(
        "INSERT INTO swarm_memory_log
         (entry_kind, signer_peer_id, recorded_unix_ms, previous_hash, entry_hash, payload_json, signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            entry_kind,
            signer_peer_id,
            recorded_unix_ms as i64,
            previous_hash,
            entry_hash,
            payload_json,
            signature,
        ],
    )
    .map_err(|err| DistributedError::Io(err.to_string()))?;
    let sequence_id = conn.last_insert_rowid();
    Ok(SwarmMemoryEntry {
        sequence_id,
        entry_kind: entry_kind.to_string(),
        signer_peer_id: signer_peer_id.to_string(),
        recorded_unix_ms,
        previous_hash,
        entry_hash,
        payload_json,
        signature: signature.to_vec(),
    })
}

fn memory_entry_hash(
    entry_kind: &str,
    signer_peer_id: &str,
    recorded_unix_ms: u128,
    previous_hash: &str,
    payload_json: &[u8],
    signature: &[u8],
) -> String {
    swarm_memory_core::memory_entry_hash(
        entry_kind,
        signer_peer_id,
        recorded_unix_ms,
        previous_hash,
        payload_json,
        signature,
    )
}

fn decode_snapshot_payload(bytes: &[u8]) -> Result<Value, DistributedError> {
    let mut decoder = GzDecoder::new(bytes);
    let mut payload = Vec::new();
    decoder
        .read_to_end(&mut payload)
        .map_err(|err| DistributedError::Io(err.to_string()))?;
    serde_json::from_slice(&payload).map_err(|err| DistributedError::Serialization(err.to_string()))
}

fn payload_matches_archeology(payload: &Value, stage_key_hash: u64, kind: &str) -> bool {
    match payload {
        Value::Object(map) => {
            let stage_matches = map
                .get("stage_key_hash")
                .and_then(Value::as_u64)
                .map(|value| value == stage_key_hash)
                .unwrap_or(false);
            let kind_matches = map
                .get("kind")
                .and_then(Value::as_str)
                .map(|value| value == kind)
                .unwrap_or(false);
            stage_matches && kind_matches
                || map
                    .values()
                    .any(|value| payload_matches_archeology(value, stage_key_hash, kind))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| payload_matches_archeology(value, stage_key_hash, kind)),
        _ => false,
    }
}

fn attestation_dir(config: &SwarmConfig) -> PathBuf {
    config.swarm_root().join("attestations")
}

fn memory_db_path(config: &SwarmConfig) -> PathBuf {
    config.swarm_root().join("swarm_memory.sqlite3")
}

fn read_json_entries<T>(dir: &Path) -> Result<Vec<T>, DistributedError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(entry.path())?;
        entries.push(
            serde_json::from_slice(&bytes)
                .map_err(|err| DistributedError::Serialization(err.to_string()))?,
        );
    }
    Ok(entries)
}

fn snapshot_directory_entries(dir: &Path) -> Result<Vec<SnapshotFileRecord>, DistributedError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    collect_snapshot_files(dir, dir, &mut files)?;
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(files)
}

fn collect_snapshot_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<SnapshotFileRecord>,
) -> Result<(), DistributedError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_snapshot_files(root, &path, files)?;
            continue;
        }
        let relative_path = path
            .strip_prefix(root)
            .map_err(|err| DistributedError::Io(err.to_string()))?
            .to_string_lossy()
            .to_string();
        let contents = String::from_utf8_lossy(&fs::read(&path)?).to_string();
        files.push(SnapshotFileRecord {
            relative_path,
            contents,
        });
    }
    Ok(())
}

fn restore_snapshot_directory_entries(dir: &Path, value: Value) -> Result<(), DistributedError> {
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    fs::create_dir_all(dir)?;
    let records: Vec<SnapshotFileRecord> = serde_json::from_value(value)
        .map_err(|err| DistributedError::Serialization(err.to_string()))?;
    for record in records {
        let path = dir.join(&record.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, record.contents.as_bytes())?;
    }
    Ok(())
}

fn unix_time_now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

fn hex_string(bytes: &[u8]) -> String {
    swarm_memory_core::hex_string(bytes)
}

mod base64_bytes {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        STANDARD.decode(encoded).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::AttestationMetadata;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_swarm_home<T>(f: impl FnOnce(&SwarmConfig) -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().expect("tempdir");
        let old_home = std::env::var_os("HOME");
        let old_swarm = std::env::var_os("ZKF_SWARM");
        let old_backend = std::env::var_os("ZKF_SWARM_KEY_BACKEND");
        let old_policy = std::env::var_os("ZKF_SECURITY_POLICY_MODE");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("ZKF_SWARM", "1");
            std::env::set_var("ZKF_SWARM_KEY_BACKEND", "file");
            std::env::set_var("ZKF_SECURITY_POLICY_MODE", "observe");
        }
        let config = SwarmConfig::from_env();
        let result = f(&config);
        unsafe {
            if let Some(old_home) = old_home {
                std::env::set_var("HOME", old_home);
            } else {
                std::env::remove_var("HOME");
            }
            if let Some(old_swarm) = old_swarm {
                std::env::set_var("ZKF_SWARM", old_swarm);
            } else {
                std::env::remove_var("ZKF_SWARM");
            }
            if let Some(old_backend) = old_backend {
                std::env::set_var("ZKF_SWARM_KEY_BACKEND", old_backend);
            } else {
                std::env::remove_var("ZKF_SWARM_KEY_BACKEND");
            }
            if let Some(old_policy) = old_policy {
                std::env::set_var("ZKF_SECURITY_POLICY_MODE", old_policy);
            } else {
                std::env::remove_var("ZKF_SECURITY_POLICY_MODE");
            }
        }
        result
    }

    fn sample_chain() -> AttestationChainMsg {
        AttestationChainMsg {
            job_id: "job-memory".to_string(),
            partition_id: 7,
            attestations: vec![AttestationMetadata {
                signer_peer_id: "peer-a".to_string(),
                public_key: vec![1; 32],
                public_key_bundle: None,
                output_digest: [2; 32],
                trace_digest: [3; 32],
                signature: vec![4; 64],
                signature_bundle: None,
                activation_level: Some(1),
            }],
        }
    }

    #[test]
    fn attestation_chain_persists_to_file_and_memory_log() {
        with_swarm_home(|config| {
            persist_attestation_chain(config, &sample_chain()).expect("persist");
            assert_eq!(load_attestation_chains(config).expect("load").len(), 1);
            let entries = load_memory_entries(config).expect("entries");
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].entry_kind, "attestation-chain");
            assert!(verify_memory_chain(config).expect("verify"));
        });
    }

    #[test]
    fn tampering_invalidates_memory_chain() {
        with_swarm_home(|config| {
            persist_attestation_chain(config, &sample_chain()).expect("persist");
            let conn = open_memory_db(config).expect("db");
            conn.execute(
                "UPDATE swarm_memory_log SET payload_json = '{\"tampered\":true}' WHERE sequence_id = 1",
                [],
            )
            .expect("update");
            assert!(!verify_memory_chain(config).expect("verify"));
        });
    }

    #[test]
    fn signed_snapshot_roundtrips() {
        with_swarm_home(|config| {
            persist_attestation_chain(config, &sample_chain()).expect("persist");
            let signer = LocalPeerIdentity::load_or_create(config, "snapshot").expect("identity");
            let snapshot = export_memory_snapshot_signed(config, &signer).expect("snapshot");

            let temp = tempfile::tempdir().expect("tempdir");
            let old_home = std::env::var_os("HOME");
            unsafe {
                std::env::set_var("HOME", temp.path());
            }
            let import_config = SwarmConfig::from_env();
            import_memory_snapshot_verified(
                &import_config,
                &snapshot,
                &signer.public_key_bytes(),
                Some(&signer.public_key_bundle()),
            )
            .expect("import");
            assert_eq!(
                load_memory_entries(&import_config).expect("entries").len(),
                1
            );
            unsafe {
                if let Some(old_home) = old_home {
                    std::env::set_var("HOME", old_home);
                } else {
                    std::env::remove_var("HOME");
                }
            }
        });
    }

    #[test]
    fn signed_snapshot_preserves_rules_baselines_reputation_root_and_head() {
        with_swarm_home(|config| {
            fs::create_dir_all(&config.rules_path).expect("rules dir");
            fs::create_dir_all(config.swarm_root().join("baselines")).expect("baselines dir");
            fs::create_dir_all(&config.reputation_log_path).expect("reputation dir");
            fs::write(config.rules_path.join("rule.json"), "{\"rule\":true}").expect("rule");
            fs::write(
                config.swarm_root().join("baselines").join("baseline.json"),
                "{\"baseline\":true}",
            )
            .expect("baseline");
            fs::write(
                config.reputation_log_path.join("peer-a.json"),
                "{\"peer\":\"a\"}",
            )
            .expect("reputation");
            persist_threat_intelligence_outcome(
                config,
                "encrypted-threat-intelligence",
                "peer-a",
                &[],
                "root-a",
                &serde_json::json!({"stage_key_hash": 9u64, "kind": "runtime-anomaly"}),
            )
            .expect("intel");
            let expected_head = memory_chain_head(config).expect("head");
            let signer = LocalPeerIdentity::load_or_create(config, "snapshot").expect("identity");
            let snapshot = export_memory_snapshot_signed(config, &signer).expect("snapshot");
            assert_eq!(snapshot.intelligence_root, "root-a");
            assert_eq!(snapshot.chain_head, expected_head);

            let temp = tempfile::tempdir().expect("tempdir");
            let old_home = std::env::var_os("HOME");
            unsafe {
                std::env::set_var("HOME", temp.path());
            }
            let import_config = SwarmConfig::from_env();
            import_memory_snapshot_verified(
                &import_config,
                &snapshot,
                &signer.public_key_bytes(),
                Some(&signer.public_key_bundle()),
            )
            .expect("import");
            assert_eq!(
                memory_chain_head(&import_config).expect("import head"),
                expected_head
            );
            assert_eq!(
                current_intelligence_root(&import_config).expect("import root"),
                "root-a".to_string()
            );
            assert!(import_config.rules_path.join("rule.json").exists());
            assert!(
                import_config
                    .swarm_root()
                    .join("baselines")
                    .join("baseline.json")
                    .exists()
            );
            assert!(
                import_config
                    .reputation_log_path
                    .join("peer-a.json")
                    .exists()
            );
            unsafe {
                if let Some(old_home) = old_home {
                    std::env::set_var("HOME", old_home);
                } else {
                    std::env::remove_var("HOME");
                }
            }
        });
    }

    #[test]
    fn archaeology_scan_finds_matching_entries() {
        with_swarm_home(|config| {
            let payload = serde_json::json!({
                "stage_key_hash": 9u64,
                "kind": "runtime-anomaly",
                "detail": "historical"
            });
            append_memory_entry(config, "threat-digest", "peer-a", &[], &payload).expect("append");
            let matches = anomaly_archaeology_scan(config, 9, "runtime-anomaly").expect("scan");
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].entry_kind, "threat-digest");
        });
    }
}
