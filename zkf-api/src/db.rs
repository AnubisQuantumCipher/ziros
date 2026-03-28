use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use postgres::{Client, NoTls};
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::auth;
use crate::types::{ApiTier, JobStatus};

const SQLITE_SCHEMA_V2: &str = "
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    key_prefix TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'free',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    email TEXT,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    owner_key_hash TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    request_ciphertext TEXT NOT NULL,
    request_nonce TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_ciphertext TEXT,
    result_nonce TEXT,
    result_digest TEXT,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    started_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (owner_key_hash) REFERENCES api_keys(key_hash)
);

CREATE TABLE IF NOT EXISTS usage (
    owner_key_hash TEXT NOT NULL,
    month TEXT NOT NULL,
    proofs INTEGER NOT NULL DEFAULT 0,
    wraps INTEGER NOT NULL DEFAULT 0,
    deploys INTEGER NOT NULL DEFAULT 0,
    benchmarks INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (owner_key_hash, month),
    FOREIGN KEY (owner_key_hash) REFERENCES api_keys(key_hash)
);
";

const POSTGRES_SCHEMA_V2: &str = "
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    key_prefix TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'free',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP::text,
    email TEXT,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    owner_key_hash TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    request_ciphertext TEXT NOT NULL,
    request_nonce TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_ciphertext TEXT,
    result_nonce TEXT,
    result_digest TEXT,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP::text,
    started_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (owner_key_hash) REFERENCES api_keys(key_hash)
);

CREATE TABLE IF NOT EXISTS usage (
    owner_key_hash TEXT NOT NULL,
    month TEXT NOT NULL,
    proofs INTEGER NOT NULL DEFAULT 0,
    wraps INTEGER NOT NULL DEFAULT 0,
    deploys INTEGER NOT NULL DEFAULT 0,
    benchmarks INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (owner_key_hash, month),
    FOREIGN KEY (owner_key_hash) REFERENCES api_keys(key_hash)
);
";

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DeploymentMode {
    Development,
    Test,
    Production,
}

impl DeploymentMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "dev" | "development" | "local" => Ok(Self::Development),
            "test" | "testing" => Ok(Self::Test),
            "prod" | "production" | "hosted" => Ok(Self::Production),
            other => Err(format!(
                "unsupported ZKF_API_MODE '{other}' (expected development|test|production)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Production => "production",
        }
    }
}

enum DatabaseDriver {
    Sqlite(Mutex<Connection>),
    Postgres(Mutex<Client>),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum EncryptionKeySource {
    Environment,
    Ephemeral,
}

impl EncryptionKeySource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Ephemeral => "ephemeral",
        }
    }
}

#[derive(Clone)]
struct ApiCrypto {
    key: [u8; 32],
    source: EncryptionKeySource,
}

impl std::fmt::Debug for ApiCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiCrypto")
            .field("source", &self.source.as_str())
            .finish()
    }
}

impl ApiCrypto {
    fn new(deployment_mode: DeploymentMode) -> Result<Self, String> {
        if let Ok(value) = std::env::var("ZKF_API_ENCRYPTION_KEY")
            && !value.trim().is_empty()
        {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            let digest = hasher.finalize();
            let mut key = [0u8; 32];
            key.copy_from_slice(&digest);
            return Ok(Self {
                key,
                source: EncryptionKeySource::Environment,
            });
        }

        if deployment_mode == DeploymentMode::Production {
            return Err(
                "ZKF_API_ENCRYPTION_KEY is required in production to encrypt queued job payloads"
                    .to_string(),
            );
        }

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Ok(Self {
            key,
            source: EncryptionKeySource::Ephemeral,
        })
    }

    fn encrypt_text(&self, plaintext: &str) -> Result<EncryptedBlob, String> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|err| format!("cipher init: {err}"))?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|err| format!("payload encryption failed: {err}"))?;
        Ok(EncryptedBlob {
            ciphertext: BASE64_STANDARD.encode(ciphertext),
            nonce: BASE64_STANDARD.encode(nonce),
            digest: sha256_hex(plaintext.as_bytes()),
        })
    }

    fn decrypt_text(
        &self,
        ciphertext: &str,
        nonce: &str,
        expected_digest: &str,
        label: &str,
    ) -> Result<String, String> {
        let ciphertext = BASE64_STANDARD
            .decode(ciphertext)
            .map_err(|err| format!("{label} ciphertext decode failed: {err}"))?;
        let nonce = BASE64_STANDARD
            .decode(nonce)
            .map_err(|err| format!("{label} nonce decode failed: {err}"))?;
        if nonce.len() != 12 {
            return Err(format!(
                "{label} nonce decode failed: expected 12 bytes, found {}",
                nonce.len()
            ));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|err| format!("cipher init: {err}"))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|err| format!("{label} decryption failed: {err}"))?;
        let digest = sha256_hex(&plaintext);
        if digest != expected_digest {
            return Err(format!(
                "{label} digest mismatch: stored {expected_digest}, decrypted {digest}"
            ));
        }
        String::from_utf8(plaintext)
            .map_err(|err| format!("{label} plaintext is not valid UTF-8: {err}"))
    }
}

struct EncryptedBlob {
    ciphertext: String,
    nonce: String,
    digest: String,
}

pub struct Database {
    driver: DatabaseDriver,
    deployment_mode: DeploymentMode,
    crypto: ApiCrypto,
}

impl std::fmt::Debug for DatabaseDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(_) => f.write_str("Sqlite(..)"),
            Self::Postgres(_) => f.write_str("Postgres(..)"),
        }
    }
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database")
            .field("driver", &self.driver)
            .field("deployment_mode", &self.deployment_mode)
            .field("crypto", &self.crypto)
            .finish()
    }
}

impl Database {
    pub fn open(locator: &str, deployment_mode: DeploymentMode) -> Result<Self, String> {
        let is_postgres =
            locator.starts_with("postgres://") || locator.starts_with("postgresql://");
        if deployment_mode == DeploymentMode::Production && !is_postgres {
            return Err(
                "ZKF_API_MODE=production requires ZKF_API_DATABASE_URL to be a postgres:// or postgresql:// URL; SQLite is dev/test only"
                    .to_string(),
            );
        }

        let crypto = ApiCrypto::new(deployment_mode)?;
        let db = if is_postgres {
            let client =
                Client::connect(locator, NoTls).map_err(|e| format!("postgres connect: {e}"))?;
            Self {
                driver: DatabaseDriver::Postgres(Mutex::new(client)),
                deployment_mode,
                crypto,
            }
        } else {
            let conn = Connection::open(locator).map_err(|e| format!("sqlite open: {e}"))?;
            Self {
                driver: DatabaseDriver::Sqlite(Mutex::new(conn)),
                deployment_mode,
                crypto,
            }
        };
        db.migrate()?;
        Ok(db)
    }

    pub fn driver_name(&self) -> &'static str {
        match &self.driver {
            DatabaseDriver::Sqlite(_) => "sqlite",
            DatabaseDriver::Postgres(_) => "postgres",
        }
    }

    pub fn deployment_mode(&self) -> DeploymentMode {
        self.deployment_mode
    }

    fn migrate(&self) -> Result<(), String> {
        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                self.migrate_sqlite(&conn)
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                self.migrate_postgres(&mut client)
            }
        }
    }

    fn migrate_sqlite(&self, conn: &Connection) -> Result<(), String> {
        let api_exists = sqlite_table_exists(conn, "api_keys")?;
        let jobs_exists = sqlite_table_exists(conn, "jobs")?;
        let usage_exists = sqlite_table_exists(conn, "usage")?;
        let has_any_tables = api_exists || jobs_exists || usage_exists;
        let schema_ready = (!api_exists || sqlite_table_has_column(conn, "api_keys", "key_hash")?)
            && (!jobs_exists || sqlite_table_has_column(conn, "jobs", "request_ciphertext")?)
            && (!usage_exists || sqlite_table_has_column(conn, "usage", "owner_key_hash")?);

        if has_any_tables && !schema_ready {
            self.rebuild_sqlite_from_legacy(conn)?;
        } else {
            conn.execute_batch(SQLITE_SCHEMA_V2)
                .map_err(|e| format!("sqlite migrate: {e}"))?;
        }

        conn.execute(
            "UPDATE jobs
             SET status = 'failed',
                 error = 'server restarted while job was running',
                 completed_at = COALESCE(completed_at, datetime('now'))
             WHERE status = 'running'",
            [],
        )
        .map_err(|e| format!("sqlite migrate running jobs: {e}"))?;
        Ok(())
    }

    fn rebuild_sqlite_from_legacy(&self, conn: &Connection) -> Result<(), String> {
        conn.execute_batch(
            "
            PRAGMA foreign_keys = OFF;
            DROP TABLE IF EXISTS api_keys_legacy;
            DROP TABLE IF EXISTS jobs_legacy;
            DROP TABLE IF EXISTS usage_legacy;
            ",
        )
        .map_err(|e| format!("sqlite legacy prep: {e}"))?;

        if sqlite_table_exists(conn, "api_keys")? {
            conn.execute_batch("ALTER TABLE api_keys RENAME TO api_keys_legacy;")
                .map_err(|e| format!("sqlite rename api_keys: {e}"))?;
        }
        if sqlite_table_exists(conn, "jobs")? {
            conn.execute_batch("ALTER TABLE jobs RENAME TO jobs_legacy;")
                .map_err(|e| format!("sqlite rename jobs: {e}"))?;
        }
        if sqlite_table_exists(conn, "usage")? {
            conn.execute_batch("ALTER TABLE usage RENAME TO usage_legacy;")
                .map_err(|e| format!("sqlite rename usage: {e}"))?;
        }

        conn.execute_batch(SQLITE_SCHEMA_V2)
            .map_err(|e| format!("sqlite create v2 schema: {e}"))?;

        if sqlite_table_exists(conn, "api_keys_legacy")? {
            let mut stmt = conn
                .prepare("SELECT key, tier, created_at, email, active FROM api_keys_legacy")
                .map_err(|e| format!("sqlite read legacy api_keys: {e}"))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })
                .map_err(|e| format!("sqlite read legacy api_keys: {e}"))?;
            for row in rows {
                let (raw_key, tier, created_at, email, active) =
                    row.map_err(|e| format!("sqlite legacy api_keys row: {e}"))?;
                let key_hash = auth::hash_api_key(&raw_key);
                let key_prefix = auth::api_key_prefix(&raw_key);
                conn.execute(
                    "INSERT OR REPLACE INTO api_keys (key_hash, key_prefix, tier, created_at, email, active)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![key_hash, key_prefix, tier, created_at, email, active],
                )
                .map_err(|e| format!("sqlite migrate api_keys row: {e}"))?;
            }
        }

        if sqlite_table_exists(conn, "jobs_legacy")? {
            let mut stmt = conn
                .prepare(
                    "SELECT id, api_key, kind, status, request, result, error, created_at, started_at, completed_at
                     FROM jobs_legacy",
                )
                .map_err(|e| format!("sqlite read legacy jobs: {e}"))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(LegacyJobRow {
                        id: row.get(0)?,
                        api_key: row.get(1)?,
                        kind: row.get(2)?,
                        status: row.get(3)?,
                        request: row.get(4)?,
                        result: row.get(5)?,
                        error: row.get(6)?,
                        created_at: row.get(7)?,
                        started_at: row.get(8)?,
                        completed_at: row.get(9)?,
                    })
                })
                .map_err(|e| format!("sqlite read legacy jobs: {e}"))?;
            for row in rows {
                let row = row.map_err(|e| format!("sqlite legacy jobs row: {e}"))?;
                self.ensure_sqlite_owner_placeholder(conn, &row.api_key, Some(&row.created_at))?;
                let request = self.crypto.encrypt_text(&row.request)?;
                let result = row
                    .result
                    .as_deref()
                    .map(|value| self.crypto.encrypt_text(value))
                    .transpose()?;
                let owner_key_hash = auth::hash_api_key(&row.api_key);
                conn.execute(
                    "INSERT INTO jobs (
                        id, owner_key_hash, kind, status, request_ciphertext, request_nonce,
                        request_digest, result_ciphertext, result_nonce, result_digest, error,
                        created_at, started_at, completed_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    params![
                        row.id,
                        owner_key_hash,
                        row.kind,
                        row.status,
                        request.ciphertext,
                        request.nonce,
                        request.digest,
                        result.as_ref().map(|value| value.ciphertext.as_str()),
                        result.as_ref().map(|value| value.nonce.as_str()),
                        result.as_ref().map(|value| value.digest.as_str()),
                        row.error,
                        row.created_at,
                        row.started_at,
                        row.completed_at,
                    ],
                )
                .map_err(|e| format!("sqlite migrate jobs row: {e}"))?;
            }
        }

        if sqlite_table_exists(conn, "usage_legacy")? {
            let mut stmt = conn
                .prepare(
                    "SELECT api_key, month, proofs, wraps, deploys, benchmarks FROM usage_legacy",
                )
                .map_err(|e| format!("sqlite read legacy usage: {e}"))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .map_err(|e| format!("sqlite read legacy usage: {e}"))?;
            for row in rows {
                let (raw_key, month, proofs, wraps, deploys, benchmarks) =
                    row.map_err(|e| format!("sqlite legacy usage row: {e}"))?;
                self.ensure_sqlite_owner_placeholder(conn, &raw_key, None)?;
                conn.execute(
                    "INSERT OR REPLACE INTO usage (owner_key_hash, month, proofs, wraps, deploys, benchmarks)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        auth::hash_api_key(&raw_key),
                        month,
                        proofs,
                        wraps,
                        deploys,
                        benchmarks
                    ],
                )
                .map_err(|e| format!("sqlite migrate usage row: {e}"))?;
            }
        }

        conn.execute_batch(
            "
            DROP TABLE IF EXISTS api_keys_legacy;
            DROP TABLE IF EXISTS jobs_legacy;
            DROP TABLE IF EXISTS usage_legacy;
            PRAGMA foreign_keys = ON;
            ",
        )
        .map_err(|e| format!("sqlite cleanup legacy tables: {e}"))?;
        Ok(())
    }

    fn ensure_sqlite_owner_placeholder(
        &self,
        conn: &Connection,
        raw_key: &str,
        created_at: Option<&str>,
    ) -> Result<(), String> {
        let created_at = created_at.unwrap_or("1970-01-01 00:00:00");
        conn.execute(
            "INSERT OR IGNORE INTO api_keys (key_hash, key_prefix, tier, created_at, email, active)
             VALUES (?1, ?2, 'free', ?3, NULL, 0)",
            params![
                auth::hash_api_key(raw_key),
                auth::api_key_prefix(raw_key),
                created_at
            ],
        )
        .map_err(|e| format!("sqlite owner placeholder: {e}"))?;
        Ok(())
    }

    fn migrate_postgres(&self, client: &mut Client) -> Result<(), String> {
        let api_exists = postgres_table_exists(client, "api_keys")?;
        let jobs_exists = postgres_table_exists(client, "jobs")?;
        let usage_exists = postgres_table_exists(client, "usage")?;
        let has_any_tables = api_exists || jobs_exists || usage_exists;
        let schema_ready = (!api_exists
            || postgres_table_has_column(client, "api_keys", "key_hash")?)
            && (!jobs_exists || postgres_table_has_column(client, "jobs", "request_ciphertext")?)
            && (!usage_exists || postgres_table_has_column(client, "usage", "owner_key_hash")?);

        if has_any_tables && !schema_ready {
            self.rebuild_postgres_from_legacy(client)?;
        } else {
            client
                .batch_execute(POSTGRES_SCHEMA_V2)
                .map_err(|e| format!("postgres migrate: {e}"))?;
        }

        client
            .execute(
                "UPDATE jobs
                 SET status = 'failed',
                     error = 'server restarted while job was running',
                     completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP::text)
                 WHERE status = 'running'",
                &[],
            )
            .map_err(|e| format!("postgres migrate running jobs: {e}"))?;
        Ok(())
    }

    fn rebuild_postgres_from_legacy(&self, client: &mut Client) -> Result<(), String> {
        client
            .batch_execute(
                "
                BEGIN;
                DROP TABLE IF EXISTS api_keys_legacy;
                DROP TABLE IF EXISTS jobs_legacy;
                DROP TABLE IF EXISTS usage_legacy;
                ",
            )
            .map_err(|e| format!("postgres legacy prep: {e}"))?;

        if postgres_table_exists(client, "api_keys")? {
            client
                .batch_execute("ALTER TABLE api_keys RENAME TO api_keys_legacy;")
                .map_err(|e| format!("postgres rename api_keys: {e}"))?;
        }
        if postgres_table_exists(client, "jobs")? {
            client
                .batch_execute("ALTER TABLE jobs RENAME TO jobs_legacy;")
                .map_err(|e| format!("postgres rename jobs: {e}"))?;
        }
        if postgres_table_exists(client, "usage")? {
            client
                .batch_execute("ALTER TABLE usage RENAME TO usage_legacy;")
                .map_err(|e| format!("postgres rename usage: {e}"))?;
        }

        client
            .batch_execute(POSTGRES_SCHEMA_V2)
            .map_err(|e| format!("postgres create v2 schema: {e}"))?;

        if postgres_table_exists(client, "api_keys_legacy")? {
            for row in client
                .query(
                    "SELECT key, tier, created_at, email, active FROM api_keys_legacy",
                    &[],
                )
                .map_err(|e| format!("postgres read legacy api_keys: {e}"))?
            {
                let raw_key: String = row.get(0);
                let tier: String = row.get(1);
                let created_at: String = row.get(2);
                let email: Option<String> = row.get(3);
                let active: i32 = row.get(4);
                client
                    .execute(
                        "INSERT INTO api_keys (key_hash, key_prefix, tier, created_at, email, active)
                         VALUES ($1, $2, $3, $4, $5, $6)
                         ON CONFLICT (key_hash) DO UPDATE SET
                            key_prefix = EXCLUDED.key_prefix,
                            tier = EXCLUDED.tier,
                            created_at = EXCLUDED.created_at,
                            email = EXCLUDED.email,
                            active = EXCLUDED.active",
                        &[
                            &auth::hash_api_key(&raw_key),
                            &auth::api_key_prefix(&raw_key),
                            &tier,
                            &created_at,
                            &email,
                            &active,
                        ],
                    )
                    .map_err(|e| format!("postgres migrate api_keys row: {e}"))?;
            }
        }

        if postgres_table_exists(client, "jobs_legacy")? {
            for row in client
                .query(
                    "SELECT id, api_key, kind, status, request, result, error, created_at, started_at, completed_at
                     FROM jobs_legacy",
                    &[],
                )
                .map_err(|e| format!("postgres read legacy jobs: {e}"))?
            {
                let legacy = LegacyJobRow {
                    id: row.get(0),
                    api_key: row.get(1),
                    kind: row.get(2),
                    status: row.get(3),
                    request: row.get(4),
                    result: row.get(5),
                    error: row.get(6),
                    created_at: row.get(7),
                    started_at: row.get(8),
                    completed_at: row.get(9),
                };
                self.ensure_postgres_owner_placeholder(
                    client,
                    &legacy.api_key,
                    Some(&legacy.created_at),
                )?;
                let request = self.crypto.encrypt_text(&legacy.request)?;
                let result = legacy
                    .result
                    .as_deref()
                    .map(|value| self.crypto.encrypt_text(value))
                    .transpose()?;
                client
                    .execute(
                        "INSERT INTO jobs (
                            id, owner_key_hash, kind, status, request_ciphertext, request_nonce,
                            request_digest, result_ciphertext, result_nonce, result_digest, error,
                            created_at, started_at, completed_at
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                        &[
                            &legacy.id,
                            &auth::hash_api_key(&legacy.api_key),
                            &legacy.kind,
                            &legacy.status,
                            &request.ciphertext,
                            &request.nonce,
                            &request.digest,
                            &result.as_ref().map(|value| value.ciphertext.clone()),
                            &result.as_ref().map(|value| value.nonce.clone()),
                            &result.as_ref().map(|value| value.digest.clone()),
                            &legacy.error,
                            &legacy.created_at,
                            &legacy.started_at,
                            &legacy.completed_at,
                        ],
                    )
                    .map_err(|e| format!("postgres migrate jobs row: {e}"))?;
            }
        }

        if postgres_table_exists(client, "usage_legacy")? {
            for row in client
                .query(
                    "SELECT api_key, month, proofs, wraps, deploys, benchmarks FROM usage_legacy",
                    &[],
                )
                .map_err(|e| format!("postgres read legacy usage: {e}"))?
            {
                let raw_key: String = row.get(0);
                let month: String = row.get(1);
                let proofs: i32 = row.get(2);
                let wraps: i32 = row.get(3);
                let deploys: i32 = row.get(4);
                let benchmarks: i32 = row.get(5);
                self.ensure_postgres_owner_placeholder(client, &raw_key, None)?;
                client
                    .execute(
                        "INSERT INTO usage (owner_key_hash, month, proofs, wraps, deploys, benchmarks)
                         VALUES ($1, $2, $3, $4, $5, $6)
                         ON CONFLICT (owner_key_hash, month) DO UPDATE SET
                            proofs = EXCLUDED.proofs,
                            wraps = EXCLUDED.wraps,
                            deploys = EXCLUDED.deploys,
                            benchmarks = EXCLUDED.benchmarks",
                        &[
                            &auth::hash_api_key(&raw_key),
                            &month,
                            &proofs,
                            &wraps,
                            &deploys,
                            &benchmarks,
                        ],
                    )
                    .map_err(|e| format!("postgres migrate usage row: {e}"))?;
            }
        }

        client
            .batch_execute(
                "
                DROP TABLE IF EXISTS api_keys_legacy;
                DROP TABLE IF EXISTS jobs_legacy;
                DROP TABLE IF EXISTS usage_legacy;
                COMMIT;
                ",
            )
            .map_err(|e| format!("postgres cleanup legacy tables: {e}"))?;
        Ok(())
    }

    fn ensure_postgres_owner_placeholder(
        &self,
        client: &mut Client,
        raw_key: &str,
        created_at: Option<&str>,
    ) -> Result<(), String> {
        let created_at = created_at.unwrap_or("1970-01-01 00:00:00");
        client
            .execute(
                "INSERT INTO api_keys (key_hash, key_prefix, tier, created_at, email, active)
                 VALUES ($1, $2, 'free', $3, NULL, 0)
                 ON CONFLICT (key_hash) DO NOTHING",
                &[
                    &auth::hash_api_key(raw_key),
                    &auth::api_key_prefix(raw_key),
                    &created_at,
                ],
            )
            .map_err(|e| format!("postgres owner placeholder: {e}"))?;
        Ok(())
    }

    pub fn get_tier(&self, api_key: &str) -> Result<ApiTier, String> {
        let key_hash = auth::hash_api_key(api_key);
        let tier = match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                conn.query_row(
                    "SELECT tier FROM api_keys WHERE key_hash = ?1 AND active = 1",
                    params![key_hash],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|_| "invalid or inactive API key".to_string())?
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                client
                    .query_opt(
                        "SELECT tier FROM api_keys WHERE key_hash = $1 AND active = 1",
                        &[&key_hash],
                    )
                    .map_err(|e| format!("get tier: {e}"))?
                    .map(|row| row.get::<_, String>(0))
                    .ok_or_else(|| "invalid or inactive API key".to_string())?
            }
        };
        parse_api_tier(&tier)
    }

    pub fn create_job(
        &self,
        id: &str,
        owner_key_hash: &str,
        kind: &str,
        request: &str,
    ) -> Result<(), String> {
        let request = self.crypto.encrypt_text(request)?;
        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                conn.execute(
                    "INSERT INTO jobs (
                        id, owner_key_hash, kind, request_ciphertext, request_nonce, request_digest
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        id,
                        owner_key_hash,
                        kind,
                        request.ciphertext,
                        request.nonce,
                        request.digest
                    ],
                )
                .map_err(|e| format!("create job: {e}"))?;
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                client
                    .execute(
                        "INSERT INTO jobs (
                            id, owner_key_hash, kind, request_ciphertext, request_nonce, request_digest
                         ) VALUES ($1, $2, $3, $4, $5, $6)",
                        &[
                            &id,
                            &owner_key_hash,
                            &kind,
                            &request.ciphertext,
                            &request.nonce,
                            &request.digest,
                        ],
                    )
                    .map_err(|e| format!("create job: {e}"))?;
            }
        }
        Ok(())
    }

    pub fn update_job_status(
        &self,
        id: &str,
        status: JobStatus,
        result: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), String> {
        let status_str = serde_json::to_string(&status).unwrap_or_default();
        let status_str = status_str.trim_matches('"');
        let encrypted_result = if matches!(status, JobStatus::Completed) {
            result
                .map(|payload| self.crypto.encrypt_text(payload))
                .transpose()?
        } else {
            None
        };

        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                match status {
                    JobStatus::Running => {
                        conn.execute(
                            "UPDATE jobs SET status = ?1, started_at = datetime('now') WHERE id = ?2",
                            params![status_str, id],
                        )
                        .map_err(|e| format!("update job: {e}"))?;
                    }
                    JobStatus::Completed | JobStatus::Failed => {
                        conn.execute(
                            "UPDATE jobs
                             SET status = ?1,
                                 result_ciphertext = ?2,
                                 result_nonce = ?3,
                                 result_digest = ?4,
                                 error = ?5,
                                 completed_at = datetime('now')
                             WHERE id = ?6",
                            params![
                                status_str,
                                encrypted_result
                                    .as_ref()
                                    .map(|value| value.ciphertext.as_str()),
                                encrypted_result.as_ref().map(|value| value.nonce.as_str()),
                                encrypted_result.as_ref().map(|value| value.digest.as_str()),
                                error,
                                id
                            ],
                        )
                        .map_err(|e| format!("update job: {e}"))?;
                    }
                    JobStatus::Queued => {}
                }
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                match status {
                    JobStatus::Running => {
                        client
                            .execute(
                                "UPDATE jobs SET status = $1, started_at = CURRENT_TIMESTAMP::text WHERE id = $2",
                                &[&status_str, &id],
                            )
                            .map_err(|e| format!("update job: {e}"))?;
                    }
                    JobStatus::Completed | JobStatus::Failed => {
                        client
                            .execute(
                                "UPDATE jobs
                                 SET status = $1,
                                     result_ciphertext = $2,
                                     result_nonce = $3,
                                     result_digest = $4,
                                     error = $5,
                                     completed_at = CURRENT_TIMESTAMP::text
                                 WHERE id = $6",
                                &[
                                    &status_str,
                                    &encrypted_result
                                        .as_ref()
                                        .map(|value| value.ciphertext.clone()),
                                    &encrypted_result.as_ref().map(|value| value.nonce.clone()),
                                    &encrypted_result.as_ref().map(|value| value.digest.clone()),
                                    &error,
                                    &id,
                                ],
                            )
                            .map_err(|e| format!("update job: {e}"))?;
                    }
                    JobStatus::Queued => {}
                }
            }
        }
        Ok(())
    }

    pub fn claim_job(&self, id: &str) -> Result<bool, String> {
        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                let updated = conn
                    .execute(
                        "UPDATE jobs SET status = 'running', started_at = datetime('now') WHERE id = ?1 AND status = 'queued'",
                        params![id],
                    )
                    .map_err(|e| format!("claim job: {e}"))?;
                Ok(updated == 1)
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                let updated = client
                    .execute(
                        "UPDATE jobs SET status = 'running', started_at = CURRENT_TIMESTAMP::text WHERE id = $1 AND status = 'queued'",
                        &[&id],
                    )
                    .map_err(|e| format!("claim job: {e}"))?;
                Ok(updated == 1)
            }
        }
    }

    #[cfg(test)]
    pub fn get_job(&self, id: &str) -> Result<JobRow, String> {
        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                let stored = conn
                    .query_row(
                        "SELECT id, status, result_ciphertext, result_nonce, result_digest, error, created_at, completed_at
                         FROM jobs WHERE id = ?1",
                        params![id],
                        |row| {
                            Ok(StoredJobRow {
                                id: row.get(0)?,
                                status: row.get(1)?,
                                result_ciphertext: row.get(2)?,
                                result_nonce: row.get(3)?,
                                result_digest: row.get(4)?,
                                error: row.get(5)?,
                                created_at: row.get(6)?,
                                completed_at: row.get(7)?,
                            })
                        },
                    )
                    .map_err(|e| format!("get job: {e}"))?;
                self.materialize_job_row(stored)
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                let row = client
                    .query_one(
                        "SELECT id, status, result_ciphertext, result_nonce, result_digest, error, created_at, completed_at
                         FROM jobs WHERE id = $1",
                        &[&id],
                    )
                    .map_err(|e| format!("get job: {e}"))?;
                self.materialize_job_row(StoredJobRow {
                    id: row.get(0),
                    status: row.get(1),
                    result_ciphertext: row.get(2),
                    result_nonce: row.get(3),
                    result_digest: row.get(4),
                    error: row.get(5),
                    created_at: row.get(6),
                    completed_at: row.get(7),
                })
            }
        }
    }

    pub fn get_job_for_owner(&self, id: &str, owner_key_hash: &str) -> Result<JobRow, String> {
        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                let stored = conn
                    .query_row(
                        "SELECT id, status, result_ciphertext, result_nonce, result_digest, error, created_at, completed_at
                         FROM jobs WHERE id = ?1 AND owner_key_hash = ?2",
                        params![id, owner_key_hash],
                        |row| {
                            Ok(StoredJobRow {
                                id: row.get(0)?,
                                status: row.get(1)?,
                                result_ciphertext: row.get(2)?,
                                result_nonce: row.get(3)?,
                                result_digest: row.get(4)?,
                                error: row.get(5)?,
                                created_at: row.get(6)?,
                                completed_at: row.get(7)?,
                            })
                        },
                    )
                    .map_err(|e| format!("get job: {e}"))?;
                self.materialize_job_row(stored)
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                let row = client
                    .query_opt(
                        "SELECT id, status, result_ciphertext, result_nonce, result_digest, error, created_at, completed_at
                         FROM jobs WHERE id = $1 AND owner_key_hash = $2",
                        &[&id, &owner_key_hash],
                    )
                    .map_err(|e| format!("get job: {e}"))?
                    .ok_or_else(|| "get job: Query returned no rows".to_string())?;
                self.materialize_job_row(StoredJobRow {
                    id: row.get(0),
                    status: row.get(1),
                    result_ciphertext: row.get(2),
                    result_nonce: row.get(3),
                    result_digest: row.get(4),
                    error: row.get(5),
                    created_at: row.get(6),
                    completed_at: row.get(7),
                })
            }
        }
    }

    fn materialize_job_row(&self, stored: StoredJobRow) -> Result<JobRow, String> {
        let result = match (
            stored.result_ciphertext.as_deref(),
            stored.result_nonce.as_deref(),
            stored.result_digest.as_deref(),
        ) {
            (Some(ciphertext), Some(nonce), Some(digest)) => {
                Some(
                    self.crypto
                        .decrypt_text(ciphertext, nonce, digest, "job result")?,
                )
            }
            (None, None, None) => None,
            _ => {
                return Err(format!(
                    "job result for {} is missing encryption metadata",
                    stored.id
                ));
            }
        };
        Ok(JobRow {
            id: stored.id,
            status: stored.status,
            result,
            error: stored.error,
            created_at: stored.created_at,
            completed_at: stored.completed_at,
        })
    }

    pub fn get_job_execution(&self, id: &str) -> Result<JobExecutionRow, String> {
        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                let row = conn
                    .query_row(
                        "SELECT id, owner_key_hash, kind, request_ciphertext, request_nonce, request_digest, status
                         FROM jobs WHERE id = ?1",
                        params![id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, String>(3)?,
                                row.get::<_, String>(4)?,
                                row.get::<_, String>(5)?,
                                row.get::<_, String>(6)?,
                            ))
                        },
                    )
                    .map_err(|e| format!("get job execution: {e}"))?;
                Ok(JobExecutionRow {
                    id: row.0,
                    owner_key_hash: row.1,
                    kind: row.2,
                    request: self
                        .crypto
                        .decrypt_text(&row.3, &row.4, &row.5, "job request")?,
                    status: row.6,
                })
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                let row = client
                    .query_one(
                        "SELECT id, owner_key_hash, kind, request_ciphertext, request_nonce, request_digest, status
                         FROM jobs WHERE id = $1",
                        &[&id],
                    )
                    .map_err(|e| format!("get job execution: {e}"))?;
                Ok(JobExecutionRow {
                    id: row.get(0),
                    owner_key_hash: row.get(1),
                    kind: row.get(2),
                    request: self.crypto.decrypt_text(
                        &row.get::<_, String>(3),
                        &row.get::<_, String>(4),
                        &row.get::<_, String>(5),
                        "job request",
                    )?,
                    status: row.get(6),
                })
            }
        }
    }

    pub fn queued_job_ids(&self) -> Result<Vec<String>, String> {
        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                let mut stmt = conn
                    .prepare("SELECT id FROM jobs WHERE status = 'queued' ORDER BY created_at ASC")
                    .map_err(|e| format!("queued jobs: {e}"))?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| format!("queued jobs: {e}"))?;
                let mut ids = Vec::new();
                for row in rows {
                    ids.push(row.map_err(|e| format!("queued jobs: {e}"))?);
                }
                Ok(ids)
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                let rows = client
                    .query(
                        "SELECT id FROM jobs WHERE status = 'queued' ORDER BY created_at ASC",
                        &[],
                    )
                    .map_err(|e| format!("queued jobs: {e}"))?;
                Ok(rows
                    .into_iter()
                    .map(|row| row.get::<_, String>(0))
                    .collect())
            }
        }
    }

    pub fn increment_usage(&self, owner_key_hash: &str, kind: &str) -> Result<(), String> {
        let month = chrono_month();
        let column = match kind {
            "prove" => "proofs",
            "wrap" => "wraps",
            "deploy" => "deploys",
            "benchmark" => "benchmarks",
            _ => return Ok(()),
        };

        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                conn.execute(
                    "INSERT INTO usage (owner_key_hash, month) VALUES (?1, ?2)
                     ON CONFLICT (owner_key_hash, month) DO NOTHING",
                    params![owner_key_hash, month],
                )
                .map_err(|e| format!("usage upsert: {e}"))?;

                conn.execute(
                    &format!(
                        "UPDATE usage SET {column} = {column} + 1 WHERE owner_key_hash = ?1 AND month = ?2"
                    ),
                    params![owner_key_hash, month],
                )
                .map_err(|e| format!("usage increment: {e}"))?;
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                client
                    .execute(
                        "INSERT INTO usage (owner_key_hash, month) VALUES ($1, $2)
                         ON CONFLICT (owner_key_hash, month) DO NOTHING",
                        &[&owner_key_hash, &month],
                    )
                    .map_err(|e| format!("usage upsert: {e}"))?;
                client
                    .execute(
                        &format!(
                            "UPDATE usage SET {column} = {column} + 1 WHERE owner_key_hash = $1 AND month = $2"
                        ),
                        &[&owner_key_hash, &month],
                    )
                    .map_err(|e| format!("usage increment: {e}"))?;
            }
        }
        Ok(())
    }

    pub fn get_usage(&self, owner_key_hash: &str) -> Result<UsageRow, String> {
        let month = chrono_month();
        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                match conn.query_row(
                    "SELECT proofs, wraps, deploys, benchmarks FROM usage WHERE owner_key_hash = ?1 AND month = ?2",
                    params![owner_key_hash, month],
                    |row| {
                        Ok(UsageRow {
                            proofs: row.get(0)?,
                            wraps: row.get(1)?,
                            deploys: row.get(2)?,
                            benchmarks: row.get(3)?,
                        })
                    },
                ) {
                    Ok(row) => Ok(row),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(UsageRow::default()),
                    Err(e) => Err(format!("get usage: {e}")),
                }
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                let Some(row) = client
                    .query_opt(
                        "SELECT proofs, wraps, deploys, benchmarks FROM usage WHERE owner_key_hash = $1 AND month = $2",
                        &[&owner_key_hash, &month],
                    )
                    .map_err(|e| format!("get usage: {e}"))? else {
                        return Ok(UsageRow::default());
                    };
                Ok(UsageRow {
                    proofs: row.get::<_, i32>(0) as u32,
                    wraps: row.get::<_, i32>(1) as u32,
                    deploys: row.get::<_, i32>(2) as u32,
                    benchmarks: row.get::<_, i32>(3) as u32,
                })
            }
        }
    }

    pub fn count_running_jobs(&self, owner_key_hash: &str) -> Result<u32, String> {
        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                conn.query_row(
                    "SELECT COUNT(*) FROM jobs WHERE owner_key_hash = ?1 AND status IN ('queued', 'running')",
                    params![owner_key_hash],
                    |row| row.get(0),
                )
                .map_err(|e| format!("count running: {e}"))
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                let row = client
                    .query_one(
                        "SELECT COUNT(*) FROM jobs WHERE owner_key_hash = $1 AND status IN ('queued', 'running')",
                        &[&owner_key_hash],
                    )
                    .map_err(|e| format!("count running: {e}"))?;
                Ok(row.get::<_, i64>(0) as u32)
            }
        }
    }

    pub fn create_api_key(
        &self,
        raw_key: &str,
        tier: &str,
        email: Option<&str>,
    ) -> Result<(), String> {
        let key_hash = auth::hash_api_key(raw_key);
        let key_prefix = auth::api_key_prefix(raw_key);
        match &self.driver {
            DatabaseDriver::Sqlite(conn) => {
                let conn = conn.lock().map_err(|e| format!("db lock: {e}"))?;
                conn.execute(
                    "INSERT INTO api_keys (key_hash, key_prefix, tier, email) VALUES (?1, ?2, ?3, ?4)",
                    params![key_hash, key_prefix, tier, email],
                )
                .map_err(|e| format!("create key: {e}"))?;
            }
            DatabaseDriver::Postgres(client) => {
                let mut client = client.lock().map_err(|e| format!("db lock: {e}"))?;
                client
                    .execute(
                        "INSERT INTO api_keys (key_hash, key_prefix, tier, email) VALUES ($1, $2, $3, $4)",
                        &[&key_hash, &key_prefix, &tier, &email],
                    )
                    .map_err(|e| format!("create key: {e}"))?;
            }
        }
        Ok(())
    }
}

fn sqlite_table_exists(conn: &Connection, table: &str) -> Result<bool, String> {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        params![table],
        |_| Ok(()),
    )
    .optional()
    .map(|row| row.is_some())
    .map_err(|e| format!("sqlite table exists ({table}): {e}"))
}

fn sqlite_table_has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| format!("sqlite table info ({table}): {e}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| format!("sqlite table info ({table}): {e}"))?;
    for row in rows {
        if row.map_err(|e| format!("sqlite table info row ({table}): {e}"))? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn postgres_table_exists(client: &mut Client, table: &str) -> Result<bool, String> {
    let row = client
        .query_one(
            "SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = current_schema()
                  AND table_name = $1
            )",
            &[&table],
        )
        .map_err(|e| format!("postgres table exists ({table}): {e}"))?;
    Ok(row.get(0))
}

fn postgres_table_has_column(
    client: &mut Client,
    table: &str,
    column: &str,
) -> Result<bool, String> {
    let row = client
        .query_one(
            "SELECT EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = $1
                  AND column_name = $2
            )",
            &[&table, &column],
        )
        .map_err(|e| format!("postgres table has column ({table}.{column}): {e}"))?;
    Ok(row.get(0))
}

fn parse_api_tier(tier: &str) -> Result<ApiTier, String> {
    match tier {
        "free" => Ok(ApiTier::Free),
        "developer" => Ok(ApiTier::Developer),
        "team" => Ok(ApiTier::Team),
        "enterprise" => Ok(ApiTier::Enterprise),
        other => Err(format!("unknown tier: {other}")),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn chrono_month() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = now / 86400;
    let years = days / 365;
    let year = 1970 + years;
    let remaining_days = days - years * 365;
    let month = (remaining_days / 30).min(11) + 1;
    format!("{year}-{month:02}")
}

#[derive(Debug)]
struct LegacyJobRow {
    id: String,
    api_key: String,
    kind: String,
    status: String,
    request: String,
    result: Option<String>,
    error: Option<String>,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

#[derive(Debug)]
struct StoredJobRow {
    id: String,
    status: String,
    result_ciphertext: Option<String>,
    result_nonce: Option<String>,
    result_digest: Option<String>,
    error: Option<String>,
    created_at: String,
    completed_at: Option<String>,
}

#[derive(Debug)]
pub struct JobRow {
    pub id: String,
    pub status: String,
    pub result: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug)]
pub struct JobExecutionRow {
    pub id: String,
    pub owner_key_hash: String,
    pub kind: String,
    pub request: String,
    pub status: String,
}

#[derive(Debug, Default)]
pub struct UsageRow {
    pub proofs: u32,
    pub wraps: u32,
    pub deploys: u32,
    pub benchmarks: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn temp_sqlite_path(name: &str) -> String {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("zkf-api-test-{name}-{nonce}.db"))
            .display()
            .to_string()
    }

    #[allow(unsafe_code)]
    fn with_encryption_key_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old = std::env::var_os("ZKF_API_ENCRYPTION_KEY");
        unsafe {
            match value {
                Some(value) => std::env::set_var("ZKF_API_ENCRYPTION_KEY", value),
                None => std::env::remove_var("ZKF_API_ENCRYPTION_KEY"),
            }
        }
        let result = f();
        unsafe {
            if let Some(old) = old {
                std::env::set_var("ZKF_API_ENCRYPTION_KEY", old);
            } else {
                std::env::remove_var("ZKF_API_ENCRYPTION_KEY");
            }
        }
        result
    }

    #[test]
    fn production_mode_rejects_sqlite_locator() {
        let err = Database::open("zkf-api.db", DeploymentMode::Production)
            .expect_err("production mode must reject sqlite");
        assert!(err.contains("ZKF_API_MODE=production"));
        assert!(err.contains("postgres://") || err.contains("postgresql://"));
    }

    #[test]
    fn production_mode_requires_encryption_key() {
        with_encryption_key_env(None, || {
            let err = ApiCrypto::new(DeploymentMode::Production)
                .expect_err("production mode must require explicit encryption key");
            assert!(err.contains("ZKF_API_ENCRYPTION_KEY"));
        });
    }

    #[test]
    fn development_mode_allows_sqlite_locator() {
        let path = temp_sqlite_path("dev-open");
        let db = Database::open(&path, DeploymentMode::Development);
        assert!(db.is_ok(), "development mode should allow sqlite");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn create_api_key_stores_hash_only() {
        let path = temp_sqlite_path("key-storage");
        let db = Database::open(&path, DeploymentMode::Development).expect("db");
        let raw_key = "zkf_test_secret_key";
        db.create_api_key(raw_key, "developer", Some("ops@example.com"))
            .expect("create key");
        assert_eq!(db.get_tier(raw_key).expect("tier"), ApiTier::Developer);

        let conn = Connection::open(&path).expect("inspect sqlite");
        let columns = sqlite_columns(&conn, "api_keys");
        assert!(columns.contains(&"key_hash".to_string()));
        assert!(columns.contains(&"key_prefix".to_string()));
        assert!(!columns.contains(&"key".to_string()));

        let row: (String, String, String) = conn
            .query_row(
                "SELECT key_hash, key_prefix, tier FROM api_keys",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("api_keys row");
        assert_eq!(row.0, auth::hash_api_key(raw_key));
        assert_eq!(row.1, auth::api_key_prefix(raw_key));
        assert_eq!(row.2, "developer");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn jobs_are_encrypted_at_rest_and_decrypt_round_trip() {
        let path = temp_sqlite_path("job-encryption");
        let db = Database::open(&path, DeploymentMode::Development).expect("db");
        let raw_key = "zkf_job_owner";
        db.create_api_key(raw_key, "developer", None)
            .expect("create key");
        let owner_hash = auth::hash_api_key(raw_key);

        db.create_job("job-1", &owner_hash, "prove", "{\"hello\":\"world\"}")
            .expect("create job");
        let execution = db.get_job_execution("job-1").expect("job execution");
        assert_eq!(execution.request, "{\"hello\":\"world\"}");

        let inspect = Connection::open(&path).expect("inspect sqlite");
        let stored: (String, String, String) = inspect
            .query_row(
                "SELECT request_ciphertext, request_nonce, request_digest FROM jobs WHERE id = 'job-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("stored job");
        assert_ne!(stored.0, "{\"hello\":\"world\"}");
        assert!(!stored.1.is_empty());
        assert_eq!(stored.2, sha256_hex(b"{\"hello\":\"world\"}"));

        db.update_job_status(
            "job-1",
            JobStatus::Completed,
            Some("{\"verified\":true}"),
            None,
        )
        .expect("complete job");
        let row = db.get_job("job-1").expect("job row");
        assert_eq!(row.result.as_deref(), Some("{\"verified\":true}"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_plaintext_tables_migrate_to_hashed_and_encrypted_schema() {
        let path = temp_sqlite_path("legacy-migration");
        let conn = Connection::open(&path).expect("legacy sqlite");
        conn.execute_batch(
            "
            CREATE TABLE api_keys (
                key TEXT PRIMARY KEY,
                tier TEXT NOT NULL DEFAULT 'free',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                email TEXT,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE jobs (
                id TEXT PRIMARY KEY,
                api_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                request TEXT NOT NULL,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                started_at TEXT,
                completed_at TEXT
            );
            CREATE TABLE usage (
                api_key TEXT NOT NULL,
                month TEXT NOT NULL,
                proofs INTEGER NOT NULL DEFAULT 0,
                wraps INTEGER NOT NULL DEFAULT 0,
                deploys INTEGER NOT NULL DEFAULT 0,
                benchmarks INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (api_key, month)
            );
            INSERT INTO api_keys (key, tier, created_at, email, active)
            VALUES ('legacy-key', 'team', '2026-03-23 00:00:00', 'legacy@example.com', 1);
            INSERT INTO jobs (id, api_key, kind, status, request, result, error, created_at, completed_at)
            VALUES ('legacy-job', 'legacy-key', 'prove', 'completed', '{\"legacy\":true}', '{\"ok\":true}', NULL, '2026-03-23 00:00:00', '2026-03-23 00:00:01');
            INSERT INTO usage (api_key, month, proofs, wraps, deploys, benchmarks)
            VALUES ('legacy-key', '2026-03', 7, 1, 0, 2);
            ",
        )
        .expect("write legacy schema");
        drop(conn);

        let db = Database::open(&path, DeploymentMode::Development).expect("migrate db");
        assert_eq!(db.get_tier("legacy-key").expect("tier"), ApiTier::Team);
        let row = db.get_job("legacy-job").expect("job row");
        assert_eq!(row.result.as_deref(), Some("{\"ok\":true}"));

        let inspect = Connection::open(&path).expect("inspect migrated sqlite");
        let api_columns = sqlite_columns(&inspect, "api_keys");
        let job_columns = sqlite_columns(&inspect, "jobs");
        let usage_columns = sqlite_columns(&inspect, "usage");
        assert!(api_columns.contains(&"key_hash".to_string()));
        assert!(!api_columns.contains(&"key".to_string()));
        assert!(job_columns.contains(&"request_ciphertext".to_string()));
        assert!(!job_columns.contains(&"request".to_string()));
        assert!(usage_columns.contains(&"owner_key_hash".to_string()));
        assert!(!usage_columns.contains(&"api_key".to_string()));

        let plaintext_request = inspect
            .query_row(
                "SELECT request_ciphertext FROM jobs WHERE id = 'legacy-job'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("ciphertext");
        assert_ne!(plaintext_request, "{\"legacy\":true}");

        let usage_row: (u32, u32) = inspect
            .query_row(
                "SELECT proofs, wraps FROM usage WHERE owner_key_hash = ?1 AND month = '2026-03'",
                params![auth::hash_api_key("legacy-key")],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("migrated usage row");
        assert_eq!(usage_row.0, 7);
        assert_eq!(usage_row.1, 1);

        let _ = std::fs::remove_file(path);
    }

    fn sqlite_columns(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .expect("table info");
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query table info");
        rows.map(|row| row.expect("column")).collect()
    }

    #[test]
    fn env_key_source_is_stable_across_opens() {
        let path = temp_sqlite_path("env-key-stable");
        with_encryption_key_env(Some("stable-test-key"), || {
            let db = Database::open(&path, DeploymentMode::Development).expect("db");
            db.create_api_key("stable-owner", "developer", None)
                .expect("create key");
            let owner_hash = auth::hash_api_key("stable-owner");
            db.create_job("stable-job", &owner_hash, "prove", "{\"stable\":1}")
                .expect("create job");
        });
        with_encryption_key_env(Some("stable-test-key"), || {
            let db = Database::open(&path, DeploymentMode::Development).expect("db reopen");
            let row = db
                .get_job_execution("stable-job")
                .expect("decrypt persisted job");
            assert_eq!(row.request, "{\"stable\":1}");
        });
        if Path::new(&path).exists() {
            let _ = std::fs::remove_file(path);
        }
    }
}
