use crate::error::DistributedError;
use crate::identity::PeerId;
use crate::swarm_identity_core;
use ed25519_dalek::{Signer, SigningKey};
use libcrux_ml_dsa::ml_dsa_44::{
    MLDSA44SigningKey, MLDSA44VerificationKey, generate_key_pair, sign as mldsa_sign,
};
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
pub use zkf_core::{PublicKeyBundle, SignatureBundle, SignatureScheme};
use zkf_runtime::swarm::{SwarmConfig, SwarmKeyBackend};

const ML_DSA_CONTEXT: &[u8] = b"zkf-swarm";
const ML_DSA_IMPLEMENTATION: &str = "libcrux-ml-dsa-0.0.8::ml_dsa_44";

pub trait KeyStorageBackend {
    fn backend_name(&self) -> &'static str;
    fn load_or_create(&self, path: &Path, label: &str) -> Result<LoadedSeed, DistributedError>;
    fn load_existing(&self, path: &Path, label: &str) -> Result<LoadedSeed, DistributedError>;
    fn regenerate(&self, path: &Path, label: &str) -> Result<LoadedSeed, DistributedError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FileBackend;

#[derive(Debug, Default, Clone, Copy)]
pub struct SecureEnclaveBackend;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MlDsaKeyProvenance {
    pub implementation: String,
    pub storage_path: String,
    pub public_key_path: String,
    pub metadata_path: String,
    pub permissions: String,
}

#[derive(Clone, Debug)]
pub struct LocalPeerIdentitySet {
    label: String,
    backend_name: &'static str,
    backend_kind: SwarmKeyBackend,
    private_key_path: PathBuf,
    public_key: [u8; 32],
    public_key_resynced: bool,
    ml_dsa_private_key_path: PathBuf,
    ml_dsa_public_key: Vec<u8>,
    stable_peer_id: PeerId,
    public_key_bundle: PublicKeyBundle,
    ml_dsa_provenance: MlDsaKeyProvenance,
}

pub type LocalPeerIdentity = LocalPeerIdentitySet;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LoadedSeed {
    seed: [u8; 32],
    public_key_resynced: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PublicKeySyncStatus {
    Unchanged,
    Created,
    Resynced,
}

impl LocalPeerIdentitySet {
    pub fn load_or_create(config: &SwarmConfig, label: &str) -> Result<Self, DistributedError> {
        ensure_backend_policy(config)?;
        let ed25519_path = config.identity_path.join(format!("{label}.ed25519"));
        let ml_dsa_path = config.identity_path.join(format!("{label}.mldsa44"));
        let backend = selected_backend(config.key_backend);
        let loaded_seed = backend.load_or_create(&ed25519_path, label)?;
        let (ml_dsa_signing_key, ml_dsa_public_key, ml_dsa_provenance) =
            load_or_create_ml_dsa_material(&ml_dsa_path, label)?;
        Ok(Self::from_material(
            ed25519_path,
            ml_dsa_path,
            label,
            config.key_backend,
            backend.backend_name(),
            loaded_seed.seed,
            loaded_seed.public_key_resynced,
            ml_dsa_signing_key,
            ml_dsa_public_key,
            ml_dsa_provenance,
        ))
    }

    pub fn rotate(config: &SwarmConfig, label: &str) -> Result<Self, DistributedError> {
        ensure_backend_policy(config)?;
        let ed25519_path = config.identity_path.join(format!("{label}.ed25519"));
        let ml_dsa_path = config.identity_path.join(format!("{label}.mldsa44"));
        let backend = selected_backend(config.key_backend);
        let loaded_seed = backend.regenerate(&ed25519_path, label)?;
        let (ml_dsa_signing_key, ml_dsa_public_key, ml_dsa_provenance) =
            regenerate_ml_dsa_material(&ml_dsa_path, label)?;
        Ok(Self::from_material(
            ed25519_path,
            ml_dsa_path,
            label,
            config.key_backend,
            backend.backend_name(),
            loaded_seed.seed,
            loaded_seed.public_key_resynced,
            ml_dsa_signing_key,
            ml_dsa_public_key,
            ml_dsa_provenance,
        ))
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    pub fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::HybridEd25519MlDsa44
    }

    pub fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        let backend = selected_backend(self.backend_kind);
        let seed = backend
            .load_existing(&self.private_key_path, &self.label)
            .expect("local swarm identity must remain readable while the process is alive");
        SigningKey::from_bytes(&seed.seed)
            .sign(bytes)
            .to_bytes()
            .to_vec()
    }

    pub fn sign_bundle(&self, bytes: &[u8]) -> SignatureBundle {
        let signing_key = load_ml_dsa_signing_key(&self.ml_dsa_private_key_path)
            .expect("local swarm ML-DSA identity must remain readable while the process is alive");
        let randomness = secure_random_array::<SIGNING_RANDOMNESS_SIZE>()
            .expect("ML-DSA signing randomness must be available");
        let signature = mldsa_sign(&signing_key, bytes, ML_DSA_CONTEXT, randomness)
            .expect("local swarm ML-DSA identity must sign successfully");
        SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa44,
            ed25519: self.sign(bytes),
            ml_dsa44: signature.as_slice().to_vec(),
        }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }

    pub fn public_key_resynced(&self) -> bool {
        self.public_key_resynced
    }

    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        self.public_key_bundle.clone()
    }

    pub fn ml_dsa_public_key_bytes(&self) -> Vec<u8> {
        self.ml_dsa_public_key.clone()
    }

    pub fn ml_dsa_provenance(&self) -> &MlDsaKeyProvenance {
        &self.ml_dsa_provenance
    }

    pub fn stable_peer_id(&self) -> PeerId {
        self.stable_peer_id.clone()
    }

    pub fn verify(public_key: &[u8], bytes: &[u8], signature: &[u8]) -> bool {
        zkf_core::verify_ed25519_signature(public_key, bytes, signature)
    }

    pub fn verify_bundle(
        public_keys: &PublicKeyBundle,
        bytes: &[u8],
        signatures: &SignatureBundle,
    ) -> bool {
        zkf_core::verify_bundle(public_keys, bytes, signatures, ML_DSA_CONTEXT)
    }

    pub fn verify_signed_message(
        legacy_public_key: &[u8],
        public_key_bundle: Option<&PublicKeyBundle>,
        bytes: &[u8],
        legacy_signature: &[u8],
        signature_bundle: Option<&SignatureBundle>,
    ) -> bool {
        zkf_core::verify_signed_message(
            legacy_public_key,
            public_key_bundle,
            bytes,
            legacy_signature,
            signature_bundle,
            ML_DSA_CONTEXT,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_material(
        private_key_path: PathBuf,
        ml_dsa_private_key_path: PathBuf,
        label: &str,
        backend_kind: SwarmKeyBackend,
        backend_name: &'static str,
        seed: [u8; 32],
        public_key_resynced: bool,
        _ml_dsa_signing_key: MLDSA44SigningKey,
        ml_dsa_public_key: MLDSA44VerificationKey,
        ml_dsa_provenance: MlDsaKeyProvenance,
    ) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_bundle = PublicKeyBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa44,
            ed25519: public_key.to_vec(),
            ml_dsa44: ml_dsa_public_key.as_slice().to_vec(),
        };
        let digest = Sha256::digest(public_key_bundle.canonical_bytes());
        Self {
            label: label.to_string(),
            backend_name,
            backend_kind,
            private_key_path,
            public_key,
            public_key_resynced,
            ml_dsa_private_key_path,
            ml_dsa_public_key: ml_dsa_public_key.as_slice().to_vec(),
            stable_peer_id: PeerId(format!("swarm-{}", hex_prefix(&digest, 16))),
            public_key_bundle,
            ml_dsa_provenance,
        }
    }
}

pub fn compute_admission_pow(public_key: &[u8], difficulty: u8) -> u64 {
    swarm_identity_core::compute_admission_pow(public_key, difficulty)
}

pub fn verify_admission_pow(public_key: &[u8], nonce: u64, difficulty: u8) -> bool {
    swarm_identity_core::verify_admission_pow(public_key, nonce, difficulty)
}

pub fn hybrid_admission_pow_identity_bytes(
    legacy_public_key: &[u8],
    public_key_bundle: Option<&PublicKeyBundle>,
) -> Vec<u8> {
    swarm_identity_core::hybrid_admission_pow_identity_bytes(
        legacy_public_key,
        public_key_bundle.map(PublicKeyBundle::canonical_bytes),
    )
}

pub fn admission_pow_identity_bytes(
    legacy_public_key: &[u8],
    public_key_bundle: Option<&PublicKeyBundle>,
) -> Vec<u8> {
    hybrid_admission_pow_identity_bytes(legacy_public_key, public_key_bundle)
}

impl KeyStorageBackend for FileBackend {
    fn backend_name(&self) -> &'static str {
        "file"
    }

    fn load_or_create(&self, path: &Path, _label: &str) -> Result<LoadedSeed, DistributedError> {
        ensure_identity_dir(path)?;
        if path.exists() {
            return read_seed_file(path);
        }
        let seed =
            zkf_core::secure_random::secure_random_seed().map_err(DistributedError::Config)?;
        write_seed_and_public_files(path, &seed)?;
        Ok(LoadedSeed {
            seed,
            public_key_resynced: false,
        })
    }

    fn load_existing(&self, path: &Path, _label: &str) -> Result<LoadedSeed, DistributedError> {
        read_seed_file(path)
    }

    fn regenerate(&self, path: &Path, _label: &str) -> Result<LoadedSeed, DistributedError> {
        ensure_identity_dir(path)?;
        let seed =
            zkf_core::secure_random::secure_random_seed().map_err(DistributedError::Config)?;
        write_private_file(path, &seed)?;
        overwrite_public_key_file(path, &seed)?;
        Ok(LoadedSeed {
            seed,
            public_key_resynced: false,
        })
    }
}

impl KeyStorageBackend for SecureEnclaveBackend {
    fn backend_name(&self) -> &'static str {
        "enclave"
    }

    fn load_or_create(&self, path: &Path, label: &str) -> Result<LoadedSeed, DistributedError> {
        #[cfg(target_os = "macos")]
        {
            ensure_identity_dir(path)?;
            let key_label = format!("zkf-swarm-{label}");
            let seed = match zkf_core::keystore::retrieve_key(&key_label) {
                Ok(bytes) => to_seed(&bytes)?,
                Err(_) => {
                    let seed = zkf_core::secure_random::secure_random_seed()
                        .map_err(DistributedError::Config)?;
                    let _ = zkf_core::keystore::store_key(&key_label, &seed)
                        .map_err(DistributedError::Config)?;
                    seed
                }
            };
            let public_key_resynced =
                sync_public_key_file(path, &seed, path.exists())? == PublicKeySyncStatus::Resynced;
            Ok(LoadedSeed {
                seed,
                public_key_resynced,
            })
        }

        #[cfg(not(target_os = "macos"))]
        {
            FileBackend.load_or_create(path, label)
        }
    }

    fn load_existing(&self, path: &Path, label: &str) -> Result<LoadedSeed, DistributedError> {
        #[cfg(target_os = "macos")]
        {
            let key_label = format!("zkf-swarm-{label}");
            let seed = to_seed(
                &zkf_core::keystore::retrieve_key(&key_label).map_err(DistributedError::Config)?,
            )?;
            let public_key_resynced =
                sync_public_key_file(path, &seed, true)? == PublicKeySyncStatus::Resynced;
            Ok(LoadedSeed {
                seed,
                public_key_resynced,
            })
        }

        #[cfg(not(target_os = "macos"))]
        {
            FileBackend.load_existing(path, label)
        }
    }

    fn regenerate(&self, path: &Path, label: &str) -> Result<LoadedSeed, DistributedError> {
        #[cfg(target_os = "macos")]
        {
            ensure_identity_dir(path)?;
            let key_label = format!("zkf-swarm-{label}");
            let _ = zkf_core::keystore::delete_key(&key_label);
            let seed =
                zkf_core::secure_random::secure_random_seed().map_err(DistributedError::Config)?;
            let _ = zkf_core::keystore::store_key(&key_label, &seed)
                .map_err(DistributedError::Config)?;
            overwrite_public_key_file(path, &seed)?;
            Ok(LoadedSeed {
                seed,
                public_key_resynced: false,
            })
        }

        #[cfg(not(target_os = "macos"))]
        {
            FileBackend.regenerate(path, label)
        }
    }
}

pub fn local_identity_label(hostname: &str, bind_port: u16) -> String {
    format!("{}-{}", sanitize_label(hostname), bind_port)
}

fn selected_backend(key_backend: SwarmKeyBackend) -> Box<dyn KeyStorageBackend> {
    match key_backend {
        SwarmKeyBackend::File => Box::new(FileBackend),
        SwarmKeyBackend::Enclave => Box::new(SecureEnclaveBackend),
    }
}

fn load_or_create_ml_dsa_material(
    path: &Path,
    _label: &str,
) -> Result<
    (
        MLDSA44SigningKey,
        MLDSA44VerificationKey,
        MlDsaKeyProvenance,
    ),
    DistributedError,
> {
    ensure_identity_dir(path)?;
    if path.exists() {
        let signing_key = load_ml_dsa_signing_key(path)?;
        let verification_key = load_ml_dsa_public_key(&ml_dsa_public_key_path(path))?;
        sync_ml_dsa_sidecars(path, &verification_key)?;
        return Ok((
            signing_key,
            verification_key.clone(),
            ml_dsa_provenance(path, &verification_key),
        ));
    }

    let randomness = secure_random_array::<KEY_GENERATION_RANDOMNESS_SIZE>()?;
    let keypair = generate_key_pair(randomness);
    write_private_file(path, keypair.signing_key.as_slice())?;
    sync_ml_dsa_sidecars(path, &keypair.verification_key)?;
    Ok((
        keypair.signing_key,
        keypair.verification_key.clone(),
        ml_dsa_provenance(path, &keypair.verification_key),
    ))
}

fn regenerate_ml_dsa_material(
    path: &Path,
    label: &str,
) -> Result<
    (
        MLDSA44SigningKey,
        MLDSA44VerificationKey,
        MlDsaKeyProvenance,
    ),
    DistributedError,
> {
    let _ = label;
    ensure_identity_dir(path)?;
    let randomness = secure_random_array::<KEY_GENERATION_RANDOMNESS_SIZE>()?;
    let keypair = generate_key_pair(randomness);
    write_private_file(path, keypair.signing_key.as_slice())?;
    sync_ml_dsa_sidecars(path, &keypair.verification_key)?;
    Ok((
        keypair.signing_key,
        keypair.verification_key.clone(),
        ml_dsa_provenance(path, &keypair.verification_key),
    ))
}

fn secure_random_array<const N: usize>() -> Result<[u8; N], DistributedError> {
    let mut bytes = [0u8; N];
    zkf_core::secure_random::secure_random_bytes(&mut bytes).map_err(DistributedError::Config)?;
    Ok(bytes)
}

fn load_ml_dsa_signing_key(path: &Path) -> Result<MLDSA44SigningKey, DistributedError> {
    verify_private_key_permissions(path)?;
    let bytes = fs::read(path)?;
    let signing_key: [u8; MLDSA44SigningKey::len()] = bytes.try_into().map_err(|_| {
        DistributedError::Config(
            "swarm ML-DSA key material is corrupt; run `zkf swarm regenerate-key --force`"
                .to_string(),
        )
    })?;
    Ok(MLDSA44SigningKey::new(signing_key))
}

fn load_ml_dsa_public_key(path: &Path) -> Result<MLDSA44VerificationKey, DistributedError> {
    let bytes = fs::read(path)?;
    let verification_key: [u8; MLDSA44VerificationKey::len()] = bytes.try_into().map_err(|_| {
        DistributedError::Config(
            "swarm ML-DSA public key is corrupt; run `zkf swarm regenerate-key --force`"
                .to_string(),
        )
    })?;
    Ok(MLDSA44VerificationKey::new(verification_key))
}

fn ml_dsa_provenance(
    path: &Path,
    _verification_key: &MLDSA44VerificationKey,
) -> MlDsaKeyProvenance {
    MlDsaKeyProvenance {
        implementation: ML_DSA_IMPLEMENTATION.to_string(),
        storage_path: path.display().to_string(),
        public_key_path: ml_dsa_public_key_path(path).display().to_string(),
        metadata_path: ml_dsa_metadata_path(path).display().to_string(),
        permissions: "0600".to_string(),
    }
}

fn sync_ml_dsa_sidecars(
    path: &Path,
    verification_key: &MLDSA44VerificationKey,
) -> Result<(), DistributedError> {
    fs::write(ml_dsa_public_key_path(path), verification_key.as_slice())?;
    fs::write(
        ml_dsa_metadata_path(path),
        serde_json::to_vec_pretty(&ml_dsa_provenance(path, verification_key))
            .map_err(|err| DistributedError::Serialization(err.to_string()))?,
    )?;
    Ok(())
}

#[allow(dead_code)]
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    swarm_identity_core::leading_zero_bits(bytes)
}

fn ensure_backend_policy(config: &SwarmConfig) -> Result<(), DistributedError> {
    #[cfg(target_os = "macos")]
    {
        let policy_mode = std::env::var("ZKF_SECURITY_POLICY_MODE")
            .unwrap_or_else(|_| "enforce".to_string())
            .to_ascii_lowercase();
        if policy_mode != "observe" && config.key_backend != SwarmKeyBackend::Enclave {
            return Err(DistributedError::Config(
                "SecurityPolicyMode::Enforce on macOS requires ZKF_SWARM_KEY_BACKEND=enclave"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn ensure_identity_dir(path: &Path) -> Result<(), DistributedError> {
    fs::create_dir_all(
        path.parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".")),
    )?;
    Ok(())
}

fn read_seed_file(path: &Path) -> Result<LoadedSeed, DistributedError> {
    verify_private_key_permissions(path)?;
    let bytes = fs::read(path)?;
    let seed = to_seed(&bytes)?;
    let public_key_resynced =
        sync_public_key_file(path, &seed, true)? == PublicKeySyncStatus::Resynced;
    Ok(LoadedSeed {
        seed,
        public_key_resynced,
    })
}

fn verify_private_key_permissions(path: &Path) -> Result<(), DistributedError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path)?;
        let mode = metadata.mode() & 0o777;
        if mode != 0o600 {
            return Err(DistributedError::Config(format!(
                "swarm identity {} has insecure permissions {:o}",
                path.display(),
                mode
            )));
        }
    }
    Ok(())
}

fn write_seed_and_public_files(path: &Path, seed: &[u8; 32]) -> Result<(), DistributedError> {
    write_private_file(path, seed)?;
    let _ = sync_public_key_file(path, seed, false)?;
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), DistributedError> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn sync_public_key_file(
    path: &Path,
    seed: &[u8; 32],
    treat_missing_as_resync: bool,
) -> Result<PublicKeySyncStatus, DistributedError> {
    let public_path = public_key_path(path);
    let expected = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    if public_path.exists() {
        let existing = fs::read(&public_path)?;
        let stored: [u8; 32] = match existing.try_into() {
            Ok(stored) => stored,
            Err(_) => {
                fs::write(&public_path, expected)?;
                return Ok(PublicKeySyncStatus::Resynced);
            }
        };
        if stored != expected {
            fs::write(&public_path, expected)?;
            return Ok(PublicKeySyncStatus::Resynced);
        }
        return Ok(PublicKeySyncStatus::Unchanged);
    }
    fs::write(public_path, expected)?;
    Ok(if treat_missing_as_resync {
        PublicKeySyncStatus::Resynced
    } else {
        PublicKeySyncStatus::Created
    })
}

fn overwrite_public_key_file(path: &Path, seed: &[u8; 32]) -> Result<(), DistributedError> {
    let public_path = public_key_path(path);
    let expected = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    fs::write(public_path, expected)?;
    Ok(())
}

fn public_key_path(path: &Path) -> PathBuf {
    let mut public = path.to_path_buf();
    public.set_extension("ed25519.pub");
    public
}

fn ml_dsa_public_key_path(path: &Path) -> PathBuf {
    let mut public = path.to_path_buf();
    public.set_extension("mldsa44.pub");
    public
}

fn ml_dsa_metadata_path(path: &Path) -> PathBuf {
    let mut public = path.to_path_buf();
    public.set_extension("mldsa44.meta.json");
    public
}

fn to_seed(bytes: &[u8]) -> Result<[u8; 32], DistributedError> {
    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        DistributedError::Config(
            "swarm identity key material is corrupt; run `zkf swarm regenerate-key --force`"
                .to_string(),
        )
    })?;
    Ok(seed)
}

fn sanitize_label(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    bytes
        .iter()
        .take(count)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_temp_home<T>(f: impl FnOnce(PathBuf) -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let old_home = std::env::var_os("HOME");
        let old_policy = std::env::var_os("ZKF_SECURITY_POLICY_MODE");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("ZKF_SECURITY_POLICY_MODE", "observe");
        }
        let result = f(temp.path().to_path_buf());
        unsafe {
            if let Some(old_home) = old_home {
                std::env::set_var("HOME", old_home);
            } else {
                std::env::remove_var("HOME");
            }
            if let Some(old_policy) = old_policy {
                std::env::set_var("ZKF_SECURITY_POLICY_MODE", old_policy);
            } else {
                std::env::remove_var("ZKF_SECURITY_POLICY_MODE");
            }
        }
        result
    }

    #[test]
    fn signature_roundtrip_verifies() {
        with_temp_home(|_| {
            let config = SwarmConfig {
                key_backend: SwarmKeyBackend::File,
                ..SwarmConfig::default()
            };
            let identity =
                LocalPeerIdentity::load_or_create(&config, "unit-test-identity").unwrap();
            let message = b"zkf-swarm";
            let signature = identity.sign_bundle(message);
            assert!(LocalPeerIdentity::verify_bundle(
                &identity.public_key_bundle(),
                message,
                &signature
            ));
            assert!(LocalPeerIdentity::verify(
                &identity.public_key_bytes(),
                message,
                &signature.ed25519
            ));
        });
    }

    #[test]
    fn insecure_permissions_are_rejected() {
        with_temp_home(|home| {
            let config = SwarmConfig {
                key_backend: SwarmKeyBackend::File,
                ..SwarmConfig::default()
            };
            let path = config.identity_path.join("bad-perms.ed25519");
            ensure_identity_dir(&path).unwrap();
            let seed = [7u8; 32];
            fs::write(&path, seed).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            let err = FileBackend.load_existing(&path, "bad-perms").unwrap_err();
            assert!(err.to_string().contains("insecure permissions"));
            drop(home);
        });
    }

    #[test]
    fn corrupt_public_key_is_resynced_from_private_seed() {
        with_temp_home(|_| {
            let config = SwarmConfig {
                key_backend: SwarmKeyBackend::File,
                ..SwarmConfig::default()
            };
            let identity = LocalPeerIdentity::load_or_create(&config, "corrupt-pub").unwrap();
            let path = config.identity_path.join("corrupt-pub.ed25519");
            fs::write(public_key_path(&path), [9u8; 32]).unwrap();
            let repaired = LocalPeerIdentity::load_or_create(&config, "corrupt-pub").unwrap();
            assert!(repaired.public_key_resynced());
            assert_eq!(repaired.public_key_bytes(), identity.public_key_bytes());
            let stored = fs::read(public_key_path(&path)).unwrap();
            assert_eq!(stored, repaired.public_key_bytes());
        });
    }

    #[test]
    fn missing_public_key_is_resynced_from_private_seed() {
        with_temp_home(|_| {
            let config = SwarmConfig {
                key_backend: SwarmKeyBackend::File,
                ..SwarmConfig::default()
            };
            let identity = LocalPeerIdentity::load_or_create(&config, "missing-pub").unwrap();
            let path = config.identity_path.join("missing-pub.ed25519");
            fs::remove_file(public_key_path(&path)).unwrap();
            let repaired = LocalPeerIdentity::load_or_create(&config, "missing-pub").unwrap();
            assert!(repaired.public_key_resynced());
            assert_eq!(repaired.public_key_bytes(), identity.public_key_bytes());
        });
    }

    #[test]
    fn rotate_rewrites_public_key_sidecars() {
        with_temp_home(|_| {
            let config = SwarmConfig {
                key_backend: SwarmKeyBackend::File,
                ..SwarmConfig::default()
            };
            let original = LocalPeerIdentity::load_or_create(&config, "rotate-me").unwrap();
            let original_public = original.public_key_bundle();
            let rotated = LocalPeerIdentity::rotate(&config, "rotate-me").unwrap();
            let rotated_public = rotated.public_key_bundle();
            assert_ne!(original_public, rotated_public);
            let stored_ed25519 = fs::read(public_key_path(
                &config.identity_path.join("rotate-me.ed25519"),
            ))
            .unwrap();
            let stored_ml_dsa = fs::read(ml_dsa_public_key_path(
                &config.identity_path.join("rotate-me.mldsa44"),
            ))
            .unwrap();
            assert_eq!(stored_ed25519, rotated.public_key_bytes());
            assert_eq!(stored_ml_dsa, rotated.ml_dsa_public_key_bytes());
        });
    }

    #[test]
    fn mldsa_metadata_sidecar_is_written() {
        with_temp_home(|_| {
            let config = SwarmConfig {
                key_backend: SwarmKeyBackend::File,
                ..SwarmConfig::default()
            };
            let identity = LocalPeerIdentity::load_or_create(&config, "sidecars").unwrap();
            let metadata_path =
                ml_dsa_metadata_path(&config.identity_path.join("sidecars.mldsa44"));
            assert!(metadata_path.exists());
            let provenance: MlDsaKeyProvenance =
                serde_json::from_slice(&fs::read(metadata_path).unwrap()).unwrap();
            assert_eq!(provenance.implementation, ML_DSA_IMPLEMENTATION);
            assert_eq!(
                identity.ml_dsa_provenance().implementation,
                ML_DSA_IMPLEMENTATION
            );
        });
    }

    #[test]
    fn admission_pow_roundtrip_verifies() {
        let public_key = [9u8; 32];
        let nonce = compute_admission_pow(&public_key, 8);
        assert!(verify_admission_pow(&public_key, nonce, 8));
        assert!(!verify_admission_pow(&public_key, nonce.wrapping_add(1), 8));
    }

    #[test]
    fn verify_signed_message_rejects_partial_bundle_surface_even_with_valid_legacy_signature() {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let message = b"zkf-distributed";
        let legacy_signature = signing_key.sign(message).to_bytes().to_vec();
        let legacy_public_key = signing_key.verifying_key().to_bytes();
        let public_key_bundle = PublicKeyBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa44,
            ed25519: legacy_public_key.to_vec(),
            ml_dsa44: vec![7; 16],
        };
        let signature_bundle = SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa44,
            ed25519: legacy_signature.clone(),
            ml_dsa44: vec![9; 32],
        };

        assert!(!LocalPeerIdentity::verify_signed_message(
            &legacy_public_key,
            Some(&public_key_bundle),
            message,
            &legacy_signature,
            None,
        ));
        assert!(!LocalPeerIdentity::verify_signed_message(
            &legacy_public_key,
            None,
            message,
            &legacy_signature,
            Some(&signature_bundle),
        ));
    }
}
