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

use crate::{PublicKeyBundle, SignatureBundle, SignatureScheme};
use ed25519_dalek::{Signer, SigningKey};
use libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE;
use libcrux_ml_dsa::ml_dsa_87::{MLDSA87SigningKey, MLDSA87VerificationKey, sign as mldsa_sign};
use std::fs;
use std::path::{Path, PathBuf};

const ML_DSA_CONTEXT: &[u8] = b"zkf-swarm";
const SWARM_ED25519_SERVICE: &str = "com.ziros.swarm.ed25519";
const SWARM_MLDSA87_SERVICE: &str = "com.ziros.swarm.mldsa87";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwarmIdentityKeyBackend {
    File,
    Enclave,
}

#[derive(Clone, Debug)]
pub struct ReadOnlySwarmSigner {
    label: String,
    ed25519_seed: [u8; 32],
    ml_dsa_private_key: Vec<u8>,
    public_key_bundle: PublicKeyBundle,
}

impl ReadOnlySwarmSigner {
    pub fn load_existing(
        identity_path: &Path,
        label: &str,
        key_backend: SwarmIdentityKeyBackend,
    ) -> Result<Self, String> {
        let ed25519_path = identity_path.join(format!("{label}.ed25519"));
        let ml_dsa_path = identity_path.join(format!("{label}.mldsa87"));
        let ed25519_seed = match key_backend {
            SwarmIdentityKeyBackend::File => read_seed_file(&ed25519_path)?,
            SwarmIdentityKeyBackend::Enclave => load_enclave_seed(&ed25519_path, label)?,
        };
        let ml_dsa_signing_key = match key_backend {
            SwarmIdentityKeyBackend::File => load_ml_dsa_signing_key(&ml_dsa_path)?,
            SwarmIdentityKeyBackend::Enclave => {
                load_enclave_ml_dsa_signing_key(&ml_dsa_path, label)?
            }
        };
        let ml_dsa_public_key = load_ml_dsa_public_key(&ml_dsa_public_key_path(&ml_dsa_path))?;
        let ed25519_public_key = SigningKey::from_bytes(&ed25519_seed)
            .verifying_key()
            .to_bytes();
        Ok(Self {
            label: label.to_string(),
            ed25519_seed,
            ml_dsa_private_key: ml_dsa_signing_key.as_slice().to_vec(),
            public_key_bundle: PublicKeyBundle {
                scheme: SignatureScheme::HybridEd25519MlDsa87,
                ed25519: ed25519_public_key.to_vec(),
                ml_dsa87: ml_dsa_public_key.as_slice().to_vec(),
            },
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn sign_bundle(&self, bytes: &[u8]) -> Result<SignatureBundle, String> {
        let ed25519 = SigningKey::from_bytes(&self.ed25519_seed)
            .sign(bytes)
            .to_bytes()
            .to_vec();
        let ml_dsa_signing_key = MLDSA87SigningKey::new(
            self.ml_dsa_private_key
                .as_slice()
                .try_into()
                .map_err(|_| "swarm ML-DSA key material is corrupt".to_string())?,
        );
        let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
        crate::secure_random::secure_random_bytes(&mut randomness)?;
        let ml_dsa_signature = mldsa_sign(&ml_dsa_signing_key, bytes, ML_DSA_CONTEXT, randomness)
            .map_err(|_| "swarm ML-DSA signing failed".to_string())?;
        Ok(SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519,
            ml_dsa87: ml_dsa_signature.as_slice().to_vec(),
        })
    }

    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        self.public_key_bundle.clone()
    }
}

fn load_enclave_seed(_path: &Path, label: &str) -> Result<[u8; 32], String> {
    #[cfg(target_os = "macos")]
    {
        let seed = crate::keystore::retrieve_service_key(SWARM_ED25519_SERVICE, label)
            .map_err(|err| format!("failed to retrieve swarm identity from enclave: {err}"))?;
        to_seed(&seed)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = label;
        read_seed_file(path)
    }
}

fn load_enclave_ml_dsa_signing_key(_path: &Path, label: &str) -> Result<MLDSA87SigningKey, String> {
    #[cfg(target_os = "macos")]
    {
        let bytes =
            crate::keystore::retrieve_service_key(SWARM_MLDSA87_SERVICE, label).map_err(|err| {
                format!("failed to retrieve swarm ML-DSA identity from enclave: {err}")
            })?;
        let signing_key: [u8; MLDSA87SigningKey::len()] = bytes
            .try_into()
            .map_err(|_| "swarm ML-DSA key material is corrupt".to_string())?;
        Ok(MLDSA87SigningKey::new(signing_key))
    }
    #[cfg(not(target_os = "macos"))]
    {
        load_ml_dsa_signing_key(path)
    }
}

fn read_seed_file(path: &Path) -> Result<[u8; 32], String> {
    verify_private_key_permissions(path)?;
    let bytes = fs::read(path)
        .map_err(|err| format!("failed to read swarm identity {}: {err}", path.display()))?;
    to_seed(&bytes)
}

fn to_seed(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "swarm identity key material is corrupt".to_string())
}

fn verify_private_key_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path)
            .map_err(|err| format!("failed to stat swarm identity {}: {err}", path.display()))?;
        let mode = metadata.mode() & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "swarm identity {} has insecure permissions {:o}",
                path.display(),
                mode
            ));
        }
    }
    Ok(())
}

fn load_ml_dsa_signing_key(path: &Path) -> Result<MLDSA87SigningKey, String> {
    verify_private_key_permissions(path)?;
    let bytes = fs::read(path)
        .map_err(|err| format!("failed to read swarm ML-DSA key {}: {err}", path.display()))?;
    let signing_key: [u8; MLDSA87SigningKey::len()] = bytes
        .try_into()
        .map_err(|_| "swarm ML-DSA key material is corrupt".to_string())?;
    Ok(MLDSA87SigningKey::new(signing_key))
}

fn load_ml_dsa_public_key(path: &Path) -> Result<MLDSA87VerificationKey, String> {
    let bytes = fs::read(path).map_err(|err| {
        format!(
            "failed to read swarm ML-DSA public key {}: {err}",
            path.display()
        )
    })?;
    let verification_key: [u8; MLDSA87VerificationKey::len()] = bytes
        .try_into()
        .map_err(|_| "swarm ML-DSA public key is corrupt".to_string())?;
    Ok(MLDSA87VerificationKey::new(verification_key))
}

fn ml_dsa_public_key_path(path: &Path) -> PathBuf {
    let mut public = path.to_path_buf();
    public.set_extension("mldsa87.pub");
    public
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_bundle;
    use libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE;
    use libcrux_ml_dsa::ml_dsa_87::generate_key_pair;
    use std::fs;

    #[test]
    fn read_only_signer_loads_existing_file_identity_and_signs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let identity_root = temp.path();
        let label = "proof-origin";
        let ed25519_path = identity_root.join(format!("{label}.ed25519"));
        let ml_dsa_path = identity_root.join(format!("{label}.mldsa87"));
        let ml_dsa_public_path = identity_root.join(format!("{label}.mldsa87.pub"));

        write_private_file(&ed25519_path, &[3u8; 32]);
        let keypair = generate_key_pair([9u8; KEY_GENERATION_RANDOMNESS_SIZE]);
        write_private_file(&ml_dsa_path, keypair.signing_key.as_slice());
        fs::write(&ml_dsa_public_path, keypair.verification_key.as_slice())
            .expect("write ML-DSA public key");

        let signer =
            ReadOnlySwarmSigner::load_existing(identity_root, label, SwarmIdentityKeyBackend::File)
                .expect("load signer");
        let message = b"proof-origin-hash";
        let signature_bundle = signer.sign_bundle(message).expect("sign bundle");
        assert!(verify_bundle(
            &signer.public_key_bundle(),
            message,
            &signature_bundle,
            ML_DSA_CONTEXT,
        ));
    }

    fn write_private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write private key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("set permissions");
        }
    }
}
