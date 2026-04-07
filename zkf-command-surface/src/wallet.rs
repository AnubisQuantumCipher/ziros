use crate::types::now_rfc3339;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
use zkf_cloudfs::CloudFS;
use zkf_wallet::{
    ApprovalMethod, ApprovalToken, AuthPolicy, BridgeOriginGrant, BridgeScope,
    KeyManagerSeedStore, PendingApprovalView, ServiceHealthSnapshot, SubmissionGrant,
    SystemBiometricAuthorizer, SystemClock, TxReviewPayload, WalletHandle, WalletNetwork,
    WalletServiceConfig, WalletSnapshot,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BridgePendingKindV1 {
    Transfer,
    Intent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBridgeSessionOpenedV1 {
    pub session_id: String,
    pub origin: String,
    pub opened_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct WalletContextV1 {
    pub network: Option<WalletNetwork>,
    pub persistent_root: Option<PathBuf>,
    pub cache_root: Option<PathBuf>,
}

impl WalletContextV1 {
    pub fn open_handle(&self) -> Result<WalletHandle, String> {
        let network = self.network.unwrap_or(WalletNetwork::Preprod);
        let cloudfs = build_cloudfs(self.persistent_root.clone(), self.cache_root.clone())?;
        WalletHandle::with_components(
            network,
            WalletServiceConfig::for_network(network),
            AuthPolicy::default(),
            cloudfs,
            Box::new(SystemBiometricAuthorizer),
            Box::new(KeyManagerSeedStore::new().map_err(|error| error.to_string())?),
            Box::new(SystemClock),
        )
        .map_err(|error| error.to_string())
    }
}

pub fn snapshot(wallet: &mut WalletHandle) -> Result<WalletSnapshot, String> {
    wallet.snapshot().map_err(|error| error.to_string())
}

pub fn unlock(wallet: &mut WalletHandle, prompt: &str) -> Result<WalletSnapshot, String> {
    wallet.unlock(prompt).map_err(|error| error.to_string())?;
    snapshot(wallet)
}

pub fn lock(wallet: &mut WalletHandle) -> Result<WalletSnapshot, String> {
    wallet.lock().map_err(|error| error.to_string())?;
    snapshot(wallet)
}

pub fn sync_health(wallet: &mut WalletHandle) -> Result<ServiceHealthSnapshot, String> {
    wallet.sync_health().map_err(|error| error.to_string())
}

pub fn grant_origin(
    wallet: &mut WalletHandle,
    origin: String,
    scopes: BTreeSet<BridgeScope>,
    note: Option<String>,
) -> Result<BridgeOriginGrant, String> {
    let grant = BridgeOriginGrant {
        origin,
        scopes,
        authorized_at: chrono::Utc::now(),
        note,
    };
    wallet
        .grant_origin(grant.clone())
        .map_err(|error| error.to_string())?;
    Ok(grant)
}

pub fn revoke_origin(wallet: &mut WalletHandle, origin: &str) -> Result<WalletSnapshot, String> {
    wallet
        .revoke_origin(origin)
        .map_err(|error| error.to_string())?;
    snapshot(wallet)
}

pub fn open_session(
    wallet: &mut WalletHandle,
    origin: &str,
) -> Result<WalletBridgeSessionOpenedV1, String> {
    let session_id = wallet
        .open_bridge_session(origin)
        .map_err(|error| error.to_string())?;
    Ok(WalletBridgeSessionOpenedV1 {
        session_id,
        origin: origin.to_string(),
        opened_at: now_rfc3339(),
    })
}

pub fn begin_native(
    wallet: &mut WalletHandle,
    review: TxReviewPayload,
) -> Result<PendingApprovalView, String> {
    wallet
        .begin_native_action(review)
        .map_err(|error| error.to_string())
}

pub fn begin_bridge(
    wallet: &mut WalletHandle,
    session_id: &str,
    kind: BridgePendingKindV1,
    review: TxReviewPayload,
) -> Result<PendingApprovalView, String> {
    match kind {
        BridgePendingKindV1::Transfer => wallet
            .begin_bridge_transfer(session_id, review)
            .map_err(|error| error.to_string()),
        BridgePendingKindV1::Intent => wallet
            .begin_bridge_intent(session_id, review)
            .map_err(|error| error.to_string()),
    }
}

pub fn pending_review(
    wallet: &WalletHandle,
    pending_id: &str,
) -> Result<PendingApprovalView, String> {
    wallet
        .pending_review(pending_id)
        .map_err(|error| error.to_string())
}

pub fn approve_pending(
    wallet: &mut WalletHandle,
    pending_id: &str,
    primary_prompt: &str,
    secondary_prompt: Option<&str>,
) -> Result<ApprovalToken, String> {
    wallet
        .approve_pending(pending_id, primary_prompt, secondary_prompt)
        .map_err(|error| error.to_string())
}

pub fn reject_pending(
    wallet: &mut WalletHandle,
    pending_id: &str,
    reason: &str,
) -> Result<(), String> {
    wallet
        .reject_pending(pending_id, reason)
        .map_err(|error| error.to_string())
}

pub fn issue_native_grant(
    wallet: &mut WalletHandle,
    method: ApprovalMethod,
    tx_digest: &str,
    token: &ApprovalToken,
) -> Result<SubmissionGrant, String> {
    wallet
        .issue_native_submission_grant(method, tx_digest, token)
        .map_err(|error| error.to_string())
}

pub fn issue_bridge_grant(
    wallet: &mut WalletHandle,
    session_id: &str,
    method: ApprovalMethod,
    tx_digest: &str,
    token: &ApprovalToken,
) -> Result<SubmissionGrant, String> {
    wallet
        .issue_bridge_submission_grant(session_id, method, tx_digest, token)
        .map_err(|error| error.to_string())
}

pub fn consume_native_grant(
    wallet: &mut WalletHandle,
    method: ApprovalMethod,
    tx_digest: &str,
    grant: &SubmissionGrant,
) -> Result<(), String> {
    wallet
        .consume_native_submission_grant(method, tx_digest, grant)
        .map_err(|error| error.to_string())
}

pub fn consume_bridge_grant(
    wallet: &mut WalletHandle,
    session_id: &str,
    method: ApprovalMethod,
    tx_digest: &str,
    grant: &SubmissionGrant,
) -> Result<(), String> {
    wallet
        .consume_bridge_submission_grant(session_id, method, tx_digest, grant)
        .map_err(|error| error.to_string())
}

fn build_cloudfs(
    persistent_root: Option<PathBuf>,
    cache_root: Option<PathBuf>,
) -> Result<CloudFS, String> {
    if persistent_root.is_none() && cache_root.is_none() {
        return CloudFS::new().map_err(|error| error.to_string());
    }
    let default = CloudFS::new().map_err(|error| error.to_string())?;
    Ok(CloudFS::from_roots(
        persistent_root.unwrap_or_else(|| default.persistent_root().to_path_buf()),
        cache_root.unwrap_or_else(|| default.cache_root().to_path_buf()),
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use zkf_wallet::{
        ApprovalMethod, BiometricAuthorizer, Clock, ReviewOutput, SeedImportKind,
        SeedImportMaterial, SeedStore, WalletNetwork,
    };

    #[derive(Debug)]
    struct FixedClock {
        now: DateTime<Utc>,
    }

    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.now
        }
    }

    #[derive(Debug, Default)]
    struct TestAuthorizer;

    impl BiometricAuthorizer for TestAuthorizer {
        fn ensure_material(&self, _network: WalletNetwork) -> Result<(), zkf_wallet::WalletError> {
            Ok(())
        }

        fn authenticate(
            &self,
            _network: WalletNetwork,
            _prompt: &str,
        ) -> Result<(), zkf_wallet::WalletError> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct TestSeedStore {
        imported: Arc<Mutex<Option<SeedImportMaterial>>>,
    }

    impl SeedStore for TestSeedStore {
        fn store_seed_material(
            &self,
            _network: WalletNetwork,
            material: &SeedImportMaterial,
        ) -> Result<(), zkf_wallet::WalletError> {
            *self.imported.lock().expect("seed lock") = Some(material.clone());
            Ok(())
        }

        fn unlock_seed_material(
            &self,
            _network: WalletNetwork,
            _prompt: &str,
        ) -> Result<SeedImportMaterial, zkf_wallet::WalletError> {
            self.imported
                .lock()
                .expect("seed lock")
                .clone()
                .ok_or_else(|| {
                    zkf_wallet::WalletError::BiometricFailed("missing seed material".to_string())
                })
        }
    }

    fn wallet_fixture() -> WalletHandle {
        let temp = tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(
            temp.path().join("persistent"),
            temp.path().join("cache"),
            false,
        );
        let seed_store = TestSeedStore::default();
        seed_store
            .store_seed_material(
                WalletNetwork::Preprod,
                &SeedImportMaterial {
                    kind: SeedImportKind::MasterSeed,
                    value: "seed-material".to_string(),
                    imported_at: Utc::now(),
                },
            )
            .expect("seed import");
        WalletHandle::with_components(
            WalletNetwork::Preprod,
            WalletServiceConfig::for_network(WalletNetwork::Preprod),
            AuthPolicy::default(),
            cloudfs,
            Box::new(TestAuthorizer),
            Box::new(seed_store),
            Box::new(FixedClock { now: Utc::now() }),
        )
        .expect("wallet fixture")
    }

    fn review(origin: &str, method: ApprovalMethod) -> TxReviewPayload {
        TxReviewPayload {
            origin: origin.to_string(),
            network: WalletNetwork::Preprod,
            method,
            tx_digest: "0xabc123".to_string(),
            outputs: vec![ReviewOutput {
                recipient: "operator".to_string(),
                token_kind: "NIGHT".to_string(),
                amount_raw: "10".to_string(),
            }],
            night_total_raw: "10".to_string(),
            dust_total_raw: "0".to_string(),
            fee_raw: "1".to_string(),
            dust_impact: None,
            shielded: true,
            prover_route: Some("midnight-proof-server".to_string()),
            warnings: Vec::new(),
            human_summary: "test transaction".to_string(),
        }
    }

    #[test]
    fn wallet_roundtrip_supports_pending_and_grants() {
        let mut wallet = wallet_fixture();
        wallet.unlock("Unlock").expect("unlock");
        let pending = begin_native(&mut wallet, review("native://wallet", ApprovalMethod::Transfer))
            .expect("begin native");
        let reviewed = pending_review(&wallet, &pending.pending_id).expect("review");
        assert_eq!(reviewed.pending_id, pending.pending_id);

        let token =
            approve_pending(&mut wallet, &pending.pending_id, "Approve", None).expect("approve");
        let grant = issue_native_grant(
            &mut wallet,
            ApprovalMethod::Transfer,
            "0xabc123",
            &token,
        )
        .expect("issue grant");
        consume_native_grant(&mut wallet, ApprovalMethod::Transfer, "0xabc123", &grant)
            .expect("consume grant");
    }

    #[test]
    fn wallet_bridge_origin_session_flow_roundtrips() {
        let mut wallet = wallet_fixture();
        let grant = grant_origin(
            &mut wallet,
            "https://dapp.example".to_string(),
            BTreeSet::from([BridgeScope::Transfer, BridgeScope::Submit]),
            Some("trusted".to_string()),
        )
        .expect("grant");
        assert_eq!(grant.origin, "https://dapp.example");
        let session = open_session(&mut wallet, "https://dapp.example").expect("session");
        assert!(!session.session_id.is_empty());
    }
}
