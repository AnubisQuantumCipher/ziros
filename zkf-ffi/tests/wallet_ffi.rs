use std::ffi::{CStr, CString};

use tempfile::tempdir;
use zkf_ffi::{
    zkf_last_error_message, zkf_string_free, zkf_wallet_bridge_make_transfer,
    zkf_wallet_bridge_open_session, zkf_wallet_bridge_session_free,
    zkf_wallet_consume_bridge_submission_grant, zkf_wallet_create_rust_test_handle_with_roots,
    zkf_wallet_destroy, zkf_wallet_grant_origin, zkf_wallet_helper_open_session_json,
    zkf_wallet_import_master_seed, zkf_wallet_issue_bridge_submission_grant_json,
    zkf_wallet_pending_approval_free, zkf_wallet_pending_approve, zkf_wallet_pending_review_json,
    zkf_wallet_unlock,
};

fn last_error() -> String {
    let pointer = zkf_last_error_message();
    if pointer.is_null() {
        "(unknown ffi error)".to_string()
    } else {
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }
}

fn owned_string(pointer: *mut std::ffi::c_char) -> String {
    assert!(!pointer.is_null(), "{}", last_error());
    let value = unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    zkf_string_free(pointer);
    value
}

fn create_wallet() -> *mut zkf_ffi::ZkfWalletHandle {
    let temp = tempdir().expect("tempdir");
    let wallet = zkf_wallet_create_rust_test_handle_with_roots(
        zkf_wallet::WalletNetwork::Preprod,
        temp.path().join("persistent"),
        temp.path().join("cache"),
    )
    .expect("test wallet");
    assert!(!wallet.is_null(), "{}", last_error());
    wallet
}

fn import_seed(wallet: *mut zkf_ffi::ZkfWalletHandle) {
    let seed = CString::new(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .expect("seed");
    let summary = zkf_wallet_import_master_seed(wallet, seed.as_ptr());
    let imported = owned_string(summary);
    assert!(imported.contains("\"kind\":\"master-seed\""));
}

fn unlock(wallet: *mut zkf_ffi::ZkfWalletHandle) {
    let prompt = CString::new("Unlock").expect("prompt");
    assert_eq!(zkf_wallet_unlock(wallet, prompt.as_ptr()), 0, "{}", last_error());
}

fn grant_origin(wallet: *mut zkf_ffi::ZkfWalletHandle) {
    let grant = CString::new(
        "{\"origin\":\"https://dapp.example\",\"scopes\":[\"transfer\",\"submit\"],\"authorized_at\":\"2026-04-03T00:00:00Z\"}",
    )
    .expect("grant json");
    assert_eq!(zkf_wallet_grant_origin(wallet, grant.as_ptr()), 0, "{}", last_error());
}

#[test]
fn bridge_review_surfaces_authorized_origin() {
    let wallet = create_wallet();
    import_seed(wallet);
    unlock(wallet);
    grant_origin(wallet);

    let origin = CString::new("https://dapp.example").expect("origin");
    let session = zkf_wallet_bridge_open_session(wallet, origin.as_ptr());
    assert!(!session.is_null(), "{}", last_error());

    let review = CString::new(
        "{\"origin\":\"https://dapp.example\",\"network\":\"preprod\",\"method\":\"transfer\",\"tx_digest\":\"tx-ffi-review\",\"outputs\":[{\"recipient\":\"midnight1dest\",\"token_kind\":\"NIGHT\",\"amount_raw\":\"10\"}],\"night_total_raw\":\"10\",\"dust_total_raw\":\"0\",\"fee_raw\":\"1\",\"shielded\":true,\"prover_route\":\"proof-server\",\"warnings\":[],\"human_summary\":\"send 10 NIGHT\"}",
    )
    .expect("review json");
    let pending = zkf_wallet_bridge_make_transfer(session, review.as_ptr());
    assert!(!pending.is_null(), "{}", last_error());

    let pending_review = owned_string(zkf_wallet_pending_review_json(pending));
    assert!(pending_review.contains("\"origin\":\"https://dapp.example\""));
    assert!(pending_review.contains("\"tx_digest\":\"tx-ffi-review\""));

    zkf_wallet_pending_approval_free(pending);
    zkf_wallet_bridge_session_free(session);
    zkf_wallet_destroy(wallet);
}

#[test]
fn bridge_origin_mismatch_fails_closed() {
    let wallet = create_wallet();
    import_seed(wallet);
    unlock(wallet);
    grant_origin(wallet);

    let origin = CString::new("https://dapp.example").expect("origin");
    let session = zkf_wallet_bridge_open_session(wallet, origin.as_ptr());
    assert!(!session.is_null(), "{}", last_error());

    let review = CString::new(
        "{\"origin\":\"https://evil.example\",\"network\":\"preprod\",\"method\":\"transfer\",\"tx_digest\":\"tx-ffi-origin-mismatch\",\"outputs\":[],\"night_total_raw\":\"10\",\"dust_total_raw\":\"0\",\"fee_raw\":\"1\",\"shielded\":true,\"prover_route\":\"proof-server\",\"warnings\":[],\"human_summary\":\"send 10 NIGHT\"}",
    )
    .expect("review json");
    let pending = zkf_wallet_bridge_make_transfer(session, review.as_ptr());
    assert!(pending.is_null(), "origin mismatch should fail");
    assert!(last_error().contains("review origin does not match"));

    zkf_wallet_bridge_session_free(session);
    zkf_wallet_destroy(wallet);
}

#[test]
fn bridge_submit_without_rust_issued_grant_fails() {
    let wallet = create_wallet();
    import_seed(wallet);
    unlock(wallet);
    grant_origin(wallet);

    let origin = CString::new("https://dapp.example").expect("origin");
    let session = zkf_wallet_bridge_open_session(wallet, origin.as_ptr());
    assert!(!session.is_null(), "{}", last_error());

    let review = CString::new(
        "{\"origin\":\"https://dapp.example\",\"network\":\"preprod\",\"method\":\"transfer\",\"tx_digest\":\"tx-ffi-no-token\",\"outputs\":[{\"recipient\":\"midnight1dest\",\"token_kind\":\"NIGHT\",\"amount_raw\":\"10\"}],\"night_total_raw\":\"10\",\"dust_total_raw\":\"0\",\"fee_raw\":\"1\",\"shielded\":true,\"prover_route\":\"proof-server\",\"warnings\":[],\"human_summary\":\"send 10 NIGHT\"}",
    )
    .expect("review json");
    let pending = zkf_wallet_bridge_make_transfer(session, review.as_ptr());
    assert!(!pending.is_null(), "{}", last_error());

    let approve_prompt = CString::new("Approve transfer").expect("approve");
    let token_json = owned_string(zkf_wallet_pending_approve(
        pending,
        approve_prompt.as_ptr(),
        std::ptr::null(),
    ));
    let method = CString::new("transfer").expect("method");
    let tx_digest = CString::new("tx-ffi-no-token").expect("tx digest");
    let grant_json = owned_string(zkf_wallet_issue_bridge_submission_grant_json(
        session,
        method.as_ptr(),
        tx_digest.as_ptr(),
        CString::new(token_json).expect("token json").as_ptr(),
    ));
    let forged_grant = CString::new(
        "{\"grant_id\":\"forged-grant\",\"token_id\":\"forged-token\",\"origin\":\"https://dapp.example\",\"network\":\"preprod\",\"method\":\"transfer\",\"tx_digest\":\"tx-ffi-no-token\",\"issued_at\":\"2026-04-03T00:00:00Z\",\"expires_at\":\"2026-04-03T00:03:00Z\"}",
    )
    .expect("forged grant");
    let status = zkf_wallet_consume_bridge_submission_grant(
        session,
        method.as_ptr(),
        tx_digest.as_ptr(),
        forged_grant.as_ptr(),
    );
    assert_eq!(status, -1, "forged grant should be rejected");
    assert!(last_error().contains("approval_required"));

    let real_grant = CString::new(grant_json).expect("real grant");
    let ok = zkf_wallet_consume_bridge_submission_grant(
        session,
        method.as_ptr(),
        tx_digest.as_ptr(),
        real_grant.as_ptr(),
    );
    assert_eq!(ok, 0, "{}", last_error());

    zkf_wallet_pending_approval_free(pending);
    zkf_wallet_bridge_session_free(session);
    zkf_wallet_destroy(wallet);
}

#[test]
fn helper_session_bundle_requires_unlock_and_import() {
    let wallet = create_wallet();

    let locked_bundle = zkf_wallet_helper_open_session_json(wallet);
    assert!(locked_bundle.is_null(), "helper session should require unlock");
    assert!(last_error().contains("wallet seed import required") || last_error().contains("auth_required"));

    import_seed(wallet);
    unlock(wallet);
    let helper_bundle = owned_string(zkf_wallet_helper_open_session_json(wallet));
    assert!(helper_bundle.contains("\"seed\":{\"kind\":\"master-seed\""));
    assert!(helper_bundle.contains("\"session\""));

    zkf_wallet_destroy(wallet);
}
