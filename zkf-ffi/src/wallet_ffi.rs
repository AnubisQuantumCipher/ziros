use crate::{c_int_error, clear_last_error, null_error, sanitize_cstring, string_arg};
use std::collections::HashMap;
use std::ffi::{c_char, c_int};
use std::path::PathBuf;
use std::sync::Mutex;
use zkf_cloudfs::CloudFS;
use zkf_wallet::{
    ApprovalMethod, ApprovalToken, AuthPolicy, BiometricAuthorizer, BridgeOriginGrant,
    KeyManagerSeedStore, MailboxEnvelope, MailboxPostFailure, MailboxPostSuccess,
    MessagingTransportUpdate, PendingApprovalView, SeedImportMaterial, SeedImportSummary,
    SeedStore, SubmissionGrant, SystemBiometricAuthorizer, SystemClock, TxReviewPayload,
    WalletChannelOpenRequest, WalletCredentialRequest, WalletCredentialResponse, WalletError,
    WalletHandle, WalletNetwork, WalletPeerId, WalletServiceConfig, WalletTransferReceipt,
};

#[repr(C)]
pub struct ZkfWalletHandle {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ZkfBridgeSessionHandle {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ZkfPendingApprovalHandle {
    _private: [u8; 0],
}

struct WalletRuntime {
    wallet: Mutex<WalletHandle>,
}

struct BridgeSessionRuntime {
    wallet: *mut WalletRuntime,
    session_id: String,
}

struct PendingApprovalRuntime {
    wallet: *mut WalletRuntime,
    pending_id: String,
}

#[derive(Debug, Default)]
struct TestingBiometricAuthorizer;

impl BiometricAuthorizer for TestingBiometricAuthorizer {
    fn ensure_material(&self, _network: WalletNetwork) -> Result<(), WalletError> {
        Ok(())
    }

    fn authenticate(&self, _network: WalletNetwork, _prompt: &str) -> Result<(), WalletError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct TestingSeedStore {
    materials: Mutex<HashMap<WalletNetwork, SeedImportMaterial>>,
}

impl SeedStore for TestingSeedStore {
    fn store_seed_material(
        &self,
        network: WalletNetwork,
        material: &SeedImportMaterial,
    ) -> Result<(), WalletError> {
        self.materials
            .lock()
            .map_err(|_| WalletError::BridgePolicyViolation("testing seed store poisoned".to_string()))?
            .insert(network, material.clone());
        Ok(())
    }

    fn unlock_seed_material(
        &self,
        network: WalletNetwork,
        _prompt: &str,
    ) -> Result<SeedImportMaterial, WalletError> {
        self.materials
            .lock()
            .map_err(|_| WalletError::BridgePolicyViolation("testing seed store poisoned".to_string()))?
            .get(&network)
            .cloned()
            .ok_or_else(|| {
                WalletError::BridgePolicyViolation(
                    "wallet seed import required before unlock".to_string(),
                )
            })
    }
}

fn json_string<T: serde::Serialize>(value: &T) -> Result<*mut c_char, String> {
    let serialized =
        serde_json::to_string(value).map_err(|err| format!("json serialization failed: {err}"))?;
    Ok(sanitize_cstring(serialized).into_raw())
}

fn optional_string_arg(ptr: *const c_char, label: &str) -> Result<Option<String>, String> {
    if ptr.is_null() {
        Ok(None)
    } else {
        string_arg(ptr, label).map(Some)
    }
}

fn parse_wallet_network(ptr: *const c_char) -> Result<WalletNetwork, String> {
    let raw = string_arg(ptr, "network")?;
    WalletNetwork::parse(raw.as_str()).map_err(|err| err.to_string())
}

fn parse_wallet_peer_id(ptr: *const c_char, label: &str) -> Result<WalletPeerId, String> {
    let raw = string_arg(ptr, label)?;
    WalletPeerId::parse(raw.as_str()).map_err(|err| err.to_string())
}

fn parse_json_arg<T: serde::de::DeserializeOwned>(
    ptr: *const c_char,
    label: &str,
) -> Result<T, String> {
    let raw = string_arg(ptr, label)?;
    serde_json::from_str(&raw).map_err(|err| format!("failed to parse {label}: {err}"))
}

fn with_wallet_mut<T>(
    handle: *mut ZkfWalletHandle,
    f: impl FnOnce(&mut WalletHandle) -> Result<T, String>,
) -> Result<T, String> {
    if handle.is_null() {
        return Err("wallet pointer is null".to_string());
    }

    let runtime = unsafe { &mut *(handle as *mut WalletRuntime) };
    let mut guard = runtime
        .wallet
        .lock()
        .map_err(|_| "wallet mutex poisoned".to_string())?;
    f(&mut guard)
}

fn with_session_ref<T>(
    handle: *mut ZkfBridgeSessionHandle,
    f: impl FnOnce(&mut WalletHandle, &str) -> Result<T, String>,
) -> Result<T, String> {
    if handle.is_null() {
        return Err("bridge session pointer is null".to_string());
    }
    let runtime = unsafe { &mut *(handle as *mut BridgeSessionRuntime) };
    let wallet = unsafe { &mut *runtime.wallet };
    let mut guard = wallet
        .wallet
        .lock()
        .map_err(|_| "wallet mutex poisoned".to_string())?;
    f(&mut guard, runtime.session_id.as_str())
}

fn with_pending_ref<T>(
    handle: *mut ZkfPendingApprovalHandle,
    f: impl FnOnce(&mut WalletHandle, &str) -> Result<T, String>,
) -> Result<T, String> {
    if handle.is_null() {
        return Err("pending approval pointer is null".to_string());
    }
    let runtime = unsafe { &mut *(handle as *mut PendingApprovalRuntime) };
    let wallet = unsafe { &mut *runtime.wallet };
    let mut guard = wallet
        .wallet
        .lock()
        .map_err(|_| "wallet mutex poisoned".to_string())?;
    f(&mut guard, runtime.pending_id.as_str())
}

fn create_wallet_internal(
    network: WalletNetwork,
    persistent_root: Option<PathBuf>,
    cache_root: Option<PathBuf>,
) -> Result<*mut ZkfWalletHandle, String> {
    let wallet = if let (Some(persistent_root), Some(cache_root)) = (persistent_root, cache_root) {
        WalletHandle::with_components(
            network,
            WalletServiceConfig::for_network(network),
            AuthPolicy::default(),
            CloudFS::from_roots(persistent_root, cache_root, false),
            Box::new(SystemBiometricAuthorizer),
            Box::new(KeyManagerSeedStore::new().map_err(|err| err.to_string())?),
            Box::new(SystemClock),
        )
        .map_err(|err| err.to_string())?
    } else {
        WalletHandle::new(network).map_err(|err| err.to_string())?
    };

    Ok(Box::into_raw(Box::new(WalletRuntime {
        wallet: Mutex::new(wallet),
    })) as *mut ZkfWalletHandle)
}

pub fn zkf_wallet_create_rust_test_handle_with_roots(
    network: WalletNetwork,
    persistent_root: PathBuf,
    cache_root: PathBuf,
) -> Result<*mut ZkfWalletHandle, String> {
    let wallet = WalletHandle::with_components(
        network,
        WalletServiceConfig::for_network(network),
        AuthPolicy::default(),
        CloudFS::from_roots(persistent_root, cache_root, false),
        Box::new(TestingBiometricAuthorizer),
        Box::new(TestingSeedStore::default()),
        Box::new(SystemClock),
    )
    .map_err(|err| err.to_string())?;
    Ok(Box::into_raw(Box::new(WalletRuntime {
        wallet: Mutex::new(wallet),
    })) as *mut ZkfWalletHandle)
}

fn create_pending_handle(
    wallet: *mut WalletRuntime,
    pending: PendingApprovalView,
) -> *mut ZkfPendingApprovalHandle {
    Box::into_raw(Box::new(PendingApprovalRuntime {
        wallet,
        pending_id: pending.pending_id,
    })) as *mut ZkfPendingApprovalHandle
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_create(network: *const c_char) -> *mut ZkfWalletHandle {
    clear_last_error();
    match parse_wallet_network(network).and_then(|network| create_wallet_internal(network, None, None)) {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_create_with_roots(
    network: *const c_char,
    persistent_root: *const c_char,
    cache_root: *const c_char,
) -> *mut ZkfWalletHandle {
    clear_last_error();
    let result = (|| {
        let network = parse_wallet_network(network)?;
        let persistent_root = optional_string_arg(persistent_root, "persistent_root")?
            .map(PathBuf::from);
        let cache_root = optional_string_arg(cache_root, "cache_root")?.map(PathBuf::from);
        create_wallet_internal(network, persistent_root, cache_root)
    })();

    match result {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_destroy(wallet: *mut ZkfWalletHandle) {
    if wallet.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(wallet as *mut WalletRuntime));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_unlock(
    wallet: *mut ZkfWalletHandle,
    prompt: *const c_char,
) -> c_int {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let prompt = string_arg(prompt, "prompt")?;
        wallet.unlock(prompt.as_str()).map_err(|err| err.to_string())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_lock(wallet: *mut ZkfWalletHandle) -> c_int {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| wallet.lock().map_err(|err| err.to_string())) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_app_backgrounded(wallet: *mut ZkfWalletHandle) -> c_int {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        wallet.app_backgrounded().map_err(|err| err.to_string())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_import_master_seed(
    wallet: *mut ZkfWalletHandle,
    master_seed: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let master_seed = string_arg(master_seed, "master_seed")?;
        let summary: SeedImportSummary = wallet
            .import_master_seed(master_seed.as_str())
            .map_err(|err| err.to_string())?;
        json_string(&summary)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_import_mnemonic(
    wallet: *mut ZkfWalletHandle,
    mnemonic: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let mnemonic = string_arg(mnemonic, "mnemonic")?;
        let summary: SeedImportSummary = wallet
            .import_mnemonic(mnemonic.as_str())
            .map_err(|err| err.to_string())?;
        json_string(&summary)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_helper_open_session_json(
    wallet: *mut ZkfWalletHandle,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let bundle = wallet.open_helper_session().map_err(|err| err.to_string())?;
        json_string(&bundle)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_helper_close_session(wallet: *mut ZkfWalletHandle) -> c_int {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        wallet.close_helper_session().map_err(|err| err.to_string())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_sync_health_json(wallet: *mut ZkfWalletHandle) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let snapshot = wallet.sync_health().map_err(|err| err.to_string())?;
        json_string(&snapshot)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_snapshot_json(wallet: *mut ZkfWalletHandle) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let snapshot = wallet.snapshot().map_err(|err| err.to_string())?;
        json_string(&snapshot)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_authorize_operation(
    wallet: *mut ZkfWalletHandle,
    method: *const c_char,
    primary_prompt: *const c_char,
    secondary_prompt: *const c_char,
    amount_raw: *const c_char,
) -> c_int {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let method = ApprovalMethod::parse(string_arg(method, "method")?.as_str())
            .map_err(|err| err.to_string())?;
        let primary_prompt = string_arg(primary_prompt, "primary_prompt")?;
        let secondary_prompt = optional_string_arg(secondary_prompt, "secondary_prompt")?;
        let amount_raw = optional_string_arg(amount_raw, "amount_raw")?;
        wallet
            .authorize_operation(
                method,
                primary_prompt.as_str(),
                secondary_prompt.as_deref(),
                amount_raw.as_deref(),
            )
            .map_err(|err| err.to_string())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_grant_origin(
    wallet: *mut ZkfWalletHandle,
    grant_json: *const c_char,
) -> c_int {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let grant = parse_json_arg::<BridgeOriginGrant>(grant_json, "grant_json")?;
        wallet.grant_origin(grant).map_err(|err| err.to_string())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_revoke_origin(
    wallet: *mut ZkfWalletHandle,
    origin: *const c_char,
) -> c_int {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let origin = string_arg(origin, "origin")?;
        wallet.revoke_origin(origin.as_str()).map_err(|err| err.to_string())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_bridge_open_session(
    wallet: *mut ZkfWalletHandle,
    origin: *const c_char,
) -> *mut ZkfBridgeSessionHandle {
    clear_last_error();
    let result: Result<*mut ZkfBridgeSessionHandle, String> = (|| {
        let origin = string_arg(origin, "origin")?;
        let session_id = with_wallet_mut(wallet, |wallet| {
            wallet
                .open_bridge_session(origin.as_str())
                .map_err(|err| err.to_string())
        })?;
        Ok(Box::into_raw(Box::new(BridgeSessionRuntime {
            wallet: wallet as *mut WalletRuntime,
            session_id,
        })) as *mut ZkfBridgeSessionHandle)
    })();

    match result {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_bridge_session_free(handle: *mut ZkfBridgeSessionHandle) {
    if handle.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(handle as *mut BridgeSessionRuntime));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_begin_native_action(
    wallet: *mut ZkfWalletHandle,
    review_json: *const c_char,
) -> *mut ZkfPendingApprovalHandle {
    clear_last_error();
    let wallet_runtime = wallet as *mut WalletRuntime;
    let result = with_wallet_mut(wallet, |wallet| {
        let review = parse_json_arg::<TxReviewPayload>(review_json, "review_json")?;
        let pending = wallet
            .begin_native_action(review)
            .map_err(|err| err.to_string())?;
        Ok(create_pending_handle(wallet_runtime, pending))
    });

    match result {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_prepare_open_channel(
    wallet: *mut ZkfWalletHandle,
    request_json: *const c_char,
) -> *mut ZkfPendingApprovalHandle {
    clear_last_error();
    let wallet_runtime = wallet as *mut WalletRuntime;
    let result = with_wallet_mut(wallet, |wallet| {
        let request = parse_json_arg::<WalletChannelOpenRequest>(request_json, "request_json")?;
        let pending = wallet
            .messaging_prepare_open_channel(request)
            .map_err(|err| err.to_string())?;
        Ok(create_pending_handle(wallet_runtime, pending))
    });
    match result {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_prepare_text(
    wallet: *mut ZkfWalletHandle,
    peer_id: *const c_char,
    text: *const c_char,
) -> *mut ZkfPendingApprovalHandle {
    clear_last_error();
    let wallet_runtime = wallet as *mut WalletRuntime;
    let result = with_wallet_mut(wallet, |wallet| {
        let peer_id = parse_wallet_peer_id(peer_id, "peer_id")?;
        let text = string_arg(text, "text")?;
        let pending = wallet
            .messaging_prepare_text(peer_id, text)
            .map_err(|err| err.to_string())?;
        Ok(create_pending_handle(wallet_runtime, pending))
    });
    match result {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_prepare_transfer_receipt(
    wallet: *mut ZkfWalletHandle,
    peer_id: *const c_char,
    receipt_json: *const c_char,
) -> *mut ZkfPendingApprovalHandle {
    clear_last_error();
    let wallet_runtime = wallet as *mut WalletRuntime;
    let result = with_wallet_mut(wallet, |wallet| {
        let peer_id = parse_wallet_peer_id(peer_id, "peer_id")?;
        let receipt =
            parse_json_arg::<WalletTransferReceipt>(receipt_json, "receipt_json")?;
        let pending = wallet
            .messaging_prepare_transfer_receipt(peer_id, receipt)
            .map_err(|err| err.to_string())?;
        Ok(create_pending_handle(wallet_runtime, pending))
    });
    match result {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_prepare_credential_request(
    wallet: *mut ZkfWalletHandle,
    peer_id: *const c_char,
    request_json: *const c_char,
) -> *mut ZkfPendingApprovalHandle {
    clear_last_error();
    let wallet_runtime = wallet as *mut WalletRuntime;
    let result = with_wallet_mut(wallet, |wallet| {
        let peer_id = parse_wallet_peer_id(peer_id, "peer_id")?;
        let request =
            parse_json_arg::<WalletCredentialRequest>(request_json, "request_json")?;
        let pending = wallet
            .messaging_prepare_credential_request(peer_id, request)
            .map_err(|err| err.to_string())?;
        Ok(create_pending_handle(wallet_runtime, pending))
    });
    match result {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_prepare_credential_response(
    wallet: *mut ZkfWalletHandle,
    peer_id: *const c_char,
    response_json: *const c_char,
) -> *mut ZkfPendingApprovalHandle {
    clear_last_error();
    let wallet_runtime = wallet as *mut WalletRuntime;
    let result = with_wallet_mut(wallet, |wallet| {
        let peer_id = parse_wallet_peer_id(peer_id, "peer_id")?;
        let response =
            parse_json_arg::<WalletCredentialResponse>(response_json, "response_json")?;
        let pending = wallet
            .messaging_prepare_credential_response(peer_id, response)
            .map_err(|err| err.to_string())?;
        Ok(create_pending_handle(wallet_runtime, pending))
    });
    match result {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_bridge_make_transfer(
    session: *mut ZkfBridgeSessionHandle,
    review_json: *const c_char,
) -> *mut ZkfPendingApprovalHandle {
    clear_last_error();
    let result = (|| {
        if session.is_null() {
            return Err("bridge session pointer is null".to_string());
        }
        let session_runtime = unsafe { &mut *(session as *mut BridgeSessionRuntime) };
        let review = parse_json_arg::<TxReviewPayload>(review_json, "review_json")?;
        with_session_ref(session, |wallet, session_id| {
            let pending = wallet
                .begin_bridge_transfer(session_id, review)
                .map_err(|err| err.to_string())?;
            Ok(create_pending_handle(session_runtime.wallet, pending))
        })
    })();

    match result {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_bridge_make_intent(
    session: *mut ZkfBridgeSessionHandle,
    review_json: *const c_char,
) -> *mut ZkfPendingApprovalHandle {
    clear_last_error();
    let result = (|| {
        if session.is_null() {
            return Err("bridge session pointer is null".to_string());
        }
        let session_runtime = unsafe { &mut *(session as *mut BridgeSessionRuntime) };
        let review = parse_json_arg::<TxReviewPayload>(review_json, "review_json")?;
        with_session_ref(session, |wallet, session_id| {
            let pending = wallet
                .begin_bridge_intent(session_id, review)
                .map_err(|err| err.to_string())?;
            Ok(create_pending_handle(session_runtime.wallet, pending))
        })
    })();

    match result {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_pending_review_json(
    pending: *mut ZkfPendingApprovalHandle,
) -> *mut c_char {
    clear_last_error();
    match with_pending_ref(pending, |wallet, pending_id| {
        let review = wallet
            .pending_review(pending_id)
            .map_err(|err| err.to_string())?;
        json_string(&review)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_pending_approve(
    pending: *mut ZkfPendingApprovalHandle,
    primary_prompt: *const c_char,
    secondary_prompt: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_pending_ref(pending, |wallet, pending_id| {
        let primary_prompt = string_arg(primary_prompt, "primary_prompt")?;
        let secondary_prompt = optional_string_arg(secondary_prompt, "secondary_prompt")?;
        let token = wallet
            .approve_pending(
                pending_id,
                primary_prompt.as_str(),
                secondary_prompt.as_deref(),
            )
            .map_err(|err| err.to_string())?;
        json_string(&token)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_pending_reject(
    pending: *mut ZkfPendingApprovalHandle,
    reason: *const c_char,
) -> c_int {
    clear_last_error();
    match with_pending_ref(pending, |wallet, pending_id| {
        let reason = string_arg(reason, "reason")?;
        wallet
            .reject_pending(pending_id, reason.as_str())
            .map_err(|err| err.to_string())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_pending_approval_free(handle: *mut ZkfPendingApprovalHandle) {
    if handle.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(handle as *mut PendingApprovalRuntime));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_commit_open_channel_json(
    wallet: *mut ZkfWalletHandle,
    token_json: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let token = parse_json_arg::<ApprovalToken>(token_json, "token_json")?;
        let view = wallet
            .messaging_commit_open_channel(&token)
            .map_err(|err| err.to_string())?;
        json_string(&view)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_commit_send_message_json(
    wallet: *mut ZkfWalletHandle,
    token_json: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let token = parse_json_arg::<ApprovalToken>(token_json, "token_json")?;
        let prepared = wallet
            .messaging_commit_send_message(&token)
            .map_err(|err| err.to_string())?;
        json_string(&prepared)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_receive_envelope_json(
    wallet: *mut ZkfWalletHandle,
    envelope_json: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let envelope = parse_json_arg::<MailboxEnvelope>(envelope_json, "envelope_json")?;
        let message = wallet
            .messaging_receive_envelope(envelope)
            .map_err(|err| err.to_string())?;
        json_string(&message)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_poll_mailbox_json(
    wallet: *mut ZkfWalletHandle,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let status = wallet
            .messaging_poll_mailbox()
            .map_err(|err| err.to_string())?;
        json_string(&status)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_update_transport_status_json(
    wallet: *mut ZkfWalletHandle,
    update_json: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let update = parse_json_arg::<MessagingTransportUpdate>(update_json, "update_json")?;
        let status = wallet
            .messaging_update_transport_status(update)
            .map_err(|err| err.to_string())?;
        json_string(&status)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_complete_mailbox_post_json(
    wallet: *mut ZkfWalletHandle,
    success_json: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let success = parse_json_arg::<MailboxPostSuccess>(success_json, "success_json")?;
        let message = wallet
            .messaging_complete_mailbox_post(success)
            .map_err(|err| err.to_string())?;
        json_string(&message)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_fail_mailbox_post_json(
    wallet: *mut ZkfWalletHandle,
    failure_json: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let failure = parse_json_arg::<MailboxPostFailure>(failure_json, "failure_json")?;
        let message = wallet
            .messaging_fail_mailbox_post(failure)
            .map_err(|err| err.to_string())?;
        json_string(&message)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_list_conversations_json(
    wallet: *mut ZkfWalletHandle,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let conversations = wallet
            .messaging_list_conversations()
            .map_err(|err| err.to_string())?;
        json_string(&conversations)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_conversation_json(
    wallet: *mut ZkfWalletHandle,
    peer_id: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let peer_id = parse_wallet_peer_id(peer_id, "peer_id")?;
        let messages = wallet
            .messaging_conversation(&peer_id)
            .map_err(|err| err.to_string())?;
        json_string(&messages)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_channel_status_json(
    wallet: *mut ZkfWalletHandle,
    peer_id: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let peer_id = parse_wallet_peer_id(peer_id, "peer_id")?;
        let status = wallet
            .messaging_channel_status(&peer_id)
            .map_err(|err| err.to_string())?;
        json_string(&status)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_messaging_close_channel_json(
    wallet: *mut ZkfWalletHandle,
    peer_id: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let peer_id = parse_wallet_peer_id(peer_id, "peer_id")?;
        let status = wallet
            .messaging_close_channel(&peer_id)
            .map_err(|err| err.to_string())?;
        json_string(&status)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_issue_native_submission_grant_json(
    wallet: *mut ZkfWalletHandle,
    method: *const c_char,
    tx_digest: *const c_char,
    token_json: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let method = ApprovalMethod::parse(string_arg(method, "method")?.as_str())
            .map_err(|err| err.to_string())?;
        let tx_digest = string_arg(tx_digest, "tx_digest")?;
        let token = parse_json_arg::<ApprovalToken>(token_json, "token_json")?;
        let grant = wallet
            .issue_native_submission_grant(method, tx_digest.as_str(), &token)
            .map_err(|err| err.to_string())?;
        json_string(&grant)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_issue_bridge_submission_grant_json(
    session: *mut ZkfBridgeSessionHandle,
    method: *const c_char,
    tx_digest: *const c_char,
    token_json: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match with_session_ref(session, |wallet, session_id| {
        let method = ApprovalMethod::parse(string_arg(method, "method")?.as_str())
            .map_err(|err| err.to_string())?;
        let tx_digest = string_arg(tx_digest, "tx_digest")?;
        let token = parse_json_arg::<ApprovalToken>(token_json, "token_json")?;
        let grant = wallet
            .issue_bridge_submission_grant(session_id, method, tx_digest.as_str(), &token)
            .map_err(|err| err.to_string())?;
        json_string(&grant)
    }) {
        Ok(value) => value,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_consume_native_submission_grant(
    wallet: *mut ZkfWalletHandle,
    method: *const c_char,
    tx_digest: *const c_char,
    grant_json: *const c_char,
) -> c_int {
    clear_last_error();
    match with_wallet_mut(wallet, |wallet| {
        let method = ApprovalMethod::parse(string_arg(method, "method")?.as_str())
            .map_err(|err| err.to_string())?;
        let tx_digest = string_arg(tx_digest, "tx_digest")?;
        let grant = parse_json_arg::<SubmissionGrant>(grant_json, "grant_json")?;
        wallet
            .consume_native_submission_grant(method, tx_digest.as_str(), &grant)
            .map_err(|err| err.to_string())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_wallet_consume_bridge_submission_grant(
    session: *mut ZkfBridgeSessionHandle,
    method: *const c_char,
    tx_digest: *const c_char,
    grant_json: *const c_char,
) -> c_int {
    clear_last_error();
    match with_session_ref(session, |wallet, session_id| {
        let method = ApprovalMethod::parse(string_arg(method, "method")?.as_str())
            .map_err(|err| err.to_string())?;
        let tx_digest = string_arg(tx_digest, "tx_digest")?;
        let grant = parse_json_arg::<SubmissionGrant>(grant_json, "grant_json")?;
        wallet
            .consume_bridge_submission_grant(session_id, method, tx_digest.as_str(), &grant)
            .map_err(|err| err.to_string())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}
