#import <stdint.h>
#import "../WalletCore/ZKFWalletWebViewHost.h"

typedef struct ZkfWalletHandle ZkfWalletHandle;
typedef struct ZkfBridgeSessionHandle ZkfBridgeSessionHandle;
typedef struct ZkfPendingApprovalHandle ZkfPendingApprovalHandle;

const char *zkf_last_error_message(void);
void zkf_string_free(char *value);

ZkfWalletHandle *zkf_wallet_create_with_roots(
    const char *network,
    const char *persistent_root,
    const char *cache_root
);
void zkf_wallet_destroy(ZkfWalletHandle *wallet);

int32_t zkf_wallet_unlock(ZkfWalletHandle *wallet, const char *prompt);
int32_t zkf_wallet_lock(ZkfWalletHandle *wallet);
int32_t zkf_wallet_app_backgrounded(ZkfWalletHandle *wallet);

char *zkf_wallet_import_master_seed(ZkfWalletHandle *wallet, const char *master_seed);
char *zkf_wallet_import_mnemonic(ZkfWalletHandle *wallet, const char *mnemonic);
char *zkf_wallet_helper_open_session_json(ZkfWalletHandle *wallet);
int32_t zkf_wallet_helper_close_session(ZkfWalletHandle *wallet);
char *zkf_wallet_sync_health_json(ZkfWalletHandle *wallet);
char *zkf_wallet_snapshot_json(ZkfWalletHandle *wallet);
int32_t zkf_wallet_grant_origin(ZkfWalletHandle *wallet, const char *grant_json);
int32_t zkf_wallet_revoke_origin(ZkfWalletHandle *wallet, const char *origin);
ZkfBridgeSessionHandle *zkf_wallet_bridge_open_session(
    ZkfWalletHandle *wallet,
    const char *origin
);
void zkf_wallet_bridge_session_free(ZkfBridgeSessionHandle *handle);

ZkfPendingApprovalHandle *zkf_wallet_begin_native_action(
    ZkfWalletHandle *wallet,
    const char *review_json
);
ZkfPendingApprovalHandle *zkf_wallet_messaging_prepare_open_channel(
    ZkfWalletHandle *wallet,
    const char *request_json
);
ZkfPendingApprovalHandle *zkf_wallet_messaging_prepare_text(
    ZkfWalletHandle *wallet,
    const char *peer_id,
    const char *text
);
ZkfPendingApprovalHandle *zkf_wallet_messaging_prepare_transfer_receipt(
    ZkfWalletHandle *wallet,
    const char *peer_id,
    const char *receipt_json
);
ZkfPendingApprovalHandle *zkf_wallet_messaging_prepare_credential_request(
    ZkfWalletHandle *wallet,
    const char *peer_id,
    const char *request_json
);
ZkfPendingApprovalHandle *zkf_wallet_messaging_prepare_credential_response(
    ZkfWalletHandle *wallet,
    const char *peer_id,
    const char *response_json
);
ZkfPendingApprovalHandle *zkf_wallet_bridge_make_transfer(
    ZkfBridgeSessionHandle *session,
    const char *review_json
);
ZkfPendingApprovalHandle *zkf_wallet_bridge_make_intent(
    ZkfBridgeSessionHandle *session,
    const char *review_json
);
char *zkf_wallet_pending_review_json(ZkfPendingApprovalHandle *pending);
char *zkf_wallet_pending_approve(
    ZkfPendingApprovalHandle *pending,
    const char *primary_prompt,
    const char *secondary_prompt
);
int32_t zkf_wallet_pending_reject(
    ZkfPendingApprovalHandle *pending,
    const char *reason
);
void zkf_wallet_pending_approval_free(ZkfPendingApprovalHandle *handle);
char *zkf_wallet_messaging_commit_open_channel_json(
    ZkfWalletHandle *wallet,
    const char *token_json
);
char *zkf_wallet_messaging_commit_send_message_json(
    ZkfWalletHandle *wallet,
    const char *token_json
);
char *zkf_wallet_messaging_receive_envelope_json(
    ZkfWalletHandle *wallet,
    const char *envelope_json
);
char *zkf_wallet_messaging_poll_mailbox_json(ZkfWalletHandle *wallet);
char *zkf_wallet_messaging_update_transport_status_json(
    ZkfWalletHandle *wallet,
    const char *update_json
);
char *zkf_wallet_messaging_complete_mailbox_post_json(
    ZkfWalletHandle *wallet,
    const char *success_json
);
char *zkf_wallet_messaging_fail_mailbox_post_json(
    ZkfWalletHandle *wallet,
    const char *failure_json
);
char *zkf_wallet_messaging_list_conversations_json(ZkfWalletHandle *wallet);
char *zkf_wallet_messaging_conversation_json(
    ZkfWalletHandle *wallet,
    const char *peer_id
);
char *zkf_wallet_messaging_channel_status_json(
    ZkfWalletHandle *wallet,
    const char *peer_id
);
char *zkf_wallet_messaging_close_channel_json(
    ZkfWalletHandle *wallet,
    const char *peer_id
);

char *zkf_wallet_issue_native_submission_grant_json(
    ZkfWalletHandle *wallet,
    const char *method,
    const char *tx_digest,
    const char *token_json
);
char *zkf_wallet_issue_bridge_submission_grant_json(
    ZkfBridgeSessionHandle *session,
    const char *method,
    const char *tx_digest,
    const char *token_json
);
int32_t zkf_wallet_consume_native_submission_grant(
    ZkfWalletHandle *wallet,
    const char *method,
    const char *tx_digest,
    const char *grant_json
);
int32_t zkf_wallet_consume_bridge_submission_grant(
    ZkfBridgeSessionHandle *session,
    const char *method,
    const char *tx_digest,
    const char *grant_json
);
