use serde::{Deserialize, Serialize};
use zkf_core::{ZkfError, ZkfResult};

/// Transaction submission request for Midnight devnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitProofRequest {
    pub contract_address: String,
    pub proof_b64: String,
    pub public_inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

/// Transaction submission response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitProofResponse {
    pub ok: bool,
    #[serde(default)]
    pub tx_hash: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// State query request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryStateRequest {
    pub contract_address: String,
    pub field: String,
}

/// State query response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryStateResponse {
    pub ok: bool,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Contract deployment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployContractRequest {
    pub compact_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_state: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

/// Contract deployment response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployContractResponse {
    pub ok: bool,
    #[serde(default)]
    pub contract_address: Option<String>,
    #[serde(default)]
    pub tx_hash: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Transaction status request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxStatusRequest {
    pub tx_hash: String,
}

/// Transaction status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxStatusResponse {
    pub ok: bool,
    pub status: TxStatus,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Network information response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub network_id: String,
    pub chain_height: u64,
    pub proof_server_version: String,
}

/// Transaction lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxStatus {
    Pending,
    Confirmed,
    Failed(String),
}

/// Client for Midnight devnet transaction lifecycle.
pub struct MidnightTxClient {
    base_url: String,
    auth_token: Option<String>,
}

impl MidnightTxClient {
    pub fn from_env() -> Option<Self> {
        let base_url = std::env::var("ZKF_MIDNIGHT_DEVNET_URL").ok()?;
        let auth_token = std::env::var("ZKF_MIDNIGHT_AUTH_TOKEN").ok();
        Some(Self {
            base_url,
            auth_token,
        })
    }

    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            auth_token: None,
        }
    }

    pub fn with_auth(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    /// Submit a proof to the devnet.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn submit_proof(&self, request: &SubmitProofRequest) -> ZkfResult<SubmitProofResponse> {
        let url = format!("{}/submit-proof", self.base_url);
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(30))
            .build();

        let mut req = agent.post(&url);
        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {}", token));
        }

        let response = req
            .send_json(
                serde_json::to_value(request).map_err(|e| ZkfError::UnsupportedBackend {
                    backend: "midnight-tx".to_string(),
                    message: format!("serialize submit request: {}", e),
                })?,
            )
            .map_err(|e| ZkfError::UnsupportedBackend {
                backend: "midnight-tx".to_string(),
                message: format!("submit proof failed: {}", e),
            })?;

        serde_json::from_reader(response.into_reader()).map_err(|e| ZkfError::UnsupportedBackend {
            backend: "midnight-tx".to_string(),
            message: format!("parse submit response: {}", e),
        })
    }

    /// Deploy a Compact contract to the devnet.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn deploy_contract(
        &self,
        request: &DeployContractRequest,
    ) -> ZkfResult<DeployContractResponse> {
        let url = format!("{}/deploy-contract", self.base_url);
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(60))
            .build();

        let mut req = agent.post(&url);
        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {}", token));
        }

        let response = req
            .send_json(
                serde_json::to_value(request).map_err(|e| ZkfError::UnsupportedBackend {
                    backend: "midnight-tx".to_string(),
                    message: format!("serialize deploy request: {}", e),
                })?,
            )
            .map_err(|e| ZkfError::UnsupportedBackend {
                backend: "midnight-tx".to_string(),
                message: format!("deploy contract failed: {}", e),
            })?;

        serde_json::from_reader(response.into_reader()).map_err(|e| ZkfError::UnsupportedBackend {
            backend: "midnight-tx".to_string(),
            message: format!("parse deploy response: {}", e),
        })
    }

    /// Poll transaction status until confirmed or failed, with timeout.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn poll_tx_status(&self, tx_hash: &str, timeout_secs: u64) -> ZkfResult<TxStatusResponse> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        loop {
            let status = self.get_tx_status(&TxStatusRequest {
                tx_hash: tx_hash.to_string(),
            })?;

            match &status.status {
                TxStatus::Confirmed | TxStatus::Failed(_) => return Ok(status),
                TxStatus::Pending => {
                    if start.elapsed() >= timeout {
                        return Err(ZkfError::Backend(format!(
                            "transaction {} still pending after {}s",
                            tx_hash, timeout_secs
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
        }
    }

    /// Get transaction status (single query, no polling).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_tx_status(&self, request: &TxStatusRequest) -> ZkfResult<TxStatusResponse> {
        let url = format!("{}/tx-status", self.base_url);
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build();

        let mut req = agent.post(&url);
        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {}", token));
        }

        let response = req
            .send_json(
                serde_json::to_value(request).map_err(|e| ZkfError::UnsupportedBackend {
                    backend: "midnight-tx".to_string(),
                    message: format!("serialize tx-status request: {}", e),
                })?,
            )
            .map_err(|e| ZkfError::UnsupportedBackend {
                backend: "midnight-tx".to_string(),
                message: format!("tx-status query failed: {}", e),
            })?;

        serde_json::from_reader(response.into_reader()).map_err(|e| ZkfError::UnsupportedBackend {
            backend: "midnight-tx".to_string(),
            message: format!("parse tx-status response: {}", e),
        })
    }

    /// Query network information.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_network_info(&self) -> ZkfResult<NetworkInfo> {
        let url = format!("{}/network-info", self.base_url);
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build();

        let response = agent
            .get(&url)
            .call()
            .map_err(|e| ZkfError::UnsupportedBackend {
                backend: "midnight-tx".to_string(),
                message: format!("network-info query failed: {}", e),
            })?;

        serde_json::from_reader(response.into_reader()).map_err(|e| ZkfError::UnsupportedBackend {
            backend: "midnight-tx".to_string(),
            message: format!("parse network-info response: {}", e),
        })
    }

    /// Query contract state.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn query_state(&self, request: &QueryStateRequest) -> ZkfResult<QueryStateResponse> {
        let url = format!("{}/query-state", self.base_url);
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build();

        let mut req = agent.post(&url);
        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {}", token));
        }

        let response = req
            .send_json(
                serde_json::to_value(request).map_err(|e| ZkfError::UnsupportedBackend {
                    backend: "midnight-tx".to_string(),
                    message: format!("serialize query request: {}", e),
                })?,
            )
            .map_err(|e| ZkfError::UnsupportedBackend {
                backend: "midnight-tx".to_string(),
                message: format!("query state failed: {}", e),
            })?;

        serde_json::from_reader(response.into_reader()).map_err(|e| ZkfError::UnsupportedBackend {
            backend: "midnight-tx".to_string(),
            message: format!("parse query response: {}", e),
        })
    }

    /// Submit a proof to the devnet with automatic retries using exponential backoff.
    ///
    /// `max_retries` controls the number of retry attempts after the first failure.
    /// Delay between retries follows `min(500 * 2^attempt, 30000)` ms.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn submit_proof_with_retry(
        &self,
        request: &SubmitProofRequest,
        max_retries: u32,
    ) -> ZkfResult<SubmitProofResponse> {
        let mut last_err = None;
        for attempt in 0..=max_retries {
            match self.submit_proof(request) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempt < max_retries {
                        let delay_ms =
                            std::cmp::min(500u64.saturating_mul(1u64 << attempt), 30_000);
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ZkfError::UnsupportedBackend {
            backend: "midnight-tx".to_string(),
            message: "submit proof failed after retries".to_string(),
        }))
    }

    /// Deploy a Compact contract to the devnet with automatic retries using exponential backoff.
    ///
    /// `max_retries` controls the number of retry attempts after the first failure.
    /// Delay between retries follows `min(500 * 2^attempt, 30000)` ms.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn deploy_contract_with_retry(
        &self,
        request: &DeployContractRequest,
        max_retries: u32,
    ) -> ZkfResult<DeployContractResponse> {
        let mut last_err = None;
        for attempt in 0..=max_retries {
            match self.deploy_contract(request) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempt < max_retries {
                        let delay_ms =
                            std::cmp::min(500u64.saturating_mul(1u64 << attempt), 30_000);
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ZkfError::UnsupportedBackend {
            backend: "midnight-tx".to_string(),
            message: "deploy contract failed after retries".to_string(),
        }))
    }

    /// Check whether the devnet node is reachable by delegating to `get_network_info`.
    ///
    /// Returns `Ok(true)` when the node responds successfully.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn health_check(&self) -> ZkfResult<bool> {
        self.get_network_info().map(|_| true)
    }

    /// Execute the full proof lifecycle:
    /// 1. Deploy the contract from `compact_source`.
    /// 2. Wait for the deploy transaction to be confirmed (up to `timeout_secs`).
    /// 3. Submit the proof (`proof_b64` + `public_inputs`) against the deployed contract.
    /// 4. Poll the submit transaction until confirmed (up to `timeout_secs`).
    /// 5. Return the contract address.
    ///
    /// Returns the contract address string on success, or an error at the first failure.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn full_lifecycle(
        &self,
        compact_source: &str,
        proof_b64: &str,
        public_inputs: Vec<String>,
        timeout_secs: u64,
    ) -> ZkfResult<String> {
        // Step 1: Deploy the contract.
        let deploy_req = DeployContractRequest {
            compact_source: compact_source.to_string(),
            initial_state: None,
            auth_token: self.auth_token.clone(),
        };
        let deploy_resp = self.deploy_contract(&deploy_req)?;
        if !deploy_resp.ok {
            return Err(ZkfError::Backend(format!(
                "deploy_contract failed: {}",
                deploy_resp
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            )));
        }
        let deploy_tx_hash = deploy_resp.tx_hash.ok_or_else(|| {
            ZkfError::Backend("deploy_contract response missing tx_hash".to_string())
        })?;
        let contract_address = deploy_resp.contract_address.ok_or_else(|| {
            ZkfError::Backend("deploy_contract response missing contract_address".to_string())
        })?;

        // Step 2: Wait for the deploy transaction to be confirmed.
        let deploy_status = self.poll_tx_status(&deploy_tx_hash, timeout_secs)?;
        if let TxStatus::Failed(reason) = deploy_status.status {
            return Err(ZkfError::Backend(format!(
                "deploy transaction {} failed: {}",
                deploy_tx_hash, reason
            )));
        }

        // Step 3: Submit the proof.
        let submit_req = SubmitProofRequest {
            contract_address: contract_address.clone(),
            proof_b64: proof_b64.to_string(),
            public_inputs,
            auth_token: self.auth_token.clone(),
        };
        let submit_resp = self.submit_proof(&submit_req)?;
        if !submit_resp.ok {
            return Err(ZkfError::Backend(format!(
                "submit_proof failed: {}",
                submit_resp
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            )));
        }
        let submit_tx_hash = submit_resp.tx_hash.ok_or_else(|| {
            ZkfError::Backend("submit_proof response missing tx_hash".to_string())
        })?;

        // Step 4: Poll the submit transaction until confirmed.
        let submit_status = self.poll_tx_status(&submit_tx_hash, timeout_secs)?;
        if let TxStatus::Failed(reason) = submit_status.status {
            return Err(ZkfError::Backend(format!(
                "submit proof transaction {} failed: {}",
                submit_tx_hash, reason
            )));
        }

        // Step 5: Return the contract address.
        Ok(contract_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_midnight_tx_client_new() {
        let client = MidnightTxClient::new("http://localhost:8080".to_string());
        assert_eq!(client.base_url, "http://localhost:8080");
        assert!(client.auth_token.is_none());
    }

    #[test]
    fn test_midnight_tx_client_with_auth() {
        let client = MidnightTxClient::new("http://localhost:8080".to_string())
            .with_auth("my-token".to_string());
        assert_eq!(client.auth_token.as_deref(), Some("my-token"));
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_health_check_returns_err_when_no_server() {
        let client = MidnightTxClient::new("http://127.0.0.1:19998".to_string());
        let result = client.health_check();
        assert!(
            result.is_err(),
            "health_check should return Err when devnet node is unreachable"
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_submit_proof_with_retry_returns_err_when_no_server() {
        let client = MidnightTxClient::new("http://127.0.0.1:19998".to_string());
        let request = SubmitProofRequest {
            contract_address: "0xdeadbeef".to_string(),
            proof_b64: "dGVzdA==".to_string(),
            public_inputs: vec![],
            auth_token: None,
        };
        // max_retries=0 to keep the test fast.
        let result = client.submit_proof_with_retry(&request, 0);
        assert!(
            result.is_err(),
            "submit_proof_with_retry should fail when server is unreachable"
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_deploy_contract_with_retry_returns_err_when_no_server() {
        let client = MidnightTxClient::new("http://127.0.0.1:19998".to_string());
        let request = DeployContractRequest {
            compact_source: "contract Foo {}".to_string(),
            initial_state: None,
            auth_token: None,
        };
        // max_retries=0 to keep the test fast.
        let result = client.deploy_contract_with_retry(&request, 0);
        assert!(
            result.is_err(),
            "deploy_contract_with_retry should fail when server is unreachable"
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_full_lifecycle_fails_fast_when_no_server() {
        let client = MidnightTxClient::new("http://127.0.0.1:19998".to_string());
        let result = client.full_lifecycle("contract Foo {}", "dGVzdA==", vec!["1".to_string()], 5);
        assert!(
            result.is_err(),
            "full_lifecycle should return Err when devnet node is unreachable"
        );
    }

    #[test]
    fn test_full_lifecycle_signature_accepts_correct_types() {
        // Compile-time test: verify that the method signature accepts the expected
        // argument types without requiring a live server.
        let _: fn(&MidnightTxClient, &str, &str, Vec<String>, u64) -> ZkfResult<String> =
            |client, src, proof, inputs, timeout| {
                client.full_lifecycle(src, proof, inputs, timeout)
            };
    }
}
