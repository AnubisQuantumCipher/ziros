use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zkf_core::{ZkfError, ZkfResult};

/// Current Midnight proof server API version.
pub const MIDNIGHT_API_VERSION: &str = "v1";

/// Structured request to the Midnight proof server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveRequest {
    #[serde(default = "default_api_version")]
    pub api_version: String,
    pub program_digest: String,
    pub compact_source: String,
    pub witness: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

/// Structured response from the Midnight proof server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveResponse {
    pub ok: bool,
    #[serde(default)]
    pub proof_b64: Option<String>,
    #[serde(default)]
    pub vk_b64: Option<String>,
    #[serde(default)]
    pub public_inputs: Option<Vec<String>>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub metadata: Option<BTreeMap<String, String>>,
}

/// Structured verify request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    #[serde(default = "default_api_version")]
    pub api_version: String,
    pub program_digest: String,
    pub proof_b64: String,
    pub vk_b64: String,
    pub public_inputs: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

/// Structured verify response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
}

/// Compile request for remote Compact compilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileRequest {
    #[serde(default = "default_api_version")]
    pub api_version: String,
    pub compact_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

/// Compile response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileResponse {
    pub ok: bool,
    #[serde(default)]
    pub circuit_ir_b64: Option<String>,
    #[serde(default)]
    pub program_digest: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

fn default_api_version() -> String {
    MIDNIGHT_API_VERSION.to_string()
}

const MOCK_RESPONSE_URL_PREFIX: &str = "mock://";

fn decode_mock_response<T>(url: &str, response_kind: &str) -> Option<ZkfResult<T>>
where
    T: DeserializeOwned,
{
    let payload = url.strip_prefix(MOCK_RESPONSE_URL_PREFIX)?;
    Some(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload.as_bytes())
            .map_err(|e| ZkfError::UnsupportedBackend {
                backend: "midnight".to_string(),
                message: format!("decode mock {response_kind} response: {e}"),
            })
            .and_then(|bytes| {
                serde_json::from_slice(&bytes).map_err(|e| ZkfError::UnsupportedBackend {
                    backend: "midnight".to_string(),
                    message: format!("parse {response_kind} response: {e}"),
                })
            }),
    )
}

/// Client for the Midnight proof server.
pub struct MidnightClient {
    prove_url: String,
    verify_url: String,
    compile_url: Option<String>,
    auth_token: Option<String>,
    timeout_ms: u64,
    max_retries: u32,
}

impl MidnightClient {
    pub fn from_env() -> Option<Self> {
        let prove_url = std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL").ok()?;
        let verify_url = std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL")
            .unwrap_or_else(|_| prove_url.replace("/prove", "/verify"));
        let compile_url = std::env::var("ZKF_MIDNIGHT_COMPILE_URL").ok();
        let auth_token = std::env::var("ZKF_MIDNIGHT_AUTH_TOKEN").ok();
        let timeout_ms = std::env::var("ZKF_MIDNIGHT_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30_000);
        let max_retries = std::env::var("ZKF_MIDNIGHT_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);

        Some(Self {
            prove_url,
            verify_url,
            compile_url,
            auth_token,
            timeout_ms,
            max_retries,
        })
    }

    pub fn new(prove_url: String, verify_url: String) -> Self {
        Self {
            prove_url,
            verify_url,
            compile_url: None,
            auth_token: None,
            timeout_ms: 30_000,
            max_retries: 3,
        }
    }

    pub fn with_compile_url(mut self, url: String) -> Self {
        self.compile_url = Some(url);
        self
    }

    pub fn with_auth(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Send a prove request with retry logic.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn prove(&self, request: &ProveRequest) -> ZkfResult<ProveResponse> {
        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            match self.try_prove(request) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempt < self.max_retries {
                        let delay_ms =
                            std::cmp::min(500u64.saturating_mul(1u64 << attempt), 30_000);
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ZkfError::UnsupportedBackend {
            backend: "midnight".to_string(),
            message: "prove request failed after retries".to_string(),
        }))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn try_prove(&self, request: &ProveRequest) -> ZkfResult<ProveResponse> {
        if let Some(response) = decode_mock_response(&self.prove_url, "prove") {
            return response;
        }

        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .build();

        let mut req = agent.post(&self.prove_url);
        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {}", token));
        }

        let response = req
            .send_json(
                serde_json::to_value(request).map_err(|e| ZkfError::UnsupportedBackend {
                    backend: "midnight".to_string(),
                    message: format!("serialize prove request: {}", e),
                })?,
            )
            .map_err(|e| ZkfError::UnsupportedBackend {
                backend: "midnight".to_string(),
                message: format!("prove request failed: {}", e),
            })?;

        let body: ProveResponse = serde_json::from_reader(response.into_reader()).map_err(|e| {
            ZkfError::UnsupportedBackend {
                backend: "midnight".to_string(),
                message: format!("parse prove response: {}", e),
            }
        })?;

        Ok(body)
    }

    /// Send a verify request with retry logic.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn verify(&self, request: &VerifyRequest) -> ZkfResult<VerifyResponse> {
        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            match self.try_verify(request) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempt < self.max_retries {
                        let delay_ms =
                            std::cmp::min(500u64.saturating_mul(1u64 << attempt), 30_000);
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ZkfError::UnsupportedBackend {
            backend: "midnight".to_string(),
            message: "verify request failed after retries".to_string(),
        }))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn try_verify(&self, request: &VerifyRequest) -> ZkfResult<VerifyResponse> {
        if let Some(response) = decode_mock_response(&self.verify_url, "verify") {
            return response;
        }

        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .build();

        let mut req = agent.post(&self.verify_url);
        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {}", token));
        }

        let response = req
            .send_json(
                serde_json::to_value(request).map_err(|e| ZkfError::UnsupportedBackend {
                    backend: "midnight".to_string(),
                    message: format!("serialize verify request: {}", e),
                })?,
            )
            .map_err(|e| ZkfError::UnsupportedBackend {
                backend: "midnight".to_string(),
                message: format!("verify request failed: {}", e),
            })?;

        let body: VerifyResponse =
            serde_json::from_reader(response.into_reader()).map_err(|e| {
                ZkfError::UnsupportedBackend {
                    backend: "midnight".to_string(),
                    message: format!("parse verify response: {}", e),
                }
            })?;

        Ok(body)
    }

    /// Send a compile request with retry logic using exponential backoff.
    ///
    /// Requires `compile_url` to be configured (via `ZKF_MIDNIGHT_COMPILE_URL` env var
    /// or `with_compile_url()`). Returns an error if no compile URL is set.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn compile(&self, request: &CompileRequest) -> ZkfResult<CompileResponse> {
        let compile_url =
            self.compile_url
                .as_deref()
                .ok_or_else(|| ZkfError::UnsupportedBackend {
                    backend: "midnight".to_string(),
                    message: "compile URL not configured; set ZKF_MIDNIGHT_COMPILE_URL".to_string(),
                })?;

        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            match self.try_compile(request, compile_url) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempt < self.max_retries {
                        let delay_ms =
                            std::cmp::min(500u64.saturating_mul(1u64 << attempt), 30_000);
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ZkfError::UnsupportedBackend {
            backend: "midnight".to_string(),
            message: "compile request failed after retries".to_string(),
        }))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn try_compile(
        &self,
        request: &CompileRequest,
        compile_url: &str,
    ) -> ZkfResult<CompileResponse> {
        if let Some(response) = decode_mock_response(compile_url, "compile") {
            return response;
        }

        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .build();

        let mut req = agent.post(compile_url);
        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {}", token));
        }

        let response = req
            .send_json(
                serde_json::to_value(request).map_err(|e| ZkfError::UnsupportedBackend {
                    backend: "midnight".to_string(),
                    message: format!("serialize compile request: {}", e),
                })?,
            )
            .map_err(|e| ZkfError::UnsupportedBackend {
                backend: "midnight".to_string(),
                message: format!("compile request failed: {}", e),
            })?;

        let body: CompileResponse =
            serde_json::from_reader(response.into_reader()).map_err(|e| {
                ZkfError::UnsupportedBackend {
                    backend: "midnight".to_string(),
                    message: format!("parse compile response: {}", e),
                }
            })?;

        Ok(body)
    }

    /// Check if the proof server is reachable by issuing a GET to `/health`
    /// on the base URL derived from the prove endpoint.
    ///
    /// Returns `Ok(true)` when the server responds with a 2xx status,
    /// `Ok(false)` when a non-2xx status is received, and `Err(...)` when the
    /// connection itself fails.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn health_check(&self) -> ZkfResult<bool> {
        if self.prove_url.starts_with(MOCK_RESPONSE_URL_PREFIX) {
            return Ok(true);
        }

        // Derive the base URL by stripping a trailing path segment (e.g. "/prove").
        let base_url = derive_base_url(&self.prove_url);
        let health_url = format!("{}/health", base_url);

        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .build();

        match agent.get(&health_url).call() {
            Ok(_) => Ok(true),
            Err(ureq::Error::Status(_, _)) => Ok(false),
            Err(e) => Err(ZkfError::UnsupportedBackend {
                backend: "midnight".to_string(),
                message: format!("health check failed: {}", e),
            }),
        }
    }
}

/// Strip the last path segment from a URL to derive a base URL.
///
/// Examples:
///   "http://localhost:8080/prove"   -> "http://localhost:8080"
///   "http://localhost:8080/v1/prove" -> "http://localhost:8080/v1"
///   "http://localhost:8080"          -> "http://localhost:8080"
fn derive_base_url(url: &str) -> &str {
    if let Some(pos) = url.rfind('/') {
        // Only strip if there is a non-empty path segment after the slash and
        // the portion before the slash still contains "://".
        let prefix = &url[..pos];
        if prefix.contains("://") {
            return prefix;
        }
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[derive(Clone)]
    struct TestHttpResponse {
        status_line: &'static str,
        body: String,
        delay_ms: u64,
    }

    const TEST_HTTP_TIMEOUT_MS: u64 = 10_000;

    fn spawn_http_server(responses: Vec<TestHttpResponse>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept request");
                let mut buffer = [0u8; 2048];
                let _ = stream.read(&mut buffer);
                if response.delay_ms > 0 {
                    thread::sleep(Duration::from_millis(response.delay_ms));
                }
                let payload = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.status_line,
                    response.body.len(),
                    response.body
                );
                let _ = stream.write_all(payload.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{}", addr)
    }

    fn mock_response_url(body: &str) -> String {
        format!(
            "{MOCK_RESPONSE_URL_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(body.as_bytes())
        )
    }

    #[test]
    fn test_derive_base_url_strips_path() {
        assert_eq!(
            derive_base_url("http://localhost:8080/prove"),
            "http://localhost:8080"
        );
        assert_eq!(
            derive_base_url("http://localhost:8080/v1/prove"),
            "http://localhost:8080/v1"
        );
        assert_eq!(
            derive_base_url("http://localhost:8080"),
            "http://localhost:8080"
        );
    }

    #[test]
    fn test_midnight_client_new_has_no_compile_url() {
        let client = MidnightClient::new(
            "http://localhost:8080/prove".to_string(),
            "http://localhost:8080/verify".to_string(),
        );
        assert!(client.compile_url.is_none());
    }

    #[test]
    fn test_midnight_client_with_compile_url() {
        let client = MidnightClient::new(
            "http://localhost:8080/prove".to_string(),
            "http://localhost:8080/verify".to_string(),
        )
        .with_compile_url("http://localhost:8080/compile".to_string());
        assert_eq!(
            client.compile_url.as_deref(),
            Some("http://localhost:8080/compile")
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_mock_urls_short_circuit_network_requests() {
        let prove_url = mock_response_url(
            &serde_json::json!({
                "ok": true,
                "proof_b64": base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]),
                "vk_b64": base64::engine::general_purpose::STANDARD.encode([4u8, 5, 6]),
                "public_inputs": ["7"],
            })
            .to_string(),
        );
        let verify_url = mock_response_url(r#"{"ok":true}"#);
        let compile_url = mock_response_url(
            &serde_json::json!({
                "ok": true,
                "circuit_ir_b64": base64::engine::general_purpose::STANDARD.encode(b"{}"),
                "program_digest": "digest",
            })
            .to_string(),
        );
        let client = MidnightClient::new(prove_url, verify_url)
            .with_compile_url(compile_url)
            .with_max_retries(0);

        let prove = client
            .prove(&ProveRequest {
                api_version: MIDNIGHT_API_VERSION.to_string(),
                program_digest: "digest".to_string(),
                compact_source: "contract Foo {}".to_string(),
                witness: BTreeMap::new(),
                network_id: None,
                contract_address: None,
                auth_token: None,
            })
            .expect("mock prove should decode");
        assert!(prove.ok);

        let verify = client
            .verify(&VerifyRequest {
                api_version: MIDNIGHT_API_VERSION.to_string(),
                program_digest: "digest".to_string(),
                proof_b64: base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]),
                vk_b64: base64::engine::general_purpose::STANDARD.encode([4u8, 5, 6]),
                public_inputs: BTreeMap::new(),
                network_id: None,
                auth_token: None,
            })
            .expect("mock verify should decode");
        assert!(verify.ok);

        let compile = client
            .compile(&CompileRequest {
                api_version: MIDNIGHT_API_VERSION.to_string(),
                compact_source: "contract Foo {}".to_string(),
                auth_token: None,
            })
            .expect("mock compile should decode");
        assert!(compile.ok);
        assert_eq!(client.health_check().expect("mock health"), true);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_health_check_returns_err_when_no_server() {
        // Connect to a port that should be closed; expect a connection error.
        let client = MidnightClient::new(
            "http://127.0.0.1:19999/prove".to_string(),
            "http://127.0.0.1:19999/verify".to_string(),
        );
        let result = client.health_check();
        assert!(
            result.is_err(),
            "health_check should return Err when the server is unreachable"
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_health_check_returns_false_for_non_success_status() {
        let base_url = spawn_http_server(vec![TestHttpResponse {
            status_line: "503 Service Unavailable",
            body: r#"{"ok":false}"#.to_string(),
            delay_ms: 0,
        }]);
        let client = MidnightClient::new(format!("{base_url}/prove"), format!("{base_url}/verify"))
            .with_timeout(TEST_HTTP_TIMEOUT_MS)
            .with_max_retries(0);
        assert!(!client.health_check().expect("health status should parse"));
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_http_roundtrip_success() {
        let base_url = spawn_http_server(vec![
            TestHttpResponse {
                status_line: "200 OK",
                body: serde_json::json!({
                    "ok": true,
                    "proof_b64": base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]),
                    "vk_b64": base64::engine::general_purpose::STANDARD.encode([4u8, 5, 6]),
                    "public_inputs": ["7"],
                    "metadata": {"transport":"http"}
                })
                .to_string(),
                delay_ms: 0,
            },
            TestHttpResponse {
                status_line: "200 OK",
                body: r#"{"ok":true}"#.to_string(),
                delay_ms: 0,
            },
        ]);
        let client = MidnightClient::new(format!("{base_url}/prove"), format!("{base_url}/verify"))
            .with_timeout(TEST_HTTP_TIMEOUT_MS)
            .with_max_retries(0);

        let prove = client
            .prove(&ProveRequest {
                api_version: MIDNIGHT_API_VERSION.to_string(),
                program_digest: "digest".to_string(),
                compact_source: "contract Foo {}".to_string(),
                witness: BTreeMap::new(),
                network_id: None,
                contract_address: None,
                auth_token: None,
            })
            .expect("http prove should succeed");
        assert!(prove.ok);

        let verify = client
            .verify(&VerifyRequest {
                api_version: MIDNIGHT_API_VERSION.to_string(),
                program_digest: "digest".to_string(),
                proof_b64: base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]),
                vk_b64: base64::engine::general_purpose::STANDARD.encode([4u8, 5, 6]),
                public_inputs: BTreeMap::new(),
                network_id: None,
                auth_token: None,
            })
            .expect("http verify should succeed");
        assert!(verify.ok);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_prove_times_out_after_retries() {
        let base_url = spawn_http_server(vec![
            TestHttpResponse {
                status_line: "200 OK",
                body: r#"{"ok":true}"#.to_string(),
                delay_ms: 200,
            },
            TestHttpResponse {
                status_line: "200 OK",
                body: r#"{"ok":true}"#.to_string(),
                delay_ms: 200,
            },
        ]);
        let client = MidnightClient::new(format!("{base_url}/prove"), format!("{base_url}/verify"))
            .with_timeout(25)
            .with_max_retries(1);
        let err = client
            .prove(&ProveRequest {
                api_version: MIDNIGHT_API_VERSION.to_string(),
                program_digest: "digest".to_string(),
                compact_source: "contract Foo {}".to_string(),
                witness: BTreeMap::new(),
                network_id: None,
                contract_address: None,
                auth_token: None,
            })
            .expect_err("timeout should fail");
        assert!(err.to_string().contains("prove request failed"));
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_http_malformed_prove_response_fails() {
        let base_url = spawn_http_server(vec![TestHttpResponse {
            status_line: "200 OK",
            body: "not-json".to_string(),
            delay_ms: 0,
        }]);
        let client = MidnightClient::new(format!("{base_url}/prove"), format!("{base_url}/verify"))
            .with_timeout(TEST_HTTP_TIMEOUT_MS)
            .with_max_retries(0);
        let err = client
            .prove(&ProveRequest {
                api_version: MIDNIGHT_API_VERSION.to_string(),
                program_digest: "digest".to_string(),
                compact_source: "contract Foo {}".to_string(),
                witness: BTreeMap::new(),
                network_id: None,
                contract_address: None,
                auth_token: None,
            })
            .expect_err("malformed JSON should fail");
        let error_text = err.to_string();
        assert!(
            error_text.contains("parse prove response")
                || error_text.contains("prove request failed"),
            "unexpected malformed prove error: {error_text}"
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_http_verify_false_is_preserved() {
        let base_url = spawn_http_server(vec![TestHttpResponse {
            status_line: "200 OK",
            body: r#"{"ok":false}"#.to_string(),
            delay_ms: 0,
        }]);
        let client = MidnightClient::new(format!("{base_url}/prove"), format!("{base_url}/verify"))
            .with_timeout(TEST_HTTP_TIMEOUT_MS)
            .with_max_retries(0);
        let verify = client
            .verify(&VerifyRequest {
                api_version: MIDNIGHT_API_VERSION.to_string(),
                program_digest: "digest".to_string(),
                proof_b64: base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]),
                vk_b64: base64::engine::general_purpose::STANDARD.encode([4u8, 5, 6]),
                public_inputs: BTreeMap::new(),
                network_id: None,
                auth_token: None,
            })
            .expect("verify call should succeed");
        assert!(!verify.ok);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_compile_returns_err_when_no_compile_url() {
        let client = MidnightClient::new(
            "http://127.0.0.1:19999/prove".to_string(),
            "http://127.0.0.1:19999/verify".to_string(),
        );
        let request = CompileRequest {
            api_version: MIDNIGHT_API_VERSION.to_string(),
            compact_source: "contract Foo {}".to_string(),
            auth_token: None,
        };
        let result = client.compile(&request);
        assert!(
            result.is_err(),
            "compile should return Err when compile_url is not configured"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("compile URL not configured"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_compile_returns_err_when_server_unreachable() {
        let client = MidnightClient::new(
            "http://127.0.0.1:19999/prove".to_string(),
            "http://127.0.0.1:19999/verify".to_string(),
        )
        .with_compile_url("http://127.0.0.1:19999/compile".to_string());
        // Override retries to 0 to keep the test fast.
        let client = MidnightClient {
            prove_url: client.prove_url,
            verify_url: client.verify_url,
            compile_url: client.compile_url,
            auth_token: client.auth_token,
            timeout_ms: 500,
            max_retries: 0,
        };
        let request = CompileRequest {
            api_version: MIDNIGHT_API_VERSION.to_string(),
            compact_source: "contract Foo {}".to_string(),
            auth_token: None,
        };
        let result = client.compile(&request);
        assert!(
            result.is_err(),
            "compile should fail when server is unreachable"
        );
    }
}
