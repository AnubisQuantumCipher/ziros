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

use std::io::{Read, Write};
use std::net::TcpListener;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::{Mutex, OnceLock};
use std::thread;

use zkf_backends::capability_report_for_backend;
use zkf_core::BackendKind;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_midnight_env<T>(
    prove_url: Option<&str>,
    verify_url: Option<&str>,
    allow_delegate: bool,
    f: impl FnOnce() -> T,
) -> T {
    let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|poison| poison.into_inner());

    unsafe {
        match prove_url {
            Some(value) => std::env::set_var("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL", value),
            None => std::env::remove_var("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL"),
        }
        match verify_url {
            Some(value) => std::env::set_var("ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL", value),
            None => std::env::remove_var("ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL"),
        }
        std::env::set_var(
            "ZKF_MIDNIGHT_ALLOW_COMPAT_DELEGATE",
            if allow_delegate { "true" } else { "false" },
        );
    }

    let result = catch_unwind(AssertUnwindSafe(f));

    unsafe {
        std::env::remove_var("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL");
        std::env::remove_var("ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL");
        std::env::remove_var("ZKF_MIDNIGHT_ALLOW_COMPAT_DELEGATE");
    }

    match result {
        Ok(value) => value,
        Err(payload) => resume_unwind(payload),
    }
}

fn spawn_health_server(status_line: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer);
        let payload = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{{\"ok\":true}}",
            status_line
        );
        let _ = stream.write_all(payload.as_bytes());
        let _ = stream.flush();
    });
    format!("http://{}", addr)
}

#[test]
fn midnight_readiness_is_unconfigured_without_urls() {
    with_midnight_env(None, None, false, || {
        let report = capability_report_for_backend(BackendKind::MidnightCompact)
            .expect("midnight capability report");
        assert!(!report.production_ready);
        assert_eq!(
            report.readiness_reason.as_deref(),
            Some("midnight-proof-server-unconfigured")
        );
    });
}

#[test]
fn midnight_readiness_is_delegate_only_without_urls_when_delegate_enabled() {
    with_midnight_env(None, None, true, || {
        let report = capability_report_for_backend(BackendKind::MidnightCompact)
            .expect("midnight capability report");
        assert!(!report.production_ready);
        assert_eq!(
            report.readiness_reason.as_deref(),
            Some("midnight-proof-server-delegate-only")
        );
    });
}

#[test]
fn midnight_readiness_rejects_mock_urls_for_production() {
    with_midnight_env(Some("mock://prove"), Some("mock://verify"), false, || {
        let report = capability_report_for_backend(BackendKind::MidnightCompact)
            .expect("midnight capability report");
        assert!(!report.production_ready);
        assert_eq!(
            report.readiness_reason.as_deref(),
            Some("midnight-proof-server-mock-only")
        );
    });
}

#[test]
fn midnight_readiness_rejects_unhealthy_server() {
    let base_url = spawn_health_server("503 Service Unavailable");
    with_midnight_env(
        Some(&format!("{base_url}/prove")),
        Some(&format!("{base_url}/verify")),
        false,
        || {
            let report = capability_report_for_backend(BackendKind::MidnightCompact)
                .expect("midnight capability report");
            assert!(!report.production_ready);
            assert_eq!(
                report.readiness_reason.as_deref(),
                Some("midnight-proof-server-unhealthy")
            );
        },
    );
}

#[test]
fn midnight_readiness_accepts_healthy_http_server() {
    let base_url = spawn_health_server("200 OK");
    with_midnight_env(
        Some(&format!("{base_url}/prove")),
        Some(&format!("{base_url}/verify")),
        false,
        || {
            let report = capability_report_for_backend(BackendKind::MidnightCompact)
                .expect("midnight capability report");
            assert!(report.production_ready);
            assert_eq!(report.readiness_reason, None);
        },
    );
}
