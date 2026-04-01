use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE;
use libcrux_ml_dsa::ml_dsa_87::sign as mldsa_sign;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_backends::blackbox_gadgets::{enrich_witness_for_proving, lower_blackbox_program};
use zkf_core::{
    BackendKind, CompiledProgram, FieldElement, Program, WitnessInputs, check_constraints,
    generate_witness, program_v2_to_zir,
};

use super::shared::{
    MIDNIGHT_GATEWAY_ML_DSA_CONTEXT, REQUIRED_COMPACTC_VERSION, compactc_version,
    compile_compact_contract, current_timestamp_rfc3339ish, import_compact_program,
    load_or_create_gateway_attestor, poseidon_commitment_from_bytes, resolve_compactc_binary,
    secure_random_array,
};
use crate::util::{sha256_hex, write_json};

#[derive(Debug, Clone, Serialize)]
struct MidnightGatewayStartedV1 {
    schema: &'static str,
    mode: &'static str,
    port: u16,
    base_url: String,
    compactc_version: Option<String>,
    attestor_public_key_present: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayReadyResponse {
    status: &'static str,
    compactc_version: Option<String>,
    attestor_public_key_present: bool,
    timestamp: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VerifyCompactRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MidnightGatewayAdmissionReportV1 {
    pub schema: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    pub contract_id: String,
    pub compactc_version: String,
    pub program_digest: String,
    pub sample_vector_result: String,
    pub poseidon_commitment: String,
    pub admitted_at: String,
    pub audit_summary: MidnightGatewayAuditSummaryV1,
    pub artifact_digests: BTreeMap<String, String>,
    pub attestor: MidnightGatewayAttestationV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MidnightGatewayAuditSummaryV1 {
    pub total_checks: usize,
    pub passed: usize,
    pub warned: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MidnightGatewayAttestationV1 {
    pub scheme: String,
    pub context: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Clone)]
struct GatewayState {
    compactc_version: Option<String>,
    attestor_public_key_hex: String,
}

pub(crate) fn handle_serve(port: u16, json: bool) -> Result<(), String> {
    let compactc_version = resolve_compactc_binary()
        .as_deref()
        .and_then(|path| compactc_version(path).ok());
    let attestor = load_or_create_gateway_attestor()?;
    let state = Arc::new(GatewayState {
        compactc_version: compactc_version.clone(),
        attestor_public_key_hex: hex_bytes(&attestor.ml_dsa87_public_key),
    });
    let attestor_public_key_present = !state.attestor_public_key_hex.is_empty();
    let server_state = Arc::clone(&state);

    actix_web::rt::System::new().block_on(async move {
        let http_server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::from(Arc::clone(&server_state)))
                .route("/health", web::get().to(health))
                .route("/ready", web::get().to(ready))
                .route("/v1/verify-compact", web::post().to(verify_compact))
        })
        .bind(("0.0.0.0", port))
        .map_err(|error| format!("failed to bind Midnight gateway: {error}"))?;
        let bound_port = http_server.addrs()[0].port();
        let started = MidnightGatewayStartedV1 {
            schema: "zkf-midnight-gateway-started-v1",
            mode: "midnight-gateway",
            port: bound_port,
            base_url: format!("http://127.0.0.1:{bound_port}"),
            compactc_version,
            attestor_public_key_present,
        };

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&started).map_err(|error| error.to_string())?
            );
        } else {
            println!(
                "Midnight gateway listening on {} (/v1/verify-compact, /ready)",
                started.base_url
            );
        }

        http_server
            .run()
            .await
            .map_err(|error| format!("Midnight gateway exited with error: {error}"))
    })
}

fn gateway_ready_response(state: &GatewayState) -> GatewayReadyResponse {
    let compactc_ready = state
        .compactc_version
        .as_deref()
        .is_some_and(|version| version == REQUIRED_COMPACTC_VERSION);
    let ready = compactc_ready && !state.attestor_public_key_hex.is_empty();
    GatewayReadyResponse {
        status: if ready { "ok" } else { "degraded" },
        compactc_version: state.compactc_version.clone(),
        attestor_public_key_present: !state.attestor_public_key_hex.is_empty(),
        timestamp: current_timestamp_rfc3339ish(),
    }
}

pub(crate) fn admit_compact_request(
    request: &VerifyCompactRequest,
) -> Result<MidnightGatewayAdmissionReportV1, String> {
    let source_root = std::env::temp_dir().join(format!(
        "zkf-midnight-gateway-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&source_root)
        .map_err(|error| format!("failed to create {}: {error}", source_root.display()))?;

    let source_path = if let Some(path) = request.contract_path.as_ref() {
        PathBuf::from(path)
    } else if let Some(source) = request.contract_source.as_ref() {
        let file_name = request
            .contract_name
            .clone()
            .unwrap_or_else(|| "midnight_contract.compact".to_string());
        let path = source_root.join(file_name);
        fs::write(&path, source).map_err(|error| format!("{}: {error}", path.display()))?;
        path
    } else {
        return Err("gateway verification requires contract_path or contract_source".to_string());
    };

    let out_dir = source_root.join("compact-out");
    let zkir_path = compile_compact_contract(&source_path, &out_dir)?;
    let compactc = resolve_compactc_binary().ok_or_else(|| {
        format!("compactc {REQUIRED_COMPACTC_VERSION} is required for gateway admission")
    })?;
    let compactc_version = compactc_version(&compactc)?;
    if compactc_version != REQUIRED_COMPACTC_VERSION {
        return Err(format!(
            "gateway admission requires compactc {}, found {}",
            REQUIRED_COMPACTC_VERSION, compactc_version
        ));
    }

    let program = import_compact_program(&zkir_path)?;
    let audit = zkf_core::audit_program_with_capability_matrix(
        &program_v2_to_zir(&program),
        None,
        &zkf_backends::backend_capability_matrix(),
    );
    if audit.summary.failed > 0 {
        return Err(format!(
            "gateway admission rejected {} because the audit failed ({} failed checks)",
            source_path.display(),
            audit.summary.failed
        ));
    }

    run_generated_smoke_vector(&program)?;

    let audit_json = audit.to_json()?;
    let source_bytes = fs::read(&source_path)
        .map_err(|error| format!("failed to read {}: {error}", source_path.display()))?;
    let zkir_bytes = fs::read(&zkir_path)
        .map_err(|error| format!("failed to read {}: {error}", zkir_path.display()))?;

    let mut report = MidnightGatewayAdmissionReportV1 {
        schema: "zkf-midnight-gateway-admission-report-v1".to_string(),
        status: "admitted".to_string(),
        template_id: request.template_id.clone(),
        contract_id: request
            .contract_name
            .clone()
            .or_else(|| {
                source_path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(|stem| stem.to_string())
            })
            .unwrap_or_else(|| "midnight_contract".to_string()),
        compactc_version,
        program_digest: program.digest_hex(),
        sample_vector_result: "generated-smoke-vector-passed".to_string(),
        poseidon_commitment: String::new(),
        admitted_at: current_timestamp_rfc3339ish(),
        audit_summary: MidnightGatewayAuditSummaryV1 {
            total_checks: audit.summary.total_checks,
            passed: audit.summary.passed,
            warned: audit.summary.warned,
            failed: audit.summary.failed,
        },
        artifact_digests: BTreeMap::from([
            ("source_sha256".to_string(), sha256_hex(&source_bytes)),
            ("zkir_sha256".to_string(), sha256_hex(&zkir_bytes)),
            (
                "audit_sha256".to_string(),
                sha256_hex(audit_json.as_bytes()),
            ),
        ]),
        attestor: MidnightGatewayAttestationV1 {
            scheme: "ml-dsa-87".to_string(),
            context: String::from_utf8_lossy(MIDNIGHT_GATEWAY_ML_DSA_CONTEXT).to_string(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
        },
    };

    let unsigned_bytes =
        serde_json::to_vec_pretty(&report).map_err(|error| format!("serialize report: {error}"))?;
    report.poseidon_commitment = poseidon_commitment_from_bytes(&unsigned_bytes)?;
    let signing_bytes =
        serde_json::to_vec_pretty(&report).map_err(|error| format!("serialize report: {error}"))?;

    let attestor = load_or_create_gateway_attestor()?;
    let randomness = secure_random_array::<SIGNING_RANDOMNESS_SIZE>()?;
    let signature = mldsa_sign(
        &attestor.signing_key()?,
        &signing_bytes,
        MIDNIGHT_GATEWAY_ML_DSA_CONTEXT,
        randomness,
    )
    .map_err(|error| format!("Midnight gateway ML-DSA-87 signing failed: {error:?}"))?;
    report.attestor.public_key_hex = hex_bytes(&attestor.ml_dsa87_public_key);
    report.attestor.signature_hex = hex_bytes(signature.as_slice());

    if let Some(output_path) = request.output_path.as_ref() {
        write_json(Path::new(output_path), &report)?;
    }

    Ok(report)
}

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "timestamp": current_timestamp_rfc3339ish(),
    }))
}

async fn ready(state: web::Data<GatewayState>) -> impl Responder {
    HttpResponse::Ok().json(gateway_ready_response(state.get_ref()))
}

async fn verify_compact(request: web::Json<VerifyCompactRequest>) -> impl Responder {
    match admit_compact_request(&request.into_inner()) {
        Ok(report) => HttpResponse::Ok().json(report),
        Err(error) => HttpResponse::UnprocessableEntity().json(serde_json::json!({
            "schema": "zkf-midnight-gateway-error-v1",
            "status": "rejected",
            "error": error,
        })),
    }
}

fn run_generated_smoke_vector(program: &Program) -> Result<(), String> {
    let mut inputs = WitnessInputs::new();
    if !program.witness_plan.input_aliases.is_empty() {
        for alias in program.witness_plan.input_aliases.keys() {
            inputs.insert(alias.clone(), FieldElement::from_i64(1));
        }
    } else {
        for signal in &program.signals {
            if signal.visibility == zkf_core::Visibility::Private
                || signal.visibility == zkf_core::Visibility::Public
            {
                inputs.insert(signal.name.clone(), FieldElement::from_i64(1));
            }
        }
    }

    crate::util::resolve_input_aliases(&mut inputs, program);
    let lowered_program = lower_blackbox_program(program).map_err(|error| error.to_string())?;
    let witness = generate_witness(&lowered_program, &inputs)
        .or_else(|_| generate_witness(program, &inputs))
        .map_err(|error| error.to_string())?;
    let mut compiled = CompiledProgram::new(BackendKind::ArkworksGroth16, lowered_program);
    compiled.original_program = Some(program.clone());
    let enriched =
        enrich_witness_for_proving(&compiled, &witness).map_err(|error| error.to_string())?;
    check_constraints(&compiled.program, &enriched).map_err(|error| error.to_string())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::midnight::shared::{REQUIRED_COMPACTC_VERSION, template_contract_source};

    #[test]
    fn gateway_ready_response_reports_degraded_without_attestor_key() {
        let response = gateway_ready_response(&GatewayState {
            compactc_version: Some(REQUIRED_COMPACTC_VERSION.to_string()),
            attestor_public_key_hex: String::new(),
        });

        assert_eq!(response.status, "degraded");
        assert!(!response.attestor_public_key_present);
    }

    #[test]
    fn gateway_requires_contract_path_or_source() {
        let error = admit_compact_request(&VerifyCompactRequest {
            template_id: None,
            contract_path: None,
            contract_source: None,
            contract_name: None,
            output_path: None,
        })
        .expect_err("gateway should reject empty requests");

        assert!(error.contains("contract_path or contract_source"));
    }

    #[test]
    fn gateway_rejects_underconstrained_contracts_after_audit() {
        let Some(compactc) = resolve_compactc_binary() else {
            return;
        };
        if compactc_version(&compactc).ok().as_deref() != Some(REQUIRED_COMPACTC_VERSION) {
            return;
        }

        let compactc_env = compactc.display().to_string();
        crate::tests::with_temp_home_and_env(&[("COMPACTC_BIN", compactc_env.as_str())], || {
            let error = admit_compact_request(&VerifyCompactRequest {
                template_id: Some("failing-audit".to_string()),
                contract_path: None,
                contract_source: Some(
                    r#"pragma language_version 0.22;

import CompactStandardLibrary;

export ledger published: Field;

witness left(): Uint<64>;
witness right(): Uint<64>;

export circuit publishSum(): [] {
  published = disclose(left() + right());
}
"#
                    .to_string(),
                ),
                contract_name: Some("failing_audit.compact".to_string()),
                output_path: None,
            })
            .expect_err("underconstrained contract should fail audit");
            assert!(
                error.contains("audit failed"),
                "unexpected gateway response: {error}"
            );
        });
    }

    #[test]
    fn gateway_admission_writes_attested_report_when_compactc_is_available() {
        let Some(compactc) = resolve_compactc_binary() else {
            return;
        };
        if compactc_version(&compactc).ok().as_deref() != Some(REQUIRED_COMPACTC_VERSION) {
            return;
        }

        let compactc_env = compactc.display().to_string();
        crate::tests::with_temp_home_and_env(&[("COMPACTC_BIN", compactc_env.as_str())], || {
            let temp = tempfile::tempdir().expect("tempdir");
            let report_path = temp.path().join("admission.json");
            let report = admit_compact_request(&VerifyCompactRequest {
                template_id: Some("token-transfer".to_string()),
                contract_path: None,
                contract_source: Some(
                    template_contract_source("token-transfer").expect("token-transfer source"),
                ),
                contract_name: Some("token_transfer.compact".to_string()),
                output_path: Some(report_path.display().to_string()),
            })
            .expect("gateway admission report");

            assert_eq!(report.schema, "zkf-midnight-gateway-admission-report-v1");
            assert_eq!(report.status, "admitted");
            assert!(!report.poseidon_commitment.is_empty());
            assert_eq!(report.attestor.scheme, "ml-dsa-87");
            assert!(!report.attestor.public_key_hex.is_empty());
            assert!(!report.attestor.signature_hex.is_empty());
            assert!(report_path.is_file());
        });
    }
}
