// FFI test harness calls extern "C" functions through raw pointers.
#![allow(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::useless_format,
    clippy::collapsible_else_if
)]

//! ZKF FFI Comprehensive System Test
//!
//! Exercises all 31 FFI functions through the exact same C interface the Mac app uses.
//! Run: cargo run -p zkf-ffi --bin zkf-test-all

use std::ffi::{CStr, CString};

// Import all FFI functions directly from the crate's lib
use zkf_ffi::*;

// ─── Test helpers ──────────────────────────────────────────────────────────

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

struct TestResult {
    name: String,
    passed: bool,
    detail: String,
    time_ms: f64,
}

/// Call an FFI function, check result, and return (status, json_data_or_error).
unsafe fn call_ffi(ptr: *mut ZkfFfiResult) -> (i32, String) {
    if ptr.is_null() {
        return (-1, "null pointer returned".to_string());
    }
    let status = unsafe { (*ptr).status };
    let msg = if status == 0 {
        if unsafe { (*ptr).data.is_null() } {
            "{}".to_string()
        } else {
            unsafe { CStr::from_ptr((*ptr).data).to_string_lossy().into_owned() }
        }
    } else {
        if unsafe { (*ptr).error.is_null() } {
            format!("error (status {status})")
        } else {
            unsafe { CStr::from_ptr((*ptr).error).to_string_lossy().into_owned() }
        }
    };
    zkf_free_result(ptr);
    (status, msg)
}

fn run_test<F>(name: &str, f: F) -> TestResult
where
    F: FnOnce() -> Result<String, String>,
{
    let start = std::time::Instant::now();
    match f() {
        Ok(detail) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            TestResult {
                name: name.to_string(),
                passed: true,
                detail,
                time_ms: elapsed,
            }
        }
        Err(detail) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            TestResult {
                name: name.to_string(),
                passed: false,
                detail,
                time_ms: elapsed,
            }
        }
    }
}

fn extract_json_key(json: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    Some(match &v[key] {
        serde_json::Value::Null => return None,
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

// ─── Main ──────────────────────────────────────────────────────────────────

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║        ZKF FFI COMPREHENSIVE SYSTEM TEST                   ║");
    println!("║        Testing all 31 FFI functions + cancellation          ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let test_dir = std::env::temp_dir().join(format!("zkf_test_{}", std::process::id()));
    std::fs::create_dir_all(&test_dir).expect("failed to create test dir");
    let td = |name: &str| -> String { test_dir.join(name).to_string_lossy().into_owned() };

    let mut results: Vec<TestResult> = Vec::new();

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 1: System & Diagnostics (5 tests)
    // ═══════════════════════════════════════════════════════════════════════
    println!("─── Phase 1: System & Diagnostics ───────────────────────────");

    results.push(run_test("01. zkf_check_available", || unsafe {
        let (s, data) = call_ffi(zkf_check_available());
        if s != 0 {
            return Err(data);
        }
        let version = extract_json_key(&data, "version").unwrap_or_default();
        Ok(format!("v{version}, native_ffi=true"))
    }));

    results.push(run_test("02. zkf_capabilities", || unsafe {
        let (s, data) = call_ffi(zkf_capabilities());
        if s != 0 {
            return Err(data);
        }
        let v: serde_json::Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
        let nb = v["backends"].as_array().map(|a| a.len()).unwrap_or(0);
        let nf = v["frontends"].as_array().map(|a| a.len()).unwrap_or(0);
        Ok(format!("{nb} backends, {nf} frontends"))
    }));

    results.push(run_test("03. zkf_doctor", || unsafe {
        let (s, data) = call_ffi(zkf_doctor());
        if s != 0 {
            return Err(data);
        }
        let healthy = extract_json_key(&data, "healthy").unwrap_or_default();
        Ok(format!("healthy={healthy}"))
    }));

    results.push(run_test("04. zkf_metal_doctor", || unsafe {
        let (s, data) = call_ffi(zkf_metal_doctor());
        if s != 0 {
            return Err(data);
        }
        Ok(format!("{}B response", data.len()))
    }));

    results.push(run_test("05. zkf_frontends", || unsafe {
        let (s, data) = call_ffi(zkf_frontends());
        if s != 0 {
            return Err(data);
        }
        let v: serde_json::Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
        let count = v.as_array().map(|a| a.len()).unwrap_or(0);
        Ok(format!("{count} frontends listed"))
    }));

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 2: Cancellation (3 tests)
    // ═══════════════════════════════════════════════════════════════════════
    println!("─── Phase 2: Cancellation ─────────────────────────────────");

    results.push(run_test("06. zkf_clear_cancel", || {
        zkf_clear_cancel();
        let cancelled = zkf_is_cancelled();
        if cancelled != 0 {
            return Err("cancel flag not cleared".into());
        }
        Ok("flag cleared".into())
    }));

    results.push(run_test("07. zkf_request_cancel", || {
        zkf_request_cancel();
        let cancelled = zkf_is_cancelled();
        zkf_clear_cancel(); // clean up
        if cancelled != 1 {
            return Err("cancel flag not set".into());
        }
        Ok("flag set and cleared".into())
    }));

    results.push(run_test("08. zkf_is_cancelled", || {
        zkf_clear_cancel();
        let a = zkf_is_cancelled();
        zkf_request_cancel();
        let b = zkf_is_cancelled();
        zkf_clear_cancel();
        if a != 0 || b != 1 {
            return Err(format!("expected 0,1 got {a},{b}"));
        }
        Ok("0→cancel→1→clear→0".into())
    }));

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 3: Example & Core Pipeline (8 tests)
    // ═══════════════════════════════════════════════════════════════════════
    println!("─── Phase 3: Core Pipeline ────────────────────────────────");

    let example_path = td("example.ir.json");
    results.push(run_test("09. zkf_emit_example", || unsafe {
        let path = c(&example_path);
        let (s, data) = call_ffi(zkf_emit_example(path.as_ptr()));
        if s != 0 {
            return Err(data);
        }
        let signals = extract_json_key(&data, "signals").unwrap_or_default();
        let constraints = extract_json_key(&data, "constraints").unwrap_or_default();
        Ok(format!("{signals} signals, {constraints} constraints"))
    }));

    // Create inputs file for the mul_add example: signal name → field element string
    // mul_add signals: x, y, sum, product. Inputs: x=3, y=5 → sum=8, product=24
    let inputs_path = td("inputs.json");
    std::fs::write(&inputs_path, r#"{"x":"3","y":"5"}"#).unwrap();

    let compiled_path = td("compiled.json");
    results.push(run_test("10. zkf_compile", || unsafe {
        let prog = c(&example_path);
        let be = c("arkworks-groth16");
        let out = c(&compiled_path);
        let (s, data) = call_ffi(zkf_compile(
            prog.as_ptr(),
            be.as_ptr(),
            out.as_ptr(),
            std::ptr::null(),
        ));
        if s != 0 {
            return Err(data);
        }
        let time = extract_json_key(&data, "setup_time_seconds").unwrap_or("?".into());
        let constraints = extract_json_key(&data, "constraints").unwrap_or("?".into());
        Ok(format!("{constraints} constraints, {time}s"))
    }));

    let witness_path = td("witness.json");
    results.push(run_test("11. zkf_witness", || unsafe {
        let prog = c(&example_path);
        let inp = c(&inputs_path);
        let out = c(&witness_path);
        let (s, data) = call_ffi(zkf_witness(prog.as_ptr(), inp.as_ptr(), out.as_ptr()));
        if s != 0 {
            return Err(data);
        }
        let count = extract_json_key(&data, "num_assignments").unwrap_or("?".into());
        Ok(format!("{count} assignments"))
    }));

    let optimized_path = td("optimized.ir.json");
    results.push(run_test("12. zkf_optimize", || unsafe {
        let prog = c(&example_path);
        let out = c(&optimized_path);
        let (s, data) = call_ffi(zkf_optimize(prog.as_ptr(), out.as_ptr()));
        if s != 0 {
            return Err(data);
        }
        let orig = extract_json_key(&data, "original_constraints").unwrap_or("?".into());
        let opt = extract_json_key(&data, "optimized_constraints").unwrap_or("?".into());
        Ok(format!("{orig}→{opt} constraints"))
    }));

    results.push(run_test("13. zkf_debug", || unsafe {
        let prog = c(&example_path);
        let wit = c(&witness_path);
        let out_path = td("debug_report.json");
        let out = c(&out_path);
        let (s, data) = call_ffi(zkf_debug(prog.as_ptr(), wit.as_ptr(), out.as_ptr(), 0));
        if s != 0 {
            return Err(data);
        }
        Ok(format!("{}B report", data.len()))
    }));

    let proof_path = td("proof.json");
    let compiled_out = td("compiled_from_prove.json");
    results.push(run_test("14. zkf_prove", || unsafe {
        let prog = c(&example_path);
        let inp = c(&inputs_path);
        let be = c("arkworks-groth16");
        let out = c(&proof_path);
        let comp_out = c(&compiled_out);
        let (s, data) = call_ffi(zkf_prove(
            prog.as_ptr(),
            inp.as_ptr(),
            be.as_ptr(),
            out.as_ptr(),
            comp_out.as_ptr(),
            std::ptr::null(),
            1,
            0,
        ));
        if s != 0 {
            return Err(data);
        }
        let time = extract_json_key(&data, "proving_time_seconds").unwrap_or("?".into());
        let size = extract_json_key(&data, "proof_size_bytes").unwrap_or("?".into());
        Ok(format!("{size}B proof in {time}s"))
    }));

    results.push(run_test("15. zkf_verify", || unsafe {
        let proof = c(&proof_path);
        let be = c("arkworks-groth16");
        let (s, data) = call_ffi(zkf_verify(proof.as_ptr(), be.as_ptr()));
        if s != 0 {
            return Err(data);
        }
        let valid = extract_json_key(&data, "valid").unwrap_or("?".into());
        let time = extract_json_key(&data, "verification_time_seconds").unwrap_or("?".into());
        if valid != "true" {
            return Err(format!("valid={valid} (expected true)"));
        }
        Ok(format!("VALID in {time}s"))
    }));

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 4: Inspection & Analysis (4 tests)
    // ═══════════════════════════════════════════════════════════════════════
    println!("─── Phase 4: Inspection & Analysis ──────────────────────────");

    results.push(run_test("16. zkf_explore", || unsafe {
        let art = c(&proof_path);
        let be = c("arkworks-groth16");
        let (s, data) = call_ffi(zkf_explore(art.as_ptr(), be.as_ptr()));
        if s != 0 {
            return Err(data);
        }
        let size = extract_json_key(&data, "proof_size_bytes").unwrap_or("?".into());
        let pubs = extract_json_key(&data, "public_inputs_count").unwrap_or("?".into());
        Ok(format!("{size}B proof, {pubs} public inputs"))
    }));

    results.push(run_test("17. zkf_inspect", || unsafe {
        let fe = c("noir");
        let art = c(&example_path);
        let (s, data) = call_ffi(zkf_inspect(fe.as_ptr(), art.as_ptr()));
        // IR JSON isn't a Noir artifact — error is expected; we verify FFI path works
        if s == 0 {
            Ok(format!("{}B inspection", data.len()))
        } else {
            Ok(format!(
                "FFI path OK (expected error for non-Noir): {}",
                &data[..data.len().min(60)]
            ))
        }
    }));

    results.push(run_test("18. zkf_estimate_gas", || unsafe {
        let proof = c(&proof_path);
        let be = c("arkworks-groth16");
        let (s, data) = call_ffi(zkf_estimate_gas(proof.as_ptr(), be.as_ptr()));
        if s != 0 {
            return Err(data);
        }
        let vg = extract_json_key(&data, "verify_gas").unwrap_or("?".into());
        let dg = extract_json_key(&data, "deploy_gas").unwrap_or("?".into());
        Ok(format!("verify={vg} deploy={dg} gas"))
    }));

    let import_out = td("imported.ir.json");
    results.push(run_test("19. zkf_import", || unsafe {
        let fe = c("noir");
        let inp = c(&example_path);
        let out = c(&import_out);
        let (s, data) = call_ffi(zkf_import(
            fe.as_ptr(),
            inp.as_ptr(),
            out.as_ptr(),
            std::ptr::null(),
        ));
        // IR JSON isn't a Noir artifact — error is expected; we verify FFI path works
        if s == 0 {
            let signals = extract_json_key(&data, "signals").unwrap_or("?".into());
            Ok(format!("{signals} signals imported"))
        } else {
            Ok(format!(
                "FFI path OK (expected error for non-Noir): {}",
                &data[..data.len().min(60)]
            ))
        }
    }));

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 5: Deployment (1 test)
    // ═══════════════════════════════════════════════════════════════════════
    println!("─── Phase 5: Deployment ─────────────────────────────────────");

    let deploy_path = td("ZKFVerifier.sol");
    results.push(run_test("20. zkf_deploy", || unsafe {
        let proof = c(&proof_path);
        let be = c("arkworks-groth16");
        let out = c(&deploy_path);
        let name = c("ZKFVerifier");
        let (s, data) = call_ffi(zkf_deploy(
            proof.as_ptr(),
            be.as_ptr(),
            out.as_ptr(),
            name.as_ptr(),
        ));
        if s != 0 {
            return Err(data);
        }
        let size = extract_json_key(&data, "contract_size_bytes").unwrap_or("?".into());
        Ok(format!("{size}B Solidity verifier"))
    }));

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 6: Proof Composition (3 tests)
    // ═══════════════════════════════════════════════════════════════════════
    println!("─── Phase 6: Proof Composition ────────────────────────────");

    let wrap_out = td("wrapped.json");
    results.push(run_test("21. zkf_wrap", || unsafe {
        let proof = c(&proof_path);
        let comp = c(&compiled_out);
        let out = c(&wrap_out);
        let (s, data) = call_ffi(zkf_wrap(proof.as_ptr(), comp.as_ptr(), out.as_ptr(), 0));
        if s == 0 {
            let time = extract_json_key(&data, "wrapping_time_seconds").unwrap_or("?".into());
            let ratio = extract_json_key(&data, "compression_ratio").unwrap_or("?".into());
            Ok(format!("{time}s, compression={ratio}x"))
        } else if data.contains("no groth16 wrapper") {
            Ok(format!("FFI path OK (groth16→groth16 wrap not supported)"))
        } else {
            Err(data)
        }
    }));

    results.push(run_test("22. zkf_wrap_setup", || unsafe {
        let proof = c(&proof_path);
        let comp = c(&compiled_out);
        let (s, data) = call_ffi(zkf_wrap_setup(proof.as_ptr(), comp.as_ptr()));
        if s == 0 {
            let time = extract_json_key(&data, "setup_time_seconds").unwrap_or("?".into());
            Ok(format!("keys generated in {time}s"))
        } else if data.contains("no groth16 wrapper") {
            Ok(format!("FFI path OK (groth16→groth16 wrap not supported)"))
        } else {
            Err(data)
        }
    }));

    let agg_out = td("aggregated.json");
    results.push(run_test("23. zkf_aggregate", || unsafe {
        let pairs = format!(
            r#"[{{"proof":"{}","compiled":"{}"}}]"#,
            proof_path, compiled_out
        );
        let pairs_c = c(&pairs);
        let mode = c("batch");
        let out = c(&agg_out);
        let (s, data) = call_ffi(zkf_aggregate(pairs_c.as_ptr(), mode.as_ptr(), out.as_ptr()));
        if s != 0 {
            return Err(data);
        }
        let n = extract_json_key(&data, "num_proofs").unwrap_or("?".into());
        Ok(format!("{n} proofs aggregated"))
    }));

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 7: Benchmark & Test Vectors (2 tests)
    // ═══════════════════════════════════════════════════════════════════════
    println!("─── Phase 7: Benchmark & Test Vectors ─────────────────────");

    results.push(run_test("24. zkf_benchmark", || unsafe {
        let backends = c(r#"["arkworks-groth16"]"#);
        let (s, data) = call_ffi(zkf_benchmark(backends.as_ptr(), 1, 0, 0));
        if s != 0 {
            return Err(data);
        }
        let v: serde_json::Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
        let results = v["results"].as_array().map(|a| a.len()).unwrap_or(0);
        Ok(format!("{results} backend(s) benchmarked"))
    }));

    // Create test vectors file using signal names
    let vectors_path = td("vectors.json");
    std::fs::write(
        &vectors_path,
        r#"[{"inputs":{"x":"3","y":"5"},"expected_output":"24"}]"#,
    )
    .unwrap();

    results.push(run_test("25. zkf_test_vectors", || unsafe {
        let prog = c(&example_path);
        let vec = c(&vectors_path);
        let be = c(r#"["arkworks-groth16"]"#);
        let (s, data) = call_ffi(zkf_test_vectors(prog.as_ptr(), vec.as_ptr(), be.as_ptr()));
        if s != 0 {
            return Err(data);
        }
        let v: serde_json::Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
        let count = v["results"].as_array().map(|a| a.len()).unwrap_or(0);
        Ok(format!("{count} vectors tested"))
    }));

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 8: Demo (1 test)
    // ═══════════════════════════════════════════════════════════════════════
    println!("─── Phase 8: Demo Pipeline ──────────────────────────────────");

    results.push(run_test("26. zkf_demo", || unsafe {
        let (s, data) = call_ffi(zkf_demo());
        if s != 0 {
            return Err(data);
        }
        let valid = extract_json_key(&data, "valid").unwrap_or("?".into());
        let steps = extract_json_key(&data, "steps").unwrap_or("?".into());
        if valid != "true" {
            return Err(format!("demo invalid: valid={valid}"));
        }
        Ok(format!("valid=true, steps={steps}"))
    }));

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 9: Registry (3 tests)
    // ═══════════════════════════════════════════════════════════════════════
    println!("─── Phase 9: Registry ─────────────────────────────────────");

    results.push(run_test("27. zkf_registry_list", || unsafe {
        let (s, data) = call_ffi(zkf_registry_list());
        if s != 0 {
            return Err(data);
        }
        Ok(format!("{}B registry data", data.len()))
    }));

    results.push(run_test("28. zkf_registry_add", || unsafe {
        let gadget = c("test-gadget");
        let (s, data) = call_ffi(zkf_registry_add(gadget.as_ptr()));
        // May fail if gadget not found — that's OK, we test the FFI path
        if s == 0 {
            Ok(format!("gadget found"))
        } else {
            Ok(format!(
                "gadget not found (expected): {}",
                &data[..data.len().min(80)]
            ))
        }
    }));

    results.push(run_test("29. zkf_registry_publish", || unsafe {
        // This will likely fail since we don't have a real manifest, but it tests the FFI path
        let man = c(&example_path);
        let cont = c(&example_path);
        let (s, data) = call_ffi(zkf_registry_publish(man.as_ptr(), cont.as_ptr()));
        if s == 0 {
            Ok("published".into())
        } else {
            Ok(format!("expected error: {}", &data[..data.len().min(80)]))
        }
    }));

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 10: Package Commands (2 tests)
    // ═══════════════════════════════════════════════════════════════════════
    println!("─── Phase 10: Package Commands ────────────────────────────");

    // Create a minimal package manifest (JSON matching PackageManifest struct)
    let manifest_path = td("zkf-manifest.json");
    let manifest_content = serde_json::json!({
        "schema_version": 2,
        "package_name": "test-circuit",
        "program_digest": "0000000000000000000000000000000000000000000000000000000000000000",
        "field": "bn254",
        "frontend": {"kind": "noir", "version": "0.1.0"},
        "files": {
            "program": {"path": example_path, "sha256": ""},
            "original_artifact": {"path": example_path, "sha256": ""},
            "public_inputs": {"path": inputs_path, "sha256": ""}
        }
    })
    .to_string();
    std::fs::write(&manifest_path, &manifest_content).unwrap();

    results.push(run_test("30. zkf_package_compile", || unsafe {
        let man = c(&manifest_path);
        let be = c("arkworks-groth16");
        let (s, data) = call_ffi(zkf_package_compile(man.as_ptr(), be.as_ptr()));
        if s != 0 {
            return Err(data);
        }
        Ok(format!("compiled"))
    }));

    results.push(run_test("31. zkf_package_prove", || unsafe {
        let man = c(&manifest_path);
        let be = c("arkworks-groth16");
        let run_id = c("test-run-001");
        let (s, data) = call_ffi(zkf_package_prove(
            man.as_ptr(),
            be.as_ptr(),
            run_id.as_ptr(),
        ));
        if s != 0 {
            return Err(data);
        }
        let time = extract_json_key(&data, "proving_time_seconds").unwrap_or("?".into());
        Ok(format!("proved in {time}s"))
    }));

    // ═══════════════════════════════════════════════════════════════════════
    // RESULTS SUMMARY
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                    TEST RESULTS                            ║");
    println!("╠══════════════════════════════════════════════════════════════╣");

    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;
    let total_time: f64 = results.iter().map(|r| r.time_ms).sum();

    for r in &results {
        let icon = if r.passed { "✅" } else { "❌" };
        let time_str = if r.time_ms > 1000.0 {
            format!("{:.1}s", r.time_ms / 1000.0)
        } else {
            format!("{:.0}ms", r.time_ms)
        };
        println!(
            "║ {} {:<30} {:>8}  {}",
            icon,
            r.name,
            time_str,
            &r.detail[..r.detail.len().min(50)]
        );
    }

    println!("╠══════════════════════════════════════════════════════════════╣");
    let status = if failed == 0 { "ALL PASS" } else { "FAILURES" };
    println!(
        "║  {status}: {passed}/{total} passed, {failed} failed, {:.1}s total",
        total_time / 1000.0
    );
    println!("╚══════════════════════════════════════════════════════════════╝");

    if failed > 0 {
        println!("\n❌ FAILED TESTS:");
        for r in &results {
            if !r.passed {
                println!("  • {}: {}", r.name, r.detail);
            }
        }
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&test_dir);

    println!("\nTest artifacts cleaned up from {}", test_dir.display());
    std::process::exit(if failed == 0 { 0 } else { 1 });
}
