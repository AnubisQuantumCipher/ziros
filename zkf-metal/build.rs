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

//! Build script for AOT Metal shader compilation.
//!
//! Compiles Metal shaders ahead of time using `xcrun -sdk macosx metal`.
//! The metal compiler acts as both compiler (-c → .air) and linker (→ .metallib).
//! If the Metal toolchain is unavailable, falls back gracefully — runtime
//! compilation still works via `newLibraryWithSource`.

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Declare custom cfg so check-cfg doesn't warn
    println!("cargo:rustc-check-cfg=cfg(metal_aot)");
    println!("cargo:rustc-check-cfg=cfg(zkf_metal_public_artifact)");
    println!("cargo:rerun-if-env-changed=ZKF_PUBLIC_ARTIFACT_BUILD");

    let public_artifact_build = env_flag("ZKF_PUBLIC_ARTIFACT_BUILD");
    if public_artifact_build {
        println!("cargo:rustc-cfg=zkf_metal_public_artifact");
    }

    // Only compile shaders on macOS
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let shader_dir = Path::new("src/shaders");

    // Verify the metal compiler actually works (xcrun -sdk macosx metal --version)
    let version_check = Command::new("xcrun")
        .args(["-sdk", "macosx", "metal", "--version"])
        .output();
    let metal_compiler_version = version_check
        .as_ref()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .replace('\n', " | ")
        })
        .unwrap_or_default();
    match version_check {
        Ok(o) if o.status.success() => {
            let ver = String::from_utf8_lossy(&o.stdout);
            eprintln!("[zkf-metal build.rs] Metal compiler: {}", ver.trim());
        }
        _ => {
            if public_artifact_build {
                panic!(
                    "ZKF public artifact build requires the Apple Metal compiler; runtime shader compilation is not allowed"
                );
            }
            println!(
                "cargo:warning=Metal compiler not available — using runtime shader compilation"
            );
            return;
        }
    }
    println!("cargo:rustc-env=ZKF_METAL_COMPILER_VERSION={metal_compiler_version}");
    println!(
        "cargo:rustc-env=ZKF_METAL_XCODE_VERSION={}",
        command_stdout(&["xcodebuild", "-version"]).replace('\n', " | ")
    );
    println!(
        "cargo:rustc-env=ZKF_METAL_SDK_VERSION={}",
        command_stdout(&["xcrun", "--sdk", "macosx", "--show-sdk-version"])
    );

    let mut all_ok = true;

    // Library 1: Main shaders (NTT + Poseidon2 + field helpers + poly + FRI + constraints)
    let main_sources = [
        "field_goldilocks.metal",
        "field_babybear.metal",
        "field_bn254_fr.metal",
        "ntt_radix2.metal",
        "ntt_bn254.metal",
        "ntt_radix2_batch.metal",
        "poseidon2.metal",
        "batch_field_ops.metal",
        "poly_ops.metal",
        "fri.metal",
        "constraint_eval.metal",
    ];
    if let Some(path) = compile_metallib(
        shader_dir,
        &main_sources,
        &out_dir,
        "main",
        true, // prepend metal_stdlib header
    ) {
        println!("cargo:rustc-env=METALLIB_MAIN={}", path.display());
        println!("cargo:rustc-env=METALLIB_MAIN_BASENAME=main.metallib");
        emit_metallib_digest("METALLIB_MAIN_SHA256", &path);
    } else {
        all_ok = false;
    }

    // Library 2: MSM shaders (separate due to duplicate struct definitions)
    let msm_sources = ["msm_bn254.metal", "msm_sort.metal", "msm_reduce.metal"];
    if let Some(path) = compile_metallib(
        shader_dir,
        &msm_sources,
        &out_dir,
        "msm",
        false, // msm_bn254.metal already has its own #include
    ) {
        println!("cargo:rustc-env=METALLIB_MSM={}", path.display());
        println!("cargo:rustc-env=METALLIB_MSM_BASENAME=msm.metallib");
        emit_metallib_digest("METALLIB_MSM_SHA256", &path);
    } else {
        all_ok = false;
    }

    // Library 2b: Pallas MSM shaders (separate due to duplicate kernel/type names)
    let pallas_msm_sources = ["msm_pallas.metal"];
    if let Some(path) = compile_metallib(
        shader_dir,
        &pallas_msm_sources,
        &out_dir,
        "msm_pallas",
        false,
    ) {
        println!("cargo:rustc-env=METALLIB_MSM_PALLAS={}", path.display());
        println!("cargo:rustc-env=METALLIB_MSM_PALLAS_BASENAME=msm_pallas.metallib");
        emit_metallib_digest("METALLIB_MSM_PALLAS_SHA256", &path);
    } else {
        all_ok = false;
    }

    // Library 2c: Vesta MSM shaders (separate due to duplicate kernel/type names)
    let vesta_msm_sources = ["msm_vesta.metal"];
    if let Some(path) =
        compile_metallib(shader_dir, &vesta_msm_sources, &out_dir, "msm_vesta", false)
    {
        println!("cargo:rustc-env=METALLIB_MSM_VESTA={}", path.display());
        println!("cargo:rustc-env=METALLIB_MSM_VESTA_BASENAME=msm_vesta.metallib");
        emit_metallib_digest("METALLIB_MSM_VESTA_SHA256", &path);
    } else {
        all_ok = false;
    }

    // Library 3: Hash shaders (SHA256 + Keccak256)
    let hash_sources = ["sha256.metal", "keccak256.metal"];
    if let Some(path) = compile_metallib(shader_dir, &hash_sources, &out_dir, "hash", true) {
        println!("cargo:rustc-env=METALLIB_HASH={}", path.display());
        println!("cargo:rustc-env=METALLIB_HASH_BASENAME=hash.metallib");
        emit_metallib_digest("METALLIB_HASH_SHA256", &path);
    } else {
        all_ok = false;
    }

    if all_ok {
        println!("cargo:rustc-cfg=metal_aot");
        eprintln!("[zkf-metal build.rs] All metallibs compiled successfully (AOT enabled)");
    } else {
        if public_artifact_build {
            panic!(
                "ZKF public artifact build requires complete AOT metallib generation; runtime shader compilation is disabled"
            );
        }
        println!(
            "cargo:warning=Some metallib compilations failed — using runtime shader compilation"
        );
    }

    // Re-run if any shader changes
    for entry in fs::read_dir(shader_dir).into_iter().flatten().flatten() {
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }
    println!("cargo:rerun-if-changed=build.rs");
}

fn compile_metallib(
    shader_dir: &Path,
    sources: &[&str],
    out_dir: &Path,
    lib_name: &str,
    prepend_header: bool,
) -> Option<PathBuf> {
    let combined_metal = out_dir.join(format!("{lib_name}.metal"));
    let air_path = out_dir.join(format!("{lib_name}.air"));
    let metallib_path = out_dir.join(format!("{lib_name}.metallib"));

    // Concatenate shader sources (matching runtime concatenation order)
    let mut combined = String::new();
    if prepend_header {
        combined.push_str("#include <metal_stdlib>\nusing namespace metal;\n\n");
    }
    for src_name in sources {
        let path = shader_dir.join(src_name);
        let content = fs::read_to_string(&path)
            .map_err(|e| {
                eprintln!(
                    "[zkf-metal build.rs] Failed to read {}: {e}",
                    path.display()
                )
            })
            .ok()?;
        if prepend_header {
            let cleaned = content
                .replace("#include <metal_stdlib>", "")
                .replace("using namespace metal;", "");
            combined.push_str(&cleaned);
        } else {
            combined.push_str(&content);
        }
        combined.push('\n');
    }
    fs::write(&combined_metal, &combined).ok()?;

    // Step 1: Compile .metal → .air
    let output = Command::new("xcrun")
        .args([
            "-sdk",
            "macosx",
            "metal",
            "-std=metal3.2",
            "-O2",
            "-Wno-unused-function",
            "-Wno-unused-variable",
            "-Wno-unused-const-variable",
            "-c",
            "-o",
        ])
        .arg(air_path.as_os_str())
        .arg(combined_metal.as_os_str())
        .output()
        .ok()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("cargo:warning=Failed to compile {lib_name}.metal to AIR: {stderr}");
        return None;
    }

    // Step 2: Link .air → .metallib (metal acts as linker without -c)
    let output = Command::new("xcrun")
        .args(["-sdk", "macosx", "metal", "-o"])
        .arg(metallib_path.as_os_str())
        .arg(air_path.as_os_str())
        .output()
        .ok()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("cargo:warning=Failed to link {lib_name}.metallib: {stderr}");
        return None;
    }

    eprintln!(
        "[zkf-metal build.rs] Compiled {lib_name}.metallib ({} bytes)",
        fs::metadata(&metallib_path).map(|m| m.len()).unwrap_or(0)
    );

    Some(metallib_path)
}

fn command_stdout(cmd: &[&str]) -> String {
    let Some((program, args)) = cmd.split_first() else {
        return String::new();
    };
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default()
}

fn emit_metallib_digest(env_name: &str, path: &Path) {
    if let Ok(bytes) = fs::read(path) {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        println!("cargo:rustc-env={env_name}={:x}", hasher.finalize());
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}
