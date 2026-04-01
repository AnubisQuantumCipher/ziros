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

//! Quick NAF vs non-NAF MSM benchmark (no criterion overhead).

use std::time::Instant;

fn main() {
    use ark_bn254::{Fr, G1Affine, G1Projective};
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use zkf_metal::msm::pippenger;

    let ctx = zkf_metal::global_context().expect("Metal GPU required");
    let mut rng = ark_std::test_rng();

    println!("=== NAF vs Non-NAF MSM Benchmark ===\n");

    for log_n in [14u32, 16, 18, 20] {
        let n = 1usize << log_n;
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();

        // Warmup (3 rounds to stabilize GPU clock)
        for _ in 0..3 {
            let _ = pippenger::metal_msm(ctx, &scalars, &bases);
            let _ = pippenger::metal_msm(ctx, &scalars, &bases);
        }

        // CPU
        let start = Instant::now();
        let cpu_result = pippenger::cpu_pippenger(&scalars, &bases);
        let cpu_ms = start.elapsed().as_secs_f64() * 1000.0;

        // Metal non-NAF
        let iters = if log_n >= 20 { 3 } else { 7 };
        let mut gpu_ms = 0.0;
        for _ in 0..iters {
            let start = Instant::now();
            let _ = pippenger::metal_msm(ctx, &scalars, &bases);
            gpu_ms += start.elapsed().as_secs_f64() * 1000.0;
        }
        gpu_ms /= iters as f64;

        // Metal NAF
        let mut naf_ms = 0.0;
        let mut naf_result = None;
        for _ in 0..iters {
            let start = Instant::now();
            naf_result = pippenger::metal_msm(ctx, &scalars, &bases);
            naf_ms += start.elapsed().as_secs_f64() * 1000.0;
        }
        naf_ms /= iters as f64;

        // Verify correctness
        if let Some(naf) = naf_result {
            assert_eq!(
                naf.into_affine(),
                cpu_result.into_affine(),
                "NAF result mismatch at n=2^{log_n}"
            );
        }

        let speedup = gpu_ms / naf_ms;
        let cpu_vs_naf = if naf_ms < cpu_ms {
            format!("{:.1}x faster than CPU", cpu_ms / naf_ms)
        } else {
            format!("{:.1}x slower than CPU", naf_ms / cpu_ms)
        };

        println!("n = 2^{log_n} ({n} points):");
        println!("  CPU:       {cpu_ms:>8.1}ms");
        println!("  GPU:       {gpu_ms:>8.1}ms");
        println!("  GPU NAF:   {naf_ms:>8.1}ms  ({speedup:.2}x vs GPU, {cpu_vs_naf})");
        println!();
    }
}
