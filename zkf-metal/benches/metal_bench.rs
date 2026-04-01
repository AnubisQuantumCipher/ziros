//! Benchmarks comparing CPU vs Metal GPU for MSM, NTT, and Poseidon2.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

#[cfg(target_os = "macos")]
mod metal_benches {
    use super::*;

    pub fn bench_msm(c: &mut Criterion) {
        use ark_bn254::{Fr, G1Affine};
        use ark_ff::UniformRand;
        use rand::thread_rng;
        use zkf_metal::msm::pippenger;

        let mut group = c.benchmark_group("MSM-BN254");

        for log_n in [14, 16, 18] {
            let n = 1usize << log_n;
            let mut rng = thread_rng();

            let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let bases: Vec<G1Affine> = (0..n).map(|_| G1Affine::rand(&mut rng)).collect();

            group.bench_with_input(
                BenchmarkId::new("cpu-pippenger", format!("2^{log_n}")),
                &n,
                |b, _| {
                    b.iter(|| pippenger::cpu_pippenger(&scalars, &bases));
                },
            );

            if let Some(ctx) = zkf_metal::global_context() {
                group.bench_with_input(
                    BenchmarkId::new("metal-pippenger", format!("2^{log_n}")),
                    &n,
                    |b, _| {
                        b.iter(|| {
                            pippenger::metal_msm(ctx, &scalars, &bases)
                                .unwrap_or_else(|| pippenger::cpu_pippenger(&scalars, &bases))
                        });
                    },
                );
            }
        }

        group.finish();
    }

    pub fn bench_ntt(c: &mut Criterion) {
        use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
        use p3_field::PrimeCharacteristicRing;
        use p3_goldilocks::Goldilocks;
        use p3_matrix::dense::RowMajorMatrix;

        let mut group = c.benchmark_group("NTT-Goldilocks");

        for log_n in [12, 14, 16, 18] {
            let n = 1usize << log_n;
            let values: Vec<Goldilocks> =
                (0..n as u64).map(|i| Goldilocks::from_u64(i + 1)).collect();

            group.bench_with_input(
                BenchmarkId::new("cpu-radix2", format!("2^{log_n}")),
                &n,
                |b, _| {
                    let cpu_dft = Radix2DitParallel::default();
                    b.iter(|| {
                        let mat = RowMajorMatrix::new(values.clone(), 1);
                        cpu_dft.dft_batch(mat)
                    });
                },
            );

            if let Some(metal_dft) = zkf_metal::ntt::p3_adapter::MetalDft::<Goldilocks>::new() {
                group.bench_with_input(
                    BenchmarkId::new("metal-ntt", format!("2^{log_n}")),
                    &n,
                    |b, _| {
                        b.iter(|| {
                            let mat = RowMajorMatrix::new(values.clone(), 1);
                            metal_dft.dft_batch(mat)
                        });
                    },
                );
            }
        }

        group.finish();
    }

    pub fn bench_poseidon2(c: &mut Criterion) {
        use p3_field::{PrimeCharacteristicRing, PrimeField64};
        use p3_goldilocks::Goldilocks;
        use p3_symmetric::Permutation;
        use zkf_metal::poseidon2::{MetalPoseidon2, goldilocks};

        let seed = 42u64;
        let (round_constants, n_ext, n_int) = goldilocks::flatten_round_constants(seed);

        let mut group = c.benchmark_group("Poseidon2-Goldilocks");

        for n_perms in [1_000, 10_000, 100_000] {
            let states: Vec<u64> = (0..n_perms * 16)
                .map(|i| (i as u64) % ((1u64 << 63) - 1))
                .collect();

            group.bench_with_input(
                BenchmarkId::new("cpu", format!("{n_perms}")),
                &n_perms,
                |b, _| {
                    use rand09::SeedableRng;
                    let mut rng = rand09::rngs::SmallRng::seed_from_u64(seed);
                    use p3_goldilocks::Poseidon2Goldilocks;
                    let cpu_perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);

                    b.iter(|| {
                        let mut s = states.clone();
                        for perm_idx in 0..n_perms {
                            let offset = perm_idx * 16;
                            let mut state: [Goldilocks; 16] =
                                std::array::from_fn(|i| Goldilocks::from_u64(s[offset + i]));
                            cpu_perm.permute_mut(&mut state);
                            for i in 0..16 {
                                s[offset + i] = state[i].as_canonical_u64();
                            }
                        }
                    });
                },
            );

            if let Some(metal) = MetalPoseidon2::new() {
                group.bench_with_input(
                    BenchmarkId::new("metal", format!("{n_perms}")),
                    &n_perms,
                    |b, _| {
                        b.iter(|| {
                            let mut s = states.clone();
                            metal.batch_permute_goldilocks(&mut s, &round_constants, n_ext, n_int);
                        });
                    },
                );
            }
        }

        group.finish();
    }
}

#[cfg(target_os = "macos")]
criterion_group!(
    benches,
    metal_benches::bench_msm,
    metal_benches::bench_ntt,
    metal_benches::bench_poseidon2,
);

#[cfg(not(target_os = "macos"))]
fn no_metal(_c: &mut Criterion) {
    eprintln!("Metal benchmarks are only available on macOS");
}

#[cfg(not(target_os = "macos"))]
criterion_group!(benches, no_metal);

criterion_main!(benches);
