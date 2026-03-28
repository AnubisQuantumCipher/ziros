use crate::audited_backend::{audited_witness_for_proving, build_audited_compiled_program};
use crate::blackbox_gadgets;
use crate::blackbox_native::{supported_blackbox_ops, validate_blackbox_constraints};
use crate::metal_runtime::append_backend_runtime_metadata;
use crate::range_decomposition;
use crate::{BackendEngine, BoundedStringCache, bounded_cache_limit};
use halo2_proofs_pse::SerdeFormat;
use halo2_proofs_pse::arithmetic::Field;
use halo2_proofs_pse::circuit::{Layouter, Region, SimpleFloorPlanner, Value};
use halo2_proofs_pse::halo2curves::bls12381::{Bls12381, Fr, G1Affine};
use halo2_proofs_pse::plonk::{
    Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Instance, Selector,
    TableColumn,
};
use halo2_proofs_pse::poly::Rotation;
use halo2_proofs_pse::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs_pse::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs_pse::poly::kzg::strategy::SingleStrategy;
use halo2_proofs_pse::transcript::{TranscriptReadBuffer, TranscriptWriterBuffer};
use num_bigint::BigInt;
use once_cell::sync::Lazy;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use zkf_core::{
    BackendCapabilities, BackendKind, BackendMode, CompiledProgram, Constraint, Expr, FieldElement,
    FieldId, Program, ProofArtifact, Signal, Visibility, Witness, ZkfError, ZkfResult,
    check_constraints, collect_public_inputs,
};

const HALO2_BLS_SETUP_BLOB_PARAMS_VERSION: u8 = 2;
const HALO2_BLS_SETUP_BLOB_K_VERSION: u8 = 3;
const HALO2_BLS_MAX_RANGE_BITS: u32 = 16;

/// Halo2 backend targeting BLS12-381 with KZG polynomial commitment.
///
/// Uses the PSE halo2 fork (v0.4.0) with `ParamsKZG<Bls12381>`, SHPLONK
/// multiopen scheme, and real BLS12-381 scalar field arithmetic.
pub struct Halo2Bls12381Backend;

#[derive(Clone)]
struct Halo2BlsSetupBundle {
    params: Arc<ParamsKZG<Bls12381>>,
    pk: halo2_proofs_pse::plonk::ProvingKey<G1Affine>,
    vk: halo2_proofs_pse::plonk::VerifyingKey<G1Affine>,
    vk_fingerprint: Vec<u8>,
}

static HALO2_BLS_SETUP_CACHE: Lazy<Mutex<BoundedStringCache<Arc<Halo2BlsSetupBundle>>>> =
    Lazy::new(|| {
        Mutex::new(BoundedStringCache::new(bounded_cache_limit(
            "ZKF_HALO2_BLS_SETUP_CACHE_LIMIT",
            2,
        )))
    });

static HALO2_BLS_PARAMS_CACHE: Lazy<Mutex<BoundedStringCache<Arc<ParamsKZG<Bls12381>>>>> =
    Lazy::new(|| {
        Mutex::new(BoundedStringCache::new(bounded_cache_limit(
            "ZKF_HALO2_BLS_PARAMS_CACHE_LIMIT",
            2,
        )))
    });

#[derive(Debug, Clone)]
struct Halo2BlsConfig {
    signal: Column<Advice>,
    op_a: Column<Advice>,
    op_b: Column<Advice>,
    op_out: Column<Advice>,
    op_aux: Column<Advice>,
    range_value: Column<Advice>,
    instance: Column<Instance>,
    q_add: Selector,
    q_sub: Selector,
    q_mul: Selector,
    q_div: Selector,
    q_bool: Selector,
    range_selectors: Vec<Selector>,
    range_tables: Vec<TableColumn>,
}

#[derive(Clone)]
struct Halo2BlsCircuit {
    program: Program,
    signal_values: HashMap<String, Fr>,
}

impl Halo2BlsCircuit {
    fn without_witness(program: Program) -> ZkfResult<Self> {
        let signal_values = build_signal_values(&program, None)?;
        Ok(Self {
            program,
            signal_values,
        })
    }

    fn with_witness(program: Program, witness: &Witness) -> ZkfResult<Self> {
        let signal_values = build_signal_values(&program, Some(witness))?;
        Ok(Self {
            program,
            signal_values,
        })
    }
}

impl Circuit<Fr> for Halo2BlsCircuit {
    type Config = Halo2BlsConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            program: self.program.clone(),
            signal_values: build_signal_values(&self.program, None).unwrap_or_default(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let signal = meta.advice_column();
        let op_a = meta.advice_column();
        let op_b = meta.advice_column();
        let op_out = meta.advice_column();
        let op_aux = meta.advice_column();
        let range_value = meta.advice_column();
        let instance = meta.instance_column();

        meta.enable_equality(signal);
        meta.enable_equality(op_a);
        meta.enable_equality(op_b);
        meta.enable_equality(op_out);
        meta.enable_equality(op_aux);
        meta.enable_equality(range_value);
        meta.enable_equality(instance);

        let q_add = meta.selector();
        let q_sub = meta.selector();
        let q_mul = meta.selector();
        let q_div = meta.selector();
        let q_bool = meta.selector();

        meta.create_gate("zkf_bls_add", |meta| {
            let q = meta.query_selector(q_add);
            let a = meta.query_advice(op_a, Rotation::cur());
            let b = meta.query_advice(op_b, Rotation::cur());
            let out = meta.query_advice(op_out, Rotation::cur());
            vec![q * (a + b - out)]
        });

        meta.create_gate("zkf_bls_sub", |meta| {
            let q = meta.query_selector(q_sub);
            let a = meta.query_advice(op_a, Rotation::cur());
            let b = meta.query_advice(op_b, Rotation::cur());
            let out = meta.query_advice(op_out, Rotation::cur());
            vec![q * (a - b - out)]
        });

        meta.create_gate("zkf_bls_mul", |meta| {
            let q = meta.query_selector(q_mul);
            let a = meta.query_advice(op_a, Rotation::cur());
            let b = meta.query_advice(op_b, Rotation::cur());
            let out = meta.query_advice(op_out, Rotation::cur());
            vec![q * (a * b - out)]
        });

        meta.create_gate("zkf_bls_div", |meta| {
            let q = meta.query_selector(q_div);
            let a = meta.query_advice(op_a, Rotation::cur());
            let b = meta.query_advice(op_b, Rotation::cur());
            let out = meta.query_advice(op_out, Rotation::cur());
            let inv = meta.query_advice(op_aux, Rotation::cur());
            let one = Expression::Constant(Fr::ONE);
            vec![q.clone() * (a - b.clone() * out), q * (b * inv - one)]
        });

        meta.create_gate("zkf_bls_bool", |meta| {
            let q = meta.query_selector(q_bool);
            let s = meta.query_advice(op_a, Rotation::cur());
            let one = Expression::Constant(Fr::ONE);
            vec![q * s.clone() * (one - s)]
        });

        let mut range_selectors = Vec::new();
        let mut range_tables = Vec::new();

        for bit_idx in 0..HALO2_BLS_MAX_RANGE_BITS {
            let selector = meta.complex_selector();
            let table = meta.lookup_table_column();

            meta.lookup(format!("zkf_bls_range_{bit_idx}"), |meta| {
                let q = meta.query_selector(selector);
                let v = meta.query_advice(range_value, Rotation::cur());
                vec![(q * v, table)]
            });

            range_selectors.push(selector);
            range_tables.push(table);
        }

        Halo2BlsConfig {
            signal,
            op_a,
            op_b,
            op_out,
            op_aux,
            range_value,
            instance,
            q_add,
            q_sub,
            q_mul,
            q_div,
            q_bool,
            range_selectors,
            range_tables,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), ErrorFront> {
        let used_range_bits = max_range_bits(&self.program).map_err(|_| ErrorFront::Synthesis)?;
        if used_range_bits > 0 {
            layouter.assign_table(
                || "zkf_bls_range_tables",
                |mut table| {
                    let max_rows = 1usize << used_range_bits;
                    for bits in 1..=used_range_bits {
                        let table_col = config.range_tables[(bits - 1) as usize];
                        let value_count = 1usize << bits;
                        for row in 0..max_rows {
                            table.assign_cell(
                                || format!("bls_range_table_{bits}[{row}]"),
                                table_col,
                                row,
                                || Value::known(Fr::from((row % value_count) as u64)),
                            )?;
                        }
                    }
                    Ok(())
                },
            )?;
        }

        let public_cells = layouter.assign_region(
            || "zkf_bls_main",
            |mut region| {
                let mut next_row = 0usize;
                let mut signal_cells = HashMap::new();
                let mut public_cells = Vec::new();

                for signal in &self.program.signals {
                    let value = self.signal_value(signal);
                    let cell = region.assign_advice(
                        || format!("bls_signal_{}", signal.name),
                        config.signal,
                        next_row,
                        || value,
                    )?;

                    if signal.visibility == Visibility::Public {
                        public_cells.push(cell.clone());
                    }

                    signal_cells.insert(signal.name.clone(), cell);
                    next_row += 1;
                }

                for constraint in &self.program.constraints {
                    match constraint {
                        Constraint::Equal { lhs, rhs, .. } => {
                            let lhs_cell = assign_expr(
                                lhs,
                                &config,
                                &signal_cells,
                                &mut region,
                                &mut next_row,
                            )?;
                            let rhs_cell = assign_expr(
                                rhs,
                                &config,
                                &signal_cells,
                                &mut region,
                                &mut next_row,
                            )?;
                            region.constrain_equal(lhs_cell.cell(), rhs_cell.cell())?;
                        }
                        Constraint::Boolean { signal, .. } => {
                            let signal_cell =
                                signal_cells.get(signal).ok_or(ErrorFront::Synthesis)?;
                            let row = next_row;
                            next_row += 1;

                            let copied = copy_cell(
                                &mut region,
                                signal_cell,
                                config.op_a,
                                row,
                                "bls_bool_copy",
                            )?;
                            config.q_bool.enable(&mut region, row)?;
                            let _ = copied;
                        }
                        Constraint::Range { signal, bits, .. } => {
                            if *bits == 0 || *bits > HALO2_BLS_MAX_RANGE_BITS {
                                return Err(ErrorFront::Synthesis);
                            }

                            let signal_cell =
                                signal_cells.get(signal).ok_or(ErrorFront::Synthesis)?;
                            let row = next_row;
                            next_row += 1;

                            let copied = copy_cell(
                                &mut region,
                                signal_cell,
                                config.range_value,
                                row,
                                "bls_range_copy",
                            )?;
                            config.range_selectors[(*bits - 1) as usize]
                                .enable(&mut region, row)?;
                            let _ = copied;
                        }
                        Constraint::BlackBox { .. } => {}
                        Constraint::Lookup { .. } => {
                            return Err(ErrorFront::Synthesis);
                        }
                    }
                }

                Ok(public_cells)
            },
        )?;

        for (index, cell) in public_cells.into_iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, index)?;
        }

        Ok(())
    }
}

impl Halo2BlsCircuit {
    fn signal_value(&self, signal: &Signal) -> Value<Fr> {
        if let Some(value) = self.signal_values.get(&signal.name) {
            Value::known(*value)
        } else {
            Value::unknown()
        }
    }
}

impl BackendEngine for Halo2Bls12381Backend {
    fn kind(&self) -> BackendKind {
        BackendKind::Halo2Bls12381
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::Halo2Bls12381,
            mode: BackendMode::Native,
            trusted_setup: true,
            recursion_ready: true,
            transparent_setup: false,
            zkvm_mode: false,
            network_target: None,
            supported_blackbox_ops: supported_blackbox_ops(),
            supported_constraint_kinds: vec![
                "equal".to_string(),
                "boolean".to_string(),
                "range".to_string(),
                "blackbox".to_string(),
            ],
            native_profiles: vec!["kzg".to_string(), "trusted_setup".to_string()],
            notes: format!(
                "PLONK+KZG on BLS12-381 via PSE halo2 fork. Real BLS12-381 Fr field, \
                 SHPLONK multiopen, deterministic trusted setup. Range constraints wider than \
                 {HALO2_BLS_MAX_RANGE_BITS} bits are lowered into \
                 {HALO2_BLS_MAX_RANGE_BITS}-bit lookup chunks automatically."
            ),
        }
    }

    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram> {
        crate::with_serialized_heavy_backend_test(|| {
            if program.field != FieldId::Bls12_381 {
                return Err(ZkfError::UnsupportedBackend {
                    backend: self.kind().to_string(),
                    message: format!(
                        "backend 'halo2-bls12-381' requires Bls12_381 circuits; got {}. Use backend 'halo2' for PastaFp circuits.",
                        program.field
                    ),
                });
            }

            let raw_program = program.clone();
            let program = &blackbox_gadgets::lower_blackbox_program(program)?;
            let program = &blackbox_gadgets::lookup_lowering::lower_lookup_constraints(program)?;
            let (lowered_program, range_decompositions) =
                range_decomposition::lower_large_range_constraints(
                    program,
                    HALO2_BLS_MAX_RANGE_BITS,
                    "halo2_bls",
                )?;
            let program = &lowered_program;
            ensure_supported_program(program)?;

            let max_bits = max_range_bits(program)?;
            let k = estimate_k(program, max_bits)?;

            let mut compiled =
                build_audited_compiled_program(self.kind(), &raw_program, program.clone())?;
            compiled.compiled_data = Some(pack_params_blob(k));
            range_decomposition::write_range_decomposition_metadata(
                &mut compiled.metadata,
                &range_decompositions,
            )?;
            compiled
                .metadata
                .insert("curve".to_string(), "bls12-381".to_string());
            compiled
                .metadata
                .insert("field".to_string(), "bls12-381-fr".to_string());
            compiled
                .metadata
                .insert("commitment".to_string(), "kzg".to_string());
            compiled.metadata.insert("k".to_string(), k.to_string());
            compiled
                .metadata
                .insert("max_range_bits_used".to_string(), max_bits.to_string());

            crate::metal_runtime::append_trust_metadata(
                &mut compiled.metadata,
                "native",
                "cryptographic",
                1,
            );
            Ok(compiled)
        })
    }

    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
        crate::with_serialized_heavy_backend_test(|| {
            if compiled.backend != self.kind() {
                return Err(ZkfError::InvalidArtifact(format!(
                    "compiled backend is {}, expected {}",
                    compiled.backend,
                    self.kind()
                )));
            }

            ensure_supported_program(&compiled.program)?;
            let enriched = audited_witness_for_proving(self.kind(), compiled, witness)?;
            let enriched = range_decomposition::enrich_range_witness(
                &compiled.program,
                &compiled.metadata,
                &enriched,
            )?;
            check_constraints(&compiled.program, &enriched)?;
            validate_blackbox_constraints(self.kind(), &compiled.program, &enriched)?;

            let setup = get_or_build_setup(compiled)?;
            let circuit = Halo2BlsCircuit::with_witness(compiled.program.clone(), &enriched)?;

            let public_inputs = collect_public_inputs(&compiled.program, &enriched)?;
            let public_inputs_fr = public_inputs
                .iter()
                .map(parse_bls12_fr)
                .collect::<ZkfResult<Vec<_>>>()?;

            let instances = vec![vec![public_inputs_fr]];
            let circuits = vec![circuit];

            let mut transcript = halo2_proofs_pse::transcript::Blake2bWrite::<
                _,
                G1Affine,
                halo2_proofs_pse::transcript::Challenge255<G1Affine>,
            >::init(vec![]);

            halo2_proofs_pse::plonk::create_proof::<
                KZGCommitmentScheme<Bls12381>,
                ProverSHPLONK<_>,
                _,
                _,
                _,
                _,
            >(
                setup.params.as_ref(),
                &setup.pk,
                &circuits,
                &instances,
                rand::rngs::OsRng,
                &mut transcript,
            )
            .map_err(|err| ZkfError::Backend(format!("halo2-bls create_proof failed: {err:?}")))?;

            let proof_bytes = transcript.finalize();

            let mut metadata = BTreeMap::new();
            metadata.insert("curve".to_string(), "bls12-381".to_string());
            metadata.insert("commitment".to_string(), "kzg".to_string());
            metadata.insert("scheme".to_string(), "shplonk".to_string());
            append_backend_runtime_metadata(&mut metadata, self.kind());

            Ok(ProofArtifact {
                backend: self.kind(),
                program_digest: compiled.program_digest.clone(),
                proof: proof_bytes,
                verification_key: setup.vk_fingerprint.clone(),
                public_inputs,
                metadata,
                security_profile: None,
                hybrid_bundle: None,
                credential_bundle: None,
                archive_metadata: None,
            })
        })
    }

    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
        if compiled.backend != self.kind() {
            return Err(ZkfError::InvalidArtifact(format!(
                "compiled backend is {}, expected {}",
                compiled.backend,
                self.kind()
            )));
        }

        if artifact.backend != self.kind() {
            return Err(ZkfError::InvalidArtifact(format!(
                "artifact backend is {}, expected {}",
                artifact.backend,
                self.kind()
            )));
        }

        if artifact.program_digest != compiled.program_digest {
            return Err(ZkfError::ProgramMismatch {
                expected: compiled.program_digest.clone(),
                found: artifact.program_digest.clone(),
            });
        }

        ensure_supported_program(&compiled.program)?;
        let setup = get_or_build_setup(compiled)?;

        if artifact.verification_key != setup.vk_fingerprint {
            return Err(ZkfError::InvalidArtifact(
                "halo2-bls verification key fingerprint mismatch".to_string(),
            ));
        }

        let public_inputs_fr = artifact
            .public_inputs
            .iter()
            .map(parse_bls12_fr)
            .collect::<ZkfResult<Vec<_>>>()?;

        let instances = vec![vec![public_inputs_fr]];

        let verifier_params = setup.params.verifier_params();
        let strategy = SingleStrategy::new(&verifier_params);
        let mut transcript = halo2_proofs_pse::transcript::Blake2bRead::<
            _,
            G1Affine,
            halo2_proofs_pse::transcript::Challenge255<G1Affine>,
        >::init(artifact.proof.as_slice());

        halo2_proofs_pse::plonk::verify_proof::<
            KZGCommitmentScheme<Bls12381>,
            VerifierSHPLONK<_>,
            _,
            _,
            _,
        >(
            &verifier_params,
            &setup.vk,
            strategy,
            &instances,
            &mut transcript,
        )
        .map(|_| true)
        .map_err(|err| ZkfError::Backend(format!("halo2-bls verify_proof failed: {err:?}")))
    }
}

fn assign_expr(
    expr: &Expr,
    config: &Halo2BlsConfig,
    signal_cells: &HashMap<String, halo2_proofs_pse::circuit::AssignedCell<Fr, Fr>>,
    region: &mut Region<'_, Fr>,
    next_row: &mut usize,
) -> Result<halo2_proofs_pse::circuit::AssignedCell<Fr, Fr>, ErrorFront> {
    match expr {
        Expr::Const(value) => {
            let row = *next_row;
            *next_row += 1;
            let constant = bigint_to_bls_fr(
                &value
                    .normalized_bigint(FieldId::Bls12_381)
                    .map_err(|_| ErrorFront::Synthesis)?,
            )
            .map_err(|_| ErrorFront::Synthesis)?;
            region.assign_advice(
                || format!("bls_const_{row}"),
                config.op_a,
                row,
                || Value::known(constant),
            )
        }
        Expr::Signal(name) => signal_cells.get(name).cloned().ok_or(ErrorFront::Synthesis),
        Expr::Add(items) => {
            if items.is_empty() {
                let zero = Expr::Const(FieldElement::from_i64(0));
                return assign_expr(&zero, config, signal_cells, region, next_row);
            }

            let mut iter = items.iter();
            let first = iter.next().ok_or(ErrorFront::Synthesis)?;
            let mut acc = assign_expr(first, config, signal_cells, region, next_row)?;

            for item in iter {
                let rhs = assign_expr(item, config, signal_cells, region, next_row)?;
                acc = assign_binary_op(BinaryOp::Add, config, region, next_row, &acc, &rhs)?;
            }

            Ok(acc)
        }
        Expr::Sub(a, b) => {
            let lhs = assign_expr(a, config, signal_cells, region, next_row)?;
            let rhs = assign_expr(b, config, signal_cells, region, next_row)?;
            assign_binary_op(BinaryOp::Sub, config, region, next_row, &lhs, &rhs)
        }
        Expr::Mul(a, b) => {
            let lhs = assign_expr(a, config, signal_cells, region, next_row)?;
            let rhs = assign_expr(b, config, signal_cells, region, next_row)?;
            assign_binary_op(BinaryOp::Mul, config, region, next_row, &lhs, &rhs)
        }
        Expr::Div(a, b) => {
            let lhs = assign_expr(a, config, signal_cells, region, next_row)?;
            let rhs = assign_expr(b, config, signal_cells, region, next_row)?;
            assign_binary_op(BinaryOp::Div, config, region, next_row, &lhs, &rhs)
        }
    }
}

#[derive(Copy, Clone)]
enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
}

fn assign_binary_op(
    op: BinaryOp,
    config: &Halo2BlsConfig,
    region: &mut Region<'_, Fr>,
    next_row: &mut usize,
    lhs: &halo2_proofs_pse::circuit::AssignedCell<Fr, Fr>,
    rhs: &halo2_proofs_pse::circuit::AssignedCell<Fr, Fr>,
) -> Result<halo2_proofs_pse::circuit::AssignedCell<Fr, Fr>, ErrorFront> {
    let row = *next_row;
    *next_row += 1;

    let a = copy_cell(region, lhs, config.op_a, row, "bls_lhs_copy")?;
    let b = copy_cell(region, rhs, config.op_b, row, "bls_rhs_copy")?;

    let a_value = a.value().copied();
    let b_value = b.value().copied();

    let (out_value, aux_value) = match op {
        BinaryOp::Add => (
            a_value.zip(b_value).map(|(x, y)| x + y),
            Value::known(Fr::ZERO),
        ),
        BinaryOp::Sub => (
            a_value.zip(b_value).map(|(x, y)| x - y),
            Value::known(Fr::ZERO),
        ),
        BinaryOp::Mul => (
            a_value.zip(b_value).map(|(x, y)| x * y),
            Value::known(Fr::ZERO),
        ),
        BinaryOp::Div => {
            let inv = b_value.map(|v| Option::<Fr>::from(v.invert()).unwrap_or(Fr::ZERO));
            (a_value.zip(inv).map(|(x, inv)| x * inv), inv)
        }
    };

    let out = region.assign_advice(
        || format!("bls_op_out_{row}"),
        config.op_out,
        row,
        || out_value,
    )?;

    region.assign_advice(
        || format!("bls_op_aux_{row}"),
        config.op_aux,
        row,
        || aux_value,
    )?;

    match op {
        BinaryOp::Add => config.q_add.enable(region, row)?,
        BinaryOp::Sub => config.q_sub.enable(region, row)?,
        BinaryOp::Mul => config.q_mul.enable(region, row)?,
        BinaryOp::Div => config.q_div.enable(region, row)?,
    }

    Ok(out)
}

fn copy_cell(
    region: &mut Region<'_, Fr>,
    source: &halo2_proofs_pse::circuit::AssignedCell<Fr, Fr>,
    column: Column<Advice>,
    row: usize,
    label: &'static str,
) -> Result<halo2_proofs_pse::circuit::AssignedCell<Fr, Fr>, ErrorFront> {
    let copied = region.assign_advice(
        || format!("{label}_{row}"),
        column,
        row,
        || source.value().copied(),
    )?;
    region.constrain_equal(source.cell(), copied.cell())?;
    Ok(copied)
}

fn ensure_supported_program(program: &Program) -> ZkfResult<()> {
    if program.field != FieldId::Bls12_381 {
        return Err(ZkfError::UnsupportedBackend {
            backend: BackendKind::Halo2Bls12381.to_string(),
            message: format!(
                "backend 'halo2-bls12-381' requires Bls12_381 circuits; got {}. Use backend 'halo2' for PastaFp circuits.",
                program.field
            ),
        });
    }

    let max_bits = max_range_bits(program)?;
    if max_bits > HALO2_BLS_MAX_RANGE_BITS {
        return Err(ZkfError::UnsupportedBackend {
            backend: BackendKind::Halo2Bls12381.to_string(),
            message: format!(
                "range bits {} exceed halo2-bls backend limit {}",
                max_bits, HALO2_BLS_MAX_RANGE_BITS
            ),
        });
    }
    Ok(())
}

fn max_range_bits(program: &Program) -> ZkfResult<u32> {
    let mut max_bits = 0u32;
    for constraint in &program.constraints {
        if let Constraint::Range { bits, .. } = constraint {
            if *bits == 0 {
                return Err(ZkfError::UnsupportedBackend {
                    backend: BackendKind::Halo2Bls12381.to_string(),
                    message: "range bits must be >= 1".to_string(),
                });
            }
            max_bits = max_bits.max(*bits);
        }
    }
    Ok(max_bits)
}

fn estimate_k(program: &Program, max_range_bits: u32) -> ZkfResult<u32> {
    let mut main_rows = program.signals.len() + 16;

    for constraint in &program.constraints {
        match constraint {
            Constraint::Equal { lhs, rhs, .. } => {
                main_rows += expr_rows(lhs);
                main_rows += expr_rows(rhs);
                main_rows += 1;
            }
            Constraint::Boolean { .. } | Constraint::Range { .. } => {
                main_rows += 1;
            }
            Constraint::BlackBox { .. } => {}
            Constraint::Lookup { .. } => {
                return Err(ZkfError::Backend(
                    "Lookup constraint must be lowered before synthesis; call lower_lookup_constraints() first".to_string(),
                ));
            }
        }
    }

    let table_rows = if max_range_bits == 0 {
        0
    } else {
        1usize << max_range_bits
    };
    let required_rows = main_rows.max(table_rows) + 64;
    let k = ceil_log2(required_rows as u64)
        .max(max_range_bits.saturating_add(2))
        .max(12);

    if k > 22 {
        return Err(ZkfError::UnsupportedBackend {
            backend: BackendKind::Halo2Bls12381.to_string(),
            message: format!("estimated circuit requires k={k}, exceeds safety bound 22"),
        });
    }

    Ok(k)
}

fn expr_rows(expr: &Expr) -> usize {
    match expr {
        Expr::Const(_) => 1,
        Expr::Signal(_) => 0,
        Expr::Add(items) => {
            if items.is_empty() {
                1
            } else {
                items.iter().map(expr_rows).sum::<usize>() + items.len().saturating_sub(1)
            }
        }
        Expr::Sub(a, b) | Expr::Mul(a, b) | Expr::Div(a, b) => 1 + expr_rows(a) + expr_rows(b),
    }
}

fn ceil_log2(value: u64) -> u32 {
    if value <= 1 {
        return 0;
    }
    let mut n = value - 1;
    let mut bits = 0u32;
    while n > 0 {
        n >>= 1;
        bits += 1;
    }
    bits
}

fn build_signal_values(
    program: &Program,
    witness: Option<&Witness>,
) -> ZkfResult<HashMap<String, Fr>> {
    let mut out = HashMap::new();

    for signal in &program.signals {
        if let Some(constant) = &signal.constant {
            out.insert(signal.name.clone(), parse_bls12_fr(constant)?);
        }
    }

    if let Some(witness) = witness {
        for (name, value) in &witness.values {
            out.insert(name.clone(), parse_bls12_fr(value)?);
        }
    }

    Ok(out)
}

/// Parse a FieldElement as a real BLS12-381 scalar field element.
fn parse_bls12_fr(value: &FieldElement) -> ZkfResult<Fr> {
    let normalized = value.normalized_bigint(FieldId::Bls12_381)?;
    bigint_to_bls_fr(&normalized)
}

fn bigint_to_bls_fr(value: &BigInt) -> ZkfResult<Fr> {
    let digits = value.to_str_radix(10);
    let mut acc = Fr::ZERO;

    for byte in digits.bytes() {
        let digit = match byte {
            b'0'..=b'9' => (byte - b'0') as u64,
            _ => {
                return Err(ZkfError::ParseField {
                    value: digits.clone(),
                });
            }
        };
        acc = acc * Fr::from(10u64) + Fr::from(digit);
    }

    Ok(acc)
}

fn derive_setup_seed(k: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-halo2-bls12381-kzg-setup-v3:");
    hasher.update(k.to_le_bytes());
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    seed
}

fn cache_insert(program_digest: String, bundle: Arc<Halo2BlsSetupBundle>) {
    if let Ok(mut cache) = HALO2_BLS_SETUP_CACHE.lock() {
        cache.insert(program_digest, bundle);
    }
}

#[cfg(test)]
pub(crate) fn clear_test_setup_cache() {
    if let Ok(mut cache) = HALO2_BLS_SETUP_CACHE.lock() {
        cache.clear();
    }
    if let Ok(mut cache) = HALO2_BLS_PARAMS_CACHE.lock() {
        cache.clear();
    }
}

fn get_or_build_setup(compiled: &CompiledProgram) -> ZkfResult<Arc<Halo2BlsSetupBundle>> {
    if let Ok(mut cache) = HALO2_BLS_SETUP_CACHE.lock()
        && let Some(bundle) = cache.get_cloned(&compiled.program_digest)
    {
        return Ok(bundle);
    }

    let blob = compiled
        .compiled_data
        .as_deref()
        .ok_or(ZkfError::MissingCompiledData)?;
    let params = load_params_from_blob(blob)?;

    let circuit = Halo2BlsCircuit::without_witness(compiled.program.clone())?;
    let vk = halo2_proofs_pse::plonk::keygen_vk(params.as_ref(), &circuit)
        .map_err(|err| ZkfError::Backend(format!("halo2-bls keygen_vk failed: {err:?}")))?;
    let pk = halo2_proofs_pse::plonk::keygen_pk(params.as_ref(), vk.clone(), &circuit)
        .map_err(|err| ZkfError::Backend(format!("halo2-bls keygen_pk failed: {err:?}")))?;

    let bundle = Arc::new(Halo2BlsSetupBundle {
        params,
        pk,
        vk: vk.clone(),
        vk_fingerprint: vk_fingerprint(&vk),
    });

    cache_insert(compiled.program_digest.clone(), bundle.clone());
    Ok(bundle)
}

fn params_for_k(k: u32) -> Arc<ParamsKZG<Bls12381>> {
    let key = k.to_string();
    if let Ok(mut cache) = HALO2_BLS_PARAMS_CACHE.lock()
        && let Some(params) = cache.get_cloned(&key)
    {
        return params;
    }

    let seed = derive_setup_seed(k);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let params = Arc::new(ParamsKZG::<Bls12381>::setup(k, &mut rng));
    if let Ok(mut cache) = HALO2_BLS_PARAMS_CACHE.lock() {
        cache.insert(key, params.clone());
    }
    params
}

fn load_params_from_blob(blob: &[u8]) -> ZkfResult<Arc<ParamsKZG<Bls12381>>> {
    match blob.first().copied() {
        Some(HALO2_BLS_SETUP_BLOB_PARAMS_VERSION) => {
            let params_bytes = unpack_legacy_params_blob(blob)?;
            let mut cursor = std::io::Cursor::new(params_bytes.as_slice());
            use halo2_proofs_pse::poly::commitment::Params as _;
            let params = ParamsKZG::<Bls12381>::read(&mut cursor)
                .map_err(|err| ZkfError::InvalidArtifact(err.to_string()))?;
            Ok(Arc::new(params))
        }
        Some(HALO2_BLS_SETUP_BLOB_K_VERSION) => Ok(params_for_k(unpack_k_blob(blob)?)),
        Some(version) => Err(ZkfError::InvalidArtifact(format!(
            "unsupported halo2-bls setup blob version {}",
            version
        ))),
        None => Err(ZkfError::InvalidArtifact(
            "empty halo2-bls setup blob".to_string(),
        )),
    }
}

fn vk_fingerprint(vk: &halo2_proofs_pse::plonk::VerifyingKey<G1Affine>) -> Vec<u8> {
    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::Processed)
        .unwrap_or_default();
    Sha256::digest(&vk_bytes).to_vec()
}

fn pack_params_blob(k: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + std::mem::size_of::<u32>());
    out.push(HALO2_BLS_SETUP_BLOB_K_VERSION);
    out.extend(k.to_le_bytes());
    out
}

#[allow(dead_code)]
fn unpack_params_blob(blob: &[u8]) -> ZkfResult<Vec<u8>> {
    match blob.first().copied() {
        Some(HALO2_BLS_SETUP_BLOB_PARAMS_VERSION) => unpack_legacy_params_blob(blob),
        Some(HALO2_BLS_SETUP_BLOB_K_VERSION) => {
            let params = params_for_k(unpack_k_blob(blob)?);
            let mut params_bytes = Vec::new();
            use halo2_proofs_pse::poly::commitment::Params as _;
            params
                .write(&mut params_bytes)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            Ok(params_bytes)
        }
        Some(version) => Err(ZkfError::InvalidArtifact(format!(
            "unsupported halo2-bls setup blob version {}",
            version
        ))),
        None => Err(ZkfError::InvalidArtifact(
            "empty halo2-bls setup blob".to_string(),
        )),
    }
}

fn unpack_legacy_params_blob(blob: &[u8]) -> ZkfResult<Vec<u8>> {
    if blob.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "empty halo2-bls setup blob".to_string(),
        ));
    }

    if blob[0] != HALO2_BLS_SETUP_BLOB_PARAMS_VERSION {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported halo2-bls setup blob version {}",
            blob[0]
        )));
    }

    if blob.len() < 9 {
        return Err(ZkfError::InvalidArtifact(
            "truncated halo2-bls setup blob".to_string(),
        ));
    }

    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&blob[1..9]);
    let params_len = usize::try_from(u64::from_le_bytes(len_bytes))
        .map_err(|_| ZkfError::InvalidArtifact("halo2-bls params length overflow".to_string()))?;

    if blob.len() != 9 + params_len {
        return Err(ZkfError::InvalidArtifact(
            "invalid halo2-bls setup blob length".to_string(),
        ));
    }

    Ok(blob[9..].to_vec())
}

fn unpack_k_blob(blob: &[u8]) -> ZkfResult<u32> {
    if blob.len() != 1 + std::mem::size_of::<u32>() {
        return Err(ZkfError::InvalidArtifact(
            "invalid halo2-bls setup descriptor length".to_string(),
        ));
    }

    let mut k_bytes = [0u8; 4];
    k_bytes.copy_from_slice(&blob[1..]);
    Ok(u32::from_le_bytes(k_bytes))
}

// --- NativeField implementation for BLS12-381 Fr ---

impl crate::native_field::NativeField for Halo2Bls12381Fr {
    fn from_field_element(fe: &FieldElement, field: FieldId) -> ZkfResult<Self> {
        let fr = parse_bls12_fr(fe)?;
        let _ = field;
        Ok(Halo2Bls12381Fr(fr))
    }

    fn to_field_element(&self) -> FieldElement {
        use halo2_proofs_pse::halo2curves::ff::PrimeField;
        let repr = self.0.to_repr();
        FieldElement::from_le_bytes(repr.as_ref())
    }

    fn field_id() -> FieldId {
        FieldId::Bls12_381
    }
}

/// Wrapper type for BLS12-381 Fr field element.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Halo2Bls12381Fr(Fr);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_returns_halo2_bls12381() {
        let backend = Halo2Bls12381Backend;
        assert_eq!(backend.kind(), BackendKind::Halo2Bls12381);
    }

    #[test]
    fn capabilities_declare_kzg_profile() {
        let caps = Halo2Bls12381Backend.capabilities();
        assert_eq!(caps.backend, BackendKind::Halo2Bls12381);
        assert!(caps.trusted_setup);
        assert!(!caps.transparent_setup);
        assert!(caps.native_profiles.contains(&"kzg".to_string()));
        assert_eq!(caps.mode, BackendMode::Native);
    }

    #[test]
    fn compile_rejects_wrong_field() {
        crate::with_serialized_heavy_backend_test(|| {
            let program = Program {
                name: "test".to_string(),
                field: FieldId::PastaFp,
                signals: Vec::new(),
                constraints: Vec::new(),
                witness_plan: Default::default(),
                ..Default::default()
            };
            let result = Halo2Bls12381Backend.compile(&program);
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(
                msg.contains("bls12-381"),
                "error should mention bls12-381 field requirement: {msg}"
            );
        });
    }

    #[test]
    fn compile_succeeds_for_bls12_381_field() {
        crate::with_serialized_heavy_backend_test(|| {
            let program = Program {
                name: "test_bls".to_string(),
                field: FieldId::Bls12_381,
                signals: vec![
                    Signal {
                        name: "x".to_string(),
                        visibility: Visibility::Public,
                        constant: None,
                        ty: None,
                    },
                    Signal {
                        name: "y".to_string(),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    },
                ],
                constraints: vec![Constraint::Equal {
                    lhs: Expr::Signal("x".to_string()),
                    rhs: Expr::Signal("y".to_string()),
                    label: Some("test_eq".to_string()),
                }],
                witness_plan: Default::default(),
                ..Default::default()
            };
            let compiled = Halo2Bls12381Backend.compile(&program);
            assert!(
                compiled.is_ok(),
                "compile should succeed: {:?}",
                compiled.err()
            );
            let compiled = compiled.unwrap();
            assert_eq!(compiled.backend, BackendKind::Halo2Bls12381);
            assert_eq!(compiled.metadata.get("curve").unwrap(), "bls12-381");
            assert_eq!(compiled.metadata.get("commitment").unwrap(), "kzg");
        });
    }

    #[test]
    fn estimate_k_scales_with_used_range_bits() {
        let program = Program {
            name: "halo2_bls_small_range".to_string(),
            field: FieldId::Bls12_381,
            signals: vec![Signal {
                name: "x".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Range {
                signal: "x".to_string(),
                bits: 8,
                label: Some("range_8".to_string()),
            }],
            witness_plan: Default::default(),
            ..Default::default()
        };

        let max_bits = max_range_bits(&program).unwrap();
        let k = estimate_k(&program, max_bits).unwrap();
        assert!(
            k < 18,
            "tiny range circuits should not reserve 16-bit tables"
        );
    }

    #[test]
    fn roundtrip_equality_constraint() {
        crate::with_serialized_heavy_backend_test(|| {
            let program = Program {
                name: "bls_roundtrip".to_string(),
                field: FieldId::Bls12_381,
                signals: vec![
                    Signal {
                        name: "a".to_string(),
                        visibility: Visibility::Public,
                        constant: None,
                        ty: None,
                    },
                    Signal {
                        name: "b".to_string(),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    },
                ],
                constraints: vec![Constraint::Equal {
                    lhs: Expr::Signal("a".to_string()),
                    rhs: Expr::Signal("b".to_string()),
                    label: Some("eq".to_string()),
                }],
                witness_plan: Default::default(),
                ..Default::default()
            };

            let compiled = Halo2Bls12381Backend.compile(&program).unwrap();

            let mut witness = Witness::default();
            witness
                .values
                .insert("a".to_string(), FieldElement::from_i64(42));
            witness
                .values
                .insert("b".to_string(), FieldElement::from_i64(42));

            let artifact = Halo2Bls12381Backend.prove(&compiled, &witness).unwrap();
            assert!(!artifact.proof.is_empty());
            assert_eq!(artifact.backend, BackendKind::Halo2Bls12381);

            let verified = Halo2Bls12381Backend.verify(&compiled, &artifact).unwrap();
            assert!(verified);
        });
    }

    #[test]
    fn range_constraint_bls12381() {
        crate::with_serialized_heavy_backend_test(|| {
            let program = Program {
                name: "bls_range".to_string(),
                field: FieldId::Bls12_381,
                signals: vec![Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                }],
                constraints: vec![Constraint::Range {
                    signal: "x".to_string(),
                    bits: 8,
                    label: Some("range_8".to_string()),
                }],
                witness_plan: Default::default(),
                ..Default::default()
            };

            let compiled = Halo2Bls12381Backend.compile(&program).unwrap();

            let mut witness = Witness::default();
            witness
                .values
                .insert("x".to_string(), FieldElement::from_i64(200));

            let artifact = Halo2Bls12381Backend.prove(&compiled, &witness).unwrap();
            let verified = Halo2Bls12381Backend.verify(&compiled, &artifact).unwrap();
            assert!(verified);
        });
    }

    #[test]
    fn large_range_constraint_bls12381_compiles_with_decomposition() {
        crate::with_serialized_heavy_backend_test(|| {
            let program = Program {
                name: "bls_large_range".to_string(),
                field: FieldId::Bls12_381,
                signals: vec![Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                }],
                constraints: vec![Constraint::Range {
                    signal: "x".to_string(),
                    bits: 40,
                    label: Some("range_40".to_string()),
                }],
                witness_plan: Default::default(),
                ..Default::default()
            };

            let compiled = Halo2Bls12381Backend.compile(&program).unwrap();
            assert!(
                compiled
                    .metadata
                    .contains_key(range_decomposition::RANGE_DECOMPOSITION_METADATA_KEY)
            );
            assert_eq!(
                compiled.metadata.get("trust_model").map(String::as_str),
                Some("cryptographic")
            );
            assert_eq!(
                compiled
                    .metadata
                    .get("max_range_bits_used")
                    .map(String::as_str),
                Some("16")
            );
            assert!(
                compiled.program.constraints.len() > program.constraints.len(),
                "large range constraints should be lowered into chunked ranges plus recombination"
            );
        });
    }
}
