use crate::audited_backend::{audited_witness_for_proving, build_audited_compiled_program};
use crate::blackbox_gadgets;
use crate::blackbox_native::{supported_blackbox_ops, validate_blackbox_constraints};
use crate::metal_runtime::append_backend_runtime_metadata;
use crate::range_decomposition;
use crate::{BackendEngine, BoundedStringCache, bounded_cache_limit};
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{Layouter, Region, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error as Halo2Error, Expression, Instance,
    ProvingKey, Selector, SingleVerifier, TableColumn, VerifyingKey, create_proof, keygen_pk,
    keygen_vk, verify_proof,
};
use halo2_proofs::poly::{Rotation, commitment::Params};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use num_bigint::BigInt;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use zkf_core::{
    BackendCapabilities, BackendKind, BackendMode, CompiledProgram, Constraint, Expr, FieldElement,
    FieldId, Program, ProofArtifact, Signal, Visibility, Witness, ZkfError, ZkfResult,
    check_constraints, collect_public_inputs,
};

const HALO2_SETUP_BLOB_PARAMS_VERSION: u8 = 1;
const HALO2_SETUP_BLOB_K_VERSION: u8 = 2;
const HALO2_MAX_RANGE_BITS: u32 = 16;

pub struct Halo2Backend;

#[derive(Clone)]
struct Halo2SetupBundle {
    params: Arc<Params<EqAffine>>,
    pk: ProvingKey<EqAffine>,
    vk: VerifyingKey<EqAffine>,
    vk_fingerprint: Vec<u8>,
}

static HALO2_SETUP_CACHE: Lazy<Mutex<BoundedStringCache<Arc<Halo2SetupBundle>>>> =
    Lazy::new(|| {
        Mutex::new(BoundedStringCache::new(bounded_cache_limit(
            "ZKF_HALO2_SETUP_CACHE_LIMIT",
            2,
        )))
    });

static HALO2_PARAMS_CACHE: Lazy<Mutex<BoundedStringCache<Arc<Params<EqAffine>>>>> =
    Lazy::new(|| {
        Mutex::new(BoundedStringCache::new(bounded_cache_limit(
            "ZKF_HALO2_PARAMS_CACHE_LIMIT",
            2,
        )))
    });

#[derive(Debug, Clone)]
pub(crate) struct Halo2Config {
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
pub(crate) struct Halo2IrCircuit {
    program: Program,
    signal_values: HashMap<String, Fp>,
}

impl Halo2IrCircuit {
    pub(crate) fn without_witness(program: Program) -> ZkfResult<Self> {
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

impl Circuit<Fp> for Halo2IrCircuit {
    type Config = Halo2Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            program: self.program.clone(),
            signal_values: build_signal_values(&self.program, None).unwrap_or_default(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
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

        meta.create_gate("zkf_add", |meta| {
            let q = meta.query_selector(q_add);
            let a = meta.query_advice(op_a, Rotation::cur());
            let b = meta.query_advice(op_b, Rotation::cur());
            let out = meta.query_advice(op_out, Rotation::cur());
            vec![q * (a + b - out)]
        });

        meta.create_gate("zkf_sub", |meta| {
            let q = meta.query_selector(q_sub);
            let a = meta.query_advice(op_a, Rotation::cur());
            let b = meta.query_advice(op_b, Rotation::cur());
            let out = meta.query_advice(op_out, Rotation::cur());
            vec![q * (a - b - out)]
        });

        meta.create_gate("zkf_mul", |meta| {
            let q = meta.query_selector(q_mul);
            let a = meta.query_advice(op_a, Rotation::cur());
            let b = meta.query_advice(op_b, Rotation::cur());
            let out = meta.query_advice(op_out, Rotation::cur());
            vec![q * (a * b - out)]
        });

        meta.create_gate("zkf_div", |meta| {
            let q = meta.query_selector(q_div);
            let a = meta.query_advice(op_a, Rotation::cur());
            let b = meta.query_advice(op_b, Rotation::cur());
            let out = meta.query_advice(op_out, Rotation::cur());
            let inv = meta.query_advice(op_aux, Rotation::cur());
            let one = Expression::Constant(Fp::ONE);

            vec![q.clone() * (a - b.clone() * out), q * (b * inv - one)]
        });

        meta.create_gate("zkf_bool", |meta| {
            let q = meta.query_selector(q_bool);
            let s = meta.query_advice(op_a, Rotation::cur());
            let one = Expression::Constant(Fp::ONE);
            vec![q * s.clone() * (one - s)]
        });

        let mut range_selectors = Vec::new();
        let mut range_tables = Vec::new();

        for _ in 0..HALO2_MAX_RANGE_BITS {
            let selector = meta.complex_selector();
            let table = meta.lookup_table_column();

            meta.lookup(|meta| {
                let q = meta.query_selector(selector);
                let v = meta.query_advice(range_value, Rotation::cur());
                vec![(q * v, table)]
            });

            range_selectors.push(selector);
            range_tables.push(table);
        }

        Halo2Config {
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
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Halo2Error> {
        let used_range_bits = max_range_bits(&self.program).map_err(|_| Halo2Error::Synthesis)?;
        if used_range_bits > 0 {
            layouter.assign_table(
                || "zkf_range_tables",
                |mut table| {
                    let max_rows = 1usize << used_range_bits;
                    for bits in 1..=used_range_bits {
                        let table_col = config.range_tables[(bits - 1) as usize];
                        let value_count = 1usize << bits;
                        for row in 0..max_rows {
                            table.assign_cell(
                                || format!("range_table_{bits}[{row}]"),
                                table_col,
                                row,
                                || Value::known(Fp::from((row % value_count) as u64)),
                            )?;
                        }
                    }
                    Ok(())
                },
            )?;
        }

        let public_cells = layouter.assign_region(
            || "zkf_main",
            |mut region| {
                let mut next_row = 0usize;
                let mut signal_cells = HashMap::new();
                let mut public_cells = Vec::new();

                for signal in &self.program.signals {
                    let value = self.signal_value(signal);
                    let cell = region.assign_advice(
                        || format!("signal_{}", signal.name),
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
                                self.program.field,
                                &config,
                                &signal_cells,
                                &mut region,
                                &mut next_row,
                            )?;
                            let rhs_cell = assign_expr(
                                rhs,
                                self.program.field,
                                &config,
                                &signal_cells,
                                &mut region,
                                &mut next_row,
                            )?;
                            region.constrain_equal(lhs_cell.cell(), rhs_cell.cell())?;
                        }
                        Constraint::Boolean { signal, .. } => {
                            let signal_cell =
                                signal_cells.get(signal).ok_or(Halo2Error::Synthesis)?;
                            let row = next_row;
                            next_row += 1;

                            let copied = copy_cell(
                                &mut region,
                                signal_cell,
                                config.op_a,
                                row,
                                "bool_signal_copy",
                            )?;
                            config.q_bool.enable(&mut region, row)?;

                            // Keep the copied cell alive and constrained in this row.
                            let _ = copied;
                        }
                        Constraint::Range { signal, bits, .. } => {
                            if *bits == 0 || *bits > HALO2_MAX_RANGE_BITS {
                                return Err(Halo2Error::Synthesis);
                            }

                            let signal_cell =
                                signal_cells.get(signal).ok_or(Halo2Error::Synthesis)?;
                            let row = next_row;
                            next_row += 1;

                            let copied = copy_cell(
                                &mut region,
                                signal_cell,
                                config.range_value,
                                row,
                                "range_signal_copy",
                            )?;
                            config.range_selectors[(*bits - 1) as usize]
                                .enable(&mut region, row)?;

                            let _ = copied;
                        }
                        Constraint::BlackBox { .. } => {}
                        Constraint::Lookup { .. } => {
                            return Err(Halo2Error::Synthesis);
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

impl Halo2IrCircuit {
    fn signal_value(&self, signal: &Signal) -> Value<Fp> {
        if let Some(value) = self.signal_values.get(&signal.name) {
            Value::known(*value)
        } else {
            Value::unknown()
        }
    }
}

impl BackendEngine for Halo2Backend {
    fn kind(&self) -> BackendKind {
        BackendKind::Halo2
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::Halo2,
            mode: BackendMode::Native,
            trusted_setup: false,
            recursion_ready: true,
            transparent_setup: true,
            zkvm_mode: false,
            network_target: None,
            supported_blackbox_ops: supported_blackbox_ops(),
            supported_constraint_kinds: vec![
                "equal".to_string(),
                "boolean".to_string(),
                "range".to_string(),
                "blackbox".to_string(),
            ],
            native_profiles: vec!["ipa".to_string()],
            notes: format!(
                "Plonkish backend implemented with Halo2 (IPA). Supports Equal/Boolean/Range/Div. \
                 Range constraints wider than {HALO2_MAX_RANGE_BITS} bits are lowered into \
                 {HALO2_MAX_RANGE_BITS}-bit lookup chunks automatically."
            ),
        }
    }

    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram> {
        crate::with_serialized_heavy_backend_test(|| {
            let raw_program = program.clone();
            let program = &blackbox_gadgets::lower_blackbox_program(program)?;
            let program = &blackbox_gadgets::lookup_lowering::lower_lookup_constraints(program)?;
            let (lowered_program, range_decompositions) =
                range_decomposition::lower_large_range_constraints(
                    program,
                    HALO2_MAX_RANGE_BITS,
                    "halo2",
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
                .insert("curve".to_string(), "pasta-vesta".to_string());
            compiled
                .metadata
                .insert("field".to_string(), "pasta-fp".to_string());
            compiled
                .metadata
                .insert("commitment".to_string(), "ipa".to_string());
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
            let circuit = Halo2IrCircuit::with_witness(compiled.program.clone(), &enriched)?;

            let public_inputs = collect_public_inputs(&compiled.program, &enriched)?;
            let public_inputs_fp = public_inputs
                .iter()
                .map(parse_pasta_fp)
                .collect::<ZkfResult<Vec<_>>>()?;

            let instance_columns: Vec<&[Fp]> = vec![public_inputs_fp.as_slice()];
            let instances: Vec<&[&[Fp]]> = vec![instance_columns.as_slice()];
            let circuits = vec![circuit];

            let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(vec![]);

            create_proof(
                setup.params.as_ref(),
                &setup.pk,
                &circuits,
                &instances,
                OsRng,
                &mut transcript,
            )
            .map_err(|err| ZkfError::Backend(format!("halo2 create_proof failed: {err:?}")))?;

            let proof_bytes = transcript.finalize();

            let mut metadata = BTreeMap::new();
            metadata.insert("curve".to_string(), "pasta-vesta".to_string());
            metadata.insert("commitment".to_string(), "ipa".to_string());
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
                "halo2 verification key fingerprint mismatch".to_string(),
            ));
        }

        let public_inputs_fp = artifact
            .public_inputs
            .iter()
            .map(parse_pasta_fp)
            .collect::<ZkfResult<Vec<_>>>()?;

        let instance_columns: Vec<&[Fp]> = vec![public_inputs_fp.as_slice()];
        let instances: Vec<&[&[Fp]]> = vec![instance_columns.as_slice()];

        let strategy = SingleVerifier::new(setup.params.as_ref());
        let mut transcript =
            Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(artifact.proof.as_slice());

        verify_proof(
            setup.params.as_ref(),
            &setup.vk,
            strategy,
            &instances,
            &mut transcript,
        )
        .map(|_| true)
        .map_err(|err| ZkfError::Backend(format!("halo2 verify_proof failed: {err:?}")))
    }

    fn compile_zir(&self, program: &zkf_core::zir_v1::Program) -> ZkfResult<CompiledProgram> {
        use crate::lowering::ZirLowering;
        use crate::lowering::halo2_lowering::Halo2Lowering;

        let v2_raw = zkf_core::program_zir_to_v2(program)?;
        let requires_safe_v2_path = program.constraints.iter().any(|constraint| {
            !matches!(
                constraint,
                zkf_core::zir_v1::Constraint::Equal { .. }
                    | zkf_core::zir_v1::Constraint::Boolean { .. }
                    | zkf_core::zir_v1::Constraint::Range { .. }
            )
        });
        if requires_safe_v2_path {
            return self.compile(&v2_raw);
        }

        let lowered = Halo2Lowering.lower(program)?;

        // Convert to v2 for the base circuit (Halo2's PLONKish circuit builder
        // still operates on IR v2 constraints). The lowered metadata captures
        // the ZIR-rich features.
        let v2 = crate::blackbox_gadgets::lower_blackbox_program(&v2_raw)?;
        ensure_supported_program(&v2)?;

        let max_bits = max_range_bits(&v2)?;
        let k = estimate_k(&v2, max_bits)?;

        let mut compiled = build_audited_compiled_program(self.kind(), &v2_raw, v2)?;
        compiled.compiled_data = Some(pack_params_blob(k));
        compiled
            .metadata
            .insert("curve".to_string(), "pasta-vesta".to_string());
        compiled
            .metadata
            .insert("field".to_string(), "pasta-fp".to_string());
        compiled
            .metadata
            .insert("commitment".to_string(), "ipa".to_string());
        compiled.metadata.insert("k".to_string(), k.to_string());
        compiled
            .metadata
            .insert("max_range_bits_used".to_string(), max_bits.to_string());

        // Store ZIR-native lowering metadata
        compiled.metadata.insert(
            "zir_plonk_gates".to_string(),
            lowered.gates.len().to_string(),
        );
        compiled
            .metadata
            .insert("zir_columns".to_string(), lowered.columns.len().to_string());
        compiled
            .metadata
            .insert("zir_lookups".to_string(), lowered.lookups.len().to_string());
        compiled.metadata.insert(
            "zir_permutations".to_string(),
            lowered.permutations.len().to_string(),
        );
        compiled.metadata.insert(
            "zir_estimated_rows".to_string(),
            lowered.estimated_rows.to_string(),
        );
        compiled
            .metadata
            .insert("zir_lowered".to_string(), "true".to_string());
        compiled
            .metadata
            .insert("zir_native_compile".to_string(), "true".to_string());

        Ok(compiled)
    }

    fn prove_zir(
        &self,
        zir_program: &zkf_core::zir_v1::Program,
        compiled: &CompiledProgram,
        witness: &Witness,
    ) -> ZkfResult<ProofArtifact> {
        let _ = zir_program;
        let mut artifact = self.prove(compiled, witness)?;
        artifact
            .metadata
            .insert("zir_native_prove".to_string(), "true".to_string());
        Ok(artifact)
    }
}

fn assign_expr(
    expr: &Expr,
    field: FieldId,
    config: &Halo2Config,
    signal_cells: &HashMap<String, halo2_proofs::circuit::AssignedCell<Fp, Fp>>,
    region: &mut Region<'_, Fp>,
    next_row: &mut usize,
) -> Result<halo2_proofs::circuit::AssignedCell<Fp, Fp>, Halo2Error> {
    match expr {
        Expr::Const(value) => {
            let row = *next_row;
            *next_row += 1;

            let constant =
                parse_pasta_fp_for_field(value, field).map_err(|_| Halo2Error::Synthesis)?;
            region.assign_advice(
                || format!("const_{row}"),
                config.op_a,
                row,
                || Value::known(constant),
            )
        }
        Expr::Signal(name) => signal_cells.get(name).cloned().ok_or(Halo2Error::Synthesis),
        Expr::Add(items) => {
            if items.is_empty() {
                let zero = Expr::Const(FieldElement::from_i64(0));
                return assign_expr(&zero, field, config, signal_cells, region, next_row);
            }

            let mut iter = items.iter();
            let first = iter.next().ok_or(Halo2Error::Synthesis)?;
            let mut acc = assign_expr(first, field, config, signal_cells, region, next_row)?;

            for item in iter {
                let rhs = assign_expr(item, field, config, signal_cells, region, next_row)?;
                acc = assign_binary_op(BinaryOp::Add, config, region, next_row, &acc, &rhs)?;
            }

            Ok(acc)
        }
        Expr::Sub(a, b) => {
            let lhs = assign_expr(a, field, config, signal_cells, region, next_row)?;
            let rhs = assign_expr(b, field, config, signal_cells, region, next_row)?;
            assign_binary_op(BinaryOp::Sub, config, region, next_row, &lhs, &rhs)
        }
        Expr::Mul(a, b) => {
            let lhs = assign_expr(a, field, config, signal_cells, region, next_row)?;
            let rhs = assign_expr(b, field, config, signal_cells, region, next_row)?;
            assign_binary_op(BinaryOp::Mul, config, region, next_row, &lhs, &rhs)
        }
        Expr::Div(a, b) => {
            let lhs = assign_expr(a, field, config, signal_cells, region, next_row)?;
            let rhs = assign_expr(b, field, config, signal_cells, region, next_row)?;
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
    config: &Halo2Config,
    region: &mut Region<'_, Fp>,
    next_row: &mut usize,
    lhs: &halo2_proofs::circuit::AssignedCell<Fp, Fp>,
    rhs: &halo2_proofs::circuit::AssignedCell<Fp, Fp>,
) -> Result<halo2_proofs::circuit::AssignedCell<Fp, Fp>, Halo2Error> {
    let row = *next_row;
    *next_row += 1;

    let a = copy_cell(region, lhs, config.op_a, row, "lhs_copy")?;
    let b = copy_cell(region, rhs, config.op_b, row, "rhs_copy")?;

    let a_value = a.value().copied();
    let b_value = b.value().copied();

    let (out_value, aux_value) = match op {
        BinaryOp::Add => (
            a_value.zip(b_value).map(|(x, y)| x + y),
            Value::known(Fp::ZERO),
        ),
        BinaryOp::Sub => (
            a_value.zip(b_value).map(|(x, y)| x - y),
            Value::known(Fp::ZERO),
        ),
        BinaryOp::Mul => (
            a_value.zip(b_value).map(|(x, y)| x * y),
            Value::known(Fp::ZERO),
        ),
        BinaryOp::Div => {
            let inv = b_value.map(|v| Option::<Fp>::from(v.invert()).unwrap_or(Fp::ZERO));
            (a_value.zip(inv).map(|(x, inv)| x * inv), inv)
        }
    };

    let out = region.assign_advice(|| format!("op_out_{row}"), config.op_out, row, || out_value)?;

    region.assign_advice(|| format!("op_aux_{row}"), config.op_aux, row, || aux_value)?;

    match op {
        BinaryOp::Add => config.q_add.enable(region, row)?,
        BinaryOp::Sub => config.q_sub.enable(region, row)?,
        BinaryOp::Mul => config.q_mul.enable(region, row)?,
        BinaryOp::Div => config.q_div.enable(region, row)?,
    }

    Ok(out)
}

fn copy_cell(
    region: &mut Region<'_, Fp>,
    source: &halo2_proofs::circuit::AssignedCell<Fp, Fp>,
    column: Column<Advice>,
    row: usize,
    label: &'static str,
) -> Result<halo2_proofs::circuit::AssignedCell<Fp, Fp>, Halo2Error> {
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
    if program.field != FieldId::PastaFp {
        return Err(ZkfError::UnsupportedBackend {
            backend: BackendKind::Halo2.to_string(),
            message: format!(
                "backend 'halo2' requires PastaFp circuits; got {}. Use backend 'halo2-bls12-381' for Bls12_381 circuits.",
                program.field
            ),
        });
    }

    let max_bits = max_range_bits(program)?;
    if max_bits > HALO2_MAX_RANGE_BITS {
        return Err(ZkfError::UnsupportedBackend {
            backend: BackendKind::Halo2.to_string(),
            message: format!(
                "range bits {} exceed halo2 backend limit {}",
                max_bits, HALO2_MAX_RANGE_BITS
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
                    backend: BackendKind::Halo2.to_string(),
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

    // Leave extra rows for blinding factors and selector/lookup plumbing.
    let required_rows = main_rows.max(table_rows) + 64;
    let k = ceil_log2(required_rows as u64)
        .max(max_range_bits.saturating_add(2))
        .max(12);

    if k > 22 {
        return Err(ZkfError::UnsupportedBackend {
            backend: BackendKind::Halo2.to_string(),
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
) -> ZkfResult<HashMap<String, Fp>> {
    let mut out = HashMap::new();

    for signal in &program.signals {
        if let Some(constant) = &signal.constant {
            out.insert(
                signal.name.clone(),
                parse_pasta_fp_for_field(constant, program.field)?,
            );
        }
    }

    if let Some(witness) = witness {
        for (name, value) in &witness.values {
            out.insert(
                name.clone(),
                parse_pasta_fp_for_field(value, program.field)?,
            );
        }
    }

    Ok(out)
}

pub(crate) fn parse_pasta_fp(value: &FieldElement) -> ZkfResult<Fp> {
    parse_pasta_fp_for_field(value, FieldId::PastaFp)
}

fn parse_pasta_fp_for_field(value: &FieldElement, field: FieldId) -> ZkfResult<Fp> {
    if field != FieldId::PastaFp {
        return Err(ZkfError::UnsupportedBackend {
            backend: BackendKind::Halo2.to_string(),
            message:
                "expected PastaFp field for backend 'halo2' scalar conversion; use backend 'halo2-bls12-381' for Bls12_381 values.".to_string(),
        });
    }

    let normalized = value.normalized_bigint(field)?;
    bigint_to_fp(&normalized)
}

fn bigint_to_fp(value: &BigInt) -> ZkfResult<Fp> {
    let digits = value.to_str_radix(10);
    let mut acc = Fp::ZERO;

    for byte in digits.bytes() {
        let digit = match byte {
            b'0'..=b'9' => (byte - b'0') as u64,
            _ => {
                return Err(ZkfError::ParseField {
                    value: digits.clone(),
                });
            }
        };

        acc = acc * Fp::from(10u64) + Fp::from(digit);
    }

    Ok(acc)
}

fn cache_insert(program_digest: String, bundle: Arc<Halo2SetupBundle>) {
    if let Ok(mut cache) = HALO2_SETUP_CACHE.lock() {
        cache.insert(program_digest, bundle);
    }
}

#[cfg(test)]
pub(crate) fn clear_test_setup_cache() {
    if let Ok(mut cache) = HALO2_SETUP_CACHE.lock() {
        cache.clear();
    }
    if let Ok(mut cache) = HALO2_PARAMS_CACHE.lock() {
        cache.clear();
    }
}

fn get_or_build_setup(compiled: &CompiledProgram) -> ZkfResult<Arc<Halo2SetupBundle>> {
    if let Ok(mut cache) = HALO2_SETUP_CACHE.lock()
        && let Some(bundle) = cache.get_cloned(&compiled.program_digest)
    {
        return Ok(bundle);
    }

    let blob = compiled
        .compiled_data
        .as_deref()
        .ok_or(ZkfError::MissingCompiledData)?;
    let params = load_params_from_blob(blob)?;

    let circuit = Halo2IrCircuit::without_witness(compiled.program.clone())?;
    let vk = keygen_vk(params.as_ref(), &circuit)
        .map_err(|err| ZkfError::Backend(format!("halo2 keygen_vk failed: {err:?}")))?;
    let pk = keygen_pk(params.as_ref(), vk.clone(), &circuit)
        .map_err(|err| ZkfError::Backend(format!("halo2 keygen_pk failed: {err:?}")))?;

    let bundle = Arc::new(Halo2SetupBundle {
        params,
        pk,
        vk: vk.clone(),
        vk_fingerprint: vk_fingerprint(&vk),
    });

    cache_insert(compiled.program_digest.clone(), bundle.clone());
    Ok(bundle)
}

fn params_for_k(k: u32) -> Arc<Params<EqAffine>> {
    let key = k.to_string();
    if let Ok(mut cache) = HALO2_PARAMS_CACHE.lock()
        && let Some(params) = cache.get_cloned(&key)
    {
        return params;
    }

    let params = Arc::new(Params::<EqAffine>::new(k));
    if let Ok(mut cache) = HALO2_PARAMS_CACHE.lock() {
        cache.insert(key, params.clone());
    }
    params
}

fn load_params_from_blob(blob: &[u8]) -> ZkfResult<Arc<Params<EqAffine>>> {
    match blob.first().copied() {
        Some(HALO2_SETUP_BLOB_PARAMS_VERSION) => {
            let params_bytes = unpack_legacy_params_blob(blob)?;
            let mut cursor = Cursor::new(params_bytes.as_slice());
            let params = Params::<EqAffine>::read(&mut cursor)
                .map_err(|err| ZkfError::InvalidArtifact(err.to_string()))?;
            Ok(Arc::new(params))
        }
        Some(HALO2_SETUP_BLOB_K_VERSION) => Ok(params_for_k(unpack_k_blob(blob)?)),
        Some(version) => Err(ZkfError::InvalidArtifact(format!(
            "unsupported halo2 setup blob version {}",
            version
        ))),
        None => Err(ZkfError::InvalidArtifact(
            "empty halo2 setup blob".to_string(),
        )),
    }
}

fn vk_fingerprint(vk: &VerifyingKey<EqAffine>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", vk.pinned()).as_bytes());
    hasher.finalize().to_vec()
}

fn pack_params_blob(k: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + std::mem::size_of::<u32>());
    out.push(HALO2_SETUP_BLOB_K_VERSION);
    out.extend(k.to_le_bytes());
    out
}

pub(crate) fn unpack_params_blob(blob: &[u8]) -> ZkfResult<Vec<u8>> {
    match blob.first().copied() {
        Some(HALO2_SETUP_BLOB_PARAMS_VERSION) => unpack_legacy_params_blob(blob),
        Some(HALO2_SETUP_BLOB_K_VERSION) => {
            let params = params_for_k(unpack_k_blob(blob)?);
            let mut params_bytes = Vec::new();
            params
                .write(&mut params_bytes)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            Ok(params_bytes)
        }
        Some(version) => Err(ZkfError::InvalidArtifact(format!(
            "unsupported halo2 setup blob version {}",
            version
        ))),
        None => Err(ZkfError::InvalidArtifact(
            "empty halo2 setup blob".to_string(),
        )),
    }
}

fn unpack_legacy_params_blob(blob: &[u8]) -> ZkfResult<Vec<u8>> {
    if blob.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "empty halo2 setup blob".to_string(),
        ));
    }

    if blob[0] != HALO2_SETUP_BLOB_PARAMS_VERSION {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported halo2 setup blob version {}",
            blob[0]
        )));
    }

    if blob.len() < 9 {
        return Err(ZkfError::InvalidArtifact(
            "truncated halo2 setup blob".to_string(),
        ));
    }

    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&blob[1..9]);
    let params_len = usize::try_from(u64::from_le_bytes(len_bytes))
        .map_err(|_| ZkfError::InvalidArtifact("halo2 params length overflow".to_string()))?;

    if blob.len() != 9 + params_len {
        return Err(ZkfError::InvalidArtifact(
            "invalid halo2 setup blob length".to_string(),
        ));
    }

    Ok(blob[9..].to_vec())
}

fn unpack_k_blob(blob: &[u8]) -> ZkfResult<u32> {
    if blob.len() != 1 + std::mem::size_of::<u32>() {
        return Err(ZkfError::InvalidArtifact(
            "invalid halo2 setup descriptor length".to_string(),
        ));
    }

    let mut k_bytes = [0u8; 4];
    k_bytes.copy_from_slice(&blob[1..]);
    Ok(u32::from_le_bytes(k_bytes))
}

// --- NativeField implementation for Halo2 Pasta Fp ---

impl crate::native_field::NativeField for Fp {
    fn from_field_element(fe: &FieldElement, field: FieldId) -> ZkfResult<Self> {
        parse_pasta_fp_for_field(fe, field)
    }

    fn to_field_element(&self) -> FieldElement {
        // Fp → bytes (little-endian) → FieldElement via ff::PrimeField::to_repr()
        let repr = ff::PrimeField::to_repr(self);
        FieldElement::from_le_bytes(repr.as_ref())
    }

    fn field_id() -> FieldId {
        FieldId::PastaFp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_range_constraint_compiles_with_decomposition() {
        crate::with_serialized_heavy_backend_test(|| {
            let program = Program {
                name: "halo2_large_range".to_string(),
                field: FieldId::PastaFp,
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

            let compiled = Halo2Backend.compile(&program).unwrap();
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

    #[test]
    fn estimate_k_scales_with_used_range_bits() {
        let program = Program {
            name: "halo2_small_range".to_string(),
            field: FieldId::PastaFp,
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
}
