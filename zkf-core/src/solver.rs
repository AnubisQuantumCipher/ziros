use crate::witness::{
    Witness, WitnessInputs, check_constraints, ensure_witness_completeness,
    generate_partial_witness,
};
use crate::{Program, ZkfError, ZkfResult};

#[cfg(feature = "acvm-solver-beta9")]
pub mod acvm_beta9_adapter;

pub trait WitnessSolver: Send + Sync {
    fn id(&self) -> &'static str;
    fn solve(&self, program: &Program, partial: &Witness) -> ZkfResult<Witness>;
}

#[derive(Debug, Copy, Clone, Default)]
pub struct NoopWitnessSolver;

impl WitnessSolver for NoopWitnessSolver {
    fn id(&self) -> &'static str {
        "noop"
    }

    fn solve(&self, _program: &Program, partial: &Witness) -> ZkfResult<Witness> {
        Ok(partial.clone())
    }
}

pub fn solve_witness(
    program: &Program,
    inputs: &WitnessInputs,
    solver: &dyn WitnessSolver,
) -> ZkfResult<Witness> {
    let partial = generate_partial_witness(program, inputs)?;
    solver.solve(program, &partial)
}

pub fn solve_and_validate_witness(
    program: &Program,
    inputs: &WitnessInputs,
    solver: &dyn WitnessSolver,
) -> ZkfResult<Witness> {
    let witness = solve_witness(program, inputs, solver)?;
    ensure_witness_completeness(program, &witness)?;
    check_constraints(program, &witness)?;
    Ok(witness)
}

pub fn available_solvers() -> Vec<&'static str> {
    vec![
        "noop",
        #[cfg(feature = "acvm-solver-beta9")]
        "acvm-beta9",
        #[cfg(feature = "acvm-solver")]
        "acvm",
    ]
}

pub fn solver_by_name(name: &str) -> ZkfResult<Box<dyn WitnessSolver>> {
    match name {
        "noop" | "manual" => Ok(Box::new(NoopWitnessSolver)),
        "acvm-beta9" | "beta9-acvm" => {
            #[cfg(feature = "acvm-solver-beta9")]
            {
                Ok(Box::new(acvm_beta9_adapter::AcvmBeta9WitnessSolver))
            }
            #[cfg(not(feature = "acvm-solver-beta9"))]
            {
                Err(ZkfError::FeatureDisabled {
                    backend: "solver:acvm-beta9".to_string(),
                })
            }
        }
        "acvm" => {
            #[cfg(feature = "acvm-solver")]
            {
                Ok(Box::new(acvm_adapter::AcvmWitnessSolver))
            }
            #[cfg(not(feature = "acvm-solver"))]
            {
                Err(ZkfError::FeatureDisabled {
                    backend: "solver:acvm".to_string(),
                })
            }
        }
        other => Err(ZkfError::UnsupportedBackend {
            backend: format!("solver:{other}"),
            message: format!(
                "unknown witness solver '{other}', available: {}",
                available_solvers().join(", ")
            ),
        }),
    }
}

#[cfg(feature = "acvm-solver")]
pub mod acvm_adapter {
    use super::WitnessSolver;
    use acvm::acir::FieldElement as AcirFieldElement;
    use acvm::acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
    use acvm::acir::circuit::{Circuit, ExpressionWidth, Opcode, PublicInputs};
    use acvm::acir::native_types::{Expression, Witness as AcirWitness, WitnessMap};
    use acvm::pwg::{ACVM, ACVMStatus};
    use bn254_blackbox_solver::Bn254BlackBoxSolver;
    use num_bigint::{BigInt, Sign};
    use num_traits::{One, Zero};
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use crate::{
        BlackBoxOp, Constraint, Expr, FieldElement, FieldId, Program, Witness, ZkfError, ZkfResult,
        field::normalize_mod,
    };

    #[derive(Debug, Copy, Clone, Default)]
    pub struct AcvmWitnessSolver;

    impl WitnessSolver for AcvmWitnessSolver {
        fn id(&self) -> &'static str {
            "acvm"
        }

        fn solve(&self, program: &Program, partial: &Witness) -> ZkfResult<Witness> {
            if program.field != FieldId::Bn254 {
                return Err(ZkfError::UnsupportedBackend {
                    backend: "solver:acvm".to_string(),
                    message: format!(
                        "ACVM solver currently supports BN254 programs only; found {}",
                        program.field
                    ),
                });
            }

            let lowered = lower_program_to_acir(program)?;
            let initial_witness = to_witness_map(program, partial, &lowered.signal_to_witness)?;
            let backend = Bn254BlackBoxSolver::default();
            let mut vm = ACVM::new(
                &backend,
                &lowered.circuit.opcodes,
                initial_witness,
                &[],
                &lowered.circuit.assert_messages,
            );

            loop {
                match vm.solve() {
                    ACVMStatus::Solved => break,
                    ACVMStatus::InProgress => continue,
                    ACVMStatus::Failure(err) => {
                        return Err(ZkfError::Backend(format!("ACVM solver failed: {}", err)));
                    }
                    ACVMStatus::RequiresForeignCall(call) => {
                        return Err(ZkfError::UnsupportedBackend {
                            backend: "solver:acvm".to_string(),
                            message: format!(
                                "ACVM solver encountered unresolved foreign call '{}'",
                                call.function
                            ),
                        });
                    }
                    ACVMStatus::RequiresAcirCall(_) => {
                        return Err(ZkfError::UnsupportedBackend {
                            backend: "solver:acvm".to_string(),
                            message: "ACVM solver generated an unexpected ACIR call during solving"
                                .to_string(),
                        });
                    }
                }
            }

            let solved = vm.finalize();
            let mut values = BTreeMap::new();
            for (signal, witness) in &lowered.signal_to_witness {
                if let Some(value) = solved.get(witness) {
                    values.insert(signal.clone(), acir_field_to_field_element(*value));
                }
            }
            Ok(Witness { values })
        }
    }

    #[derive(Debug)]
    struct LoweredAcirProgram {
        circuit: Circuit,
        signal_to_witness: HashMap<String, AcirWitness>,
    }

    #[derive(Debug)]
    struct LoweringContext<'a> {
        signal_to_witness: &'a HashMap<String, AcirWitness>,
        opcodes: Vec<Opcode>,
        next_witness_index: u32,
    }

    impl<'a> LoweringContext<'a> {
        fn witness_for_signal(&self, signal: &str) -> ZkfResult<AcirWitness> {
            self.signal_to_witness
                .get(signal)
                .copied()
                .ok_or_else(|| ZkfError::UnknownSignal {
                    signal: signal.to_string(),
                })
        }

        fn allocate_aux_witness(&mut self) -> AcirWitness {
            let witness = AcirWitness(self.next_witness_index);
            self.next_witness_index += 1;
            witness
        }
    }

    #[derive(Debug, Clone)]
    struct QuadExpr {
        constant: BigInt,
        linear: HashMap<u32, BigInt>,
        quadratic: HashMap<(u32, u32), BigInt>,
    }

    impl QuadExpr {
        fn zero() -> Self {
            Self {
                constant: BigInt::zero(),
                linear: HashMap::new(),
                quadratic: HashMap::new(),
            }
        }

        fn constant(value: BigInt) -> Self {
            let mut out = Self::zero();
            out.constant = value;
            out
        }

        fn signal(index: u32) -> Self {
            let mut out = Self::zero();
            out.linear.insert(index, BigInt::one());
            out
        }

        fn add(mut self, rhs: Self) -> Self {
            self.constant += rhs.constant;
            for (witness, coeff) in rhs.linear {
                *self.linear.entry(witness).or_insert_with(BigInt::zero) += coeff;
            }
            for (term, coeff) in rhs.quadratic {
                *self.quadratic.entry(term).or_insert_with(BigInt::zero) += coeff;
            }
            self
        }

        fn sub(mut self, rhs: Self) -> Self {
            self.constant -= rhs.constant;
            for (witness, coeff) in rhs.linear {
                *self.linear.entry(witness).or_insert_with(BigInt::zero) -= coeff;
            }
            for (term, coeff) in rhs.quadratic {
                *self.quadratic.entry(term).or_insert_with(BigInt::zero) -= coeff;
            }
            self
        }

        fn mul(self, rhs: Self) -> ZkfResult<Self> {
            if !self.quadratic.is_empty() && !rhs.is_constant_only() {
                return Err(ZkfError::UnsupportedBackend {
                    backend: "solver:acvm".to_string(),
                    message: "expression degree exceeds ACIR quadratic form".to_string(),
                });
            }
            if !rhs.quadratic.is_empty() && !self.is_constant_only() {
                return Err(ZkfError::UnsupportedBackend {
                    backend: "solver:acvm".to_string(),
                    message: "expression degree exceeds ACIR quadratic form".to_string(),
                });
            }

            let left = self;
            let right = rhs;
            let mut out = QuadExpr::zero();
            out.constant = &left.constant * &right.constant;

            for (witness, coeff) in &left.linear {
                *out.linear.entry(*witness).or_insert_with(BigInt::zero) += coeff * &right.constant;
            }
            for (witness, coeff) in &right.linear {
                *out.linear.entry(*witness).or_insert_with(BigInt::zero) += coeff * &left.constant;
            }

            for ((a, b), coeff) in &left.quadratic {
                *out.quadratic.entry((*a, *b)).or_insert_with(BigInt::zero) +=
                    coeff * &right.constant;
            }
            for ((a, b), coeff) in &right.quadratic {
                *out.quadratic.entry((*a, *b)).or_insert_with(BigInt::zero) +=
                    coeff * &left.constant;
            }

            for (left_witness, left_coeff) in &left.linear {
                for (right_witness, right_coeff) in &right.linear {
                    let key = if left_witness <= right_witness {
                        (*left_witness, *right_witness)
                    } else {
                        (*right_witness, *left_witness)
                    };
                    *out.quadratic.entry(key).or_insert_with(BigInt::zero) +=
                        left_coeff * right_coeff;
                }
            }

            out.prune_zeros();
            Ok(out)
        }

        fn is_constant_only(&self) -> bool {
            self.linear.is_empty() && self.quadratic.is_empty()
        }

        fn prune_zeros(&mut self) {
            self.linear.retain(|_, coeff| !coeff.is_zero());
            self.quadratic.retain(|_, coeff| !coeff.is_zero());
            if self.constant.is_zero() {
                self.constant = BigInt::zero();
            }
        }
    }

    fn lower_program_to_acir(program: &Program) -> ZkfResult<LoweredAcirProgram> {
        let mut signal_to_witness = HashMap::new();
        for (index, signal) in program.signals.iter().enumerate() {
            signal_to_witness.insert(signal.name.clone(), AcirWitness(index as u32));
        }

        let mut lowering = LoweringContext {
            signal_to_witness: &signal_to_witness,
            opcodes: Vec::new(),
            next_witness_index: program.signals.len() as u32,
        };
        for constraint in &program.constraints {
            lower_constraint_to_opcodes(constraint, &mut lowering)?;
        }

        let private_parameters = program
            .signals
            .iter()
            .enumerate()
            .map(|(index, _)| AcirWitness(index as u32))
            .collect::<BTreeSet<_>>();
        let public_parameters = PublicInputs(
            program
                .signals
                .iter()
                .enumerate()
                .filter_map(|(index, signal)| {
                    if matches!(signal.visibility, crate::Visibility::Public) {
                        Some(AcirWitness(index as u32))
                    } else {
                        None
                    }
                })
                .collect(),
        );

        let circuit = Circuit {
            current_witness_index: if lowering.next_witness_index == 0 {
                0
            } else {
                lowering.next_witness_index - 1
            },
            opcodes: lowering.opcodes,
            expression_width: ExpressionWidth::Unbounded,
            private_parameters,
            public_parameters,
            return_values: PublicInputs(BTreeSet::new()),
            assert_messages: Vec::new(),
            recursive: false,
        };
        Ok(LoweredAcirProgram {
            circuit,
            signal_to_witness,
        })
    }

    fn lower_constraint_to_opcodes(
        constraint: &Constraint,
        lowering: &mut LoweringContext<'_>,
    ) -> ZkfResult<()> {
        match constraint {
            Constraint::Equal { lhs, rhs, .. } => {
                let lhs_quad = lower_expr_to_quad(lhs, lowering)?;
                let rhs_quad = lower_expr_to_quad(rhs, lowering)?;
                let diff = lhs_quad.sub(rhs_quad);
                lowering
                    .opcodes
                    .push(Opcode::AssertZero(quad_to_acir_expression(diff)));
            }
            Constraint::Boolean { signal, .. } => {
                let witness = lowering.witness_for_signal(signal)?;
                let expression = Expression {
                    mul_terms: vec![(AcirFieldElement::one(), witness, witness)],
                    linear_combinations: vec![(AcirFieldElement::from(-1_i128), witness)],
                    q_c: AcirFieldElement::zero(),
                };
                // x * (1 - x) = 0 expands to x^2 - x = 0
                lowering.opcodes.push(Opcode::AssertZero(expression));
            }
            Constraint::Range { signal, bits, .. } => {
                let witness = lowering.witness_for_signal(signal)?;
                lowering
                    .opcodes
                    .push(Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                        input: FunctionInput {
                            witness,
                            num_bits: *bits,
                        },
                    }));
            }
            Constraint::BlackBox {
                op,
                inputs,
                outputs,
                params,
                ..
            } => lower_blackbox_constraint(*op, inputs, outputs, params, lowering)?,
            Constraint::Lookup { .. } => {
                return Err(crate::ZkfError::Backend(
                    "Lookup constraint must be lowered before ACIR synthesis; \
                     call lower_lookup_constraints() first"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn lower_blackbox_constraint(
        op: BlackBoxOp,
        inputs: &[Expr],
        outputs: &[String],
        params: &BTreeMap<String, String>,
        lowering: &mut LoweringContext<'_>,
    ) -> ZkfResult<()> {
        let input_num_bits = parse_input_num_bits(params, inputs.len())?;
        let lowered_inputs = inputs
            .iter()
            .zip(input_num_bits.iter())
            .map(|(expr, bits)| lower_expr_to_function_input(expr, *bits, lowering))
            .collect::<ZkfResult<Vec<_>>>()?;

        let lowered_outputs = outputs
            .iter()
            .map(|name| lowering.witness_for_signal(name))
            .collect::<ZkfResult<Vec<_>>>()?;

        let call = match op {
            BlackBoxOp::Poseidon => {
                let state_len = parse_poseidon_state_len(
                    params,
                    lowered_inputs.len(),
                    lowered_outputs.len(),
                    "solver:acvm",
                )?;
                if lowered_inputs.len() != state_len as usize {
                    return Err(ZkfError::UnsupportedBackend {
                        backend: "solver:acvm".to_string(),
                        message: format!(
                            "poseidon expects {} inputs based on state length, found {}",
                            state_len,
                            lowered_inputs.len()
                        ),
                    });
                }
                if lowered_outputs.len() != state_len as usize {
                    return Err(ZkfError::UnsupportedBackend {
                        backend: "solver:acvm".to_string(),
                        message: format!(
                            "poseidon expects {} outputs based on state length, found {}",
                            state_len,
                            lowered_outputs.len()
                        ),
                    });
                }
                BlackBoxFuncCall::Poseidon2Permutation {
                    inputs: lowered_inputs,
                    outputs: lowered_outputs,
                    len: state_len,
                }
            }
            BlackBoxOp::Sha256 => BlackBoxFuncCall::SHA256 {
                inputs: lowered_inputs,
                outputs: witnesses_array::<32>(
                    lowered_outputs,
                    "solver:acvm",
                    "sha256 expects 32 outputs",
                )?,
            },
            BlackBoxOp::Blake2s => BlackBoxFuncCall::Blake2s {
                inputs: lowered_inputs,
                outputs: witnesses_array::<32>(
                    lowered_outputs,
                    "solver:acvm",
                    "blake2s expects 32 outputs",
                )?,
            },
            BlackBoxOp::Keccak256 => {
                if lowered_inputs.is_empty() {
                    return Err(ZkfError::UnsupportedBackend {
                        backend: "solver:acvm".to_string(),
                        message:
                            "keccak256 requires at least one input (message size input missing)"
                                .to_string(),
                    });
                }
                let message_len = params
                    .get("keccak_message_inputs_len")
                    .and_then(|raw| raw.parse::<usize>().ok())
                    .unwrap_or(lowered_inputs.len().saturating_sub(1));
                if message_len >= lowered_inputs.len() {
                    return Err(ZkfError::UnsupportedBackend {
                        backend: "solver:acvm".to_string(),
                        message:
                            "keccak256 metadata is invalid: message input length does not leave var_message_size"
                                .to_string(),
                    });
                }
                let (message_inputs, size_input) = lowered_inputs.split_at(message_len);
                BlackBoxFuncCall::Keccak256 {
                    inputs: message_inputs.to_vec(),
                    var_message_size: size_input[0],
                    outputs: witnesses_array::<32>(
                        lowered_outputs,
                        "solver:acvm",
                        "keccak256 expects 32 outputs",
                    )?,
                }
            }
            BlackBoxOp::Pedersen => {
                let domain_separator = params
                    .get("domain_separator")
                    .and_then(|raw| raw.parse::<u32>().ok())
                    .unwrap_or(0);
                match lowered_outputs.len() {
                    1 => BlackBoxFuncCall::PedersenHash {
                        inputs: lowered_inputs,
                        domain_separator,
                        output: lowered_outputs[0],
                    },
                    2 => BlackBoxFuncCall::PedersenCommitment {
                        inputs: lowered_inputs,
                        domain_separator,
                        outputs: (lowered_outputs[0], lowered_outputs[1]),
                    },
                    count => {
                        return Err(ZkfError::UnsupportedBackend {
                            backend: "solver:acvm".to_string(),
                            message: format!(
                                "pedersen expects 1 (hash) or 2 (commitment) outputs, found {count}"
                            ),
                        });
                    }
                }
            }
            BlackBoxOp::SchnorrVerify => {
                if lowered_inputs.len() < 66 {
                    return Err(ZkfError::UnsupportedBackend {
                        backend: "solver:acvm".to_string(),
                        message: format!(
                            "schnorr_verify expects at least 66 inputs (pkx,pky,64-byte signature,message), found {}",
                            lowered_inputs.len()
                        ),
                    });
                }
                if lowered_outputs.len() != 1 {
                    return Err(ZkfError::UnsupportedBackend {
                        backend: "solver:acvm".to_string(),
                        message: format!(
                            "schnorr_verify expects 1 output, found {}",
                            lowered_outputs.len()
                        ),
                    });
                }
                let public_key_x = lowered_inputs[0];
                let public_key_y = lowered_inputs[1];
                let signature = function_input_array::<64>(
                    lowered_inputs[2..66].to_vec(),
                    "solver:acvm",
                    "schnorr_verify expects a 64-byte signature",
                )?;
                let message = lowered_inputs[66..].to_vec();
                BlackBoxFuncCall::SchnorrVerify {
                    public_key_x,
                    public_key_y,
                    signature,
                    message,
                    output: lowered_outputs[0],
                }
            }
            BlackBoxOp::EcdsaSecp256k1 | BlackBoxOp::EcdsaSecp256r1 => {
                if lowered_inputs.len() != 160 {
                    return Err(ZkfError::UnsupportedBackend {
                        backend: "solver:acvm".to_string(),
                        message: format!(
                            "{} expects exactly 160 inputs (32 pkx + 32 pky + 64 sig + 32 hash), found {}",
                            op.as_str(),
                            lowered_inputs.len()
                        ),
                    });
                }
                if lowered_outputs.len() != 1 {
                    return Err(ZkfError::UnsupportedBackend {
                        backend: "solver:acvm".to_string(),
                        message: format!(
                            "{} expects 1 output, found {}",
                            op.as_str(),
                            lowered_outputs.len()
                        ),
                    });
                }
                let public_key_x = function_input_array::<32>(
                    lowered_inputs[0..32].to_vec(),
                    "solver:acvm",
                    "ecdsa public key x must have 32 bytes",
                )?;
                let public_key_y = function_input_array::<32>(
                    lowered_inputs[32..64].to_vec(),
                    "solver:acvm",
                    "ecdsa public key y must have 32 bytes",
                )?;
                let signature = function_input_array::<64>(
                    lowered_inputs[64..128].to_vec(),
                    "solver:acvm",
                    "ecdsa signature must have 64 bytes",
                )?;
                let hashed_message = function_input_array::<32>(
                    lowered_inputs[128..160].to_vec(),
                    "solver:acvm",
                    "ecdsa hashed message must have 32 bytes",
                )?;
                match op {
                    BlackBoxOp::EcdsaSecp256k1 => BlackBoxFuncCall::EcdsaSecp256k1 {
                        public_key_x,
                        public_key_y,
                        signature,
                        hashed_message,
                        output: lowered_outputs[0],
                    },
                    BlackBoxOp::EcdsaSecp256r1 => BlackBoxFuncCall::EcdsaSecp256r1 {
                        public_key_x,
                        public_key_y,
                        signature,
                        hashed_message,
                        output: lowered_outputs[0],
                    },
                    _ => unreachable!(),
                }
            }
            BlackBoxOp::RecursiveAggregationMarker => {
                return Err(ZkfError::UnsupportedBackend {
                    backend: "solver:acvm".to_string(),
                    message:
                        "recursive_aggregation_marker requires recursive proof composition and is not solvable in ACVM witness solver"
                            .to_string(),
                });
            }
            BlackBoxOp::ScalarMulG1 | BlackBoxOp::PointAddG1 | BlackBoxOp::PairingCheck => {
                return Err(ZkfError::UnsupportedBackend {
                    backend: "solver:acvm".to_string(),
                    message: format!(
                        "{} is a circuit-level EC operation handled by the proving backend, not solvable in ACVM witness solver",
                        op.as_str()
                    ),
                });
            }
        };
        lowering.opcodes.push(Opcode::BlackBoxFuncCall(call));
        Ok(())
    }

    fn lower_expr_to_function_input(
        expr: &Expr,
        num_bits: u32,
        lowering: &mut LoweringContext<'_>,
    ) -> ZkfResult<FunctionInput> {
        if let Expr::Signal(name) = expr {
            return Ok(FunctionInput {
                witness: lowering.witness_for_signal(name)?,
                num_bits,
            });
        }
        let lowered = lower_expr_to_quad(expr, lowering)?;
        let aux = lowering.allocate_aux_witness();
        let relation = QuadExpr::signal(aux.0).sub(lowered);
        lowering
            .opcodes
            .push(Opcode::AssertZero(quad_to_acir_expression(relation)));
        Ok(FunctionInput {
            witness: aux,
            num_bits,
        })
    }

    fn parse_input_num_bits(params: &BTreeMap<String, String>, len: usize) -> ZkfResult<Vec<u32>> {
        let default_bits = 254u32;
        let Some(raw) = params.get("input_num_bits") else {
            return Ok(vec![default_bits; len]);
        };
        if raw.trim().is_empty() {
            return Ok(vec![default_bits; len]);
        }
        let parsed = raw
            .split(',')
            .map(|segment| {
                segment
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| ZkfError::UnsupportedBackend {
                        backend: "solver:acvm".to_string(),
                        message: format!("invalid input_num_bits entry '{segment}'"),
                    })
            })
            .collect::<ZkfResult<Vec<_>>>()?;
        if parsed.len() != len {
            return Err(ZkfError::UnsupportedBackend {
                backend: "solver:acvm".to_string(),
                message: format!(
                    "input_num_bits length mismatch: expected {len}, found {}",
                    parsed.len()
                ),
            });
        }
        Ok(parsed)
    }

    fn parse_poseidon_state_len(
        params: &BTreeMap<String, String>,
        input_len: usize,
        output_len: usize,
        backend: &str,
    ) -> ZkfResult<u32> {
        if let Some(raw) = params.get("state_len").or_else(|| params.get("len")) {
            return raw
                .trim()
                .parse::<u32>()
                .map_err(|_| ZkfError::UnsupportedBackend {
                    backend: backend.to_string(),
                    message: format!("invalid poseidon state length '{raw}'"),
                });
        }

        if input_len == output_len {
            return u32::try_from(input_len).map_err(|_| ZkfError::UnsupportedBackend {
                backend: backend.to_string(),
                message: format!(
                    "poseidon state length {} exceeds supported u32 range",
                    input_len
                ),
            });
        }

        Err(ZkfError::UnsupportedBackend {
            backend: backend.to_string(),
            message: format!(
                "poseidon requires explicit state length (input_count={input_len}, output_count={output_len})"
            ),
        })
    }

    fn witnesses_array<const N: usize>(
        values: Vec<AcirWitness>,
        backend: &str,
        context: &str,
    ) -> ZkfResult<Box<[AcirWitness; N]>> {
        values
            .try_into()
            .map(Box::new)
            .map_err(|_| ZkfError::UnsupportedBackend {
                backend: backend.to_string(),
                message: context.to_string(),
            })
    }

    fn function_input_array<const N: usize>(
        values: Vec<FunctionInput>,
        backend: &str,
        context: &str,
    ) -> ZkfResult<Box<[FunctionInput; N]>> {
        values
            .try_into()
            .map(Box::new)
            .map_err(|_| ZkfError::UnsupportedBackend {
                backend: backend.to_string(),
                message: context.to_string(),
            })
    }

    fn lower_expr_to_quad(expr: &Expr, lowering: &mut LoweringContext<'_>) -> ZkfResult<QuadExpr> {
        match expr {
            Expr::Const(value) => {
                let constant = value.to_bigint().map_err(|_| ZkfError::ParseField {
                    value: value.to_decimal_string(),
                })?;
                Ok(QuadExpr::constant(constant))
            }
            Expr::Signal(name) => {
                let witness = lowering.witness_for_signal(name)?;
                Ok(QuadExpr::signal(witness.0))
            }
            Expr::Add(parts) => {
                let mut out = QuadExpr::zero();
                for part in parts {
                    out = out.add(lower_expr_to_quad(part, lowering)?);
                }
                Ok(out)
            }
            Expr::Sub(lhs, rhs) => {
                Ok(lower_expr_to_quad(lhs, lowering)?.sub(lower_expr_to_quad(rhs, lowering)?))
            }
            Expr::Mul(lhs, rhs) => {
                lower_expr_to_quad(lhs, lowering)?.mul(lower_expr_to_quad(rhs, lowering)?)
            }
            Expr::Div(lhs, rhs) => {
                let numerator = lower_expr_to_quad(lhs, lowering)?;
                let denominator = lower_expr_to_quad(rhs, lowering)?;
                if !denominator.quadratic.is_empty() {
                    return Err(ZkfError::UnsupportedBackend {
                        backend: "solver:acvm".to_string(),
                        message: "ACVM solver division requires denominator to be linear"
                            .to_string(),
                    });
                }

                let quotient_witness = lowering.allocate_aux_witness();
                let quotient = QuadExpr::signal(quotient_witness.0);
                let relation = denominator.clone().mul(quotient)?.sub(numerator);
                lowering
                    .opcodes
                    .push(Opcode::AssertZero(quad_to_acir_expression(relation)));

                Ok(QuadExpr::signal(quotient_witness.0))
            }
        }
    }

    fn quad_to_acir_expression(mut expr: QuadExpr) -> Expression {
        expr.prune_zeros();
        let mut mul_terms = expr
            .quadratic
            .into_iter()
            .map(|((lhs, rhs), coeff)| {
                (
                    bigint_to_acir_field(coeff),
                    AcirWitness(lhs),
                    AcirWitness(rhs),
                )
            })
            .collect::<Vec<_>>();
        mul_terms.sort_by_key(|(_, lhs, rhs)| (lhs.0, rhs.0));

        let mut linear_combinations = expr
            .linear
            .into_iter()
            .map(|(witness, coeff)| (bigint_to_acir_field(coeff), AcirWitness(witness)))
            .collect::<Vec<_>>();
        linear_combinations.sort_by_key(|(_, witness)| witness.0);

        Expression {
            mul_terms,
            linear_combinations,
            q_c: bigint_to_acir_field(expr.constant),
        }
    }

    fn bigint_to_acir_field(value: BigInt) -> AcirFieldElement {
        let normalized = normalize_mod(value, FieldId::Bn254.modulus());
        let (_, mut bytes) = normalized.to_bytes_be();
        if bytes.is_empty() {
            bytes.push(0);
        }
        AcirFieldElement::from_be_bytes_reduce(&bytes)
    }

    fn acir_field_to_field_element(value: AcirFieldElement) -> FieldElement {
        let bigint = BigInt::from_bytes_be(Sign::Plus, &value.to_be_bytes());
        FieldElement::from_bigint_with_field(bigint, FieldId::Bn254)
    }

    fn to_witness_map(
        program: &Program,
        partial: &Witness,
        signal_to_witness: &HashMap<String, AcirWitness>,
    ) -> ZkfResult<WitnessMap> {
        let mut map = WitnessMap::new();

        for signal in &program.signals {
            let value = partial
                .values
                .get(&signal.name)
                .or(signal.constant.as_ref());
            let Some(value) = value else {
                continue;
            };
            let witness =
                signal_to_witness
                    .get(&signal.name)
                    .ok_or_else(|| ZkfError::UnknownSignal {
                        signal: signal.name.clone(),
                    })?;

            let bigint = value.normalized_bigint(FieldId::Bn254)?;
            let (_, mut bytes) = bigint.to_bytes_be();
            if bytes.is_empty() {
                bytes.push(0);
            }
            map.insert(*witness, AcirFieldElement::from_be_bytes_reduce(&bytes));
        }

        Ok(map)
    }
}
