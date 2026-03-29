#![allow(dead_code)]

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpecPlonky3FieldId {
    Goldilocks,
    BabyBear,
    Mersenne31,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpecVisibility {
    Public,
    Private,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpecSignal {
    pub signal_name: String,
    pub signal_visibility: SpecVisibility,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpecExpr {
    Const(u64),
    Signal(String),
    Add(Vec<SpecExpr>),
    Sub(Box<SpecExpr>, Box<SpecExpr>),
    Mul(Box<SpecExpr>, Box<SpecExpr>),
    Div(Box<SpecExpr>, Box<SpecExpr>),
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpecConstraint {
    Equal {
        equal_lhs: SpecExpr,
        equal_rhs: SpecExpr,
    },
    Boolean {
        boolean_signal: String,
    },
    Range {
        range_signal: String,
        range_bits: u32,
    },
    BlackBox,
    Lookup,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpecProgram {
    pub program_field: SpecPlonky3FieldId,
    pub program_signals: Vec<SpecSignal>,
    pub program_constraints: Vec<SpecConstraint>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpecWitness {
    pub witness_values: Vec<(String, u64)>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpecPlonky3LoweringError {
    UnknownSignal(String),
    UnsupportedRangeBits {
        unsupported_field: SpecPlonky3FieldId,
        unsupported_bits: u32,
        unsupported_max_bits: u32,
    },
    UnsupportedConstraint(String),
    DivisionByZero,
    MissingWitnessValue(String),
    BaseSignalCountOutOfBounds {
        offending_base_signal_count: usize,
        available_lowered_width: usize,
    },
    PublicInputIndexOutOfBounds {
        offending_public_index: usize,
        available_base_signal_count: usize,
    },
    RowIndexOutOfBounds {
        offending_row_index: usize,
        available_row_len: usize,
    },
    DerivedSourceIndexOutOfBounds {
        offending_source_index: usize,
        available_base_signal_count: usize,
    },
    DerivedTargetIndexOutOfBounds {
        offending_derived_index: usize,
        available_lowered_width: usize,
    },
    MalformedLoweredProgram(String),
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AirExpr {
    Const(u64),
    Signal(usize),
    Add(Vec<AirExpr>),
    Sub(Box<AirExpr>, Box<AirExpr>),
    Mul(Box<AirExpr>, Box<AirExpr>),
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DerivedComputation {
    Division {
        division_numerator: AirExpr,
        division_denominator: AirExpr,
    },
    RangeBit {
        range_source_index: usize,
        range_bit: u32,
    },
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedColumn {
    pub derived_index: usize,
    pub derived_computation: DerivedComputation,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoweredProgram {
    pub lowered_base_signal_count: usize,
    pub lowered_signal_order: Vec<String>,
    pub lowered_public_signal_indices: Vec<usize>,
    pub lowered_constraints: Vec<AirExpr>,
    pub lowered_derived_columns: Vec<DerivedColumn>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LoweringContext {
    context_field: SpecPlonky3FieldId,
    context_signal_order: Vec<String>,
    context_signal_indices: Vec<(String, usize)>,
    context_public_signal_indices: Vec<usize>,
    context_constraints: Vec<AirExpr>,
    context_derived_columns: Vec<DerivedColumn>,
}

#[cfg_attr(hax, hax_lib::include)]
pub fn plonky3_supported_field(_field: SpecPlonky3FieldId) -> bool {
    true
}

#[cfg_attr(hax, hax_lib::include)]
pub fn field_modulus_u64(field: SpecPlonky3FieldId) -> u64 {
    match field {
        SpecPlonky3FieldId::Goldilocks => 18_446_744_069_414_584_321u64,
        SpecPlonky3FieldId::BabyBear => 2_013_265_921u64,
        SpecPlonky3FieldId::Mersenne31 => 2_147_483_647u64,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn max_safe_range_bits(field: SpecPlonky3FieldId) -> u32 {
    match field {
        SpecPlonky3FieldId::Goldilocks => 63,
        SpecPlonky3FieldId::BabyBear => 30,
        SpecPlonky3FieldId::Mersenne31 => 30,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn add_mod_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    let rhs_complement = modulus - rhs;
    if lhs >= rhs_complement {
        lhs - rhs_complement
    } else {
        lhs + rhs
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn sub_mod_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    if lhs >= rhs {
        lhs - rhs
    } else {
        add_mod_u64(modulus - rhs, lhs, modulus)
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn fixed_bit_steps() -> Vec<()> {
    vec![(); 64]
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MulState {
    mul_lhs: u64,
    mul_rhs: u64,
    mul_acc: u64,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InverseState {
    inverse_base: u64,
    inverse_exp: u64,
    inverse_acc: u64,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pow2State {
    pow2_remaining_bit: u32,
    pow2_acc: u64,
}

#[cfg_attr(hax, hax_lib::include)]
pub fn mul_mod_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    let mut state = MulState {
        mul_lhs: lhs,
        mul_rhs: rhs,
        mul_acc: 0,
    };
    for _ in fixed_bit_steps() {
        if state.mul_rhs != 0 {
            let next_acc = if state.mul_rhs & 1 == 1 {
                add_mod_u64(state.mul_acc, state.mul_lhs, modulus)
            } else {
                state.mul_acc
            };
            let next_lhs = add_mod_u64(state.mul_lhs, state.mul_lhs, modulus);
            state = MulState {
                mul_lhs: next_lhs,
                mul_rhs: state.mul_rhs >> 1u32,
                mul_acc: next_acc,
            };
        } else {
            state = MulState {
                mul_lhs: state.mul_lhs,
                mul_rhs: state.mul_rhs,
                mul_acc: state.mul_acc,
            };
        }
    }
    state.mul_acc
}

#[cfg_attr(hax, hax_lib::include)]
pub fn mod_inverse_u64(value: u64, modulus: u64) -> Option<u64> {
    if value == 0 {
        None
    } else {
        let mut state = InverseState {
            inverse_base: value,
            inverse_exp: modulus - 2,
            inverse_acc: 1,
        };
        for _ in fixed_bit_steps() {
            if state.inverse_exp != 0 {
                let next_acc = if state.inverse_exp & 1 == 1 {
                    mul_mod_u64(state.inverse_acc, state.inverse_base, modulus)
                } else {
                    state.inverse_acc
                };
                let next_base = mul_mod_u64(state.inverse_base, state.inverse_base, modulus);
                state = InverseState {
                    inverse_base: next_base,
                    inverse_exp: state.inverse_exp >> 1u32,
                    inverse_acc: next_acc,
                };
            } else {
                state = InverseState {
                    inverse_base: state.inverse_base,
                    inverse_exp: state.inverse_exp,
                    inverse_acc: state.inverse_acc,
                };
            }
        }
        Some(state.inverse_acc)
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn row_value_at(row: &[u64], row_index: usize) -> Result<u64, SpecPlonky3LoweringError> {
    match row.get(row_index) {
        Some(value) => Ok(*value),
        None => Err(SpecPlonky3LoweringError::RowIndexOutOfBounds {
            offending_row_index: row_index,
            available_row_len: row.len(),
        }),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn row_value_set(
    row: &mut [u64],
    row_index: usize,
    value: u64,
) -> Result<(), SpecPlonky3LoweringError> {
    if row_index < row.len() {
        row[row_index] = value;
        Ok(())
    } else {
        Err(SpecPlonky3LoweringError::DerivedTargetIndexOutOfBounds {
            offending_derived_index: row_index,
            available_lowered_width: row.len(),
        })
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn eval_air_expr_concrete(
    expr: &AirExpr,
    row: &[u64],
    modulus: u64,
) -> Result<u64, SpecPlonky3LoweringError> {
    match expr {
        AirExpr::Const(value) => Ok(*value % modulus),
        AirExpr::Signal(index) => row_value_at(row, *index),
        AirExpr::Add(values) => {
            let mut acc = 0;
            let mut error = None;
            for value in values.iter() {
                if error.is_none() {
                    match eval_air_expr_concrete(value, row, modulus) {
                        Ok(item) => acc = add_mod_u64(acc, item, modulus),
                        Err(err) => error = Some(err),
                    }
                }
            }
            match error {
                Some(err) => Err(err),
                None => Ok(acc),
            }
        }
        AirExpr::Sub(lhs, rhs) => match eval_air_expr_concrete(lhs, row, modulus) {
            Ok(lhs_value) => match eval_air_expr_concrete(rhs, row, modulus) {
                Ok(rhs_value) => Ok(sub_mod_u64(lhs_value, rhs_value, modulus)),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        },
        AirExpr::Mul(lhs, rhs) => match eval_air_expr_concrete(lhs, row, modulus) {
            Ok(lhs_value) => match eval_air_expr_concrete(rhs, row, modulus) {
                Ok(rhs_value) => Ok(mul_mod_u64(lhs_value, rhs_value, modulus)),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        },
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn lookup_signal_index(signal_indices: &[(String, usize)], name: &String) -> Option<usize> {
    let mut found = None;
    for (current_name, current_index) in signal_indices.iter() {
        if found.is_none() && current_name == name {
            found = Some(*current_index);
        }
    }
    found
}

#[cfg_attr(hax, hax_lib::include)]
fn lookup_witness_value(values: &[(String, u64)], name: &String) -> Option<u64> {
    let mut found = None;
    for (current_name, current_value) in values.iter() {
        if found.is_none() && current_name == name {
            found = Some(*current_value);
        }
    }
    found
}

#[cfg_attr(hax, hax_lib::include)]
fn constraints_supported(
    constraints: &[SpecConstraint],
    signal_indices: &[(String, usize)],
    field: SpecPlonky3FieldId,
) -> bool {
    let mut supported = true;
    for constraint in constraints.iter() {
        if supported {
            supported = match constraint {
                SpecConstraint::Equal {
                    equal_lhs,
                    equal_rhs,
                } => {
                    expr_is_supported(equal_lhs, signal_indices)
                        && expr_is_supported(equal_rhs, signal_indices)
                }
                SpecConstraint::Boolean { boolean_signal } => {
                    lookup_signal_index(signal_indices, boolean_signal).is_some()
                }
                SpecConstraint::Range {
                    range_signal,
                    range_bits,
                } => {
                    lookup_signal_index(signal_indices, range_signal).is_some()
                        && *range_bits <= max_safe_range_bits(field)
                }
                SpecConstraint::BlackBox | SpecConstraint::Lookup => false,
            };
        }
    }
    supported
}

#[cfg_attr(hax, hax_lib::include)]
fn pow2_u64(bit: u32) -> u64 {
    let mut state = Pow2State {
        pow2_remaining_bit: bit,
        pow2_acc: 1,
    };
    for _ in fixed_bit_steps() {
        if state.pow2_remaining_bit == 0 {
            state = Pow2State {
                pow2_remaining_bit: state.pow2_remaining_bit,
                pow2_acc: state.pow2_acc,
            };
        } else {
            state = Pow2State {
                pow2_remaining_bit: state.pow2_remaining_bit - 1,
                pow2_acc: add_mod_u64(state.pow2_acc, state.pow2_acc, u64::MAX),
            };
        }
    }
    state.pow2_acc
}

#[cfg_attr(hax, hax_lib::include)]
fn range_bit_temp_name(signal: &String, current_bit: u32, bit_index: usize) -> String {
    #[cfg(hax)]
    {
        let _ = signal;
        let _ = current_bit;
        let _ = bit_index;
        "__range_bit_tmp".to_string()
    }
    #[cfg(not(hax))]
    {
        format!("__range_{}_bit_{}_{}", signal, current_bit, bit_index)
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn division_temp_name(derived_column_count: usize) -> String {
    #[cfg(hax)]
    {
        let _ = derived_column_count;
        "__div_tmp".to_string()
    }
    #[cfg(not(hax))]
    {
        format!("__div_tmp_{}", derived_column_count)
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn lower_range_bits(
    signal: &String,
    source_index: usize,
    bits: u32,
    context: &mut LoweringContext,
    mut recomposed_terms: Vec<AirExpr>,
) -> Result<Vec<AirExpr>, SpecPlonky3LoweringError> {
    for current_bit in 0..bits {
        let bit_index = context.context_signal_order.len();
        let bit_name = range_bit_temp_name(signal, current_bit, bit_index);
        context.context_signal_order.push(bit_name.clone());
        context.context_signal_indices.push((bit_name, bit_index));
        context.context_derived_columns.push(DerivedColumn {
            derived_index: bit_index,
            derived_computation: DerivedComputation::RangeBit {
                range_source_index: source_index,
                range_bit: current_bit,
            },
        });

        let bit_signal = AirExpr::Signal(bit_index);
        context.context_constraints.push(AirExpr::Mul(
            Box::new(bit_signal.clone()),
            Box::new(AirExpr::Sub(
                Box::new(AirExpr::Const(1)),
                Box::new(bit_signal.clone()),
            )),
        ));

        let weighted = if current_bit == 0 {
            bit_signal
        } else {
            let coefficient = pow2_u64(current_bit);
            AirExpr::Mul(Box::new(AirExpr::Const(coefficient)), Box::new(bit_signal))
        };
        let _ = signal;
        recomposed_terms.push(weighted);
    }
    Ok(recomposed_terms)
}

#[cfg_attr(hax, hax_lib::include)]
fn signal_indices_equal(lhs: &[usize], rhs: &[usize]) -> bool {
    let mut same = lhs.len() == rhs.len();
    for (index, lhs_head) in lhs.iter().enumerate() {
        if same {
            same = match rhs.get(index) {
                Some(rhs_head) => *rhs_head == *lhs_head,
                None => false,
            };
        }
    }
    same
}

#[cfg_attr(hax, hax_lib::include)]
pub fn validate_lowered_program(lowered: &LoweredProgram) -> Result<(), SpecPlonky3LoweringError> {
    let lowered_width = lowered.lowered_signal_order.len();
    if lowered.lowered_base_signal_count > lowered_width {
        Err(SpecPlonky3LoweringError::BaseSignalCountOutOfBounds {
            offending_base_signal_count: lowered.lowered_base_signal_count,
            available_lowered_width: lowered_width,
        })
    } else {
        let mut error = None;
        for public_index in lowered.lowered_public_signal_indices.iter() {
            if error.is_none() && *public_index >= lowered.lowered_base_signal_count {
                error = Some(SpecPlonky3LoweringError::PublicInputIndexOutOfBounds {
                    offending_public_index: *public_index,
                    available_base_signal_count: lowered.lowered_base_signal_count,
                });
            }
        }

        for derived in lowered.lowered_derived_columns.iter() {
            if error.is_none() {
                if derived.derived_index >= lowered_width {
                    error = Some(SpecPlonky3LoweringError::DerivedTargetIndexOutOfBounds {
                        offending_derived_index: derived.derived_index,
                        available_lowered_width: lowered_width,
                    });
                } else {
                    match &derived.derived_computation {
                        DerivedComputation::Division { .. } => {}
                        DerivedComputation::RangeBit {
                            range_source_index, ..
                        } => {
                            if *range_source_index >= lowered.lowered_base_signal_count {
                                error =
                                    Some(SpecPlonky3LoweringError::DerivedSourceIndexOutOfBounds {
                                        offending_source_index: *range_source_index,
                                        available_base_signal_count: lowered
                                            .lowered_base_signal_count,
                                    });
                            }
                        }
                    }
                }
            }
        }

        match error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn fill_derived_columns(
    derived_columns: &[DerivedColumn],
    row: &mut [u64],
    modulus: u64,
) -> Result<(), SpecPlonky3LoweringError> {
    let mut error = None;
    for derived in derived_columns.iter() {
        if error.is_none() {
            let next_value = match &derived.derived_computation {
                DerivedComputation::Division {
                    division_numerator,
                    division_denominator,
                } => match eval_air_expr_concrete(division_denominator, row, modulus) {
                    Ok(denominator) => match mod_inverse_u64(denominator, modulus) {
                        Some(inverse) => {
                            match eval_air_expr_concrete(division_numerator, row, modulus) {
                                Ok(numerator) => Some(mul_mod_u64(numerator, inverse, modulus)),
                                Err(err) => {
                                    error = Some(err);
                                    None
                                }
                            }
                        }
                        None => {
                            error = Some(SpecPlonky3LoweringError::DivisionByZero);
                            None
                        }
                    },
                    Err(err) => {
                        error = Some(err);
                        None
                    }
                },
                DerivedComputation::RangeBit {
                    range_source_index,
                    range_bit,
                } => match row_value_at(row, *range_source_index) {
                    Ok(source_value) => Some((source_value >> range_bit) & 1),
                    Err(err) => {
                        error = Some(err);
                        None
                    }
                },
            };
            if let Some(value) = next_value
                && let Err(err) = row_value_set(row, derived.derived_index, value)
            {
                error = Some(err);
            }
        }
    }
    match error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn signal_expr(
    name: &String,
    signal_indices: &[(String, usize)],
) -> Result<AirExpr, SpecPlonky3LoweringError> {
    match lookup_signal_index(signal_indices, name) {
        Some(index) => Ok(AirExpr::Signal(index)),
        None => Err(SpecPlonky3LoweringError::UnknownSignal(name.clone())),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn lower_expr(
    expr: &SpecExpr,
    context: &mut LoweringContext,
) -> Result<AirExpr, SpecPlonky3LoweringError> {
    match expr {
        SpecExpr::Const(value) => Ok(AirExpr::Const(*value)),
        SpecExpr::Signal(name) => signal_expr(name, &context.context_signal_indices),
        SpecExpr::Add(values) => {
            let mut lowered = Vec::new();
            let mut error = None;
            for value in values.iter() {
                if error.is_none() {
                    match lower_expr(value, context) {
                        Ok(item) => lowered.push(item),
                        Err(err) => error = Some(err),
                    }
                }
            }
            match error {
                Some(err) => Err(err),
                None => Ok(AirExpr::Add(lowered)),
            }
        }
        SpecExpr::Sub(lhs, rhs) => match lower_expr(lhs, context) {
            Ok(lhs_value) => match lower_expr(rhs, context) {
                Ok(rhs_value) => Ok(AirExpr::Sub(Box::new(lhs_value), Box::new(rhs_value))),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        },
        SpecExpr::Mul(lhs, rhs) => match lower_expr(lhs, context) {
            Ok(lhs_value) => match lower_expr(rhs, context) {
                Ok(rhs_value) => Ok(AirExpr::Mul(Box::new(lhs_value), Box::new(rhs_value))),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        },
        SpecExpr::Div(lhs, rhs) => match lower_expr(lhs, context) {
            Ok(numerator) => match lower_expr(rhs, context) {
                Ok(denominator) => {
                    let div_index = context.context_signal_order.len();
                    let div_name = division_temp_name(context.context_derived_columns.len());
                    context.context_signal_order.push(div_name.clone());
                    context.context_signal_indices.push((div_name, div_index));
                    let quotient = AirExpr::Signal(div_index);
                    context.context_derived_columns.push(DerivedColumn {
                        derived_index: div_index,
                        derived_computation: DerivedComputation::Division {
                            division_numerator: numerator.clone(),
                            division_denominator: denominator.clone(),
                        },
                    });
                    context.context_constraints.push(AirExpr::Sub(
                        Box::new(AirExpr::Mul(
                            Box::new(denominator),
                            Box::new(quotient.clone()),
                        )),
                        Box::new(numerator),
                    ));
                    Ok(quotient)
                }
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        },
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn lower_constraint(
    constraint: &SpecConstraint,
    context: &mut LoweringContext,
) -> Result<(), SpecPlonky3LoweringError> {
    match constraint {
        SpecConstraint::Equal {
            equal_lhs,
            equal_rhs,
        } => match lower_expr(equal_lhs, context) {
            Ok(lhs) => match lower_expr(equal_rhs, context) {
                Ok(rhs) => {
                    context
                        .context_constraints
                        .push(AirExpr::Sub(Box::new(lhs), Box::new(rhs)));
                    Ok(())
                }
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        },
        SpecConstraint::Boolean { boolean_signal } => {
            match signal_expr(boolean_signal, &context.context_signal_indices) {
                Ok(s) => {
                    context.context_constraints.push(AirExpr::Mul(
                        Box::new(s.clone()),
                        Box::new(AirExpr::Sub(Box::new(AirExpr::Const(1)), Box::new(s))),
                    ));
                    Ok(())
                }
                Err(err) => Err(err),
            }
        }
        SpecConstraint::Range {
            range_signal,
            range_bits,
        } => {
            let max_bits = max_safe_range_bits(context.context_field);
            if *range_bits > max_bits {
                Err(SpecPlonky3LoweringError::UnsupportedRangeBits {
                    unsupported_field: context.context_field,
                    unsupported_bits: *range_bits,
                    unsupported_max_bits: max_bits,
                })
            } else {
                match lookup_signal_index(&context.context_signal_indices, range_signal) {
                    Some(source_index) => {
                        let source = AirExpr::Signal(source_index);
                        match lower_range_bits(
                            range_signal,
                            source_index,
                            *range_bits,
                            context,
                            Vec::new(),
                        ) {
                            Ok(recomposed_terms) => {
                                let recomposed = match recomposed_terms.as_slice().split_first() {
                                    None => AirExpr::Const(0),
                                    Some((first, remaining)) => {
                                        if remaining.is_empty() {
                                            first.clone()
                                        } else {
                                            AirExpr::Add(recomposed_terms)
                                        }
                                    }
                                };
                                context
                                    .context_constraints
                                    .push(AirExpr::Sub(Box::new(recomposed), Box::new(source)));
                                Ok(())
                            }
                            Err(err) => Err(err),
                        }
                    }
                    None => Err(SpecPlonky3LoweringError::UnknownSignal(
                        range_signal.clone(),
                    )),
                }
            }
        }
        SpecConstraint::BlackBox => Err(SpecPlonky3LoweringError::UnsupportedConstraint(
            "blackbox".to_string(),
        )),
        SpecConstraint::Lookup => Err(SpecPlonky3LoweringError::UnsupportedConstraint(
            "lookup".to_string(),
        )),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn lower_constraints_slice(
    constraints: &[SpecConstraint],
    context: &mut LoweringContext,
) -> Result<(), SpecPlonky3LoweringError> {
    let mut error = None;
    for constraint in constraints.iter() {
        if error.is_none() {
            match lower_constraint(constraint, context) {
                Ok(()) => {}
                Err(err) => error = Some(err),
            }
        }
    }
    match error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn public_signal_indices(program: &SpecProgram) -> Vec<usize> {
    let mut indices = Vec::new();
    for (index, signal) in program.program_signals.iter().enumerate() {
        if signal.signal_visibility == SpecVisibility::Public {
            indices.push(index);
        }
    }
    indices
}

#[cfg_attr(hax, hax_lib::include)]
pub fn expr_is_supported(expr: &SpecExpr, signal_indices: &[(String, usize)]) -> bool {
    match expr {
        SpecExpr::Const(_) => true,
        SpecExpr::Signal(name) => lookup_signal_index(signal_indices, name).is_some(),
        SpecExpr::Add(values) => {
            let mut supported = !values.is_empty();
            for value in values.iter() {
                if supported {
                    supported = expr_is_supported(value, signal_indices);
                }
            }
            supported
        }
        SpecExpr::Sub(lhs, rhs) | SpecExpr::Mul(lhs, rhs) | SpecExpr::Div(lhs, rhs) => {
            expr_is_supported(lhs, signal_indices) && expr_is_supported(rhs, signal_indices)
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn is_supported_plonky3_program(program: &SpecProgram) -> bool {
    let mut supported =
        plonky3_supported_field(program.program_field) && !program.program_signals.is_empty();
    let mut signal_indices = Vec::new();
    for (index, signal) in program.program_signals.iter().enumerate() {
        if supported {
            if lookup_signal_index(&signal_indices, &signal.signal_name).is_some() {
                supported = false;
            } else {
                signal_indices.push((signal.signal_name.clone(), index));
            }
        }
    }
    supported
        && constraints_supported(
            &program.program_constraints,
            &signal_indices,
            program.program_field,
        )
}

#[cfg_attr(hax, hax_lib::include)]
pub fn lower_program(program: &SpecProgram) -> Result<LoweredProgram, SpecPlonky3LoweringError> {
    if program.program_signals.is_empty() {
        Ok(LoweredProgram {
            lowered_base_signal_count: 0,
            lowered_signal_order: Vec::new(),
            lowered_public_signal_indices: Vec::new(),
            lowered_constraints: Vec::new(),
            lowered_derived_columns: Vec::new(),
        })
    } else {
        let mut signal_order = Vec::new();
        let mut signal_indices = Vec::new();
        for (index, signal) in program.program_signals.iter().enumerate() {
            signal_order.push(signal.signal_name.clone());
            signal_indices.push((signal.signal_name.clone(), index));
        }

        let mut context = LoweringContext {
            context_field: program.program_field,
            context_signal_order: signal_order,
            context_signal_indices: signal_indices,
            context_public_signal_indices: public_signal_indices(program),
            context_constraints: Vec::new(),
            context_derived_columns: Vec::new(),
        };

        match lower_constraints_slice(&program.program_constraints, &mut context) {
            Ok(()) => Ok(LoweredProgram {
                lowered_base_signal_count: program.program_signals.len(),
                lowered_signal_order: context.context_signal_order,
                lowered_public_signal_indices: context.context_public_signal_indices,
                lowered_constraints: context.context_constraints,
                lowered_derived_columns: context.context_derived_columns,
            }),
            Err(err) => Err(err),
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn public_input_positions_preserved(
    program: &SpecProgram,
    lowered: &LoweredProgram,
) -> Result<bool, SpecPlonky3LoweringError> {
    match validate_lowered_program(lowered) {
        Ok(()) => Ok(signal_indices_equal(
            &public_signal_indices(program),
            &lowered.lowered_public_signal_indices,
        )),
        Err(err) => Err(err),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn build_trace_row(
    lowered: &LoweredProgram,
    witness: &SpecWitness,
    field: SpecPlonky3FieldId,
) -> Result<Vec<u64>, SpecPlonky3LoweringError> {
    match validate_lowered_program(lowered) {
        Ok(()) => {
            let mut row = vec![0u64; lowered.lowered_signal_order.len()];
            let mut error = None;
            for (index, signal_name) in lowered.lowered_signal_order.iter().enumerate() {
                if error.is_none() && index < lowered.lowered_base_signal_count {
                    match lookup_witness_value(&witness.witness_values, signal_name) {
                        Some(value) => match row_value_set(&mut row, index, value) {
                            Ok(()) => {}
                            Err(err) => error = Some(err),
                        },
                        None => {
                            error = Some(SpecPlonky3LoweringError::MissingWitnessValue(
                                signal_name.clone(),
                            ));
                        }
                    }
                }
            }
            match error {
                Some(err) => Err(err),
                None => {
                    let modulus = field_modulus_u64(field);
                    match fill_derived_columns(&lowered.lowered_derived_columns, &mut row, modulus)
                    {
                        Ok(()) => Ok(row),
                        Err(err) => Err(err),
                    }
                }
            }
        }
        Err(err) => Err(err),
    }
}
