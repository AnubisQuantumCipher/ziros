#![allow(dead_code)]

// Proof-facing surface for the recursive visit schedule of
// `proof_kernel::eval_expr_constant_time`. This deliberately erases field
// arithmetic and witness values: the Month 2 F* claim is limited to the
// evaluator shell's schedule being independent of secret data.
#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum CtExpr {
    Const,
    Signal,
    Add(Box<CtExpr>, Box<CtExpr>),
    Sub(Box<CtExpr>, Box<CtExpr>),
    Mul(Box<CtExpr>, Box<CtExpr>),
    Div(Box<CtExpr>, Box<CtExpr>),
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct CtWitnessMask;

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum CtFieldMarker {
    Primary,
    Secondary,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum CtTrace {
    Const,
    Signal,
    Add(Box<CtTrace>, Box<CtTrace>),
    Sub(Box<CtTrace>, Box<CtTrace>),
    Mul(Box<CtTrace>, Box<CtTrace>),
    Div(Box<CtTrace>, Box<CtTrace>),
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum CtEvalResult {
    Const,
    Signal,
    Add(Box<CtEvalResult>, Box<CtEvalResult>),
    Sub(Box<CtEvalResult>, Box<CtEvalResult>),
    Mul(Box<CtEvalResult>, Box<CtEvalResult>),
    Div(Box<CtEvalResult>, Box<CtEvalResult>),
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn structural_trace(expr: &CtExpr) -> CtTrace {
    match expr {
        CtExpr::Const => CtTrace::Const,
        CtExpr::Signal => CtTrace::Signal,
        CtExpr::Add(lhs, rhs) => CtTrace::Add(
            Box::new(structural_trace(lhs)),
            Box::new(structural_trace(rhs)),
        ),
        CtExpr::Sub(lhs, rhs) => CtTrace::Sub(
            Box::new(structural_trace(lhs)),
            Box::new(structural_trace(rhs)),
        ),
        CtExpr::Mul(lhs, rhs) => CtTrace::Mul(
            Box::new(structural_trace(lhs)),
            Box::new(structural_trace(rhs)),
        ),
        CtExpr::Div(lhs, rhs) => CtTrace::Div(
            Box::new(structural_trace(lhs)),
            Box::new(structural_trace(rhs)),
        ),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn eval_expr_reference_result(
    expr: &CtExpr,
    _witness: &CtWitnessMask,
    _field: CtFieldMarker,
) -> CtEvalResult {
    match expr {
        CtExpr::Const => CtEvalResult::Const,
        CtExpr::Signal => CtEvalResult::Signal,
        CtExpr::Add(lhs, rhs) => CtEvalResult::Add(
            Box::new(eval_expr_reference_result(lhs, _witness, _field)),
            Box::new(eval_expr_reference_result(rhs, _witness, _field)),
        ),
        CtExpr::Sub(lhs, rhs) => CtEvalResult::Sub(
            Box::new(eval_expr_reference_result(lhs, _witness, _field)),
            Box::new(eval_expr_reference_result(rhs, _witness, _field)),
        ),
        CtExpr::Mul(lhs, rhs) => CtEvalResult::Mul(
            Box::new(eval_expr_reference_result(lhs, _witness, _field)),
            Box::new(eval_expr_reference_result(rhs, _witness, _field)),
        ),
        CtExpr::Div(lhs, rhs) => CtEvalResult::Div(
            Box::new(eval_expr_reference_result(lhs, _witness, _field)),
            Box::new(eval_expr_reference_result(rhs, _witness, _field)),
        ),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn eval_expr_constant_time_trace(
    expr: &CtExpr,
    _witness: &CtWitnessMask,
    _field: CtFieldMarker,
) -> CtTrace {
    match expr {
        CtExpr::Const => CtTrace::Const,
        CtExpr::Signal => CtTrace::Signal,
        CtExpr::Add(lhs, rhs) => CtTrace::Add(
            Box::new(eval_expr_constant_time_trace(lhs, _witness, _field)),
            Box::new(eval_expr_constant_time_trace(rhs, _witness, _field)),
        ),
        CtExpr::Sub(lhs, rhs) => CtTrace::Sub(
            Box::new(eval_expr_constant_time_trace(lhs, _witness, _field)),
            Box::new(eval_expr_constant_time_trace(rhs, _witness, _field)),
        ),
        CtExpr::Mul(lhs, rhs) => CtTrace::Mul(
            Box::new(eval_expr_constant_time_trace(lhs, _witness, _field)),
            Box::new(eval_expr_constant_time_trace(rhs, _witness, _field)),
        ),
        CtExpr::Div(lhs, rhs) => CtTrace::Div(
            Box::new(eval_expr_constant_time_trace(lhs, _witness, _field)),
            Box::new(eval_expr_constant_time_trace(rhs, _witness, _field)),
        ),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn eval_expr_constant_time_result(
    expr: &CtExpr,
    _witness: &CtWitnessMask,
    _field: CtFieldMarker,
) -> CtEvalResult {
    match expr {
        CtExpr::Const => CtEvalResult::Const,
        CtExpr::Signal => CtEvalResult::Signal,
        CtExpr::Add(lhs, rhs) => CtEvalResult::Add(
            Box::new(eval_expr_constant_time_result(lhs, _witness, _field)),
            Box::new(eval_expr_constant_time_result(rhs, _witness, _field)),
        ),
        CtExpr::Sub(lhs, rhs) => CtEvalResult::Sub(
            Box::new(eval_expr_constant_time_result(lhs, _witness, _field)),
            Box::new(eval_expr_constant_time_result(rhs, _witness, _field)),
        ),
        CtExpr::Mul(lhs, rhs) => CtEvalResult::Mul(
            Box::new(eval_expr_constant_time_result(lhs, _witness, _field)),
            Box::new(eval_expr_constant_time_result(rhs, _witness, _field)),
        ),
        CtExpr::Div(lhs, rhs) => CtEvalResult::Div(
            Box::new(eval_expr_constant_time_result(lhs, _witness, _field)),
            Box::new(eval_expr_constant_time_result(rhs, _witness, _field)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_trace_matches_constant_time_trace() {
        let expr = CtExpr::Div(
            Box::new(CtExpr::Add(
                Box::new(CtExpr::Signal),
                Box::new(CtExpr::Const),
            )),
            Box::new(CtExpr::Mul(
                Box::new(CtExpr::Signal),
                Box::new(CtExpr::Sub(
                    Box::new(CtExpr::Const),
                    Box::new(CtExpr::Signal),
                )),
            )),
        );
        let witness = CtWitnessMask;
        assert_eq!(
            eval_expr_constant_time_trace(&expr, &witness, CtFieldMarker::Primary),
            structural_trace(&expr)
        );
    }

    #[test]
    fn reference_result_matches_constant_time_result() {
        let expr = CtExpr::Div(
            Box::new(CtExpr::Add(
                Box::new(CtExpr::Signal),
                Box::new(CtExpr::Const),
            )),
            Box::new(CtExpr::Mul(
                Box::new(CtExpr::Signal),
                Box::new(CtExpr::Sub(
                    Box::new(CtExpr::Const),
                    Box::new(CtExpr::Signal),
                )),
            )),
        );
        let witness = CtWitnessMask;
        assert_eq!(
            eval_expr_constant_time_result(&expr, &witness, CtFieldMarker::Secondary),
            eval_expr_reference_result(&expr, &witness, CtFieldMarker::Secondary)
        );
    }
}
