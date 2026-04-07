use vstd::prelude::*;

verus! {

pub open spec fn audit_underconstrained_boundary(
    total_constraints: nat,
    visited_constraints: nat,
    private_signal_count: nat,
    classified_private_signal_count: nat,
) -> bool {
    visited_constraints == total_constraints
        && classified_private_signal_count == private_signal_count
}

pub open spec fn audit_constraint_checker_boundary(
    total_constraints: nat,
    has_failure: bool,
    first_failing_constraint_index: nat,
    checked_constraint_count: nat,
    result_ok: bool,
) -> bool {
    if has_failure {
        !result_ok
            && first_failing_constraint_index < total_constraints
            && checked_constraint_count == first_failing_constraint_index + 1
    } else {
        result_ok
            && first_failing_constraint_index == total_constraints
            && checked_constraint_count == total_constraints
    }
}

pub open spec fn audit_report_aggregation_boundary(
    total_checks: nat,
    passed_checks: nat,
    warned_checks: nat,
    failed_checks: nat,
    skipped_checks: nat,
) -> bool {
    passed_checks + warned_checks + failed_checks + skipped_checks == total_checks
}

pub proof fn audit_underconstrained_detection_complete_ok(
    total_constraints: nat,
    visited_constraints: nat,
    private_signal_count: nat,
    classified_private_signal_count: nat,
)
    requires
        audit_underconstrained_boundary(
            total_constraints,
            visited_constraints,
            private_signal_count,
            classified_private_signal_count,
        ),
    ensures
        visited_constraints == total_constraints,
        classified_private_signal_count == private_signal_count,
{
}

pub proof fn audit_constraint_checker_evaluates_all_ok(
    total_constraints: nat,
    has_failure: bool,
    first_failing_constraint_index: nat,
    checked_constraint_count: nat,
    result_ok: bool,
)
    requires
        audit_constraint_checker_boundary(
            total_constraints,
            has_failure,
            first_failing_constraint_index,
            checked_constraint_count,
            result_ok,
        ),
    ensures
        has_failure ==> (
            !result_ok
                && first_failing_constraint_index < total_constraints
                && checked_constraint_count == first_failing_constraint_index + 1
        ),
        !has_failure ==> (
            result_ok
                && first_failing_constraint_index == total_constraints
                && checked_constraint_count == total_constraints
        ),
{
}

pub proof fn audit_report_aggregation_correct_ok(
    total_checks: nat,
    passed_checks: nat,
    warned_checks: nat,
    failed_checks: nat,
    skipped_checks: nat,
)
    requires
        audit_report_aggregation_boundary(
            total_checks,
            passed_checks,
            warned_checks,
            failed_checks,
            skipped_checks,
        ),
    ensures
        passed_checks + warned_checks + failed_checks + skipped_checks == total_checks,
{
}

} // verus!
