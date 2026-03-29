use zkf_backends::backend_capability_matrix;
use zkf_core::{
    AuditReport, BackendKind, Program, audit_program, audit_program_with_capability_matrix,
};

const STACK_GROW_RED_ZONE: usize = 8 * 1024 * 1024;
const STACK_GROW_SIZE: usize = 64 * 1024 * 1024;

pub fn audit_program_default(program: &Program, backend: Option<BackendKind>) -> AuditReport {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        let zir = zkf_core::program_v2_to_zir(program);
        audit_program(&zir, backend)
    })
}

pub fn audit_program_with_live_capabilities(
    program: &Program,
    backend: Option<BackendKind>,
) -> AuditReport {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        let zir = zkf_core::program_v2_to_zir(program);
        let matrix = backend_capability_matrix();
        audit_program_with_capability_matrix(&zir, backend, &matrix)
    })
}

pub fn audit_program_with_live_capabilities_owned(
    program: Program,
    backend: Option<BackendKind>,
) -> AuditReport {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        let zir = zkf_core::lowering::program_v2_into_zir(program);
        let matrix = backend_capability_matrix();
        audit_program_with_capability_matrix(&zir, backend, &matrix)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::templates::range_proof;

    #[test]
    fn audit_wrappers_match_core_on_same_program() {
        let template = range_proof().expect("range template");
        let zir = zkf_core::program_v2_to_zir(&template.program);

        let default_report = audit_program_default(&template.program, None);
        let core_report = zkf_core::audit_program(&zir, None);
        assert_eq!(
            default_report.summary.overall_status,
            core_report.summary.overall_status
        );

        let live_report = audit_program_with_live_capabilities(&template.program, None);
        assert_eq!(
            live_report.summary.overall_status,
            core_report.summary.overall_status
        );

        let owned_live_report =
            audit_program_with_live_capabilities_owned(template.program.clone(), None);
        assert_eq!(
            owned_live_report.summary.overall_status,
            core_report.summary.overall_status
        );
    }
}
