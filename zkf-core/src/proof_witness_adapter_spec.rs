#![allow(dead_code)]

use crate::proof_kernel_spec::{SpecKernelProgram, SpecKernelWitness};

// Proof-facing shell surface for the witness-to-kernel adapter boundary.
//
// This keeps the kernel model explicit without claiming any stronger
// translator semantics than the current public boundary requires.
#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecWitnessAdapterSurface {
    pub(crate) kernel_program: SpecKernelProgram,
    pub(crate) kernel_witness: SpecKernelWitness,
    pub(crate) signal_names: Vec<String>,
    pub(crate) constraint_labels: Vec<Option<String>>,
    pub(crate) table_names: Vec<String>,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn supported_shell_surface(
    kernel_program: SpecKernelProgram,
    kernel_witness: SpecKernelWitness,
    signal_names: Vec<String>,
    constraint_labels: Vec<Option<String>>,
    table_names: Vec<String>,
) -> SpecWitnessAdapterSurface {
    SpecWitnessAdapterSurface {
        kernel_program,
        kernel_witness,
        signal_names,
        constraint_labels,
        table_names,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn shell_surface_is_structural_copy(surface: &SpecWitnessAdapterSurface) -> bool {
    surface.signal_names.len() == surface.kernel_witness.values.len()
        && surface.constraint_labels.len() == surface.kernel_program.constraints.len()
        && surface.table_names.len() == surface.kernel_program.lookup_tables.len()
}
