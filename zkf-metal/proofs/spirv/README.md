# SPIR-V Validation Surface

Phase 2 keeps the existing GPU ledger claims at `bounded_checked` and adds a
checked SPIR-V validation lane for the four critical Metal shader families:

- `ntt`
- `msm`
- `poseidon2`
- `hash`

The lane uses two linked artifacts per family:

1. The production Metal sources, compiled to AIR with `xcrun metal`, proving
   the shipped entrypoint surface still compiles on the local Apple toolchain.
2. Portable OpenCL-style mirror kernels under `kernels/`, compiled to LLVM
   bitcode and translated to SPIR-V with pinned Khronos tooling. The mirror
   kernels intentionally preserve the production entrypoint names so reflection
   and entrypoint-set checks are structural, not ad hoc.

`spirv-val` validates the generated SPIR-V modules, `spirv-cross` reflects them
back out to confirm the expected kernel entrypoints are present, and the lane
then runs the existing randomized macOS CPU/Metal differential tests for the
actual production shaders.

## GPUVerify note

GPUVerify remains non-blocking in this tranche. The production Metal shaders and
the portable mirrors do not normalize cleanly into GPUVerify's OpenCL/CUDA
subset without semantic rewrites around address-space and kernel-family
specialization. The Phase 2 lane therefore records this as an intentional skip
and relies on SPIR-V validation plus the existing bounded differential evidence.
