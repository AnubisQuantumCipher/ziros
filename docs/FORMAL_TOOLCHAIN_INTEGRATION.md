# ZirOS Rust Verification Tool Doctrine

This document is the permanent doctrine for choosing Rust verification tools in
ZirOS. The doctrine is claim-first and boundary-first: use the tool that fits
the semantic risk in front of you, and do not widen a theorem claim beyond what
the tool run actually proves.

The core rule is simple:

- RefinedRust is the default development lane for unsafe, FFI, raw-pointer, and
  layout-sensitive Rust.
- Verus is the default theorem lane for safe proof-core logic and shell
  contracts.
- Kani and Thrust are support lanes.
- Flux, Creusot, and Prusti are comparison tools only in this checkout.

No tool in this doctrine proves Groth16, FRI, Nova, or HyperNova protocol
soundness by itself.

## Permanent Doctrine

### RefinedRust as a major development lane

RefinedRust should shape how ZirOS writes low-level Rust. When a feature needs
unsafe code, aliasing-sensitive mutation, memory-layout reasoning, FFI,
host-boundary buffers, or explicit ownership transfer, the implementation
should be split into a small proof-bearing capsule that is realistic for
RefinedRust to translate and discharge.

Do not wait until the end of development to discover whether a boundary is
RefinedRust-shaped. Design the boundary that way from the start:

- move pointer arithmetic and layout checks into a narrow helper layer,
- keep proof-bearing state explicit,
- keep unsupported Rust features out of the capsule,
- and leave larger operational shells outside the counted proof claim.

RefinedRust is admitted as a counted lane only after the admitted surface has
generated Rocq/Radium output and a passing `dune build` over the generated and
stable proof files.

### Verus as the default safe proof-core lane

Use Verus first for safe Rust proof cores, arithmetic invariants, state
machines, deterministic transformations, fail-closed policy logic, and shell
contracts around effectful boundaries. Verus is the right default when the hard
problem is the semantic relation, not raw memory reasoning.

### Support lanes

- Kani is bounded evidence for counterexamples, bug-finding, panic/overflow
  checks, and regression harnesses.
- Thrust is non-counted support evidence for safe-Rust refinement screening,
  invariant discovery, and cheap regression triage.

Neither Kani nor Thrust may increase `mechanized_total`.

### Comparison-only tools

Flux, Creusot, and Prusti are useful comparison points for refinement typing,
deductive verification ergonomics, and annotation tradeoffs. They are not
admitted assurance lanes in ZirOS today. They may inform design choices, but
they do not create counted or support-lane claims unless a later policy tranche
adds tool pins, runners, evidence roots, and truth-surface updates.

## Decision Tree

1. Is the claim about protocol cryptography, recursion soundness, or algebraic
   protocol security rather than a Rust implementation boundary?
   - Route out of this doctrine to the protocol-proof surfaces.
2. Is the target unsafe, FFI-facing, raw-pointer-heavy, aliasing-sensitive, or
   layout-sensitive?
   - Primary lane: RefinedRust.
   - Optional secondary lane: Verus for a pure model or shell contract if the
     safe boundary is stable.
   - Optional support: Kani for bounded regression or concrete counterexamples.
3. Is the target safe proof-core logic, arithmetic, deterministic scheduling
   logic, or a pure state-machine boundary?
   - Primary lane: Verus.
   - Optional support: Thrust for screening and Kani for bounded search.
4. Is the immediate need cheap safe-Rust screening rather than a counted
   theorem?
   - Primary lane: Thrust.
5. Is the immediate need bounded bug-finding or a concrete failing execution?
   - Primary lane: Kani.
6. Is someone proposing Flux, Creusot, or Prusti?
   - Treat them as comparison-only and do not promote any result into the truth
     surfaces.

## Derived Rules

- Prefer RefinedRust over Verus when ownership, mutation, aliasing, memory
  layout, or unsafe semantics are the hard part.
- Prefer Verus over RefinedRust when the semantics are naturally pure and the
  theorem should speak about an abstract transition relation or arithmetic
  invariant.
- If a RefinedRust target is too large or feature-rich, extract a smaller
  capsule. Do not weaken the claim to fit the existing module.
- If a safe Rust surface needs quick automation before theorem promotion, use
  Thrust or Kani as support and keep the counted claim with Verus or Rocq.
- If a proposal depends on Flux, Creusot, or Prusti changing a ledger total,
  reject it unless the truth surfaces are explicitly upgraded first.

## Counting Policy

- RefinedRust may become `mechanized_local` only after `cargo refinedrust`
  generates the Rocq/Radium translation and `dune build` checks the generated
  and stable proof files for the admitted surface.
- Verus may become `mechanized_local` when the shipped theorem file and runner
  prove the claimed boundary and the ledger row is updated honestly.
- Kani is bounded support evidence only.
- Thrust is non-counted support evidence only.
- A generated artifact, solver success, checked-in pin file, or local memo alone
  does not widen any theorem claim in `zkf-ir-spec/verification-ledger.json`.

## Tool Pins

- RefinedRust: `formal/tools/refinedrust-pin.json`
- Thrust: `formal/tools/thrust-pin.json`

The pins record upstream commit IDs, expected checker or solver assumptions, and
the local counting policy. They do not create proof claims by themselves.

## Evidence Layout

RefinedRust counted evidence belongs under:

```text
formal/refinedrust/<surface>/
```

Current counted RefinedRust surface:

- `runtime-buffer-bridge`: `runtime.buffer_resident_accounting_refinedrust`

Thrust support evidence belongs under:

```text
formal/tool-evidence/thrust/
```

Fresh runner output for RefinedRust, Kani, Thrust, and comparison runs belongs
under:

```text
target-local/formal/
```

## Evidence Requirements

### RefinedRust

- A narrow admitted surface under `formal/refinedrust/<surface>/`
- `cargo refinedrust` success
- `dune build` success
- Surface `STATUS.md` naming boundary, exclusions, theorem ids, and checked log
  path
- Honest notes about unsupported features and trusted assumptions

### Verus

- A shipped proof file under the relevant crate proof surface
- A reproducible runner command
- A named theorem matching the claimed boundary
- Explicit preconditions and trusted assumptions in notes or proof comments

### Kani

- Harness path
- Feature configuration and bounds
- Recorded run result
- Explicit statement that the evidence is bounded and non-counted

### Thrust

- Target name
- Solver args and timeout
- Recorded trusted-function inventory
- Machine-readable output under `target-local/formal/thrust` or a promoted
  evidence root
- Explicit statement that the evidence is non-counted

### Flux, Creusot, Prusti

- Comparison memo only
- Upstream version or commit used for the comparison
- Exact exercised feature subset
- Explicit statement that no ZirOS assurance claim changed

## Operator Commands

```bash
scripts/run_refinedrust_proofs.sh [--strict] [surface...]
scripts/run_thrust_checks.sh [--strict] [target...]
```

Strict mode fails closed on missing tools, missing surfaces, failed proof
builds, or failed solver checks. Non-strict mode emits machine-readable skipped
evidence when the optional toolchain is unavailable.

## Red Flags

- Unsafe code that was not first carved into a RefinedRust-capable capsule
- Large mixed-feature modules being offered as RefinedRust targets
- Counting Kani or Thrust
- Claiming RefinedRust coverage from translation output without a passing
  `dune build`
- Treating Flux, Creusot, or Prusti as admitted assurance lanes
- Using any tool here to imply protocol cryptography closure
- Non-strict, skipped, or timeout runs being described as proof success
- Hidden trusted functions, hidden solver assumptions, or undocumented excluded
  features

## Comparison Summary

- RefinedRust: foundational lane for small unsafe or layout-sensitive Rust
  capsules with Rocq-checked output.
- Verus: strongest default lane for safe implementation theorems and shell
  contracts.
- Kani: fastest bounded bug-finding lane.
- Thrust: cheap safe-Rust refinement screening.
- Flux: comparison point for refinement-type ergonomics on safe Rust.
- Creusot: comparison point for Why3-style deductive verification over Rust.
- Prusti: comparison point for contract-style verification over Rust.
