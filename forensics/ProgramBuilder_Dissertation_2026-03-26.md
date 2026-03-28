# ProgramBuilder in ZirOS / ZKF

Source-grounded forensic dissertation

Date: 2026-03-26
Workspace: `/Users/sicarii/Projects/ZK DEV`
Primary scope: the `ProgramBuilder` subsystem and the surfaces that construct, lower, serialize, compile, prove, verify, scaffold, and test programs authored through it.

## Abstract

`ProgramBuilder` is the imperative application-authoring subsystem of this ZirOS checkout. It lives in `zkf-lib`, not in `zkf-core` and not in any proving backend. That placement matters. The builder is not the canonical proving IR, and it is not the final backend circuit representation. It is an app-facing construction layer that lets Rust authors assemble circuits through explicit signal declarations, witness assignments, gadget emissions, metadata annotations, aliases, and helper constraints, then lower that author intent into the system’s shared `ir-v2` `Program`.

The builder is deliberately positioned as an escape hatch rather than the default path. The documentation and CLI make `zirapp.json` and `AppSpecV1` the primary app-authoring surface for most users. `ProgramBuilder` remains the direct Rust surface for cases where declarative JSON becomes too awkward, too repetitive, or too opaque. The current checkout uses it in exactly that way. Simple templates such as Poseidon commitments and range proofs use it for clarity; much larger domain programs such as private identity KYC, private satellite conjunction, private powered descent, and private N-body orbital simulation also use it as the core construction mechanism.

Architecturally, the builder writes a `zir-v1` style intermediate structure first. Only on `build()` does it validate signal references, hints, aliases, and types, then lower into `ir-v2` with `program_zir_to_v2`. That is the builder’s central contract: it is a structured authoring surface over a richer, typed, app-oriented intermediate representation that eventually becomes the common IR consumed by the rest of the stack. This means the builder can expose surfaces that `ir-v2` does not natively preserve, but it also means some surfaces currently fail closed during lowering. Memory regions and custom gates are the clearest examples: the builder will let authors express them, but `build()` will reject programs using them because `zir-to-ir-v2` lowering does not support them.

The most important honest conclusion is that `ProgramBuilder` is strong engineering infrastructure, but it is not itself a mechanized proof surface. Its assurances are bounded and implementation-based: explicit validation, type checking, structured lowering, audit-aware backend flows, blackbox-lowering preservation, unit tests, integration tests, and standalone smoke coverage. The mechanized theorem surfaces described elsewhere in ZirOS live lower in the stack. The builder’s job is not to replace those proofs. Its job is to make it possible to author application programs that can enter those downstream validated lanes without lying about what the authoring layer itself guarantees.

## Scope and Corpus

This dissertation was assembled from the current checkout rather than historical prose. The highest-signal files for this subsystem were:

- `zkf-lib/src/app/builder.rs`
- `zkf-lib/src/app/spec.rs`
- `zkf-lib/src/app/templates.rs`
- `zkf-lib/src/app/api.rs`
- `zkf-lib/src/lib.rs`
- `zkf-core/src/zir.rs`
- `zkf-core/src/ir.rs`
- `zkf-core/src/lowering/mod.rs`
- `zkf-core/src/type_check.rs`
- `zkf-gadgets/src/gadget.rs`
- `zkf-gadgets/src/registry.rs`
- `zkf-gadgets/src/poseidon.rs`
- `zkf-gadgets/src/boolean.rs`
- `zkf-gadgets/src/merkle.rs`
- `zkf-gadgets/src/range.rs`
- `zkf-backends/src/blackbox_gadgets/mod.rs`
- `zkf-backends/src/audited_backend.rs`
- `zkf-backends/src/arkworks.rs`
- `zkf-integration-tests/tests/developer_use_cases.rs`
- `zkf-lib/examples/financial_loan_qualification.rs`
- `zkf-lib/examples/private_identity_service_tier.rs`
- `zkf-lib/src/app/private_identity.rs`
- `zkf-lib/src/app/orbital.rs`
- `zkf-lib/src/app/descent.rs`
- `zkf-lib/src/app/satellite.rs`
- `private_budget_approval/README.md`
- `private_budget_approval/src/spec.rs`
- `private_budget_approval/src/main.rs`
- `private_budget_approval/tests/smoke.rs`
- `private_budget_approval/zirapp.json`
- `docs/APP_DEVELOPER_GUIDE.md`
- `docs/TUTORIAL.md`
- `docs/CLI.md`
- `zkf-cli/src/cmd/app.rs`
- `zkf-python/src/lib.rs`

The discussion below follows the repo-forensics phase contract, but narrowed to the ProgramBuilder subsystem rather than the entire monorepo.

## PHASE 1 — STRUCTURAL CENSUS

### Files Examined

- `zkf-lib/src/app/builder.rs`
- `zkf-lib/src/app/spec.rs`
- `zkf-lib/src/app/templates.rs`
- `zkf-lib/src/app/mod.rs`
- `zkf-lib/src/lib.rs`
- `docs/APP_DEVELOPER_GUIDE.md`
- `docs/TUTORIAL.md`
- `docs/CLI.md`
- `README.md`
- `zkf-cli/src/cmd/app.rs`
- `zkf-python/src/lib.rs`

### Findings

The first structural fact is simple: `ProgramBuilder` is a `zkf-lib` application-layer API. It is re-exported from `zkf-lib/src/lib.rs`, alongside `BooleanOp`, templates, input helpers, app-spec functions, verifier export helpers, and compile/prove/verify utilities. That placement makes the intended audience clear. The builder is not a low-level core primitive. It is part of the embeddable app surface for authors building standalone ZirOS applications.

The second structural fact is that the builder sits beside, not above, the declarative app-spec system. The developer guide, tutorial, CLI reference, and scaffold generator all present `zirapp.json` and `AppSpecV1` as the default path. The language is consistent: `ProgramBuilder` is the “escape hatch” when declarative authoring is not enough. The CLI’s generated README repeats this explicitly. That is not accidental phrasing. It reflects how the code is organized. `AppSpecV1` can reconstruct a program by replaying builder operations, but the scaffold path defaults to JSON because JSON is easier to generate, inspect, version, and expose to non-Rust surfaces.

The third structural fact is that `ProgramBuilder` is broader than a toy arithmetic DSL. The builder is used in at least four distinct modes across the repo:

- hand-authored imperative circuits in examples and integration tests
- shared template construction in `zkf-lib/src/app/templates.rs`
- large domain-specific template/showcase builders in `private_identity.rs`, `orbital.rs`, `descent.rs`, `satellite.rs`, and `multi_satellite.rs`
- external standalone app scaffolds that ultimately load `zirapp.json`, build a `Program`, then run the normal embedded proving path

The fourth structural fact is subtle but crucial: the builder’s public vocabulary is more semantic than the underlying `Program` data model. The builder offers methods named `private_input`, `public_input`, `public_output`, and `private_signal`, but the eventual `ir-v2::Signal` only stores `name`, `visibility`, `constant`, and optional `ty`. There is no core “input” versus “output” marker. In the implementation, `public_input` and `public_output` are identical calls to `add_signal(..., Visibility::Public, ...)`. `private_input` and `private_signal` are identical calls to `add_signal(..., Visibility::Private, ...)`. That means the “input” and “output” words in the builder API are author-intent conventions, not core IR distinctions. The actual execution semantics of “what the user must supply” and “what the app wants to expose” live in witness assignments, expected-input lists, public-output lists, and app-level contract data, not in the bare signal structure.

The fifth structural fact is that the builder is intentionally layered over `zir-v1`, not directly over `ir-v2`. The developer guide says this plainly, and the code confirms it. `builder.rs` collects `zkf_core::zir` signals, constraints, assignments, hints, tables, memory regions, custom gates, metadata, and aliases; only `build()` lowers that accumulated `zir::Program` into `ir-v2`. That gives the builder more expressive room, but it also introduces the possibility that some surfaces exist in builder-space and `zir-v1` while still lacking an `ir-v2` representation.

### Gaps and Concerns

The structural gap most users will miss is the semantic collapse between inputs, outputs, and generic signals. The API names suggest stronger distinctions than the core program model actually carries. This is not necessarily wrong, but it does mean builder authors need to understand that declaring a public output is largely a visibility choice plus an app-contract convention, not a separate IR category.

A second structural concern is ecosystem reach. The direct builder API is Rust-only. Python gets `AppSpecV1` construction, template registry, and template instantiation, but not a first-class `ProgramBuilder` object. The declarative spec path therefore functions as the cross-language bridge, while the imperative builder remains native to Rust.

### Verdict

Structurally, `ProgramBuilder` is the imperative authoring wing of the `zkf-lib` app surface. It is neither the default beginner path nor the canonical proving IR. It is a deliberately explicit construction layer used when authors need more control than `zirapp.json` provides.

## PHASE 2 — CRYPTOGRAPHIC OR COMPUTATIONAL CORE

### Files Examined

- `zkf-lib/src/app/builder.rs`
- `zkf-core/src/zir.rs`
- `zkf-core/src/type_check.rs`
- `zkf-gadgets/src/gadget.rs`
- `zkf-gadgets/src/registry.rs`
- `zkf-gadgets/src/poseidon.rs`
- `zkf-gadgets/src/boolean.rs`
- `zkf-gadgets/src/merkle.rs`
- `zkf-gadgets/src/range.rs`

### Findings

Internally, `ProgramBuilder` is a stateful accumulator. Its fields capture nearly the entire authoring session:

- `name` and `field`
- `signals` and `signal_indices`
- `constraints`
- witness `assignments` and `hints`
- `lookup_tables`
- `memory_regions`
- `custom_gates`
- `metadata`
- `input_aliases`
- `registry`
- `gadget_invocations` and `helper_invocations`

That state explains the builder’s working style. It is not purely functional and it does not rebuild immutable trees on every call. Instead, it incrementally accumulates a partially authored program until `build()`.

Expression handling is intentionally minimal. `Expr` supports constants, signals, addition, subtraction, multiplication, and division. There is no native conditional expression, boolean operator, or comparison node. Instead, the builder implements higher-level helpers as constraint patterns or gadget emissions. `constrain_select_labeled`, for example, expresses an if/else mux as `when_false + selector * (when_true - when_false)` after separately constraining `selector` to be boolean. `boolean_op` delegates to the boolean gadget. `constrain_geq_labeled` and `constrain_leq_labeled` translate ordering into slack-signal arithmetic plus range constraints.

Signal management is one of the subsystem’s stronger parts. Every new signal flows through `upsert_signal`, which merges duplicate declarations instead of blindly duplicating names. `merge_visibility` allows a private signal to be upgraded to public or constant when appropriate but rejects incompatible public-versus-constant collisions. `merge_signal_ty` lets a generic `field` placeholder absorb a more specific type like `bool` or `uint(bits)`, but rejects conflicting specialized types. The practical result is that authors can predeclare a signal loosely and let later helper calls refine its type, while genuine contradictions are rejected.

This refinement behavior matters because raw declarations default to `zir::SignalType::Field`. Type specificity comes later. `constrain_boolean_labeled` marks a signal as `Bool`. `constrain_range_labeled` marks it as `UInt { bits }`. Gadget emissions may introduce output signals with more specific types, such as the boolean gadget returning a `Bool`. The builder therefore uses a “field first, refine later” model rather than requiring exhaustive type annotations up front.

The helper methods are not all equal in how early they validate. `constrain_boolean_labeled`, `constrain_range_labeled`, `constrain_copy_labeled`, and `constrain_permutation_labeled` check known signal names immediately because they reference named signals directly. By contrast, raw equality constraints and assignments can hold undeclared signal references until `build()`, because they work over arbitrary `Expr` trees and expression validation is deferred. That is a tradeoff between authoring flexibility and immediate feedback.

Witness-related helpers show the same explicitness. `add_assignment` merely records a target expression in the witness plan. `bind_labeled` is the stronger convenience helper: it ensures the target exists, records an assignment, and emits an equality constraint tying the target to the expression. In other words, `bind` means “compute this value in the witness plan and prove the binding,” not merely “suggest a witness value.”

The relation helpers are worth spelling out carefully:

- `constrain_leq_labeled` creates a private slack signal, binds it to `rhs - lhs`, range-constrains it, then emits an `anchor` equality.
- `constrain_geq_labeled` does the same with `lhs - rhs`.
- `constrain_nonzero_labeled` creates an inverse witness signal and constrains `signal * inverse = 1`.
- `constrain_select_labeled` implements an arithmetic mux and separately constrains the selector boolean.

The `anchor` pattern deserves honest treatment. The helper creates or reuses a constant-one signal and constrains `signal * one = signal`. Algebraically that is redundant. The code does not document a deeper theorem behind it. The observable value is that it gives the helper a dedicated labeled constraint suffix `:anchor` and forces the signal to appear in a multiplicative equality form. It should not be oversold as a distinct semantic guarantee beyond what the code actually proves.

Blackbox and gadget support are the builder’s biggest extensibility mechanism. There are two paths:

- `constrain_blackbox_labeled`, which directly emits a `zir::Constraint::BlackBox`
- `emit_gadget_labeled`, which asks a registered `Gadget` implementation to emit signals, assignments, constraints, and lookup tables

`emit_gadget_labeled` does substantial work rather than merely forwarding data. It:

- looks up a `GadgetSpec`
- validates field support
- calls the gadget registry
- creates a per-invocation namespace like `__gadget_poseidon_0__`
- preserves explicit user-specified output names
- rewrites all internal signal names and lookup table names to avoid collisions
- rewrites emitted constraints and assignments accordingly
- decorates labels with a caller-provided prefix

That namespacing logic is why multiple gadget invocations do not collide even if the gadget implementation uses generic internal names. The unit tests explicitly check this with repeated Merkle gadget emission.

Gadget support itself is not static folklore. The `zkf-gadgets` layer exposes a formal `GadgetSpec` registry, including name, description, input/output counts, supported fields, required params, approximate constraint cost, audit status, and production-safety flags. Some field support is capability-backed. `poseidon`, `merkle`, and `sha256` ask the current backend capability matrix which fields are actually supported for the corresponding blackbox operation. That means builder-side gadget acceptance can depend on the binary’s real backend surface, not just on a hard-coded list.

Finally, `validate_blackbox_surface` enforces some immediate truthfulness for raw blackbox ops:

- Poseidon requires BN254 with 4 inputs and 4 outputs on this builder surface.
- SHA-256 requires exactly 32 outputs.
- Pedersen, ECDSA, and Schnorr verification are restricted to BN254.

This is important because the builder does not pretend any blackbox arity or field combination is acceptable merely because a constraint enum exists.

### Gaps and Concerns

The builder’s biggest computational limitation is that its parity surface is wider than the final lowered IR. Authors can define memory regions and custom gates and attach matching constraints, but those constructs are not representable in `ir-v2`, so `build()` will fail later when lowering is attempted. The unit tests call this out honestly, but the UX is still “accept during authoring, reject during build,” not “reject at API call time.”

A second concern is semantic visibility. Because `bind`, `emit_gadget`, and undeclared output helpers often auto-create private targets, authors who forget to predeclare public outputs can accidentally construct correct-but-private signals. The builder does not infer exposure intent.

### Verdict

The computational core of `ProgramBuilder` is explicit, disciplined, and more capable than a toy arithmetic builder. Its strongest qualities are type refinement, helper composition, and gadget namespacing. Its main weakness is not computational dishonesty but representational mismatch: some builder-era constructs still outrun what `ir-v2` can carry.

## PHASE 3 — RUNTIME / GRAPH / SCHEDULER LAYER

### Files Examined

- `zkf-lib/src/app/api.rs`
- `zkf-core/src/lowering/mod.rs`
- `zkf-core/src/ir.rs`
- `zkf-backends/src/audited_backend.rs`
- `zkf-backends/src/arkworks.rs`
- `zkf-backends/src/blackbox_gadgets/mod.rs`

### Findings

`ProgramBuilder` itself has no runtime, scheduler, or graph engine. Its product is an `ir-v2::Program`. The runtime story begins immediately after `build()`, inside `zkf-lib/src/app/api.rs`.

The builder’s lowering boundary is deterministic. `build()` first assembles a `zir::Program`, validates it, and calls `program_zir_to_v2`. That lowering converts typed ZIR signals into `ir-v2` signals with string type annotations such as `bool` or `uint(16)`, translates constraints, carries lookup tables forward, copies metadata, and initializes an empty `input_aliases` map in the `ir-v2` witness plan. The builder then restores the author’s aliases into that map manually. This restoration matters because `program_zir_to_v2` itself does not preserve aliases.

Alias restoration is not decorative. The app API resolves input aliases before witness generation in both `witness_from_inputs` and `witness_from_compiled_inputs`. That means builder-authored programs can expose stable external names while using different internal signal names if necessary. The builder test suite explicitly checks that this survives lowering.

Once a built program enters the embedded API, the standard path is:

1. compile the `Program`
2. resolve aliases and generate a witness
3. enrich or prepare the witness when lowering introduced auxiliary signals
4. prove with the selected backend
5. verify against the compiled artifact

The builder does not choose the runtime backend directly. `compile_default` does that from the program’s field. For example, BN254 defaults to Arkworks Groth16. This is another place where the builder is an authoring surface rather than an execution policy surface.

The digest and program-identity story is stronger than many builder-style systems. `prove_with_inputs` compares the digest of the caller’s source `Program` against the compiled artifact’s expected program digest. If they do not match, the proof flow rejects the request. This prevents a common class of accidental or malicious “compile one program, prove another” mismatches. Builder-produced programs therefore carry into the normal digest guardrails without special casing.

Progress-aware proving also works transparently for builder-authored programs. `compile_and_prove_with_progress` emits stage events for compile, witness generation, witness preparation, and proving. The builder does not participate in this logic directly, but because it emits a normal `Program`, app UIs can treat builder-authored circuits like any other circuit in the embedded flow.

The most important runtime interaction is with blackbox lowering and audited witness preparation. If the compiled artifact differs from the source program because blackbox constraints were lowered, backends may retain `compiled.original_program`. The audited witness path then:

- enriches the witness with auxiliary values
- validates blackbox constraints against the original program when retained
- checks constraints on the compiled program
- validates blackbox constraints again on the compiled surface

This matters for builder usage because many of its high-level conveniences eventually emit blackbox constraints or gadgets that become blackbox constraints. The builder itself does not solve the soundness problem. It relies on the audited backend path to retain and validate the original semantic surface when lowering changes the executable circuit.

### Gaps and Concerns

There is no builder-level way to express runtime policy. The builder cannot demand a specific backend route, a strict trust lane, a certified GPU requirement, or a scheduler strategy. Those concerns live downstream in compile/prove configuration and backend/runtime metadata.

A second concern is that the builder’s author-intent vocabulary disappears after build unless higher app surfaces preserve it. Once lowered, a `constrain_geq_labeled` helper is just assignments, equalities, and ranges. That is fine for proving, but it means runtime tooling only sees the expanded form unless labels or app metadata preserve enough context.

### Verdict

The runtime story for `ProgramBuilder` is clean because the builder does not invent a parallel execution engine. It emits a normal `Program` and relies on the shared embedded API, digest guards, alias resolution, audited witness preparation, and backend compilation pipeline that the rest of the framework already uses.

## PHASE 4 — GPU / ACCELERATION LAYER

### Files Examined

- `zkf-gadgets/src/gadget.rs`
- `zkf-gadgets/src/poseidon.rs`
- `zkf-gadgets/src/merkle.rs`
- `zkf-gadgets/src/range.rs`
- `zkf-backends/src/blackbox_gadgets/mod.rs`
- `zkf-backends/src/plonky3.rs` via search results
- `zkf-lib/src/app/orbital.rs`
- `zkf-lib/src/app/descent.rs`
- `zkf-lib/src/app/satellite.rs`

### Findings

The honest answer is that `ProgramBuilder` has no direct GPU or acceleration logic. It does not know about Metal devices, runtime attestation, threadgroup sizing, or trusted GPU lanes. It cannot dispatch anything. What it can do is emit circuit structure that later backends may accelerate.

This happens in three main ways.

First, raw blackbox constraints produced by the builder, especially Poseidon and SHA-256, can later be lowered or specialized by backends. The Poseidon gadget in `zkf-gadgets/src/poseidon.rs` explicitly says it emits blackbox Poseidon so backends that support native Poseidon can handle it directly while others decompose it into round constraints. That is the right architectural boundary: the builder states the intended operation; the backend decides how it is realized.

Second, gadget field support is partly driven by live backend capability discovery. `builtin_supported_fields("poseidon")`, `builtin_supported_fields("merkle")`, and `builtin_supported_fields("sha256")` consult `BackendCapabilityMatrix::current()` to determine which fields the current binary claims for those operations. That means the builder’s acceptance policy already reflects the acceleration and backend surface in a limited but meaningful way. It does not talk to a GPU, but it does refuse gadget-field combinations that the installed backend matrix does not support.

Third, the builder is used to author large programs that later run through acceleration-aware backends and strict runtime surfaces. The orbital, powered descent, and satellite showcase builders construct substantial programs with hundreds or thousands of signals and constraints, annotate them with rich metadata, and then rely on the normal compile/prove/export stack. Those programs are still builder-authored applications even when they later participate in strict cryptographic lanes or hardware-aware proof paths. In other words, the builder is upstream of acceleration, not outside it.

It is also worth noting what the builder does not encode. There is no `gpu_hash`, `metal_poseidon`, or `strict_accelerated_only` method. There are no acceleration metadata keys inserted automatically. When showcase builders attach metadata like `application`, `integrator`, `fixed_point_scale`, `determinism`, or domain-specific bounds, those entries describe the application’s math and semantics, not the execution hardware.

The separation is healthy. It keeps authoring logic backend-neutral and prevents application authors from smuggling hardware claims into the circuit structure itself. The hardware truth surfaces belong in runtime telemetry, backend metadata, and verified acceleration layers, not in the builder API.

### Gaps and Concerns

The cost of this clean separation is that the builder cannot express trust-lane requirements. An author cannot say “this circuit must only run on a certified GPU lane” through `ProgramBuilder` itself. If that policy matters, it must be enforced later in the runtime or deployment envelope.

A second concern is discoverability. Because acceleration is downstream, builder users may not realize which helpers are likely to map efficiently to native backend support and which will be fully lowered into arithmetic constraints. The subsystem exposes some truth through gadget specs and capability-backed field support, but it does not yet offer a first-class “cost or execution-plan preview” at authoring time.

### Verdict

`ProgramBuilder` is acceleration-adjacent, not acceleration-owning. It emits backend-neutral circuit intent. GPU specialization and verified hardware behavior happen later, in the backend and runtime layers.

## PHASE 5 — FORMAL VERIFICATION SURFACE

### Files Examined

- `zkf-lib/src/app/builder.rs`
- `zkf-core/src/type_check.rs`
- `zkf-core/src/lowering/mod.rs`
- `zkf-backends/src/blackbox_gadgets/mod.rs`
- `zkf-backends/src/audited_backend.rs`
- `AGENTS.md`

### Findings

This phase requires direct honesty. `ProgramBuilder` is not itself a mechanized theorem surface. There is no Lean theorem proving that arbitrary builder sessions preserve a formal semantic specification. The subsystem’s guarantees are implementation guarantees, not theorem-prover guarantees.

What it does have is a fail-closed validation chain.

At authoring time, the builder accumulates data permissively. At `build()` time, it validates:

- every alias target references a declared signal
- every assignment target is declared
- every signal mentioned inside assignment expressions is declared
- every hint target is declared
- every hint source is declared
- the entire `zir::Program` passes `zkf_core::type_check::type_check`

If any of that fails, `build()` returns a single `InvalidArtifact` error summarizing the accumulated failures. The builder does not emit a half-valid `Program`.

The type checker is the second guardrail. It catches duplicate signals, undeclared signals in constraints, invalid boolean applications, invalid range applications, and blackbox output references to undeclared signals. The checker is deliberately lenient where the type system is intentionally partial, but it still blocks structural nonsense.

The lowering layer is the third guardrail. `program_zir_to_v2` only knows how to represent a subset of ZIR constraints in `ir-v2`. Equality, boolean, range, blackbox, lookup, permutation, and copy survive. Permutation and copy lower into plain equalities. Custom gates and memory constraints fail with `UnsupportedBackend` errors. That means the builder’s parity surface is honest at build time: unsupported constructs do not silently evaporate.

The blackbox path is the fourth guardrail. `ProgramBuilder` can emit blackbox constraints and gadgets that emit blackbox constraints. Those operations are not trusted as opaque wishes. The backend layer lowers blackbox constraints into arithmetic constraints or validates them through dedicated enrichment and audit logic. The comments in `zkf-backends/src/blackbox_gadgets/mod.rs` are blunt: without lowering, blackbox ops would create a soundness gap. The subsystem closes that gap downstream by expressing the operations in enforceable circuit form and by retaining the original program when necessary.

The audited backend path is the fifth guardrail. The repo instructions insist that:

- `lower_blackbox_program()` must run before synthesis
- `enrich_witness_for_proving()` must run before constraint checking in prove paths
- `original_program` must be retained when blackbox lowering occurs

The audited witness path in `audited_backend.rs` implements that discipline. If an original program is retained, it validates blackbox semantics against that original surface before and after compiled-program constraint checks. This is exactly the kind of fail-closed behavior the builder needs downstream, because many high-level builder programs rely on blackbox-friendly authoring patterns.

The builder’s own unit tests reinforce the honesty of this boundary. They check that memory and custom-gate surfaces “fail honestly at build.” That wording is accurate. The API exposes those methods, but the current stack does not pretend they are fully lowered or production-ready through `ir-v2`.

### Gaps and Concerns

The primary gap is categorical: this subsystem is bounded, not mechanized. It is tested and validated, but it is not proven in the same sense as the repository’s formal GPU and proof-boundary surfaces.

A second concern is representational loss. Because helpers like `constrain_geq_labeled` and `constrain_select_labeled` lower into simpler primitives, downstream proof or audit tooling may only see the expanded circuit, not the original high-level intent, unless labels and metadata are rich enough to reconstruct it.

### Verdict

The builder is not a theorem, but it is not bluff either. Its assurance story is “validate, lower, audit, enrich, and fail closed,” not “trust the author.” Within that narrower scope, it behaves honestly.

## PHASE 6 — DISTRIBUTED / SWARM / CONSENSUS LAYER

### Files Examined

- `zkf-lib/src/app/builder.rs`
- `zkf-lib/src/app/api.rs`
- workspace metadata from `cargo metadata`
- search results across the repo for `ProgramBuilder`

### Findings

There is essentially no direct distributed or swarm logic in the ProgramBuilder subsystem. No builder method configures distributed proving, consensus, job orchestration, or swarm behavior. No `ProgramBuilder` call site was found in the repo’s distributed or swarm-oriented crates during the targeted search.

That absence is informative rather than disappointing. The builder’s job is authoring a `Program`. Distributed execution, if used, operates on compiled programs, proof jobs, artifacts, and runtime orchestration surfaces later in the stack. In other words, the builder is upstream of distribution but not distribution-aware.

This also means builder-authored applications remain portable. The same authored `Program` can be sent through different operational environments without changing the authoring surface. That is usually the correct separation. Circuit authoring and proof-job scheduling should not be welded together.

### Gaps and Concerns

The lack of distributed hooks means authors cannot declare distribution-sensitive constraints at the builder level, such as “must preserve this metadata through remote prove jobs” or “must carry this application contract into a swarm audit surface.” If those capabilities matter, they need to be layered elsewhere.

### Verdict

For ProgramBuilder specifically, the distributed phase is intentionally thin. The subsystem does not attempt to be a swarm DSL. It emits portable programs and leaves distribution to later layers.

## PHASE 7 — IDENTITY / SUPPLY CHAIN / APPLICATION TRUST LAYER

### Files Examined

- `zkf-lib/src/app/private_identity.rs`
- `zkf-lib/src/app/templates.rs`
- `zkf-lib/src/app/orbital.rs`
- `zkf-lib/src/app/descent.rs`
- `zkf-lib/src/app/satellite.rs`
- `zkf-lib/examples/private_identity_service_tier.rs`
- `private_budget_approval/README.md`
- `private_budget_approval/zirapp.json`
- `private_budget_approval/src/spec.rs`
- `private_budget_approval/src/main.rs`

### Findings

This is where the builder stops looking like a convenience wrapper and starts looking like a real application substrate.

The private identity template shows the pattern clearly. `private_identity_kyc()` uses `ProgramBuilder` to assemble a BN254 circuit with private subject values, public registry roots and policy parameters, Poseidon commitments, Merkle path checks, status-bit decomposition, range constraints, and explicit expected-input/public-output lists. The builder is not merely wiring arithmetic. It is encoding an application contract: what the prover must know, what the verifier sees, and which semantic checks the circuit enforces.

The larger showcase builders go further. The orbital, powered-descent, and satellite programs use the builder to generate domain programs with rich metadata entries such as application name, body count, integration steps, integrator, fixed-point scale, physical bounds, determinism notes, and error-model notes. This is not proof-validity metadata in the cryptographic sense, but it is application-truth metadata. It tells downstream tools and exported bundles what the circuit claims to represent.

The standalone `private_budget_approval` app provides an especially useful external perspective. Its README explicitly says the app remains on the exposed app-spec / ProgramBuilder surface and avoids framework changes. The generated loader reads `zirapp.json`, deserializes `AppSpecV1`, calls `zkf_lib::build_app_spec`, then runs `check`, `compile_and_prove_default`, and `verify`. Its smoke tests prove, verify, tamper-check, and export Solidity/Foundry artifacts from that builder/spec-authored application. This is the builder subsystem functioning as product infrastructure, not internal experimentation.

The app-trust story also depends on sidecar structures outside the core `Program`:

- `TemplateProgram.expected_inputs`
- `TemplateProgram.public_outputs`
- `TemplateProgram.sample_inputs`
- `AppSpecV1.expected_inputs`
- `AppSpecV1.public_outputs`
- `AppSpecV1.description`
- `AppSpecV1.template_id`
- `AppSpecV1.template_args`

These fields compensate for the core IR’s lack of explicit input/output roles. They turn a bare circuit into an application contract that scaffolds, CLIs, and examples can present coherently.

Input aliases belong in this phase too. They let external application interfaces keep stable names even if internal builder names differ. That is a small feature with large trust implications for app maintainability, because it reduces the need for external callers to mirror internal refactors.

There is also an important negative finding. The builder does not itself encode supply-chain trust lanes, setup provenance, or deployment-grade certification semantics. Those live later in the runtime, backend metadata, and export/evidence layers. The builder contributes application meaning, not operational trust classification.

One subtle concern emerged from the template/AppSpec conversion path. `instantiate_template()` converts a built `Program` back to ZIR with `program_v2_to_zir`, and that function creates a fresh metadata map containing `ir_family`, `source_ir`, and `program_digest_v2`. It does not merge the original `Program.metadata`. As a result, application metadata authored inside template programs is not preserved when templates are instantiated into `AppSpecV1`. For simple templates this may be harmless. For richer showcases it means some app-semantics metadata present in the built program is lost in the scaffoldable declarative form.

### Gaps and Concerns

The metadata-loss issue above is the most concrete application-trust gap in the current builder-adjacent design. Rich builder-authored template metadata exists, but the current template-to-AppSpec roundtrip does not preserve it.

A second concern is that the builder exposes application meaning but not deployment trust-lane meaning. Authors can say what a circuit models; they cannot, from the builder alone, say whether that circuit must be treated as native, compatibility, strict, bounded, or mechanized in later surfaces.

### Verdict

The application-trust layer is where ProgramBuilder is most valuable. It enables real app contracts, not just equations. Its main current weakness is lossy metadata preservation when rich templates are normalized back into scaffold-friendly AppSpecs.

## PHASE 8 — CLI / API / AGENTIC / FFI SURFACE

### Files Examined

- `docs/CLI.md`
- `docs/TUTORIAL.md`
- `zkf-cli/src/cmd/app.rs`
- `zkf-python/src/lib.rs`
- `zkf-lib/src/lib.rs`
- `zkf-lib/src/app/spec.rs`
- `zkf-lib/src/app/api.rs`

### Findings

From an interface-design perspective, the builder sits behind three public faces.

The first face is the Rust library face. `zkf-lib` re-exports `ProgramBuilder` directly, alongside app-spec builders, templates, gadgets, compile/prove/verify helpers, and verifier export helpers. This is the canonical direct entrypoint for imperative authors.

The second face is the CLI scaffold face. `zkf app init` and `ziros app init` do not generate imperative builder code by default. They instantiate a template into `AppSpecV1`, validate it with `build_app_spec`, write `zirapp.json`, write a generic `src/spec.rs` loader, and produce a runnable `src/main.rs` that compiles, proves, and verifies through `zkf-lib`. The generated README explicitly tells users that `ProgramBuilder` remains available when they need advanced authoring. That is a deliberate onboarding strategy: start declarative, escape to imperative only when necessary.

The third face is the Python face, and it is revealing. Python exposes:

- `build_app_spec(spec_json)`
- `template_registry()`
- `instantiate_template(template_id, template_args_json)`

It does not expose a Python `ProgramBuilder` object. This confirms that the cross-language contract is declarative rather than imperative. Non-Rust consumers are expected to manipulate `AppSpecV1` JSON or template IDs rather than script a stateful builder API.

The agentic/API portion is similar. The app API in `zkf-lib/src/app/api.rs` works on finished `Program` values, not on a builder session. It offers compile, prove, verify, check, default backend resolution, alias resolution, and progress reporting. Once again, the builder’s responsibility ends at program construction.

An important interface detail is that `AppSpecV1` is not merely a serialized `Program`. It includes builder-flavored operations such as `Leq`, `Geq`, `Nonzero`, `Select`, and `Gadget`, which are higher-level than the core IR. `build_app_spec()` reconstructs those by replaying builder helpers. But the reverse direction is asymmetrical: when a built template program is converted back into `AppSpecV1`, it is mostly normalized into lower-level `Assign`, `Equal`, `Boolean`, `Range`, `Lookup`, `BlackBox`, `CustomGate`, `MemoryRead`, `MemoryWrite`, `Permutation`, and `Copy` operations. The roundtrip therefore preserves behavior, not necessarily the most semantic author syntax.

This asymmetry is reasonable. It means AppSpec is a declarative builder language, not simply a JSON dump of `Program` and not a guaranteed reversible copy of the original author’s helper vocabulary.

### Gaps and Concerns

The absence of a non-Rust builder surface is a real limitation. Today, imperative builder authoring is effectively reserved for Rust users. Everyone else gets the declarative layer.

A second concern is that some developers may misread `AppSpecV1` as the canonical internal representation. It is not. It is a declarative replay language that depends on builder semantics and then lowers further.

### Verdict

Across CLI, library, and Python surfaces, the repo is consistent: `ProgramBuilder` is the advanced Rust-native authoring API; `AppSpecV1` and templates are the portable declarative interface.

## PHASE 9 — TESTING / RELIABILITY

### Files Examined

- `zkf-lib/src/app/builder.rs`
- `zkf-lib/src/app/spec.rs`
- `zkf-lib/src/app/api.rs`
- `zkf-gadgets/src/registry.rs`
- `zkf-gadgets/src/poseidon.rs`
- `zkf-gadgets/src/boolean.rs`
- `zkf-gadgets/src/merkle.rs`
- `zkf-gadgets/src/range.rs`
- `zkf-integration-tests/tests/developer_use_cases.rs`
- `private_budget_approval/tests/smoke.rs`
- template-module tests discovered in `private_identity.rs`, `orbital.rs`, `descent.rs`, `satellite.rs`, and `multi_satellite.rs`

### Findings

The builder subsystem has stronger test coverage than many “builder” abstractions usually do.

At the unit level, `zkf-lib/src/app/builder.rs` tests cover:

- alias restoration after lowering
- boolean and range type annotation propagation
- built-in gadget emission and lowering
- gadget metadata enumeration
- undeclared signal detection at build
- unsupported gadget-field rejection
- hint and metadata round trips
- typed helper emission for Poseidon, SHA-256, and boolean ops
- contract-rich gadget error messages
- namespace isolation across repeated gadget invocations
- label decoration for relation helpers
- honest failure for unsupported memory/custom-gate surfaces

This is good coverage for a builder module because it validates both success paths and its most important failure modes.

At the spec layer, `zkf-lib/src/app/spec.rs` tests cover template registry integrity, template roundtripping, and builder helper expansion from declarative ops such as `Leq`, `Nonzero`, and `Select`. That matters because much of the app-facing ecosystem reaches builder behavior through `AppSpecV1` rather than direct Rust authoring.

At the gadget layer, there are unit tests for the registry and individual gadgets. These do not test the builder directly, but they test the contracts the builder depends on: required params, supported fields, emitted constraints, and registry shape.

At the integration level, `zkf-integration-tests/tests/developer_use_cases.rs` is the strongest evidence that the builder is used for real circuits rather than just samples. Those tests construct DeFi, identity, nullifier, compliance, authentication, and governance patterns with `ProgramBuilder`, then run them across multiple backends including Arkworks Groth16, Halo2, and Plonky3. The file’s framing is explicit: these are meant to represent what ZK developers actually build.

The external-app smoke coverage in `private_budget_approval/tests/smoke.rs` adds another important reliability layer. It proves that a builder/spec-authored standalone application can:

- load its declarative spec
- build a program
- check witness generation
- prove
- verify
- detect tampered public inputs
- export Solidity verifier and Foundry test assets

This is exactly the kind of end-to-end assurance that authoring layers often lack.

The builder also benefits indirectly from broader stack checks such as `check()` in the embedded API, which validates witness completeness and can reject underconstrained programs. The builder does not own that logic, but builder-authored programs pass through it.

### Gaps and Concerns

I did not find dedicated fuzzing, `proptest!`, or other property-based stress tests specifically targeting builder method composition. The existing tests are good, but they are mostly example-driven and regression-driven rather than generative over large builder-session search spaces.

A second gap is author-intent preservation testing. The suite checks labels and namespacing, but there is limited evidence that downstream tooling reconstructs high-level helper intent reliably once programs have been lowered and normalized.

### Verdict

The testing posture for ProgramBuilder is solid and much better than superficial. It covers unit semantics, declarative replay, gadget contracts, multi-backend application circuits, and standalone-app export flows. Its main remaining opportunity is more property-based testing of arbitrary builder compositions.

## PHASE 10 — HONEST ASSESSMENT

### Files Examined

- Entire source corpus listed above

### Findings

`ProgramBuilder` is the subsystem ZirOS uses when it needs imperative, explicit, source-level circuit authoring without dropping to raw `Program` JSON by hand. It is broad enough to support large application circuits, but narrow enough to stay understandable. It is explicit enough to avoid magical witness inference, but ergonomic enough to save authors from rebuilding the same witness assignments, relation encodings, and gadget namespacing patterns over and over.

Its best design choice is the layering choice. By authoring in `zir-v1` and lowering to `ir-v2` only at `build()`, the builder gets a typed, app-oriented construction space with labels, metadata, lookup tables, custom gates, memory regions, aliases, and gadget emissions. That gives authors a better interface than direct raw-IR construction would. The cost is representational mismatch, but the code handles that mismatch honestly by failing at build time where lowering is unsupported.

Its second best design choice is that it does not try to own the entire stack. The builder does not compile, prove, verify, schedule, dispatch to GPU, or classify trust lanes. It hands a normal `Program` to the rest of the framework and lets the existing compile/prove/check surfaces do their work. That prevents duplicated semantics and keeps the builder composable.

Its third best design choice is the gadget model. The registry/spec/emission pattern is clean. Field support is checked. Contracts are discoverable. Internal names are namespaced. Error messages include required params and nearby gadget names. For a builder API, that is disciplined engineering.

Its biggest conceptual limitation is that the author-facing method names imply a richer semantic model than the core IR stores. There is no true input/output distinction in the final `Program`; there are only signals, witness plans, visibility, and app-side contracts. Once you understand that, the system makes sense. If you do not understand it, you may overestimate what the builder preserves structurally.

Its biggest practical limitation is the parity surface. Custom gates and memory regions exist in the builder API, but not in `ir-v2` lowering. That is honest but incomplete. The subsystem advertises those methods as available authoring vocabulary while still treating them as unsupported for finalized lowered programs.

Its biggest interface limitation is language reach. Direct imperative authoring is Rust-only. Python and scaffolded external apps go through `AppSpecV1`.

Its biggest concrete gap, based on the current code, is metadata preservation across template instantiation. Builder-authored template metadata is richer than what survives the current `program_v2_to_zir` path.

On the assurance question, the right classification for ProgramBuilder is bounded and implementation-grounded, not mechanized. It is validated, type-checked, tested, and integrated into audited backend flows, but it is not itself the repository’s formal proof artifact. That is acceptable if stated plainly, and the current code largely does state it plainly. The subsystem does not pretend to be more verified than it is.

### Gaps and Concerns

- The public/private input/output vocabulary should be taught more aggressively as author intent rather than core IR ontology.
- Template metadata preservation from builder-authored programs into `AppSpecV1` deserves repair.
- Unsupported parity surfaces should either move closer to early rejection or gain clearer public documentation that they are builder-visible but lowering-incomplete.
- Non-Rust imperative authoring remains absent.

### Verdict

ProgramBuilder is one of the healthier subsystem designs in this checkout. It is not a bluff surface, not a toy, and not a proof surface pretending to be something it is not. It is a serious imperative authoring layer that cleanly bridges human-authored circuit logic into the shared proving stack. Its deficiencies are real, but they are mostly honest deficiencies rather than hidden ones.

## Appendix A — Public Method Inventory

This appendix lists the public `ProgramBuilder` surface in plain language.

### Constructor and Registry Surface

- `new(name, field)`: create a builder with built-in gadgets pre-registered.
- `with_registry(name, field, registry)`: create a builder with an explicit gadget registry.
- `available_gadgets()`: return the current built-in gadget specs.
- `gadget_info(name)`: return a specific gadget spec if present.
- `register_gadget(gadget)`: add a custom gadget implementation to the registry.

### Signal Declaration Surface

- `private_input(name)`: declare a private signal. Semantically this is author intent for an externally supplied private value.
- `public_input(name)`: declare a public signal. Semantically this is author intent for a public input.
- `public_output(name)`: also declare a public signal. Structurally identical to `public_input`.
- `private_signal(name)`: declare a private signal, typically for derived intermediates.
- `constant_signal(name, value)`: declare a constant signal with fixed value.

### Witness and Metadata Surface

- `input_alias(alias, target)`: map an external input key to an internal signal name.
- `add_assignment(target, expr)`: add a witness-plan assignment without automatically constraining it.
- `add_hint(target, source)`: add a witness hint edge.
- `metadata_entry(key, value)`: store arbitrary metadata on the authored program.

### Primitive Constraint Surface

- `constrain_equal(lhs, rhs)` and labeled variant: emit an equality.
- `constrain_boolean(signal)` and labeled variant: mark a signal boolean and emit a boolean constraint.
- `constrain_range(signal, bits)` and labeled variant: mark a signal bounded and emit a range constraint.
- `bind(target, expr)` and labeled variant: assignment plus equality tie-back.

### Derived Helper Surface

- `constrain_leq(slack, lhs, rhs, bits)` and labeled variant: encode `lhs <= rhs` through slack arithmetic and range checking.
- `constrain_geq(slack, lhs, rhs, bits)` and labeled variant: encode `lhs >= rhs`.
- `constrain_nonzero(signal)` and labeled variant: enforce multiplicative invertibility through an inverse witness.
- `constrain_select(target, selector, when_true, when_false)` and labeled variant: arithmetic conditional select.

### Blackbox and Gadget Surface

- `poseidon_hash(inputs, outputs)`: convenience wrapper over the Poseidon gadget with width inference for 2- and 4-lane cases.
- `sha256_hash(inputs, outputs)`: convenience wrapper over the SHA-256 gadget.
- `boolean_op(op, inputs, output)`: convenience wrapper over the boolean gadget.
- `emit_gadget(gadget, inputs, outputs, params)` and labeled variant: invoke a gadget through the registry and merge its emitted structure.
- `constrain_blackbox(op, inputs, outputs, params)` and labeled variant: emit a raw blackbox constraint after surface validation.

### Parity / Extended Surface

- `add_lookup_table(name, columns, values)`: define a lookup table.
- `constrain_lookup(inputs, table)` and labeled variant: emit a lookup constraint.
- `define_memory_region(name, size, read_only)`: define a named memory region.
- `constrain_memory_read(memory, index, value)` and labeled variant: express a memory-read relation.
- `constrain_memory_write(memory, index, value)` and labeled variant: express a memory-write relation.
- `define_custom_gate(name, input_count, output_count, constraint_expr)`: define a custom gate signature.
- `constrain_custom_gate(gate, inputs, outputs, params)` and labeled variant: invoke a named custom gate.
- `constrain_copy(from, to)` and labeled variant: equate two named signals through a copy relation.
- `constrain_permutation(left, right)` and labeled variant: express a permutation-style equality relation.

### Finalization Surface

- `build()`: validate the accumulated `zir-v1` program, lower it to `ir-v2`, restore input aliases, and either return a finalized `Program` or fail closed.

## Appendix B — Practical Interpretation

If you are deciding when to use this subsystem, the short answer is:

- use `zirapp.json` / `AppSpecV1` when you want a scaffoldable, cross-language, declarative contract
- use `ProgramBuilder` when the circuit is easier to express as code than as JSON
- use direct raw `Program` construction only when you truly want the lowest shared IR surface

In this repo, the imperative builder is what the author reaches for when circuit logic becomes structured, repetitive, domain-heavy, or metadata-rich. The source supports that choice.
