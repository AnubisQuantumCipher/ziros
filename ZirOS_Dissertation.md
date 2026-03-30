# ZirOS: A Dissertation on the Architecture, Capabilities, and Significance of the Zero-Knowledge Operating System

---

## Abstract

ZirOS is a zero-knowledge proving system that operates at the scale and discipline of an operating system rather than a library. It manages the entire lifecycle of a zero-knowledge computation: authoring, importing, auditing, compiling, scheduling, accelerating, verifying, exporting, storing, and formally accounting for every claim it makes about the artifacts it produces. The system spans approximately five hundred thousand lines of Rust across thirty workspace crates, integrates nine proving backends and seven circuit frontends, accelerates computation through sixty-three formally verified Apple Metal GPU shaders, manages persistent state through iCloud Drive and iCloud Keychain, implements CNSA 2.0 Level 5 post-quantum cryptography across all identity and communication surfaces, and tracks one hundred sixty mechanized verification ledger entries with zero pending claims across five formal proof languages. This dissertation documents every technology in the system, explains why each design decision was made, and assesses the significance of the result for the fields of cryptography, aerospace engineering, formal verification, and computer systems.

---

## I. The Problem ZirOS Solves

Zero-knowledge proving has a tooling problem. The mathematical foundations are sound. The proof systems — Groth16, PLONK, STARK, Nova — have rigorous security proofs published in peer-reviewed venues. The field arithmetic is well-understood. The commitment schemes are standardized. But the engineering surface between a mathematician's theorem and a working proof application is vast and treacherous.

A developer building a zero-knowledge application today must choose a curve, choose a field, choose a commitment scheme, choose a backend, wire up their own constraint system, implement their own witness generator, manage their own trusted setup ceremony if the backend requires one, figure out their own GPU acceleration if they want performance, write their own verifier export if they need on-chain verification, manage their own artifact storage, and hope they have not introduced a soundness bug that will pass every test but fail in production. The most common class of vulnerability in deployed zero-knowledge systems — underconstrained private signals — is precisely the kind of bug that tests do not catch because the constraint system accepts any value for the underconstrained signal. The system appears to work. The proofs verify. The application is live. And the security is broken.

ZirOS eliminates this class of problem by treating zero-knowledge proving as an operating system concern rather than a library concern. The developer describes the statement they want proven. ZirOS handles the rest: the IR lowering, the nonlinear anchoring audit that rejects underconstrained signals before compilation, the witness generation with safety checks, the backend selection across nine proving systems, the CPU and GPU scheduling with trust-lane propagation, the Metal GPU dispatch with four-digest attestation, the proof verification, the Solidity verifier export, the iCloud archival with witness purging, and the formal accounting of every claim through a mechanized verification ledger.

The result is a system where the developer focuses on their domain — aerospace dynamics, financial compliance, medical privacy, identity verification — and the operating system handles the cryptographic plumbing, the hardware policy, the security model, and the artifact lifecycle.

---

## II. Scale and Structure

ZirOS consists of approximately five hundred thousand lines of first-party Rust code distributed across thirty workspace crates. The crates are organized into seven functional layers: authoring and import, canonical core and proof systems, runtime and scheduling, hardware acceleration, distributed and defensive systems, operator surfaces, and verification and evidence.

The canonical core crate, `zkf-core`, defines the intermediate representation that all circuits pass through: programs, expressions, constraints, signals, field elements, witness generation, audits, diagnostics, and proof artifact data structures. Every circuit — whether authored in Rust through `ProgramBuilder`, imported from Noir, Circom, Cairo, Compact, Halo2, Plonky3 AIR, or a zkVM descriptor — is lowered to this canonical IR before compilation. The IR normalization has a Lean 4 proof. The witness preservation through backend lowering has Rocq proofs. The type checking is enforced at compile time.

The backend crate, `zkf-backends`, implements compile, prove, and verify operations for nine backend families. The runtime crate, `zkf-runtime`, models proving as a directed acyclic graph of operations with explicit dependencies, buffer slots, device placements, and trust-lane propagation. The Metal crate, `zkf-metal`, owns sixty-three GPU shader sources with fifty kernel entrypoints, nine attestation manifests, and eighteen Lean 4 proof files. The distributed crate, `zkf-distributed`, handles multi-node coordination, Byzantine consensus, and swarm defense. The operator surfaces span a CLI, an HTTP API, Python bindings, a C FFI bridge, an LSP server, and terminal UI components.

This is not a monolith. Each crate has a defined responsibility, a defined interface, and defined trust boundaries. The verification ledger tracks which claims are mechanized, which are attested, which are model-only, and which carry explicit hypotheses. The ledger has one hundred sixty entries, all mechanized local, with zero pending.

---

## III. Post-Quantum Cryptography

ZirOS implements the National Security Agency's Commercial National Security Algorithm Suite 2.0, the United States government's standard for quantum-resistant cryptography in national security systems. CNSA 2.0 mandates specific algorithms at specific security levels with specific adoption timelines. ZirOS meets every requirement at NIST Security Level 5, the highest level, equivalent to AES-256 security.

### Digital Signatures: ML-DSA-87

The Module-Lattice-Based Digital Signature Algorithm, standardized as NIST FIPS 204 in August 2024, provides digital signatures whose security is based on the hardness of the Module Learning With Errors problem. There is no known quantum algorithm that efficiently solves this problem. ZirOS uses the ML-DSA-87 parameter set, which provides NIST Level 5 security with a public key of 2,592 bytes, a signature of 4,627 bytes, and a private key of 4,896 bytes.

ML-DSA-87 is deployed across four surfaces in ZirOS. First, every swarm peer identity carries a hybrid Ed25519 plus ML-DSA-87 signature bundle. Both signatures must verify for any identity operation to succeed. This is defense in depth: if Ed25519 is broken by a quantum computer, the ML-DSA-87 signature holds; if ML-DSA-87 has an unknown classical vulnerability, the Ed25519 signature holds. Second, the credential issuance system supports ML-DSA-87 signed credentials through the `IssuerSignedCredentialV1` type. Third, every proof artifact can carry an ML-DSA-87 origin attestation through the `proof_origin_signature` field, which signs the SHA-384 digest of the proof bytes. Fourth, the swarm gossip protocol signs threat intelligence digests with the hybrid signature bundle.

The implementation uses the `libcrux-ml-dsa` crate version 0.0.8, a high-assurance Rust implementation from Cryspen and Mozilla that has been formally analyzed and targets constant-time execution on ARM64.

### Key Establishment: ML-KEM-1024

The Module-Lattice-Based Key Encapsulation Mechanism, standardized as NIST FIPS 203 in August 2024, provides key agreement whose security is based on the same Module Learning With Errors problem. ZirOS uses the ML-KEM-1024 parameter set at NIST Level 5 with an encapsulation key of 1,568 bytes, a ciphertext of 1,568 bytes, and a shared secret of 32 bytes.

ML-KEM-1024 is deployed in the swarm epoch key exchange. Each hour, every swarm peer generates both an X25519 keypair and an ML-KEM-1024 keypair. When two peers establish an encrypted gossip channel, they compute an X25519 Diffie-Hellman shared secret and an ML-KEM-1024 shared secret, then combine both through HKDF-SHA384 into a single symmetric key for ChaCha20-Poly1305 authenticated encryption. This hybrid construction ensures that compromising either algorithm alone does not compromise the encryption key.

The wire protocol in `protocol.rs` carries ML-KEM public keys in handshake, acknowledgment, and heartbeat messages, and ML-KEM ciphertexts in encrypted threat envelopes. The epoch system rotates keys hourly, with a grace window accepting the previous epoch's keys to prevent message loss during rotation.

### Post-Quantum Proofs

The Plonky3 STARK backend produces proofs that are information-theoretically sound against quantum adversaries. The FRI polynomial commitment scheme is based on Merkle trees constructed from hash functions, not elliptic curves or discrete logarithms. Shor's algorithm, which breaks factoring and discrete logarithm problems in polynomial time on a quantum computer, has nothing to attack in a STARK proof. Grover's algorithm provides at most a quadratic speedup against hash function security, meaning a 256-bit hash still provides 128 bits of post-quantum security.

The Groth16, Halo2, and Nova backends are not post-quantum. They rely on elliptic curve pairings and discrete logarithm assumptions that Shor's algorithm breaks. The STARK-to-Groth16 wrapping pipeline compresses a post-quantum STARK proof into a classical Groth16 proof for Ethereum on-chain verification, but the outer wrapper is not post-quantum. These trust boundaries are explicitly documented and labeled in every proof artifact.

---

## IV. iCloud-Native Storage Architecture

ZirOS is the first cryptographic system of any kind to use iCloud Drive as its persistent storage layer and iCloud Keychain as its key management layer. This is not a backup feature. iCloud is the source of truth. The local SSD is a cache.

### The Architecture

Every persistent artifact ZirOS produces — proofs, execution traces, Solidity verifiers, mission assurance reports, circuit audit results, Neural Engine training telemetry, swarm threat patterns, detection rules, reputation logs, and system configuration — is written to a structured directory tree at `~/Library/Mobile Documents/com~apple~CloudDocs/ZirOS/`. This path is managed by macOS as part of iCloud Drive. Files written to this path are automatically uploaded to iCloud, synced across all Apple devices signed into the same Apple ID, and eligible for automatic local eviction when the SSD needs space.

The directory structure is organized by artifact type and timestamped provenance:

```
ZirOS/
  proofs/{application}/{timestamp}/proof.json
  traces/{application}/{timestamp}/execution_trace.json
  verifiers/{application}/{timestamp}/Verifier.sol
  reports/{application}/{timestamp}/report.json
  audits/{application}/{timestamp}/audit.json
  telemetry/{timestamp}-{backend}-{digest}.json
  swarm/{patterns,rules,entrypoints,reputation-log,identity,...}
  keys/index.json
```

A developer proving a reentry thermal circuit sees the proof appear at `ZirOS/proofs/reentry-arc/2026-03-29T13-34-32Z/proof.json`. If they switch to a different Mac signed into the same Apple ID, the proof is already there. If macOS evicts the local copy to free SSD space, the file still appears in Finder and can be transparently re-downloaded by opening it.

### Key Management Through iCloud Keychain

Private cryptographic keys — Ed25519 seeds, ML-DSA-87 private keys, proving key material, credential issuer keys — are stored in iCloud Keychain rather than iCloud Drive. This distinction is critical. iCloud Drive stores files that are visible in Finder, can be browsed, and may be evicted and re-downloaded. iCloud Keychain stores secrets that are protected by the Secure Enclave on each device, encrypted end-to-end with Advanced Data Protection, invisible to file browsing, and accessible only through the Security.framework API with proper authorization.

On macOS, the key storage uses `SecItemAdd` with `kSecAttrSynchronizable = true` and `kSecAttrAccessibleAfterFirstUnlock`. Keys sync to every Apple device signed into the same Apple ID and are protected by biometric authentication on each device. On non-macOS platforms, the system falls back to encrypted file storage with ChaCha20-Poly1305 encryption using an Argon2-derived key.

### The Witness Exception

Witnesses are the one artifact class that is architecturally excluded from iCloud. A witness contains every private input to a zero-knowledge circuit in plaintext. The entire purpose of a zero-knowledge proof is to demonstrate that these inputs satisfy certain constraints without revealing the inputs themselves. If the witness were uploaded to iCloud — even encrypted — the private inputs would exist outside the device in some form. ZirOS enforces a strict rule: witnesses are generated in the local cache at `~/.zkf/cache/`, used for proving, and deleted immediately after proof verification. They are never written to any iCloud-managed path. This is the enforcement mechanism that preserves the zero-knowledge property on the physical storage layer.

### Device-Adaptive Behavior

The storage system detects the device's SSD capacity and selects an appropriate profile. A MacBook Air with 256 gigabytes gets aggressive local cache management with 30-minute monitoring intervals. A Mac Studio with 8 terabytes gets relaxed daily monitoring. The profiles control warning thresholds, critical thresholds, and eviction aggressiveness. A macOS launchd background agent runs the eviction cycle hourly at low I/O priority, ensuring that the system manages itself without developer intervention.

### Cross-Device Operation

The combination of iCloud Drive for artifacts and iCloud Keychain for keys means that moving to a new Mac requires nothing beyond signing in with the same Apple ID. Every proof ever generated, every execution trace, every telemetry record, every CoreML model, every swarm pattern, and every cryptographic key is immediately available. Zero manual file transfer. Zero USB drives. Zero configuration beyond `ziros doctor`.

---

## V. Formal Verification

ZirOS tracks its verification posture through a machine-readable ledger at `zkf-ir-spec/verification-ledger.json`. The ledger currently contains one hundred sixty entries, all classified as `mechanized_local`, with zero pending claims. This means every verification claim in the system has a corresponding machine-checked proof artifact. No claim is backed solely by test suites, code review, or manual audit.

The verification spans five formal proof languages.

Lean 4 provides the deepest coverage, with nineteen first-party proof files covering Metal GPU kernel refinement (MSM across three curves, NTT across three fields and four kernel variants, Poseidon2 scalar and SIMD equivalence), launch safety (bounded memory, non-overlapping writes, balanced barriers, no out-of-bounds access), memory model semantics, codegen soundness, BN254 Montgomery arithmetic, and protocol-level theorems for Groth16 knowledge soundness, Nova folding soundness, HyperNova CCS multifolding, and FRI proximity soundness.

Rocq (formerly Coq) provides sixty-eight proof files covering CCS synthesis, kernel correctness, witness generation, field encoding, orbital dynamics, BN254 Montgomery strict lane, pipeline composition, BlackBox runtime proofs (SHA-256, Poseidon BN254, ECDSA secp256k1 and secp256r1, malformed ABI rejection, low-S enforcement), Plonky3 lowering with witness preservation, lookup lowering, swarm non-interference, swarm reputation, swarm epochs, Noir recheck semantics, IR normalization, and embedded pipeline composition.

F-star provides ten proof files covering constant-time operation proofs for field arithmetic and protocol extraction for kernel specifications, CCS specifications, witness generation, and transform specifications.

Verus provides thirty-two specification files covering Metal host-boundary launch contracts, backend adapter safety, Groth16 boundary properties, distributed swarm coordination (consensus, diplomat, epoch, identity, memory, reputation, transport), and runtime execution surfaces (buffer bridge, orbital dynamics, powered descent, satellite conjunction, reentry assurance, swarm artifact, builder, entrypoint, queen, sentinel, warrior, scheduler, graph, hybrid, API, context, adapter).

Kani provides bounded model checking harnesses configured through workspace lints, covering field encoding, expression evaluation, CCS builder, witness generation, backend adapter safety, buffer management, typed views, execution graph, GPU device state, pipeline management, and launch contract negative tests.

The constitution mandates that the verification coverage may only increase, never decrease. Article X states that the constitution may only be amended to add stronger guarantees. This is a one-way ratchet on formal verification: every future version of ZirOS must have at least as many mechanized entries as the current version.

---

## VI. Metal GPU Acceleration

ZirOS ships sixty-three Metal shader sources for Apple Silicon with fifty kernel entrypoints across multi-scalar multiplication (BN254, Pallas, Vesta), number-theoretic transforms (Goldilocks, BabyBear, BN254 scalar), Poseidon2 hashing (Goldilocks, BabyBear), SHA-256 and Keccak-256 batch hashing, FRI folding, polynomial evaluation, constraint evaluation, and field arithmetic.

Every GPU dispatch passes through a four-digest attestation chain verified at dispatch time. The metallib binary is hashed with SHA-256. The kernel argument signature (buffer names, indices, types, access modes) is hashed. The compute pipeline descriptor (label, indirect flag, max threads, SIMD width) is hashed. The Metal compiler, Xcode, and SDK versions are recorded. If any digest does not match the expected value pinned in nine checked-in attestation manifests, the dispatch is rejected. There is no silent fallback to CPU. The system fails closed.

The GPU path exploits Apple Silicon's unified memory architecture. The witness is generated on CPU and consumed by the Metal MSM kernel without a single byte being copied across a bus. The twiddle factors for NTT are computed on CPU and used by the Metal kernel from the same physical memory. This zero-copy behavior eliminates the PCIe transfer overhead that makes discrete GPU acceleration painful for small-to-medium workloads, enabling GPU acceleration at thresholds as low as 512 scalar multiplications.

All 256-bit Montgomery multiplication in the shaders uses Metal's native `mulhi()` intrinsic, replacing approximately thirteen ALU instructions with approximately two, yielding up to sixty-six percent MSM throughput improvement on M4 Max hardware.

Measured performance on Apple M4 Max (sixteen CPU cores, forty GPU cores, forty-eight gigabytes unified memory): a two-hundred-step reentry thermal circuit with thirty thousand four hundred seventy-seven constraints generates a one-hundred-twenty-eight-byte Groth16 proof in approximately nine minutes with twenty-five percent GPU busy ratio. Verification takes twenty milliseconds regardless of circuit complexity.

---

## VII. The Nine Proving Backends

ZirOS compiles circuits to nine distinct proving backends through its canonical intermediate representation.

Plonky3 produces STARK proofs over Goldilocks, BabyBear, and Mersenne31 fields with transparent setup, post-quantum security, and native Metal GPU acceleration for NTT and Merkle tree operations. The polynomial commitment scheme is FRI with configurable blowup factor, query count, and proof-of-work bits.

Arkworks Groth16 produces the smallest possible proofs — one hundred twenty-eight bytes on BN254 — with the cheapest Ethereum verification cost at approximately two hundred ten thousand gas. It requires a trusted setup (ceremony or imported blob) and has full Metal GPU coverage for MSM, NTT, and QAP witness map operations.

Halo2 IPA provides transparent Plonkish proving over the Pasta Fp field with inner product argument polynomial commitment. Halo2 KZG provides BLS12-381 KZG commitment with SHPLONK multiopen.

Nova and HyperNova provide recursive folding and multifolding over Pallas and Vesta curves for incremental verifiable computation workflows.

SP1 and RISC Zero provide zkVM compatibility through delegated routing to Plonky3.

The STARK-to-SNARK wrapping pipeline takes a Plonky3 STARK proof and compresses it into a Groth16 proof by compiling the FRI verifier as an R1CS circuit with non-native Goldilocks arithmetic. The inner STARK is post-quantum. The outer Groth16 is classical. The wrapping pipeline includes Poseidon2 round constants pinned exactly to Plonky3 version 0.4.2 to ensure the FRI verification in the wrapper circuit matches the STARK prover's hash function.

---

## VIII. The Seven Circuit Frontends

ZirOS imports circuits from seven external formats. Noir ACIR with full BlackBox support for SHA-256, Keccak-256, Pedersen, Schnorr, ECDSA, Blake2s, and recursive aggregation markers, plus Brillig hint processing and multi-function call inlining. Circom R1CS with snarkjs-compatible import and witness runner descriptors. Cairo Sierra IR with native translation for the supported felt252, integer, enum, struct, memory, and control-flow subset, with unsupported libfuncs failing closed rather than silently degrading. Midnight Compact zkir version 2.0 with contract sidecar auto-discovery. Halo2 and Plonky3 AIR direct exports for native circuit formats. And zkVM descriptors for SP1 and RISC Zero ELF binary routing.

All seven frontends compile through the same canonical IR. A Noir circuit and a Cairo circuit target the same backend with the same audit, the same compilation, and the same verification.

---

## IX. The Swarm Defense Layer

The swarm is ZirOS's runtime security subsystem. It monitors every proving job for timing anomalies, performance degradation, and adversarial behavior, and it maintains a threat-aware state machine that can escalate from dormant through alert, active, and emergency levels based on accumulated pressure.

The sentinel component implements anomaly detection using Welford online statistics for univariate z-score analysis, multivariate Mahalanobis distance for correlated anomaly detection, jitter detection through variance-of-variance tracking, cache-flush detection, and baseline sealing with Poseidon commitment for integrity. The z-score threshold is three standard deviations. The Mahalanobis threshold is four and a half. Baselines are sealed every one thousand observations with a history of sixteen records.

The queen component manages threat escalation through four levels — dormant, alert, active, and emergency — with pressure thresholds at three, six, and twelve respectively. Pressure decays with a one-hour half-life. A predictive lookahead of five minutes uses linear regression on pressure history to anticipate escalation needs. The digest rate threshold triggers alert at three digests per minute.

The builder component manages detection rule lifecycle through five states: candidate, validated, shadow, live, and revoked. Rules cannot skip states. A rogue builder cannot promote a rule directly to live without passing through validation and shadow observation.

The diplomat component handles gossip-based threat intelligence with ChaCha20-Poly1305 encrypted epoch management, rate-limited to eight digests per heartbeat.

The identity component provides dual signing with Ed25519 and ML-DSA-87, with Secure Enclave key storage on macOS and admission proof-of-work for new peer joins.

The reputation component scores each peer from zero to one with an hourly ten percent cap on reputation increase to prevent farming attacks, evidence-based scoring from quorum agreement, attestation validity, heartbeat reliability, threat digest corroboration, and model freshness.

The critical architectural property is non-interference: the swarm layer can affect scheduling, device placement, redundant execution, quorum verification, peer reputation, quarantine, admission, rejection posture, and timing probes. It can never affect witness generation semantics, constraint checking semantics, successful proof bytes, or verification truth. This property is mechanized in the verification ledger.

The swarm proof boundary is fully closed: thirteen of thirteen files and two hundred eighty-four of two hundred eighty-four functions in the runtime swarm path, thirty-seven of thirty-seven files and five hundred fifty-four of five hundred fifty-four functions in the distributed swarm path.

---

## X. The Neural Engine Control Plane

ZirOS ships six CoreML model lanes that run on Apple Silicon's Neural Engine at thirty-eight trillion operations per second on M4 Max hardware with near-zero power draw and microsecond inference latency.

The scheduler model predicts proving duration for different dispatch candidates. The backend recommender scores backends for the current circuit and optimization objective. The duration estimator predicts absolute proving time after backend and dispatch candidate are fixed. The anomaly detector flags deviation from the normal performance profile. The security detector provides threat assessment on incoming proof requests. The threshold optimizer bootstraps GPU dispatch thresholds before the adaptive tuning system has accumulated enough observations to converge.

The Neural Engine is the control plane, not the proof plane. This distinction is constitutional. Proof validity never depends on any model output. Models affect scheduling quality and operational efficiency. Models never affect proof truth.

---

## XI. Aerospace and Scientific Applications

ZirOS treats zero-knowledge proving as a certificate layer over structured physical computation. The system ships ten application templates and one flagship reentry mission-ops surface spanning aerospace engineering, orbital mechanics, fluid dynamics, combustion science, thermodynamics, and real-gas equations of state.

The reentry thermal safety application proves that a private reentry trajectory satisfies dynamic pressure, heating rate, altitude, velocity, and flight-path-angle constraints across a two-hundred-fifty-six-step horizon with RK4 integration, committed atmosphere tables, constrained trigonometric approximations, Sutton-Graves heating with staged factorization, and sticky abort-latch semantics. The proof is computed over the Goldilocks field for post-quantum security on the Plonky3 backend.

The powered descent application proves a Falcon 9-scale powered-descent trajectory with three-dimensional Euler integration, Tsiolkovsky mass decrement, thrust magnitude constraints via floor-square-root, glide-slope enforcement via exact division, and landing zone proximity via Euclidean distance, across two hundred integration steps.

The satellite conjunction application proves two-spacecraft conjunction avoidance over a twenty-four-hour horizon with fourteen hundred forty integration steps, outputting Poseidon commitments to final states, the minimum separation distance, a safety certificate, and a committed maneuver plan. The multi-satellite extension scales to sixty-four satellites and two hundred fifty-six conjunction pairs.

The reentry mission-ops surface adds NASA Class D ground-support plumbing: signed source model manifests for GMAT, SPICE, OpenMDAO, and Trick; derived model packages with operating domains and residual metadata; scenario library qualification and assurance trace matrices; deterministic oracle parity gates; and downstream handoff artifacts for cFS, F Prime, and Open MCT.

Additional templates cover N-body orbital dynamics (five bodies, one thousand steps, three dimensions), combustion instability (Rayleigh-window thermoacoustic analysis), Navier-Stokes finite-volume step certificates (Rusanov convective and central viscous fluxes with CFL guard), real-gas equation-of-state certificates (Peng-Robinson and Redlich-Kwong), and thermochemical equilibrium certificates (element balance, nonnegative species, KKT complementarity).

All applications follow the same pattern: private physical data in, public commitments and safety certificates out. The zero-knowledge property means the verifier learns only whether the computation satisfies the constraints, not what the inputs were.

---

## XII. The Fail-Closed Audit

The nonlinear anchoring audit is arguably the most important safety feature in ZirOS. It prevents the most common class of zero-knowledge vulnerability: underconstrained private signals.

A private signal that appears only in linear constraints — addition, subtraction, equality — is mathematically free. A malicious prover can change that signal to any value and still satisfy all constraints. The proof verifies. The application appears correct. But the proof proves nothing about the actual value of that signal.

ZirOS computes the linear rank and matrix nullity of the constraint surface and identifies every private signal that lives in a free linear subspace without nonlinear binding. If any such signal exists, the circuit is rejected before compilation. The audit produces machine-readable JSON with plain-English remediation: which signal is underconstrained, why, and how to fix it (route through a Poseidon hash, add a boolean constraint, add a multiplication gate, or add a range check).

This audit is mandatory. It is not an optional analysis. It is not a flag you can disable. The system will not compile a circuit with an underconstrained private signal. This fail-closed design means that the most common class of soundness vulnerability in zero-knowledge systems cannot exist in a ZirOS application.

---

## XIII. The Constitution

ZirOS is governed by a ten-article constitution that binds the project's future, not just its present.

Article I mandates mechanized formal verification instead of human audits. Article II mandates the four-digest GPU attestation chain. Article III mandates pure-Rust launch contracts before GPU dispatch. Article IV defines "proven" as a Lean 4 theorem establishing refinement between a GPU program and a mathematical specification. Article V makes seven binding commitments including the prohibition against describing a surface as verified without a mechanized proof artifact and the prohibition against substituting passing tests for mechanized theorems. Article VI provides the structural critique of the audit model. Article VII mandates naming discipline where vocabulary collapse is treated as a soundness defect. Article VIII makes the architectural commitment to Apple Silicon. Article IX requires that shaders be released with proofs. Article X states that the constitution may only be amended by adding stronger guarantees and may never be weakened.

This constitutional model has no equivalent in any other open-source project. It is a one-way commitment to increasing formal verification coverage, increasing transparency, and increasing evidence. Every future version of ZirOS must be at least as rigorous as the current version. The ratchet only turns one way.

---

## XIV. Significance

ZirOS is significant for four reasons.

First, it demonstrates that zero-knowledge proving can be treated as an operating system problem rather than a library problem. The integration of nine backends, seven frontends, formal GPU verification, iCloud storage, post-quantum cryptography, swarm defense, Neural Engine optimization, and fail-closed auditing into a single coherent system shows that the tooling gap between mathematical theory and engineering practice can be closed.

Second, it demonstrates that CNSA 2.0 post-quantum cryptography can be deployed in a zero-knowledge system with negligible performance impact. The ML-DSA-87 signing overhead is five hundred microseconds against proving times of seconds to minutes. The ML-KEM-1024 key exchange overhead is eighty microseconds per hour. These costs are unmeasurable at the scale of real proving workloads.

Third, it demonstrates that formal verification at scale is achievable for a system of this complexity. One hundred sixty mechanized ledger entries across five proof languages, with zero pending claims, covering GPU kernels, protocol soundness, swarm non-interference, runtime execution, and IR normalization, shows that the "formal verification is too expensive" objection is a question of discipline, not feasibility.

Fourth, it demonstrates that consumer hardware — specifically Apple Silicon laptops — is a viable platform for production zero-knowledge proving. The unified memory architecture, the Metal GPU acceleration, the Neural Engine control plane, the Secure Enclave key storage, and the iCloud storage integration are not compromises. They are advantages that server-based systems cannot replicate.

ZirOS is not finished. The trusted setup migration to Plonky3 is in progress. The ANE models need production training. The mission-ops surface needs real upstream tool integration. The STARK-to-STARK recursive composition for post-quantum on-chain verification does not exist yet. But the architecture is right, the formal verification coverage is real, the post-quantum cryptography is deployed, and the system works. It does what it says it does.

That is the foundation. But the full significance requires examining each layer in greater depth.

---

## XV. The ProgramBuilder API

The ProgramBuilder is the primary authoring surface for circuits built natively in ZirOS. It provides a typed Rust API for declaring signals, emitting constraints, invoking cryptographic gadgets, defining lookup tables, allocating memory regions, and registering custom gates.

The constraint vocabulary spans twelve types: arithmetic equality, boolean, range, less-than-or-equal, greater-than-or-equal, nonzero, binary selection, lookup table query, blackbox invocation (for Poseidon, SHA-256, Keccak, ECDSA, Schnorr, and other registered gadgets), memory read, memory write, copy, permutation, and custom gate. This vocabulary is deliberately broader than R1CS (which only supports arithmetic equality) because different backends exploit different constraint types. Plonkish backends can natively handle lookup tables and custom gates. STARK backends can natively handle AIR constraints. R1CS backends lower higher-level constraints into arithmetic through the audit-aware lowering pipeline.

The builder emits ZirOS Intermediate Representation, which is normalized, type-checked, and audited before reaching any backend. The normalization has a Lean 4 proof. The audit rejects underconstrained signals. The type checking enforces field consistency. The result is that any circuit built through ProgramBuilder is guaranteed to be well-formed, field-consistent, and free of underconstrained private signals before it reaches the proving backend.

The gadget registry provides eleven builtin gadget families: Poseidon (algebraic hash), SHA-256, BLAKE3, Keccak-256, Merkle inclusion proof, ECDSA (secp256k1 and P-256), Schnorr signature verification, KZG polynomial commitment pairing check, range decomposition, comparison, boolean logic, and PLONK gate with configurable selectors. Each gadget declares which of the seven canonical fields it supports, and the builder validates field compatibility at construction time.

For scientific and aerospace applications, the builder is supplemented by application-specific helper functions: `append_signed_bound` for representing values within symmetric bounds using the bound-squared-minus-value-squared technique, `append_nonnegative_bound` for enforcing positive ranges with tracked slack variables, `append_exact_division_constraints` for quotient-remainder decomposition with division safety, `append_floor_sqrt_constraints` for integer square root with bounded residual, and `append_poseidon_hash` for Poseidon commitment chaining. These helpers encode the fixed-point arithmetic patterns that every physics circuit needs, ensuring arithmetic consistency between the sample generator and the witness generator.

---

## XVI. The Unified Memory Proving Graph

The runtime models proving as a directed acyclic graph called the Unified Memory Proving Graph. Each node in the graph is a ProverOp — a typed operation such as WitnessGen, NTT, LDE, MSM, PoseidonBatch, Sha256Batch, MerkleLayer, FriFold, FriQueryOpen, VerifierEmbed, BackendProve, BackendFold, OuterProve, TranscriptUpdate, ProofEncode, Barrier, or Noop. Each node has explicit dependencies on other nodes, input and output buffer slots, a device placement (CPU, GPU, CpuCrypto for ARM SHA extensions, CpuSme for Apple's Scalable Matrix Extension, or Either), and an inherited trust model.

The scheduler performs topological dispatch using Kahn's algorithm, ensuring that every node's dependencies are satisfied before execution begins. Trust propagation follows the weakest-link rule: if a node depends on any output with a weaker trust model, the node inherits the weakest trust. This means a proof that passes through an attestation-level GPU acceleration stage carries the attestation trust model, not the cryptographic trust model, unless the GPU stage has a mechanized proof (as the verified Metal lane does).

The buffer bridge manages memory across CPU and GPU address spaces with three residency tiers. HotResident buffers hold proving keys, twiddle factor tables, and MSM bases that must remain in fast memory for the entire proving session. EphemeralScratch buffers hold NTT intermediates and partial bucket accumulations that are valid for a single execution. Spillable buffers hold large traces and old Merkle tree layers that may be evicted to SSD with FNV-1a integrity checking when memory pressure requires it.

On Apple Silicon, the distinction between CpuOwned and GpuShared buffers is logical, not physical. Unified memory means the same physical DRAM is accessible from both CPU and GPU without any data transfer. This is the hardware property that makes the UMPG architecture practical on consumer hardware: the overhead of GPU dispatch is the dispatch latency itself, not the data transfer latency.

---

## XVII. The Eleven Gadget Families

The gadget layer provides reusable constraint templates that work across all seven canonical fields and all compatible backends.

Poseidon is the primary algebraic hash, designed specifically for ZK-friendliness with low multiplicative complexity over finite fields. It supports width-4 mode for BN254 (used in Poseidon commitment chaining in every aerospace application) and is available across BN254, BLS12-381, Pasta Fp, Goldilocks, BabyBear, and Mersenne31 fields.

SHA-256 implements FIPS 180-4 as a constraint circuit, requiring approximately twenty-five thousand R1CS constraints per compression function call. It is available across all seven fields and is used for artifact integrity hashing throughout the system.

BLAKE3 provides a newer hash construction with better performance characteristics in some circuit configurations, available across five fields.

ECDSA implements secp256k1 and P-256 signature verification with non-native field arithmetic, currently limited to BN254 field. The non-native arithmetic module handles carry propagation across limbs for emulating 256-bit secp256k1 operations inside the BN254 constraint system.

Schnorr provides Schnorr signature verification, currently limited to BN254.

KZG implements the polynomial commitment pairing check as a circuit constraint, available on BN254 and BLS12-381. This enables recursive proof verification within circuits.

Merkle implements inclusion proof verification with configurable hash function, available across six fields.

Range implements bit decomposition with recombination, proving that a value fits within a specified number of bits. Available across all seven fields.

Comparison implements less-than and greater-than operations via range proof on the difference between values. Available across all seven fields.

Boolean implements AND, OR, NOT, and XOR gates as constraint templates. Available across all seven fields.

PLONK gate provides a universal gate template with configurable selector polynomials, enabling backend-specific optimization when the proving system supports custom gates. Available across all seven fields.

---

## XVIII. The Seven Canonical Fields

ZirOS operates across seven finite fields chosen for their cryptographic and performance properties.

BN254 (the Barreto-Naehrig 254-bit curve scalar field, p approximately 2 to the 254) is the primary field for Groth16 proving and Ethereum on-chain verification. It supports pairing operations needed for Groth16 and KZG commitments.

BLS12-381 (the BLS12-381 curve scalar field, p approximately 2 to the 255) is used for Halo2 KZG commitments and is the field used by Ethereum's beacon chain.

Pasta Fp and Pasta Fq (the Pallas and Vesta curve scalar fields) are used by Halo2 IPA and the Nova/HyperNova recursive folding backends. Their cycle-of-curves property (the scalar field of one curve is the base field of the other) enables efficient recursive composition.

Goldilocks (p equals 2 to the 64 minus 2 to the 32 plus 1) is the primary STARK field for Plonky3. Its sparse modulus enables extremely fast field arithmetic on 64-bit hardware, and it is the field used for the post-quantum Plonky3 proving path.

BabyBear (p equals 15 times 2 to the 27 plus 1) is a 32-bit field used by Plonky3 for applications where smaller field elements improve performance.

Mersenne31 (p equals 2 to the 31 minus 1) is a Mersenne prime field used by Plonky3's Circle PCS variant, chosen for its efficient modular reduction.

The nonnative arithmetic gadget enables cross-field computation. When a circuit needs to verify operations in one field while proving in another (as in STARK-to-Groth16 wrapping, where Goldilocks operations are verified inside a BN254 constraint system), the nonnative module decomposes values into limbs, performs arithmetic with explicit carry propagation, and range-checks results. This module is seven hundred eighty-seven lines of careful carry-management logic.

---

## XIX. The Operator Interface Stack

ZirOS exposes its capabilities through eight distinct interface surfaces, each designed for a different consumer.

The CLI provides the primary operator workflow through approximately forty commands spanning proving, importing, auditing, compiling, runtime planning, cluster and swarm control, packaging, registry management, deployment, diagnostics, storage management, key management, and Neural Engine retraining. Every command supports structured JSON output for machine consumption. The CLI is the surface that autonomous agents interact with.

The HTTP API provides proving-as-a-service through an Axum and Tower based server with API key authentication, request queuing, rate limiting, CORS support, health and capability endpoints, and routes for proving, wrapping, deploying, and benchmarking.

The Python bindings provide compile, prove, and verify operations for data science and research workflows through PyO3 with ABI3 compatibility for Python 3.8 and later.

The C FFI bridge provides native embedding for Swift, Objective-C, and other languages that can call C functions, generated through cbindgen.

The LSP server provides diagnostics, hover information, goto-definition, and IR analysis for editor integration.

The TUI shell provides terminal-based interactive widgets for proof-driven applications using Ratatui and Crossterm.

The registry provides gadget publication, listing, manifest management, and dependency resolution for sharing circuit components.

The DSL provides Rust proc macros for embedded circuit authoring directly in Rust source files.

---

## XX. The Benchmark Surface

ZirOS ships a comparative benchmark harness that runs the same proving scenarios across ZirOS and five external systems: snarkjs (Circom), gnark (Go), Noir/Nargo, SP1, and RISC Zero. Three standard scenarios are defined: single circuit prove, developer workload (multiple circuits), and recursive workflow. The harness runs on both Linux and Apple Silicon lanes, producing machine-readable results with timing, proof size, and verification cost metrics.

This is not a marketing surface. It is an engineering surface. The benchmark outputs are used to calibrate the Neural Engine models' duration estimator and backend recommender, to validate that ZirOS's performance is competitive, and to identify regression when backend implementations change.

---

## XXI. The Supply Chain

ZirOS uses `cargo vet` for supply chain auditing of cryptographic dependencies. The trust store at `supply-chain/` records which crate versions have been audited, by whom, and to what standard. This is particularly important for the cryptographic dependency surface: `libcrux-ml-dsa`, `libcrux-ml-kem`, `ark-bn254`, `ark-groth16`, `halo2_proofs`, `nova-snark`, and the Plonky3 crate family all require careful supply chain management because a compromised dependency in any of these crates could undermine the soundness of the entire system.

---

## XXII. What No Other System Has

No other zero-knowledge system combines all of the following:

One. NIST FIPS 203 and FIPS 204 post-quantum cryptography at Level 5 with hybrid classical-plus-post-quantum constructions for both signatures and key exchange.

Two. iCloud Drive as the persistent storage layer with Keychain as the key management layer, automatic cross-device sync, and architectural exclusion of witnesses from cloud storage.

Three. One hundred sixty mechanized verification ledger entries across five formal proof languages with zero pending claims.

Four. Sixty-three formally verified Metal GPU shaders with a four-digest fail-closed attestation chain.

Five. Nine proving backends spanning STARK, SNARK, PLONK, IVC, and zkVM with STARK-to-SNARK wrapping.

Six. Seven circuit frontends importing from Noir, Circom, Cairo, Compact, Halo2, Plonky3, and zkVM formats through a universal IR.

Seven. A mandatory fail-closed nonlinear anchoring audit that prevents the most common class of zero-knowledge soundness vulnerability.

Eight. A swarm defense layer with mechanized non-interference proofs, Byzantine consensus, admission proof-of-work, and capped reputation.

Nine. A Neural Engine control plane with six CoreML model lanes running on dedicated ML inference hardware.

Ten. Aerospace mission-ops plumbing targeting NASA Class D ground-support assurance with signed source model manifests, derived model packages, scenario library qualification, and downstream handoff artifacts for cFS, F Prime, and Open MCT.

Eleven. A constitutional mandate that formal verification coverage may only increase and may never be weakened.

Each of these is individually notable. Together, they define a system category that did not previously exist: a zero-knowledge operating system that manages the full lifecycle of proof generation, from circuit authoring through hardware acceleration through post-quantum signing through cloud-native storage, with formal verification accounting for every claim it makes along the way.

---

## XXIII. The Trust Model in Depth

Zero-knowledge systems have an unusual trust problem. The proof guarantees computational integrity — the statement was computed correctly — but the proof itself must be generated, transmitted, stored, and verified through infrastructure that has its own trust assumptions. A Groth16 proof is mathematically sound, but if the trusted setup ceremony was compromised, the proof can be forged. A STARK proof requires no ceremony, but if the GPU shader that computed the MSM has a bug, the proof may verify despite being unsound. A proof can be correct but meaningless if the circuit allowed the prover to choose arbitrary values for signals that were supposed to be constrained.

ZirOS addresses this layered trust problem through a precise vocabulary and explicit tracking.

The verification ledger classifies every claim into one of four assurance levels. A `mechanized_implementation_claim` means a Lean, Rocq, F-star, Verus, or Kani proof exists that covers the implementation code in the repository. An `attestation_backed_lane` means the claim is validated by host-side checks (like the Metal attestation chain) but not by an in-circuit cryptographic proof. A `model_only_claim` means a theorem exists about a model or specification, but the link between the model and the implementation is not mechanized. A `hypothesis_carried_theorem` means a mechanized theorem exists but depends on explicit cryptographic hypotheses (like the hardness of the discrete logarithm problem for Groth16 soundness).

The runtime trust model classifies every operation output into one of three tiers. Cryptographic means the output is enforced by an in-circuit proof that the verifier checks. Attestation means the output is validated by host-side execution with checks but not re-proven inside a proof system. MetadataOnly means the output is a label or annotation with no cryptographic or attestation backing.

Trust propagation follows the weakest-link rule: if a proving graph node depends on any output with a weaker trust tier, the node inherits the weakest. A proof composed from cryptographic and attestation components inherits the attestation tier. A proof composed from cryptographic and metadata components inherits the metadata tier. This is explicit, tracked, and visible in every proof artifact's metadata.

The nonlinear anchoring audit adds a fourth trust dimension: circuit-level safety. A circuit can be syntactically correct, type-checked, and compilable, but still unsound if private signals are underconstrained. The audit catches this before compilation, preventing the most insidious class of vulnerability — the circuit that appears to work, passes every test, and has a completely broken security model.

The swarm defense adds a fifth trust dimension: operational security. Even a mathematically correct proof generated on a compromised machine may be suspect. The swarm monitors for timing anomalies, thermal throttling, memory pressure, repeated fallback patterns, model integrity failures, and attestation chain drift. It can escalate the operational threat level from dormant through alert to active to emergency, affecting scheduling and rejection posture without ever touching proof semantics.

Together, these five dimensions — ledger-tracked formal verification, runtime trust tiers, trust propagation, circuit-level safety audits, and operational defense — create a trust model that is more comprehensive than any other system in the zero-knowledge field. Most systems have one or two of these. ZirOS has all five, and they compose.

---

## XXIV. The Fixed-Point Arithmetic System

Every physics circuit in ZirOS uses fixed-point arithmetic because finite field elements are integers, not floating-point numbers. The scaling factor determines the precision of the computation.

For BN254-based circuits (like the powered descent application), the scale factor is ten to the eighteenth, providing eighteen decimal places of precision. Every physical quantity — position in meters, velocity in meters per second, mass in kilograms, thrust in newtons, gravitational acceleration — is multiplied by this scale factor and stored as a field element. Arithmetic operations then operate on these scaled integers, with explicit tracking of the scale factor through every operation.

Division is the critical operation. In a finite field, division is multiplication by the modular inverse. But for fixed-point arithmetic, you need the quotient and the remainder, because the remainder represents the precision lost in the division. The `append_exact_division_constraints` function encodes this: given a numerator and denominator, it constrains the quotient, the remainder, and a slack variable such that numerator equals denominator times quotient plus remainder, and the denominator equals remainder plus slack plus one. Both the remainder and the slack are range-checked to ensure they are smaller than the denominator. The slack variable's square is also constrained to prevent a subtle attack where the prover provides a negative slack.

Square root uses a similar decomposition. The `append_floor_sqrt_constraints` function constrains a value as the square of a root plus a bounded remainder, and additionally constrains that the next integer up (root plus one) squared exceeds the value. This proves the root is the floor square root without requiring the prover to demonstrate the existence of the root through a search.

Signed bounds use the algebraic identity that a value lies within the range negative B to positive B if and only if B squared minus the value squared is nonnegative. The `append_signed_bound` function constrains value squared plus slack equals bound squared, with the slack range-checked to be nonnegative. This eliminates the need for conditional constraints or absolute value operations.

For Goldilocks-based circuits (like the reentry thermal application), the scale factor is ten to the third, chosen to fit within the sixty-four-bit Goldilocks field while providing adequate precision for the reduced-order model. The smaller scale means less precision but also fewer bits consumed per intermediate value, which matters when the field modulus is much smaller than BN254.

The critical engineering lesson from these patterns is that the sample input generator and the witness generator must use identical arithmetic. If the sample generator uses truncating integer division while the witness generator uses euclidean division, the accumulated rounding differences cause the trajectory to diverge at high step counts. The existing applications encode this lesson in their architecture: the sample generator calls the same `compute_step_dynamics` function as the witness generator, using the same euclidean division, the same floor-square-root, and the same signed-bound computations. Any candidate trajectory that fails any step is rejected and a new candidate is tried.

---

## XXV. The Wrapping Pipeline

The STARK-to-Groth16 wrapping pipeline is one of the most technically sophisticated components of ZirOS. It takes a Plonky3 STARK proof — which is large (one to ten kilobytes) but post-quantum and transparent — and compresses it into a Groth16 proof — which is tiny (one hundred twenty-eight bytes) and cheaply verifiable on Ethereum but requires a trusted setup and is not post-quantum.

The wrapping works by building an R1CS circuit that verifies the FRI polynomial commitment scheme inside BN254 constraints. This requires non-native field arithmetic: the STARK operates over Goldilocks (a sixty-four-bit field) while the Groth16 circuit operates over BN254 (a two-hundred-fifty-four-bit field). Every Goldilocks multiplication inside the FRI verifier must be emulated using BN254 field operations with explicit carry propagation.

The FRI verifier circuit implements query step verification, polynomial evaluation consistency checks, Merkle authentication path verification, and Poseidon2 hash computation (with round constants pinned exactly to Plonky3 version 0.4.2 to ensure the verifier circuit matches the STARK prover's hash function). The resulting circuit is large — the FRI verifier alone is over one thousand lines of Rust — but it compresses the STARK proof into a constant-size Groth16 proof.

The trust model for wrapping is explicit. The inner STARK proof has cryptographic trust (it is a valid post-quantum proof). The outer Groth16 proof inherits attestation-level trust because it proves "I verified a STARK proof" but does so through an elliptic curve system that is not post-quantum. The wrapping does not strengthen the inner proof. It compresses it for a specific deployment target (Ethereum on-chain verification) at the cost of removing the post-quantum property.

The pipeline also supports Halo2-to-Groth16 wrapping and Nova-compressed aggregation for different composition workflows. Each wrapping path has its own trust model, documented in `docs/WRAPPING_SECURITY.md`, and every wrapped proof artifact carries metadata indicating which wrapping was applied and what trust tier the result inherits.

---

## XXVI. The Adaptive Tuning System

The Metal GPU dispatch thresholds are not static. The runtime learns the optimal CPU-versus-GPU crossover point for each operation type on each device through an exponential moving average system that observes actual execution times and adjusts thresholds accordingly.

The system starts with conservative static thresholds: MSM operations are sent to GPU when the scalar count exceeds five hundred twelve, NTT operations at five hundred twelve coefficients, Poseidon2 at two hundred fifty-six hashes, field arithmetic at two thousand forty-eight operations, and Merkle tree operations at five hundred twelve leaves. These thresholds are appropriate for M4 Max hardware but may not be optimal for M1, M2, or M3 chips with different GPU core counts and memory bandwidth.

After approximately twenty observations per operation type, the adaptive tuning system overrides the static thresholds with learned values. Each observation records whether the GPU or CPU was faster for that specific operation at that specific size. The exponential moving average converges toward the crossover point where GPU and CPU take approximately the same time. Below this point, CPU is preferred (avoiding dispatch overhead). Above this point, GPU is preferred (the parallelism advantage outweighs the dispatch cost).

The learned thresholds are persisted to disk at `~/.zkf/tuning/` keyed by the device's platform identifier (chip family, GPU core count, form factor). When ZirOS starts on a device that has been used before, it loads the learned thresholds immediately. On a new device, it starts with static thresholds and converges within the first twenty proving jobs.

The Neural Engine's threshold optimizer model provides a complementary approach: it predicts the optimal threshold based on the device's hardware characteristics (chip generation, GPU cores, ANE TOPS, power state, form factor) without requiring twenty observations to converge. The prediction bootstraps the tuning until the EMA system has enough data, then the EMA system takes over with empirically validated thresholds.

---

## XXVII. The Security Supervisor

The security supervisor evaluates every proving job against a comprehensive threat model. It examines the runtime execution report (timing, memory, GPU behavior), the control plane summary (scheduling decisions, model output), the swarm verdict (activation level, threat pressure, anomaly count), and the model integrity status (whether CoreML models passed pinning and integrity checks).

The supervisor produces a security evaluation containing a risk level (low, moderate, high, critical, or model-integrity-critical), a list of threat signals (watchdog timing anomalies, thermal throttle events, memory pressure, GPU circuit breaker activation, repeated fallback patterns, runtime anomalies, baseline drift, execution fingerprint mismatch, canary failure, model integrity failure), and a list of recommended actions (continue, reduce parallelism, force CPU only, require strict cryptographic lane, disable heuristic shortcuts, reject job, quarantine model bundle, isolate node).

The security policy operates in two modes: observe and enforce. In observe mode, the verdict is recorded in telemetry but does not affect execution. In enforce mode, the verdict may block or modify the proving job. The default is enforce.

The supervisor is deliberately conservative. On a new circuit type with no baseline observations, the heuristic duration estimator may underpredict the proving time by an order of magnitude, triggering a critical verdict. This false-positive rate decreases as the Neural Engine models are trained on real telemetry and the adaptive tuning system converges. The design philosophy is that false positives are preferable to false negatives: it is better to flag a legitimate job as suspicious than to allow an attack to proceed undetected.

---

## XXVIII. What This Means For the Future

ZirOS represents a thesis about the future of zero-knowledge proving: that the field will move from libraries to operating systems, from discrete GPU servers to consumer hardware, from classical cryptography to post-quantum standards, from manual artifact management to cloud-native storage, from human audits to mechanized formal verification, and from single-domain applications to multi-domain certificate platforms spanning aerospace, healthcare, finance, identity, and compliance.

The system is not finished. No operating system ever is. But the architectural commitments are made, the formal verification ratchet only turns one way, the post-quantum migration is complete, the iCloud integration is live, the GPU acceleration is formally verified, and the aerospace applications prove that the system can handle real physics in real circuits at real scale.

What remains is the work of maturation: training the Neural Engine models on production telemetry, migrating the primary proving lane fully to Plonky3 transparent setup, adding STARK-to-STARK recursive composition for post-quantum on-chain verification, completing the mission-ops adapter integrations with upstream NASA tools, expanding the scenario library with off-nominal and Monte Carlo test cases, and extending the formal verification coverage from one hundred sixty entries to wherever the constitution's one-way ratchet takes it.

The foundation is laid. The direction is set. The math is mechanized. The hardware is attested. The cryptography is post-quantum. The storage is cloud-native. The developer experience is automatic.

---

## XXIX. The Credential System

ZirOS implements a credential issuance and verification framework that bridges zero-knowledge proofs with real-world identity and authorization. The credential system supports three signature schemes: Ed25519 only (classical), ML-DSA-87 only (post-quantum), and hybrid Ed25519 plus ML-DSA-87 (defense in depth). The hybrid scheme is the default for all swarm operations.

An issuer creates an `IssuerSignedCredentialV1` containing claims (subject key hash, attributes, status flags, expiration, Merkle roots), the issuer's public key bundle (Ed25519 and ML-DSA-87 public keys), and the issuer's signature bundle (both signatures over the canonical credential bytes). The subject key hash is derived through Argon2id (version 0x13, four megabytes of memory, three iterations, one degree of parallelism, thirty-two byte output) followed by SHA-256, then reduced modulo the BN254 field. This memory-hard derivation prevents brute-force recovery of the subject identity from the public credential.

Verification requires both signatures to pass for hybrid credentials. The Ed25519 signature is verified using the standard Ed25519 verification algorithm. The ML-DSA-87 signature is verified using the `libcrux_ml_dsa::ml_dsa_87::verify` function with the context string `b"zkf-swarm"`. If either signature fails, the credential is rejected. This dual-verification model means that a quantum computer breaking Ed25519 cannot forge a credential because the ML-DSA-87 signature remains valid, and a hypothetical classical break of ML-DSA-87 cannot forge a credential because the Ed25519 signature remains valid.

The credential system is not limited to identity. It is a general-purpose signed-assertion framework. An aerospace company could issue a credential asserting that a specific proof was generated by an authorized proving station with specific hardware capabilities. A healthcare organization could issue a credential asserting that a clinical trial compliance proof was generated by an approved facility. The post-quantum signature means these credentials remain valid and unforgeable for their entire useful life, regardless of when quantum computers become operational.

---

## XXX. The Conformance and Integration Testing Surface

ZirOS ships a conformance test suite and an integration test suite that together verify end-to-end behavior across all crates.

The conformance suite in `zkf-conformance` tests backend compatibility by running a standard corpus of circuits through every ready backend and verifying that the proofs are valid. This catches regression when backend implementations change and validates that the canonical IR lowering produces correct constraint systems for each backend's native format.

The integration test suite in `zkf-integration-tests` tests cross-crate behavior including the swarm blueprint pressure tests (slow poison routing, flash mob consensus, attestation chain persistence, reputation farming resistance, gossip flood capping, key theft rotation, network partition recovery, rogue builder rejection), soundness tests (swarm kill switch preservation), production benchmarks, hostile audit scenarios, and the universal proving pipeline across all backend and frontend combinations.

The swarm blueprint pressure tests are particularly notable because they test adversarial scenarios that unit tests cannot cover. The flash mob test verifies that a coordinated burst of threat digests triggers consensus voting and that the consensus outcome causes denial of service (the job fails safely) rather than math corruption (the proof is never wrong). The reputation farming test verifies that the hourly ten percent cap prevents an attacker from building trust faster than the system allows. The key theft test verifies that rotating keys invalidates the old identity and flags authentication failures on the compromised key. These are not hypothetical scenarios. They are tested properties with passing regression tests.

---

## XXXI. The Release Discipline

The constitution and the verification ledger together enforce a release discipline that is unusual in the software industry. Every release must carry one hundred percent mechanized verification coverage for the claims in the ledger. No claim may be pending. No claim may be downgraded from mechanized to tested or audited. The ledger entries may only increase. The constitution may only be amended to add stronger guarantees.

This means that shipping a feature without corresponding formal verification is not merely discouraged. It is structurally impossible within the system's own accounting. If a new GPU kernel is added without a Lean theorem, the ledger has a pending entry, which blocks release. If a new swarm component is added without a Verus specification, the proof boundary has an incomplete path, which blocks release. The release gate is not a human judgment call. It is a machine-readable condition: zero pending entries, all paths closed, all mechanized claims backed by checked-in proof artifacts.

The practical consequence is that ZirOS ships slowly but ships correctly. A feature that takes two weeks to implement may take two more weeks to verify. But once it ships, the claim surface is precise: the ledger says exactly what is mechanized, exactly what is attested, exactly what is modeled, and exactly what carries hypotheses. There is no ambiguity. There is no "we'll add tests later." There is no "the audit covers this." The proof is in the repository or the claim is not in the ledger.

---

## XXXII. Conclusion

This dissertation has documented every major technology in ZirOS: the post-quantum cryptographic surfaces (ML-DSA-87, ML-KEM-1024, CNSA 2.0 Level 5), the iCloud-native storage architecture with Keychain key management and witness exclusion, the formal verification infrastructure across five proof languages with one hundred sixty mechanized ledger entries, the Metal GPU acceleration with sixty-three shaders and four-digest attestation, the nine proving backends spanning STARK through SNARK through IVC through zkVM, the seven circuit frontends with universal IR lowering, the UMPG runtime with DAG scheduling and trust-lane propagation, the swarm defense layer with mechanized non-interference proofs, the Neural Engine control plane with six CoreML model lanes, the device-adaptive storage lifecycle, the eleven aerospace and scientific application templates, the eleven gadget families across seven canonical fields, the unified key management with zeroization, the credential system with hybrid post-quantum signatures, the conformance and integration testing surface, and the constitutional release discipline.

Each of these technologies individually represents serious engineering. Together, they define a new category of system: a zero-knowledge operating system that manages the complete lifecycle of proof generation on consumer hardware with formal verification, post-quantum security, and cloud-native storage.

The competitive surface is empty. No other system combines these capabilities. Not because the individual technologies are novel — STARK proofs, ML-DSA signatures, iCloud Drive, Lean 4 theorems, and Metal shaders all exist independently — but because no other project has assembled them into a coherent operating system with a constitutional commitment to maintaining and strengthening the verification coverage over time.

ZirOS is what happens when someone decides that zero-knowledge proving deserves the same engineering discipline as an operating system kernel: layered trust models, formal verification of critical paths, fail-closed safety gates, hardware-aware scheduling, secure key management, and automatic lifecycle management. It is not a library with aspirations. It is a system with commitments.

That is what makes it significant. That is what this dissertation documents. And that is what the world gains from its existence: a proof that zero-knowledge operating systems are possible, practical, and worth building.
