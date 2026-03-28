# AegisVault Terminal Validation

## Goal

Phase 5 closes the reference-app lane for `zkf-tui` by validating the shipped AegisVault dashboard
across the terminal profiles the blueprint calls out, plus compact resize-smoke layouts.

## Automated Commands

```bash
cargo test -p zkf-tui --lib
cargo check -p zkf-tui --examples
cargo run -p zkf-tui --example aegisvault_validation
cargo run -p zkf-tui --example aegisvault
```

## Validation Matrix

The automated validation example renders the AegisVault reference dashboard against these profiles:

- `iTerm2` — `140x40`
- `Terminal.app` — `120x36`
- `VS Code Terminal` — `120x34`
- `Windows Terminal` — `132x36`
- `Compact` — `84x24`
- `Tight` — `72x22`

Each profile must keep these sections visible:

- `Vault`
- `Credential`
- `Health`
- `Proof`
- `Audit`
- `Activity`
- `Status`
- `Commands`

## Runtime Expectations

The validation example also runs a full local proof demo and checks that progress reporting still
emits all four stages in order:

1. `Compile`
2. `Witness`
3. `Constraint Check`
4. `Prove`

## Notes

- The terminal-profile matrix is deterministic and CI-friendly because it uses ratatui test
  backends instead of depending on GUI automation.
- The live `aegisvault` example is still the runtime smoke path for the current host terminal.
- The shipped AegisVault reference proof path opts into the existing development-only deterministic
  Groth16 override so the example can prove locally without a trusted CRS blob. Production apps
  should use imported trusted setup material instead.
- If you need manual terminal QA beyond the automated profiles, run the validation example inside
  the target terminal app and compare the same section set and progress behavior.
