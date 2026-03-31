# Release Checklist

1. Update version surfaces to `v0.1.0` or the next intended tag.
2. Regenerate or verify `support-matrix.json`, proof-boundary surfaces, and any
   other machine-readable truth outputs touched by the release.
3. Update [CHANGELOG.md](CHANGELOG.md).
4. Run `cargo fmt --all -- --check`.
5. Run `cargo clippy --workspace -- -D warnings`.
6. Run `make test`.
7. Run `make audit`.
8. Run `./scripts/run_conformance_suite.sh`.
9. Build the release binary:
   `./zkf-build.sh --release -p zkf-cli`
10. Run `./target-public/release/zkf-cli doctor`.
11. On Apple Silicon, run the Metal preflight on the final release binary:
   `./target-public/release/zkf-cli metal-doctor --json`
12. On Apple Silicon, after any strip/sign/package step that can change the binary
    hash, generate and install the matching strict soak report for the final release binary:
   `./target-public/release/zkf-cli runtime certify --mode soak --proof <proof.json> --compiled <compiled.json> --parallel-jobs auto`
13. Rerun `./target-public/release/zkf-cli metal-doctor --strict --json` and require
    `production_ready=true`.
14. Run `make demo`.
15. Remove `target-public/` and rerun `./zkf-build.sh --release -p zkf-cli` from a clean tree.
16. Validate fresh-app bootstrap with:
    `zkf-cli app init --template range-proof --name test-app --out /tmp/test-fresh`
    followed by `cargo test --manifest-path /tmp/test-fresh/Cargo.toml`.
17. Confirm binary size and checksum.
18. Tag the release: `git tag v0.1.0`.
19. Create the GitHub release, attach the macOS ARM64 binary, and paste the
    release notes from the verified changelog/truth surfaces.
