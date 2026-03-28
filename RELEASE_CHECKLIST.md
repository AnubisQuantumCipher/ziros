# Release Checklist

1. Update version surfaces to `v0.1.0` or the next intended tag.
2. Regenerate or verify `support-matrix.json`, proof-boundary surfaces, and any
   other machine-readable truth outputs touched by the release.
3. Update [CHANGELOG.md](/Users/sicarii/Projects/ZK DEV/CHANGELOG.md).
4. Run `cargo fmt --all -- --check`.
5. Run `cargo clippy --workspace -- -D warnings`.
6. Run `make test`.
7. Run `make audit`.
8. Run `./scripts/run_conformance_suite.sh`.
9. Run `./target-local/release/zkf-cli doctor`.
10. On Apple Silicon, run `./target-local/release/zkf-cli metal-doctor`.
11. Run `make demo`.
12. Remove `target-local/` and rerun `./install.sh` from a clean tree.
13. Validate fresh-app bootstrap with:
    `zkf-cli app init --template range-proof --name test-app --out /tmp/test-fresh`
    followed by `cargo test --manifest-path /tmp/test-fresh/Cargo.toml`.
14. Build the release binary:
    `./zkf-build.sh --release -p zkf-cli`
15. Confirm binary size and checksum.
16. Tag the release: `git tag v0.1.0`.
17. Create the GitHub release, attach the macOS ARM64 binary, and paste the
    release notes from the verified changelog/truth surfaces.
