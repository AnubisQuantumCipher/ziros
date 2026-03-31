# Build

ZirOS builds as a single Cargo workspace and writes artifacts to `target-public/`
via [`.cargo/config.toml`](.cargo/config.toml).

## Prerequisites

- Rust stable via `rustup`
- Xcode Command Line Tools on macOS
- Apple Silicon for the full Metal-accelerated path

## Standard Build

Use the workspace build wrapper so Cargo job count and macOS allocator settings
match the intended developer path. On macOS release builds, the wrapper also
ensures the shipped `zkf-cli` binary is built with `metal-gpu`:

```bash
./zkf-build.sh --release
```

Useful variants:

```bash
./zkf-build.sh
./zkf-build.sh --release -p zkf-cli
./zkf-build.sh --release -p zkf-cli --features all-native-backends
./zkf-build.sh test --workspace --all-targets --no-fail-fast
./zkf-build.sh clippy --workspace -- -D warnings
```

## Fresh Clone Path

```bash
./zkf-build.sh --release -p zkf-cli
./target-public/release/zkf-cli doctor
```

## Environment Notes

- `CARGO_TARGET_DIR` overrides the default target location when needed.
- `ZKF_ALLOW_DEV_DETERMINISTIC_GROTH16=1` is development-only. Do not use it to
  describe a production trust lane.
- `MallocNanoZone=0` is set automatically by `zkf-build.sh` on macOS to avoid
  allocator failures on large proving and wrapping builds.

## Optional Native Backends

The default release binary ships the primary ZirOS backend surface without the
optional native zkVM SDK stacks. To enable the SP1 and RISC Zero native lanes
in a local build, compile `zkf-cli` with:

```bash
./zkf-build.sh --release -p zkf-cli --features all-native-backends
```

## Release Artifact

The primary binary is:

```bash
target-public/release/zkf-cli
```
