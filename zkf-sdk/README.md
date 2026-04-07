# zkf-sdk

`zkf-sdk` is the public ZirOS SDK for application developers.

It is licensed under Apache License 2.0 and exposes the supported builder API,
core IR types, proof entrypoints, and selected subsystem-facing request types.
Developers should depend on this crate instead of linking to `zkf-lib` or
`zkf-core` directly.

The ZirOS core implementation remains private. This SDK is the public API layer
used to build applications, examples, and integration code against ZirOS.

Examples:

- `cargo check -p zkf-sdk --example simple_circuit`
- `cargo test -p zkf-sdk`

Documentation and usage examples live alongside the ZirOS workspace sources and
the SDK examples in this crate.
