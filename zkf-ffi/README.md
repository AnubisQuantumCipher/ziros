# zkf-ffi

`zkf-ffi` is the C-compatible embedding surface for ZirOS. It exists for Swift,
Objective-C, and other native host integrations that need proof operations
without linking against Rust internals directly.

## Public API Surface

- FFI crate: `zkf-ffi`
- Exported surfaces: C ABI functions and generated headers for native hosts
- Binary: `zkf-test-all`
