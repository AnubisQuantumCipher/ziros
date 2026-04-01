#![allow(unexpected_cfgs)]

#[cfg(hax)]
fn main() {}

#[cfg(not(hax))]
fn main() {
    std::process::exit(
        zkf_backends::wrapping::groth16_recursive_verifier::recursive_groth16_worker_main(),
    );
}
