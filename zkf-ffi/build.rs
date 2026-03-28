fn main() {
    use std::fs;
    use std::path::PathBuf;

    fn fatal(message: impl std::fmt::Display) -> ! {
        eprintln!("{message}");
        std::process::exit(1);
    }

    fn required_env(name: &str) -> PathBuf {
        match std::env::var(name) {
            Ok(value) => PathBuf::from(value),
            Err(error) => fatal(format!("missing {name}: {error}")),
        }
    }

    fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => fatal(format!("{context}: {error}")),
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    let crate_dir = required_env("CARGO_MANIFEST_DIR");
    let output = crate_dir.join("include").join("zkf_ffi.h");
    let out_dir = required_env("OUT_DIR");
    let cbindgen_crate_dir = out_dir.join("cbindgen-crate");
    let cbindgen_src_dir = cbindgen_crate_dir.join("src");

    must(
        fs::create_dir_all(&cbindgen_src_dir),
        "create temporary cbindgen src dir",
    );
    let source = must(
        fs::read_to_string(crate_dir.join("src").join("lib.rs")),
        "read ffi source",
    );
    let cbindgen_source = source.replace("#[unsafe(no_mangle)]", "#[no_mangle]");
    must(
        fs::write(cbindgen_src_dir.join("lib.rs"), cbindgen_source),
        "write temporary cbindgen lib.rs",
    );
    must(
        fs::write(
            cbindgen_crate_dir.join("Cargo.toml"),
            r#"[package]
name = "zkf-ffi-cbindgen"
version = "0.0.0"
edition = "2024"

[lib]
name = "zkf_ffi"
crate-type = ["rlib"]

[workspace]
"#,
        ),
        "write temporary cbindgen Cargo.toml",
    );

    let config = must(
        cbindgen::Config::from_file(crate_dir.join("cbindgen.toml")),
        "load cbindgen.toml",
    );
    let bindings = must(
        cbindgen::Builder::new()
            .with_config(config)
            .with_crate(cbindgen_crate_dir)
            .generate(),
        "generate zkf_ffi.h",
    );
    bindings.write_to_file(output);
}
