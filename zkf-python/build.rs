fn main() {
    if std::env::var_os("CARGO_CFG_TEST").is_none() {
        pyo3_build_config::add_extension_module_link_args();
    }
}
