fn main() {
    if let Err(error) = zkf_agent::serve_daemon(None) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
