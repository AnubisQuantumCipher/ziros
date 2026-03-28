pub fn load_app_spec() -> Result<zkf_lib::AppSpecV1, Box<dyn std::error::Error>> {
    let spec_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("zirapp.json");
    let spec_json = std::fs::read_to_string(spec_path)?;
    let spec = serde_json::from_str(&spec_json)?;
    Ok(spec)
}

pub fn load_program() -> Result<(zkf_lib::AppSpecV1, zkf_lib::Program), Box<dyn std::error::Error>>
{
    let spec = load_app_spec()?;
    let program = zkf_lib::build_app_spec(&spec)?;
    Ok((spec, program))
}
