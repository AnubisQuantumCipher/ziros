use super::shared::midnight_template_catalog;

pub(crate) fn handle_templates(json: bool) -> Result<(), String> {
    let catalog = midnight_template_catalog()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&catalog).map_err(|error| error.to_string())?
        );
        return Ok(());
    }

    for entry in catalog {
        println!(
            "{}: {} [{}]",
            entry.template_id, entry.description, entry.backend_lane
        );
    }
    Ok(())
}
