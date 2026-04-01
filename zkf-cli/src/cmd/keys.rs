use zkf_keymanager::KeyManager;

pub(crate) fn handle_keys(command: crate::cli::KeysCommands) -> Result<(), String> {
    match command {
        crate::cli::KeysCommands::List { json } => handle_list(json),
        crate::cli::KeysCommands::Inspect { id, json } => handle_inspect(&id, json),
        crate::cli::KeysCommands::Rotate { id } => handle_rotate(&id),
        crate::cli::KeysCommands::Audit { json } => handle_audit(json),
        crate::cli::KeysCommands::Revoke { id, force } => handle_revoke(&id, force),
    }
}

fn handle_list(json: bool) -> Result<(), String> {
    let manager = KeyManager::new().map_err(|err| err.to_string())?;
    let entries = manager.list_all().map_err(|err| err.to_string())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).map_err(|err| err.to_string())?
        );
        return Ok(());
    }

    for entry in entries {
        println!(
            "{} service={} backend={} type={:?}",
            entry.id,
            entry.service,
            entry.backend.as_str(),
            entry.key_type
        );
    }
    Ok(())
}

fn handle_inspect(id: &str, json: bool) -> Result<(), String> {
    let manager = KeyManager::new().map_err(|err| err.to_string())?;
    let entry = manager.inspect(id).map_err(|err| err.to_string())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&entry).map_err(|err| err.to_string())?
        );
    } else {
        println!(
            "key {}: service={} backend={} digest={}",
            entry.id,
            entry.service,
            entry.backend.as_str(),
            entry.digest
        );
    }
    Ok(())
}

fn handle_rotate(id: &str) -> Result<(), String> {
    let manager = KeyManager::new().map_err(|err| err.to_string())?;
    let entry = manager.rotate(id).map_err(|err| err.to_string())?;
    println!(
        "rotated key {} service={} backend={}",
        entry.id,
        entry.service,
        entry.backend.as_str()
    );
    Ok(())
}

fn handle_audit(json: bool) -> Result<(), String> {
    let manager = KeyManager::new().map_err(|err| err.to_string())?;
    let report = manager.audit().map_err(|err| err.to_string())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
        );
        return Ok(());
    }

    println!(
        "key audit: healthy={} backend={} keys={}",
        report.healthy,
        report.backend.as_str(),
        report.key_count
    );
    for item in report.items {
        println!(
            "{} present={} age_seconds={}",
            item.entry.id, item.present, item.age_seconds
        );
    }
    Ok(())
}

fn handle_revoke(id: &str, force: bool) -> Result<(), String> {
    if !force {
        return Err("refusing to revoke without --force".to_string());
    }
    let manager = KeyManager::new().map_err(|err| err.to_string())?;
    manager.revoke(id).map_err(|err| err.to_string())?;
    println!("revoked key {id}");
    Ok(())
}
