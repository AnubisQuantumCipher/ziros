use crate::cli::RegistryCommands;
use std::path::PathBuf;

pub(crate) fn handle_registry(command: RegistryCommands) -> Result<(), String> {
    // Default registry location.
    let registry_dir = dirs_or_default().join("zkf-registry");
    let remote_cache_dir = registry_dir.join(".remote-cache");

    match command {
        RegistryCommands::Add { gadget } => {
            let mut registry = zkf_registry::LocalRegistry::open(&registry_dir)
                .map_err(|e| format!("failed to open registry: {}", e))?;

            if let Some(manifest) = registry.get(&gadget).cloned() {
                println!("Installed gadget: {} v{}", manifest.name, manifest.version);
                println!("Description: {}", manifest.description);
                println!("Supported fields: {:?}", manifest.supported_fields);
            } else {
                let remote =
                    zkf_registry::RemoteRegistry::new(None, Some(remote_cache_dir.clone()));
                if let Some((manifest, content)) = remote.fetch_package(&gadget) {
                    registry
                        .publish(manifest.clone(), &content)
                        .map_err(|e| format!("failed to install remote gadget: {}", e))?;
                    println!(
                        "Installed gadget: {} v{} from remote registry",
                        manifest.name, manifest.version
                    );
                    println!("Description: {}", manifest.description);
                    println!("Supported fields: {:?}", manifest.supported_fields);
                    return Ok(());
                }

                // Check built-in gadgets.
                let builtin_registry = zkf_gadgets::GadgetRegistry::with_builtins();
                if builtin_registry.get(&gadget).is_some() {
                    println!(
                        "Gadget '{}' is a built-in gadget. No installation needed.",
                        gadget
                    );
                    println!("Use it directly via the gadget API.");
                } else {
                    return Err(format!(
                        "gadget '{}' not found in registry or built-ins",
                        gadget
                    ));
                }
            }
            Ok(())
        }
        RegistryCommands::List { json } => {
            let registry = zkf_registry::LocalRegistry::open(&registry_dir)
                .map_err(|e| format!("failed to open registry: {}", e))?;
            let combined = zkf_registry::CombinedRegistry::new(
                registry,
                Some(zkf_registry::RemoteRegistry::new(
                    None,
                    Some(remote_cache_dir.clone()),
                )),
            );

            let mut all_gadgets = Vec::new();

            // Built-in gadgets.
            let builtin_registry = zkf_gadgets::GadgetRegistry::with_builtins();
            for name in builtin_registry.list() {
                all_gadgets.push(serde_json::json!({
                    "name": name,
                    "source": "builtin",
                }));
            }

            // Registry gadgets.
            for manifest in combined.list() {
                all_gadgets.push(serde_json::json!({
                    "name": manifest.name,
                    "version": manifest.version,
                    "description": manifest.description,
                    "source": "registry",
                }));
            }

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&all_gadgets).map_err(|e| e.to_string())?
                );
            } else {
                println!("Available gadgets:");
                println!();
                for gadget in &all_gadgets {
                    let name = gadget["name"].as_str().unwrap_or("?");
                    let source = gadget["source"].as_str().unwrap_or("?");
                    let desc = gadget
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("");
                    if desc.is_empty() {
                        println!("  {} ({})", name, source);
                    } else {
                        println!("  {} ({}) - {}", name, source, desc);
                    }
                }
            }
            Ok(())
        }
        RegistryCommands::Publish { manifest, content } => {
            let manifest_data = std::fs::read_to_string(&manifest)
                .map_err(|e| format!("failed to read manifest: {}", e))?;
            let gadget_manifest: zkf_registry::GadgetManifest =
                serde_json::from_str(&manifest_data)
                    .map_err(|e| format!("failed to parse manifest: {}", e))?;
            let content_data =
                std::fs::read(&content).map_err(|e| format!("failed to read content: {}", e))?;

            let mut registry = zkf_registry::LocalRegistry::open(&registry_dir)
                .map_err(|e| format!("failed to open registry: {}", e))?;

            registry
                .publish(gadget_manifest.clone(), &content_data)
                .map_err(|e| format!("failed to publish: {}", e))?;

            println!(
                "Published {} v{} to local registry",
                gadget_manifest.name, gadget_manifest.version
            );
            Ok(())
        }
    }
}

fn dirs_or_default() -> PathBuf {
    dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// Minimal fallback for `dirs` crate functionality.
mod dirs {
    use std::path::PathBuf;

    pub fn data_local_dir() -> Option<PathBuf> {
        std::env::var("HOME")
            .ok()
            .map(|home| PathBuf::from(home).join(".local/share"))
    }
}
