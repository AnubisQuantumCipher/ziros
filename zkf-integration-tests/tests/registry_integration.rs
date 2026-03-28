use zkf_registry::manifest::{GadgetDependency, GadgetManifest};
use zkf_registry::{
    CombinedRegistry, LocalRegistry, RemoteRegistry, VersionReq, resolve_dependencies,
};

fn temp_dir(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "zkf-integ-{}-{}",
        label,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn local_registry_publish_get_remove_cycle() {
    let dir = temp_dir("cycle");
    let mut registry = LocalRegistry::open(&dir).unwrap();

    let manifest = GadgetManifest::new("test_gadget", "1.0.0", "A test gadget");
    registry.publish(manifest, b"content").unwrap();

    let retrieved = registry.get("test_gadget");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().version, "1.0.0");

    registry.remove("test_gadget").unwrap();
    assert!(registry.get("test_gadget").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dependency_resolution_topological_order() {
    let dir = temp_dir("topo");
    let mut registry = LocalRegistry::open(&dir).unwrap();

    registry
        .publish(GadgetManifest::new("base", "1.0.0", "base gadget"), b"")
        .unwrap();

    let mut mid = GadgetManifest::new("mid", "1.0.0", "mid gadget");
    mid.dependencies.push(GadgetDependency {
        name: "base".to_string(),
        version_req: "^1.0".to_string(),
    });
    registry.publish(mid, b"").unwrap();

    let mut top = GadgetManifest::new("top", "1.0.0", "top gadget");
    top.dependencies.push(GadgetDependency {
        name: "mid".to_string(),
        version_req: "^1.0".to_string(),
    });
    registry.publish(top, b"").unwrap();

    let order = resolve_dependencies(&registry, &["top".to_string()]).unwrap();
    assert_eq!(order, vec!["base", "mid", "top"]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn circular_dependency_detected() {
    let dir = temp_dir("circular");
    let mut registry = LocalRegistry::open(&dir).unwrap();

    let mut a = GadgetManifest::new("A", "1.0.0", "a");
    a.dependencies.push(GadgetDependency {
        name: "B".to_string(),
        version_req: "*".to_string(),
    });
    registry.publish(a, b"").unwrap();

    let mut b = GadgetManifest::new("B", "1.0.0", "b");
    b.dependencies.push(GadgetDependency {
        name: "A".to_string(),
        version_req: "*".to_string(),
    });
    registry.publish(b, b"").unwrap();

    let result = resolve_dependencies(&registry, &["A".to_string()]);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("circular"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn version_conflict_detection() {
    let dir = temp_dir("conflict");
    let mut registry = LocalRegistry::open(&dir).unwrap();

    registry
        .publish(GadgetManifest::new("lib", "2.0.0", "library"), b"")
        .unwrap();

    let mut a = GadgetManifest::new("A", "1.0.0", "a");
    a.dependencies.push(GadgetDependency {
        name: "lib".to_string(),
        version_req: "^1.0".to_string(), // Requires 1.x but lib is 2.0.0
    });
    registry.publish(a, b"").unwrap();

    let result = resolve_dependencies(&registry, &["A".to_string()]);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("version conflict"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn semver_range_matching() {
    let req = VersionReq::parse(">=1.0, <2.0").unwrap();
    assert!(req.matches("1.0.0"));
    assert!(req.matches("1.5.3"));
    assert!(!req.matches("2.0.0"));
    assert!(!req.matches("0.9.9"));

    let caret = VersionReq::parse("^0.2.3").unwrap();
    assert!(caret.matches("0.2.3"));
    assert!(caret.matches("0.2.9"));
    assert!(!caret.matches("0.3.0"));

    let tilde = VersionReq::parse("~1.2.3").unwrap();
    assert!(tilde.matches("1.2.3"));
    assert!(tilde.matches("1.2.9"));
    assert!(!tilde.matches("1.3.0"));
}

#[test]
fn combined_registry_local_takes_priority() {
    let local_dir = temp_dir("combined-local");
    let cache_dir = temp_dir("combined-cache");

    let mut local = LocalRegistry::open(&local_dir).unwrap();
    local
        .publish(GadgetManifest::new("shared", "2.0.0", "Local"), b"")
        .unwrap();

    // Pre-populate remote cache with older version
    std::fs::create_dir_all(cache_dir.join("shared")).unwrap();
    let old = GadgetManifest::new("shared", "1.0.0", "Remote");
    std::fs::write(
        cache_dir.join("shared").join("manifest.json"),
        serde_json::to_string(&old).unwrap(),
    )
    .unwrap();

    let remote = RemoteRegistry::new(
        Some("http://127.0.0.1:1".to_string()), // unreachable
        Some(cache_dir.clone()),
    );
    let combined = CombinedRegistry::new(local, Some(remote));

    let got = combined.get("shared").unwrap();
    assert_eq!(got.version, "2.0.0", "local should override remote cache");

    let _ = std::fs::remove_dir_all(&local_dir);
    let _ = std::fs::remove_dir_all(&cache_dir);
}

#[test]
fn manifest_content_digest_verification() {
    let mut manifest = GadgetManifest::new("test", "1.0.0", "test");
    let content = b"hello world";
    manifest.set_content_digest(content);
    assert!(manifest.content_sha256.is_some());
    assert!(manifest.verify_content_digest(content));
    assert!(!manifest.verify_content_digest(b"tampered"));
}
