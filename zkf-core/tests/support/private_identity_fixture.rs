use std::path::{Path, PathBuf};
use std::process::Command;

pub fn private_identity_artifact_path(manifest_dir: &str) -> PathBuf {
    Path::new(manifest_dir).join("../private_identity/target/private_identity.json")
}

pub fn ensure_private_identity_artifact(manifest_dir: &str) -> PathBuf {
    let artifact_path = private_identity_artifact_path(manifest_dir);
    if artifact_path.is_file() {
        return artifact_path;
    }

    let project_dir = Path::new(manifest_dir).join("../private_identity");
    let output = Command::new("nargo")
        .arg("compile")
        .current_dir(&project_dir)
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "failed to run `nargo compile` in {} while generating {}. Ensure nargo 1.0.0-beta.19 is installed and on PATH: {err}",
                project_dir.display(),
                artifact_path.display(),
            )
        });

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "`nargo compile` failed in {} while generating {}.\nstdout:\n{}\nstderr:\n{}",
            project_dir.display(),
            artifact_path.display(),
            stdout.trim(),
            stderr.trim(),
        );
    }

    assert!(
        artifact_path.is_file(),
        "`nargo compile` finished but {} was not created",
        artifact_path.display(),
    );

    artifact_path
}
