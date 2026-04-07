use std::path::{Path, PathBuf};
use std::process::Command;

pub fn private_identity_artifact_path(manifest_dir: &str) -> PathBuf {
    Path::new(manifest_dir).join("../private_identity/target/private_identity.json")
}

pub fn ensure_private_identity_artifact(manifest_dir: &str) -> Option<PathBuf> {
    let artifact_path = private_identity_artifact_path(manifest_dir);
    if artifact_path.is_file() {
        return Some(artifact_path);
    }

    let project_dir = Path::new(manifest_dir).join("../private_identity");
    if !project_dir.is_dir() {
        eprintln!(
            "skipping private_identity beta.19 import test because project directory is missing: {}",
            project_dir.display()
        );
        return None;
    }
    let output = match Command::new("nargo")
        .arg("compile")
        .current_dir(&project_dir)
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            eprintln!(
                "skipping private_identity beta.19 import test because `nargo compile` could not start in {} while generating {}: {}",
                project_dir.display(),
                artifact_path.display(),
                err,
            );
            return None;
        }
    };

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

    Some(artifact_path)
}
