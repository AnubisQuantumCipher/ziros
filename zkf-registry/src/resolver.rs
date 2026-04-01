// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

use crate::registry::LocalRegistry;
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// VersionReq — lightweight semver version requirement parser & matcher.
// ---------------------------------------------------------------------------

/// A parsed semantic version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl SemVer {
    /// Parse a `"major.minor.patch"` string. Missing minor/patch default to 0.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let parts: Vec<&str> = s.split('.').collect();
        if parts.is_empty() || parts.len() > 3 {
            return Err(format!("invalid version: {}", s));
        }
        let major = parts[0]
            .parse::<u64>()
            .map_err(|_| format!("invalid major version in '{}'", s))?;
        let minor = if parts.len() > 1 {
            parts[1]
                .parse::<u64>()
                .map_err(|_| format!("invalid minor version in '{}'", s))?
        } else {
            0
        };
        let patch = if parts.len() > 2 {
            parts[2]
                .parse::<u64>()
                .map_err(|_| format!("invalid patch version in '{}'", s))?
        } else {
            0
        };
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

/// A single version comparator (e.g. `>=1.2.0` or `^1.2`).
#[derive(Debug, Clone)]
enum Comparator {
    /// Matches any version.
    Any,
    /// Exact match: `=1.2.3` or just `1.2.3`.
    Eq(SemVer),
    /// Greater than or equal.
    Gte(SemVer),
    /// Greater than.
    Gt(SemVer),
    /// Less than or equal.
    Lte(SemVer),
    /// Less than.
    Lt(SemVer),
    /// Caret: `^1.2.3` — compatible with 1.x.y where x >= 2.
    Caret(SemVer),
    /// Tilde: `~1.2.3` — compatible with 1.2.x where x >= 3.
    Tilde(SemVer),
}

impl Comparator {
    fn matches(&self, v: &SemVer) -> bool {
        match self {
            Comparator::Any => true,
            Comparator::Eq(req) => v == req,
            Comparator::Gte(req) => v >= req,
            Comparator::Gt(req) => v > req,
            Comparator::Lte(req) => v <= req,
            Comparator::Lt(req) => v < req,
            Comparator::Caret(req) => {
                if req.major != 0 {
                    // ^1.2.3 := >=1.2.3, <2.0.0
                    v.major == req.major && v >= req
                } else if req.minor != 0 {
                    // ^0.2.3 := >=0.2.3, <0.3.0
                    v.major == 0 && v.minor == req.minor && v >= req
                } else {
                    // ^0.0.3 := >=0.0.3, <0.0.4
                    v.major == 0 && v.minor == 0 && v.patch == req.patch
                }
            }
            Comparator::Tilde(req) => {
                // ~1.2.3 := >=1.2.3, <1.3.0
                v.major == req.major && v.minor == req.minor && v.patch >= req.patch
            }
        }
    }
}

/// A version requirement that may consist of multiple comma-separated comparators,
/// all of which must be satisfied (intersection).
///
/// Supports: `*`, `=1.2.3`, `>=1.0`, `<2.0`, `^1.2`, `~1.2.3`, and combinations
/// like `">=1.0, <2.0"`.
#[derive(Debug, Clone)]
pub struct VersionReq {
    comparators: Vec<Comparator>,
}

impl VersionReq {
    /// Parse a version requirement string.
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() || input == "*" {
            return Ok(Self {
                comparators: vec![Comparator::Any],
            });
        }

        let mut comparators = Vec::new();
        for part in input.split(',') {
            comparators.push(Self::parse_one(part.trim())?);
        }

        if comparators.is_empty() {
            return Err("empty version requirement".to_string());
        }

        Ok(Self { comparators })
    }

    fn parse_one(s: &str) -> Result<Comparator, String> {
        let s = s.trim();
        if s == "*" {
            return Ok(Comparator::Any);
        }
        if let Some(rest) = s.strip_prefix(">=") {
            return Ok(Comparator::Gte(SemVer::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix('>') {
            return Ok(Comparator::Gt(SemVer::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix("<=") {
            return Ok(Comparator::Lte(SemVer::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix('<') {
            return Ok(Comparator::Lt(SemVer::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix('^') {
            return Ok(Comparator::Caret(SemVer::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix('~') {
            return Ok(Comparator::Tilde(SemVer::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix('=') {
            return Ok(Comparator::Eq(SemVer::parse(rest)?));
        }
        // Bare version string treated as exact match.
        Ok(Comparator::Eq(SemVer::parse(s)?))
    }

    /// Check whether a version string satisfies this requirement.
    pub fn matches(&self, version: &str) -> bool {
        match SemVer::parse(version) {
            Ok(v) => self.comparators.iter().all(|c| c.matches(&v)),
            Err(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Dependency resolver with version checking.
// ---------------------------------------------------------------------------

/// Resolve gadget dependencies in topological order, checking version compatibility.
pub fn resolve_dependencies(
    registry: &LocalRegistry,
    root_names: &[String],
) -> Result<Vec<String>, String> {
    let mut resolved = Vec::new();
    let mut visited = BTreeSet::new();
    let mut in_progress = BTreeSet::new();
    // Track version requirements: gadget name -> list of (required_by, version_req_string).
    let mut version_reqs: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();

    for name in root_names {
        resolve_one(
            registry,
            name,
            &mut resolved,
            &mut visited,
            &mut in_progress,
            &mut version_reqs,
        )?;
    }

    // After resolution, verify that all version constraints are compatible.
    check_version_conflicts(registry, &version_reqs)?;

    Ok(resolved)
}

fn resolve_one(
    registry: &LocalRegistry,
    name: &str,
    resolved: &mut Vec<String>,
    visited: &mut BTreeSet<String>,
    in_progress: &mut BTreeSet<String>,
    version_reqs: &mut BTreeMap<String, Vec<(String, String)>>,
) -> Result<(), String> {
    if visited.contains(name) {
        return Ok(());
    }
    if in_progress.contains(name) {
        return Err(format!("circular dependency detected: {}", name));
    }

    in_progress.insert(name.to_string());

    if let Some(manifest) = registry.get(name) {
        for dep in &manifest.dependencies {
            // Record the version requirement.
            version_reqs
                .entry(dep.name.clone())
                .or_default()
                .push((name.to_string(), dep.version_req.clone()));

            resolve_one(
                registry,
                &dep.name,
                resolved,
                visited,
                in_progress,
                version_reqs,
            )?;
        }
    }

    in_progress.remove(name);
    visited.insert(name.to_string());
    resolved.push(name.to_string());

    Ok(())
}

/// After topological sort, verify that all version requirements on a given gadget
/// are mutually compatible with the version actually present in the registry.
fn check_version_conflicts(
    registry: &LocalRegistry,
    version_reqs: &BTreeMap<String, Vec<(String, String)>>,
) -> Result<(), String> {
    for (gadget_name, reqs) in version_reqs {
        let actual_version = match registry.get(gadget_name) {
            Some(m) => m.version.clone(),
            None => continue, // Missing gadget is not a version conflict.
        };

        for (required_by, req_str) in reqs {
            let vr = VersionReq::parse(req_str).map_err(|e| {
                format!(
                    "invalid version requirement '{}' for '{}' (required by '{}'): {}",
                    req_str, gadget_name, required_by, e
                )
            })?;

            if !vr.matches(&actual_version) {
                return Err(format!(
                    "version conflict: '{}' requires '{}' {} but registry has {}",
                    required_by, gadget_name, req_str, actual_version
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{GadgetDependency, GadgetManifest};

    // -- SemVer tests -------------------------------------------------------

    #[test]
    fn parse_semver() {
        let v = SemVer::parse("1.2.3").unwrap();
        assert_eq!(
            v,
            SemVer {
                major: 1,
                minor: 2,
                patch: 3
            }
        );
    }

    #[test]
    fn parse_semver_missing_patch() {
        let v = SemVer::parse("1.2").unwrap();
        assert_eq!(
            v,
            SemVer {
                major: 1,
                minor: 2,
                patch: 0
            }
        );
    }

    #[test]
    fn parse_semver_major_only() {
        let v = SemVer::parse("3").unwrap();
        assert_eq!(
            v,
            SemVer {
                major: 3,
                minor: 0,
                patch: 0
            }
        );
    }

    // -- VersionReq tests ---------------------------------------------------

    #[test]
    fn version_req_star() {
        let req = VersionReq::parse("*").unwrap();
        assert!(req.matches("0.0.1"));
        assert!(req.matches("99.99.99"));
    }

    #[test]
    fn version_req_exact() {
        let req = VersionReq::parse("=1.2.3").unwrap();
        assert!(req.matches("1.2.3"));
        assert!(!req.matches("1.2.4"));
    }

    #[test]
    fn version_req_bare_exact() {
        let req = VersionReq::parse("1.0.0").unwrap();
        assert!(req.matches("1.0.0"));
        assert!(!req.matches("1.0.1"));
    }

    #[test]
    fn version_req_gte_lt_range() {
        let req = VersionReq::parse(">=1.0, <2.0").unwrap();
        assert!(req.matches("1.0.0"));
        assert!(req.matches("1.5.3"));
        assert!(req.matches("1.99.99"));
        assert!(!req.matches("0.9.9"));
        assert!(!req.matches("2.0.0"));
        assert!(!req.matches("2.0.1"));
    }

    #[test]
    fn version_req_caret() {
        let req = VersionReq::parse("^1.2").unwrap();
        assert!(req.matches("1.2.0"));
        assert!(req.matches("1.9.9"));
        assert!(!req.matches("2.0.0"));
        assert!(!req.matches("1.1.9"));
    }

    #[test]
    fn version_req_caret_zero_major() {
        let req = VersionReq::parse("^0.2.3").unwrap();
        assert!(req.matches("0.2.3"));
        assert!(req.matches("0.2.9"));
        assert!(!req.matches("0.3.0"));
        assert!(!req.matches("0.2.2"));
    }

    #[test]
    fn version_req_caret_zero_zero() {
        let req = VersionReq::parse("^0.0.5").unwrap();
        assert!(req.matches("0.0.5"));
        assert!(!req.matches("0.0.6"));
        assert!(!req.matches("0.0.4"));
    }

    #[test]
    fn version_req_tilde() {
        let req = VersionReq::parse("~1.2.3").unwrap();
        assert!(req.matches("1.2.3"));
        assert!(req.matches("1.2.9"));
        assert!(!req.matches("1.3.0"));
        assert!(!req.matches("1.2.2"));
    }

    #[test]
    fn version_req_gt() {
        let req = VersionReq::parse(">1.0.0").unwrap();
        assert!(req.matches("1.0.1"));
        assert!(!req.matches("1.0.0"));
    }

    #[test]
    fn version_req_lte() {
        let req = VersionReq::parse("<=2.0.0").unwrap();
        assert!(req.matches("2.0.0"));
        assert!(req.matches("1.99.99"));
        assert!(!req.matches("2.0.1"));
    }

    // -- Resolver tests -----------------------------------------------------

    fn temp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "zkf-{}-test-{}",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn resolves_empty_dependencies() {
        let dir = temp_dir("resolver-empty");
        let registry = LocalRegistry::open(&dir).unwrap();
        let result = resolve_dependencies(&registry, &["nonexistent".to_string()]).unwrap();
        assert_eq!(result, vec!["nonexistent"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolves_topological_order() {
        let dir = temp_dir("resolver-topo");
        let mut registry = LocalRegistry::open(&dir).unwrap();

        // C depends on nothing.
        registry
            .publish(GadgetManifest::new("C", "1.0.0", "base"), b"c")
            .unwrap();

        // B depends on C.
        let mut b = GadgetManifest::new("B", "1.0.0", "mid");
        b.dependencies.push(GadgetDependency {
            name: "C".to_string(),
            version_req: "^1.0".to_string(),
        });
        registry.publish(b, b"b").unwrap();

        // A depends on B.
        let mut a = GadgetManifest::new("A", "1.0.0", "top");
        a.dependencies.push(GadgetDependency {
            name: "B".to_string(),
            version_req: "^1.0".to_string(),
        });
        registry.publish(a, b"a").unwrap();

        let result = resolve_dependencies(&registry, &["A".to_string()]).unwrap();
        assert_eq!(result, vec!["C", "B", "A"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_circular_dependency() {
        let dir = temp_dir("resolver-cycle");
        let mut registry = LocalRegistry::open(&dir).unwrap();

        let mut a = GadgetManifest::new("A", "1.0.0", "a");
        a.dependencies.push(GadgetDependency {
            name: "B".to_string(),
            version_req: "*".to_string(),
        });
        registry.publish(a, b"a").unwrap();

        let mut b = GadgetManifest::new("B", "1.0.0", "b");
        b.dependencies.push(GadgetDependency {
            name: "A".to_string(),
            version_req: "*".to_string(),
        });
        registry.publish(b, b"b").unwrap();

        let result = resolve_dependencies(&registry, &["A".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("circular"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_version_conflict() {
        let dir = temp_dir("resolver-conflict");
        let mut registry = LocalRegistry::open(&dir).unwrap();

        // Lib at version 2.0.0
        registry
            .publish(GadgetManifest::new("lib", "2.0.0", "library"), b"lib")
            .unwrap();

        // A requires lib ^1.0 (incompatible with 2.0.0).
        let mut a = GadgetManifest::new("A", "1.0.0", "a");
        a.dependencies.push(GadgetDependency {
            name: "lib".to_string(),
            version_req: "^1.0".to_string(),
        });
        registry.publish(a, b"a").unwrap();

        let result = resolve_dependencies(&registry, &["A".to_string()]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("version conflict"), "got: {}", err);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compatible_version_passes() {
        let dir = temp_dir("resolver-compat");
        let mut registry = LocalRegistry::open(&dir).unwrap();

        registry
            .publish(GadgetManifest::new("lib", "1.5.0", "library"), b"lib")
            .unwrap();

        // A requires lib >=1.0, <2.0
        let mut a = GadgetManifest::new("A", "1.0.0", "a");
        a.dependencies.push(GadgetDependency {
            name: "lib".to_string(),
            version_req: ">=1.0, <2.0".to_string(),
        });
        registry.publish(a, b"a").unwrap();

        // B also requires lib ~1.5
        let mut b = GadgetManifest::new("B", "1.0.0", "b");
        b.dependencies.push(GadgetDependency {
            name: "lib".to_string(),
            version_req: "~1.5.0".to_string(),
        });
        registry.publish(b, b"b").unwrap();

        let result = resolve_dependencies(&registry, &["A".to_string(), "B".to_string()]).unwrap();
        assert!(result.contains(&"lib".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
