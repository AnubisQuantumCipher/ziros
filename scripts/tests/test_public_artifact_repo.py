import importlib.util
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "export_zkf_metal_public_artifact_repo.py"


def load_module():
    spec = importlib.util.spec_from_file_location("test_public_artifact_repo", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        if sys.path and sys.path[0] == str(SCRIPT.parent):
            sys.path.pop(0)
    return module


class PublicArtifactRepoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_private_source_commitment_root_is_order_independent(self):
        manifests_a = {
            "hash": {
                "programs": [
                    {
                        "lowering": {
                            "source_sha256": {
                                "./b.rs": "2" * 64,
                                "a.rs": "1" * 64,
                            }
                        }
                    }
                ]
            }
        }
        manifests_b = {
            "hash": {
                "programs": [
                    {
                        "lowering": {
                            "source_sha256": {
                                "a.rs": "1" * 64,
                                "./b.rs": "2" * 64,
                            }
                        }
                    }
                ]
            }
        }
        self.assertEqual(
            self.module.private_source_commitment_root(manifests_a),
            self.module.private_source_commitment_root(manifests_b),
        )

    def test_private_source_path_normalization_rejects_absolute_paths(self):
        with self.assertRaises(RuntimeError):
            self.module.normalize_private_source_path(
                "/Users/sicarii/Projects/ZK DEV/zkf-metal/src/proof_ir.rs"
            )

    def test_normalize_library_key_accepts_public_filename(self):
        self.assertEqual(
            self.module.normalize_library_key("main.metallib"),
            "main_library",
        )

    def test_build_bundle_statement_redacts_private_source_fields(self):
        bundle = {
            "bundle_id": "kernel-families",
            "theorem_ids": ["gpu.hash_differential_bounded"],
            "summary": "summary",
            "formal_statement": "formal",
        }
        selected = [
            {
                "theorem_id": "gpu.hash_differential_bounded",
                "program_id": "hash_sha256_batch",
                "toolchain": {
                    "metal_compiler_version": "metal",
                    "xcode_version": "xcode",
                    "sdk_version": "sdk",
                },
                "artifacts": [
                    {
                        "kernel_program_label": "hash_sha256_batch",
                        "entrypoint_label": "batch_sha256",
                        "library_id": "hash_library",
                        "metallib_public_name": "hash.metallib",
                        "metallib_digest": "a" * 64,
                        "reflection_digest": "b" * 64,
                        "pipeline_descriptor_digest": "c" * 64,
                    }
                ],
            }
        ]
        statement = self.module.build_bundle_statement(
            bundle,
            selected,
            private_source_root="d" * 64,
            bundle_evidence_digest_value="e" * 64,
        )
        serialized = str(statement)
        self.assertNotIn("source_sha256", serialized)
        self.assertNotIn("source_paths", serialized)
        self.assertEqual(
            statement["artifact_bindings"]["private_source_commitment_root"],
            "d" * 64,
        )
        self.assertEqual(
            statement["artifact_bindings"]["bundle_evidence_digest"],
            "e" * 64,
        )
        self.assertEqual(
            statement["artifact_bindings"]["reflection_digest_scheme"],
            self.module.PUBLIC_REFLECTION_DIGEST_SCHEME_V1,
        )

    def test_build_integrity_bundle_evidence_redacts_source_map(self):
        bundle = {
            "bundle_id": "build-integrity",
            "theorem_ids": ["public.build_integrity_commitment"],
        }
        selected = [
            {
                "theorem_id": "gpu.hash_differential_bounded",
                "program_id": "hash_sha256_batch",
                "toolchain": {
                    "metal_compiler_version": "metal",
                    "xcode_version": "xcode",
                    "sdk_version": "sdk",
                },
                "artifacts": [
                    {
                        "kernel_program_label": "hash_sha256_batch",
                        "entrypoint_label": "batch_sha256",
                        "library_id": "hash_library",
                        "metallib_public_name": "hash.metallib",
                        "metallib_digest": "a" * 64,
                        "reflection_digest": "b" * 64,
                        "pipeline_descriptor_digest": "c" * 64,
                    }
                ],
            }
        ]
        evidence = self.module.build_bundle_evidence(
            bundle,
            selected,
            theorem_records_by_id={},
            private_source_root="d" * 64,
        )
        serialized = str(evidence)
        self.assertNotIn("source_sha256", serialized)
        self.assertNotIn("a.rs", serialized)
        self.assertEqual(evidence["kind"], "build_integrity")
        self.assertNotIn("source_entry_count", evidence)

    def test_leak_hits_for_text_catches_source_paths(self):
        hits = self.module.leak_hits_for_text(
            "/Users/sicarii/Projects/ZK DEV/zkf-metal/src/proof_ir.rs"
        )
        self.assertTrue(any("absolute path" == hit for hit in hits))
        self.assertTrue(any("source filename" == hit for hit in hits))

    def test_binary_leak_hits_allow_sanitized_tcb_markers_but_reject_private_paths(self):
        self.assertEqual(
            self.module.binary_leak_hits_for_blob("library/std/src/io/mod.rs"),
            [],
        )
        self.assertEqual(
            self.module.binary_leak_hits_for_blob("registry/serde_json-1.0.149/src/de.rs"),
            [],
        )
        self.assertIn(
            "private source marker",
            self.module.binary_leak_hits_for_blob("workspace/zkf-core/src/ir.rs"),
        )
        self.assertEqual(
            self.module.binary_leak_hits_for_blob("public zkf-metal runtime.metal-doctor"),
            [],
        )
        self.assertIn(
            "private source marker",
            self.module.binary_leak_hits_for_blob("shader/main.metal:"),
        )

    def test_metallib_digest_set_root_sorts_and_deduplicates(self):
        root = self.module.metallib_digest_set_root(
            [
                {"metallib_digest": "b" * 64},
                {"metallib_digest": "a" * 64},
                {"metallib_digest": "b" * 64},
            ]
        )
        expected = self.module.sha256_bytes(
            f"{'a' * 64}\n{'b' * 64}".encode("utf-8")
        )
        self.assertEqual(root, expected)

    def test_generate_public_proof_bundles_copies_generated_native_artifacts(self):
        requests = [{"bundle_id": "kernel-families"}]
        captured_env = {}

        def fake_run_checked(command, *, cwd, env):
            del cwd
            captured_env.update(env)
            generated_root = Path(command[command.index("--out-dir") + 1])
            (generated_root / "zkproofs").mkdir(parents=True, exist_ok=True)
            (generated_root / "verification_keys").mkdir(parents=True, exist_ok=True)
            (generated_root / "zkproofs" / "kernel-families.bin").write_bytes(b"proof")
            (generated_root / "verification_keys" / "kernel-families.bin").write_bytes(b"vk")

        with tempfile.TemporaryDirectory() as tempdir:
            out_dir = Path(tempdir)
            with mock.patch.object(self.module, "run_checked", side_effect=fake_run_checked):
                proof_paths, verification_key_paths = self.module.generate_public_proof_bundles(
                    requests,
                    out_dir=out_dir,
                    proof_mode="groth16",
                )
            self.assertEqual(proof_paths["kernel-families"].read_bytes(), b"proof")
            self.assertEqual(
                verification_key_paths["kernel-families"].read_bytes(), b"vk"
            )

        self.assertEqual(
            captured_env["CARGO_TARGET_DIR"],
            str(ROOT / "target-public-proof"),
        )

    def test_sanitize_toolchain_identity_removes_installed_dir(self):
        sanitized = self.module.sanitize_toolchain_identity(
            {
                "metal_compiler_version": (
                    "Apple metal version 32023.864 | Target: air64-apple-darwin25.0.0 "
                    "| Thread model: posix | InstalledDir: /private/var/run/toolchain/bin"
                ),
                "xcode_version": "Xcode 26.3 | Build version 17C529",
                "sdk_version": "26.2",
            }
        )
        self.assertNotIn("InstalledDir", sanitized["metal_compiler_version"])
        self.assertNotIn("/private/var", sanitized["metal_compiler_version"])

    def test_sanitize_orbital_showcase_source_redacts_hidden_branding(self):
        source = "Desktop/ZirOS_Private_NBody_5Body_1000Step\\nZirOS can prove this."
        sanitized = self.module.sanitize_orbital_showcase_source(source)
        self.assertNotIn("ZirOS", sanitized)
        self.assertIn("zkf-metal-private-nbody-5body-1000step", sanitized)

    def test_discover_metallibs_excludes_export_output_tree(self):
        with tempfile.TemporaryDirectory() as tempdir:
            temp_root = Path(tempdir)
            out_dir = temp_root / "target" / "zkf-metal-public-repo"
            excluded_candidate = out_dir / "binary" / "hash.metallib"
            real_candidate = temp_root / "target-local" / "build" / "hash.metallib"
            excluded_candidate.parent.mkdir(parents=True, exist_ok=True)
            real_candidate.parent.mkdir(parents=True, exist_ok=True)
            excluded_candidate.write_bytes(b"hash-metallib")
            real_candidate.write_bytes(b"hash-metallib")
            digest = self.module.sha256_file(real_candidate)

            with mock.patch.object(self.module, "ROOT", temp_root):
                discovered = self.module.discover_metallibs(
                    {"hash_library": digest},
                    excluded_roots=[out_dir],
                )

            self.assertEqual(discovered["hash_library"], real_candidate.resolve())


if __name__ == "__main__":
    unittest.main()
