import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def load_module(name: str):
    path = SCRIPTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"test_{name}", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        if sys.path and sys.path[0] == str(path.parent):
            sys.path.pop(0)
    return module


class CompetitionBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("competition_bootstrap")

    def test_build_toolchain_manifest_reports_missing_required_tool(self):
        with tempfile.TemporaryDirectory(prefix="zkf-toolchain-lock-") as tempdir:
            tempdir_path = Path(tempdir)
            lock = tempdir_path / "toolchain-lock.json"
            out = tempdir_path / "toolchain_manifest.json"
            lock.write_text(
                json.dumps(
                    {
                        "schema": "zkf-competition-toolchain-lock-v1",
                        "tools": [
                            {
                                "id": "missing-tool",
                                "label": "Missing Tool",
                                "required": True,
                                "install_supported": False,
                                "probe_commands": [["definitely-missing-binary", "--version"]],
                                "operator_action": "install the missing tool",
                            }
                        ],
                    }
                )
            )
            manifest = self.module.build_toolchain_manifest(
                lock_path=lock,
                out_path=out,
                install_missing=False,
            )
            self.assertTrue(out.exists())
        self.assertFalse(manifest["summary"]["required_toolchains_ready"])
        self.assertEqual(manifest["tools"][0]["failure_reason"], "toolchain-missing")

    def test_build_toolchain_manifest_marks_dependency_not_ready(self):
        with tempfile.TemporaryDirectory(prefix="zkf-toolchain-lock-deps-") as tempdir:
            tempdir_path = Path(tempdir)
            lock = tempdir_path / "toolchain-lock.json"
            out = tempdir_path / "toolchain_manifest.json"
            lock.write_text(
                json.dumps(
                    {
                        "schema": "zkf-competition-toolchain-lock-v1",
                        "tools": [
                            {
                                "id": "base",
                                "label": "Base",
                                "required": True,
                                "install_supported": False,
                                "probe_commands": [["definitely-missing-binary", "--version"]],
                                "operator_action": "install base",
                            },
                            {
                                "id": "child",
                                "label": "Child",
                                "required": True,
                                "install_supported": False,
                                "depends_on": ["base"],
                                "probe_commands": [["python3", "--version"]],
                                "operator_action": "install child",
                            },
                        ],
                    }
                )
            )
            manifest = self.module.build_toolchain_manifest(
                lock_path=lock,
                out_path=out,
                install_missing=False,
            )
        entries = {entry["tool"]: entry for entry in manifest["tools"]}
        self.assertEqual(entries["child"]["failure_reason"], "dependency-not-ready")

    def test_build_toolchain_manifest_marks_probe_command_failed_when_binary_is_present(self):
        with tempfile.TemporaryDirectory(prefix="zkf-toolchain-lock-probe-") as tempdir:
            tempdir_path = Path(tempdir)
            lock = tempdir_path / "toolchain-lock.json"
            out = tempdir_path / "toolchain_manifest.json"
            lock.write_text(
                json.dumps(
                    {
                        "schema": "zkf-competition-toolchain-lock-v1",
                        "tools": [
                            {
                                "id": "docker-like",
                                "label": "Docker",
                                "required": True,
                                "install_supported": False,
                                "probe_commands": [["python3", "-c", "import sys; sys.stderr.write('daemon unavailable'); sys.exit(1)"]],
                                "operator_action": "start docker",
                            }
                        ],
                    }
                )
            )
            manifest = self.module.build_toolchain_manifest(
                lock_path=lock,
                out_path=out,
                install_missing=False,
            )
        self.assertEqual(manifest["tools"][0]["failure_reason"], "probe-command-failed")
        self.assertIn("daemon unavailable", manifest["tools"][0]["probe_stderr_preview"])

    def test_build_toolchain_manifest_enforces_host_memory_requirement(self):
        with tempfile.TemporaryDirectory(prefix="zkf-toolchain-lock-host-") as tempdir:
            tempdir_path = Path(tempdir)
            lock = tempdir_path / "toolchain-lock.json"
            out = tempdir_path / "toolchain_manifest.json"
            lock.write_text(
                json.dumps(
                    {
                        "schema": "zkf-competition-toolchain-lock-v1",
                        "tools": [
                            {
                                "id": "docker",
                                "label": "Docker",
                                "required": True,
                                "install_supported": False,
                                "probe_commands": [["python3", "-c", "print('Server 27.0.0')"]],
                                "host_requirements": {
                                    "Darwin": {
                                        "probe_command": [["python3", "-c", "print(1024)"]][0],
                                        "minimum_memory_bytes": 2048,
                                        "failure_reason": "docker-memory-too-low",
                                        "operator_action": "raise docker memory",
                                    }
                                },
                                "operator_action": "start docker",
                            }
                        ],
                    }
                )
            )
            with patch.object(self.module.platform, "system", return_value="Darwin"):
                manifest = self.module.build_toolchain_manifest(
                    lock_path=lock,
                    out_path=out,
                    install_missing=False,
                )
        entry = manifest["tools"][0]
        self.assertEqual(entry["failure_reason"], "docker-memory-too-low")
        self.assertFalse(entry["ready"])
        self.assertEqual(entry["host_requirement"]["observed_memory_bytes"], 1024)
        self.assertEqual(entry["host_requirement"]["minimum_memory_bytes"], 2048)


class CompetitionScenarioRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("../benchmarks/run_competition_scenario")

    def test_resolve_artifact_path_uses_repo_root_for_config_hints(self):
        workdir = ROOT / "benchmarks" / "workspaces" / "sp1-official" / "script"
        path = self.module.resolve_artifact_path(
            "benchmarks/workspaces/sp1-official/out/single_circuit_prove/proof.bin",
            workdir=workdir,
            from_config=True,
        )
        self.assertEqual(
            path,
            ROOT / "benchmarks" / "workspaces" / "sp1-official" / "out" / "single_circuit_prove" / "proof.bin",
        )


class CompetitiveHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("competitive_harness")

    def test_run_zkf_benchmark_honors_explicit_requested_backend(self):
        capabilities = [
            {
                "backend": "plonky3",
                "production_ready": False,
                "implementation_type": "native",
            }
        ]
        report = {
            "results": [
                {
                    "backend": "plonky3",
                    "case_name": "tiny",
                    "field": "goldilocks",
                    "prove_ms_mean": 1.25,
                    "status": {"kind": "ok"},
                }
            ]
        }
        with tempfile.TemporaryDirectory(prefix="zkf-harness-test-") as tempdir:
            workdir = Path(tempdir)
            with patch.object(
                self.module,
                "run",
                return_value=subprocess.CompletedProcess(["zkf"], 0, "", ""),
            ), patch.object(self.module, "read_json", return_value=report):
                result = self.module.run_zkf_benchmark(
                    ["zkf-cli"],
                    capabilities,
                    1,
                    workdir,
                    ["plonky3"],
                )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["requested_backends"], ["plonky3"])
        self.assertEqual(result["forced_requested_backends"], ["plonky3"])
        self.assertEqual(result["selection_mode"], "requested-explicit")
        self.assertEqual(result["fastest_result"]["backend"], "plonky3")

    def test_summarize_report_tracks_gate_fields(self):
        summary = self.module.summarize_report(
            {
                "benchmark": {"status": "ok", "selection_mode": "production-ready"},
                "wrap": {"status": "ok"},
            },
            [
                {
                    "id": "tool-a",
                    "scenarios": [
                        {"id": "single_circuit_prove", "status": "ok"},
                        {"id": "developer_workload", "status": "ok"},
                        {"id": "recursive_workflow", "status": "ok"},
                    ],
                }
            ],
            {
                "summary": {"required_toolchains_ready": True},
                "tools": [{"tool": "tool-a", "ready": True}],
            },
            ["single_circuit_prove", "developer_workload", "recursive_workflow"],
        )
        self.assertTrue(summary["required_toolchains_ready"])
        self.assertTrue(summary["mixed_corpus_complete"])
        self.assertTrue(summary["external_evidence_complete"])
        self.assertTrue(summary["competition_gate_passed"])

    def test_execute_runner_reads_repo_runner_json_contract(self):
        with tempfile.TemporaryDirectory(prefix="zkf-runner-test-") as tempdir:
            tempdir_path = Path(tempdir)
            runner = tempdir_path / "runner.sh"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "out=\"\"\n"
                "while [[ $# -gt 0 ]]; do\n"
                "  case \"$1\" in\n"
                "    --out) out=\"$2\"; shift 2 ;;\n"
                "    --lane) shift 2 ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                "python3 - <<'PY' \"$out\"\n"
                "import json, sys\n"
                "from pathlib import Path\n"
                "path = Path(sys.argv[1])\n"
                "path.parent.mkdir(parents=True, exist_ok=True)\n"
                "path.write_text(json.dumps({\n"
                "  'schema': 'zkf-competition-scenario-v1',\n"
                "  'status': 'ok',\n"
                "  'elapsed_ms': 12.5,\n"
                "  'tool_version': 'demo 1.0',\n"
                "  'proof_path': '/tmp/proof.json',\n"
                "  'verify_status': 'passed',\n"
                "  'failure_reason': None,\n"
                "  'operator_action': None,\n"
                "  'lane': 'linux'\n"
                "}))\n"
                "PY\n"
            )
            runner.chmod(0o755)
            result = self.module.execute_runner(
                runner,
                tool="snarkjs",
                scenario="single_circuit_prove",
                lane="linux",
                workdir=tempdir_path,
                toolchain_entries=[],
            )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["verify_status"], "passed")
        self.assertEqual(result["runner_schema"], "zkf-competition-scenario-v1")

    def test_collect_ne_advisory_uses_runtime_policy_command_and_marks_available(self):
        policy_report = {
            "recommend_metal_first": True,
            "backends": ["plonky3", "halo2"],
            "recommended_parallel_jobs": 2,
            "model": None,
        }
        with patch.object(
            self.module,
            "run",
            return_value=subprocess.CompletedProcess(
                ["zkf-cli"],
                0,
                json.dumps(policy_report),
                "",
            ),
        ):
            advisory = self.module.collect_ne_advisory(
                ["zkf-cli"],
                lane="apple-silicon",
                benchmark_backends=["plonky3", "halo2"],
            )
        self.assertTrue(advisory["available"])
        self.assertEqual(advisory["policy_source"], "runtime-policy-heuristic")
        self.assertIn("--requested-jobs", advisory["command"])
        self.assertIn("--total-jobs", advisory["command"])
        self.assertEqual(advisory["recommended_job_order"], ["zkf-self-check", "competitors"])

    def test_collect_ne_advisory_falls_back_to_heuristic_only_on_runtime_failure(self):
        with patch.object(
            self.module,
            "run",
            return_value=subprocess.CompletedProcess(
                ["zkf-cli"],
                2,
                "",
                "runtime policy failed",
            ),
        ):
            advisory = self.module.collect_ne_advisory(
                ["zkf-cli"],
                lane="apple-silicon",
                benchmark_backends=["plonky3"],
            )
        self.assertTrue(advisory["available"])
        self.assertEqual(advisory["policy_source"], "heuristic-only")
        self.assertEqual(advisory["reason"], "runtime-policy-command-failed")
        self.assertEqual(advisory["recommended_parallelism"], 1)

    def test_repo_scenario_config_is_used_without_env_override(self):
        runner_module = load_module("../benchmarks/run_competition_scenario")
        with tempfile.TemporaryDirectory(prefix="zkf-scenario-config-") as tempdir:
            tempdir_path = Path(tempdir)
            scenario_dir = ROOT / "benchmarks" / "scenarios" / "demo-tool"
            scenario_dir.mkdir(parents=True, exist_ok=True)
            config_path = scenario_dir / "single_circuit_prove.json"
            report_path = tempdir_path / "report.json"
            proof_path = tempdir_path / "proof.json"
            config_path.write_text(
                json.dumps(
                    {
                        "schema": "zkf-competition-scenario-config-v1",
                        "workdir": tempdir,
                        "command": [
                            "python3",
                            "-c",
                            (
                                "from pathlib import Path; "
                                f"Path({str(proof_path)!r}).write_text('proof')"
                            ),
                        ],
                        "verify_command": ["python3", "-c", "print('verified')"],
                        "proof_path": str(proof_path),
                    }
                )
            )
            try:
                with patch.object(
                    sys,
                    "argv",
                    [
                        "run_competition_scenario.py",
                        "--tool",
                        "demo-tool",
                        "--scenario",
                        "single_circuit_prove",
                        "--out",
                        str(report_path),
                        "--lane",
                        "linux",
                    ],
                ):
                    rc = runner_module.main()
                self.assertEqual(rc, 0)
                payload = json.loads(report_path.read_text())
                self.assertEqual(payload["status"], "ok")
                self.assertEqual(payload["verify_status"], "passed")
            finally:
                config_path.unlink(missing_ok=True)


class FinalizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("finalize_no_dashboard_release")

    def test_validate_bundle_competitive_report_requires_ok_benchmark_wrap_and_gate(self):
        with tempfile.TemporaryDirectory(prefix="zkf-finalizer-gate-") as tempdir:
            bundle_dir = Path(tempdir)
            assistant_dir = bundle_dir / "assistant"
            assistant_dir.mkdir(parents=True, exist_ok=True)
            (assistant_dir / "competition_gate.json").write_text(
                json.dumps(
                    {
                        "schema": "zkf-competition-gate-v1",
                        "competition_gate_passed": True,
                        "required_toolchains_ready": True,
                    }
                )
            )
            (assistant_dir / "toolchain_manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "zkf-competition-toolchain-manifest-v1",
                        "summary": {"required_toolchains_ready": True},
                    }
                )
            )
            payload = {
                "summary": {
                    "zkf_benchmark_status": "ok",
                    "zkf_wrap_status": "ok",
                }
            }
            summary, gate, toolchain = self.module.validate_bundle_competitive_report(
                payload,
                bundle_dir=bundle_dir,
            )
        self.assertEqual(summary["zkf_benchmark_status"], "ok")
        self.assertTrue(gate["competition_gate_passed"])
        self.assertTrue(toolchain["summary"]["required_toolchains_ready"])

    def test_validate_workspace_validation_report_requires_passed_summary(self):
        with tempfile.TemporaryDirectory(prefix="zkf-finalizer-validation-") as tempdir:
            report_path = Path(tempdir) / "workspace_validation.json"
            report_path.write_text(
                json.dumps(
                    {
                        "schema": "zkf-workspace-validation-v1",
                        "summary": {"passed": True},
                    }
                )
            )
            payload = self.module.validate_workspace_validation_report(report_path)
        self.assertTrue(payload["summary"]["passed"])

    def test_validate_post_soak_checks_report_requires_passed_summary(self):
        with tempfile.TemporaryDirectory(prefix="zkf-finalizer-post-soak-") as tempdir:
            report_path = Path(tempdir) / "post_soak_release_checks.json"
            report_path.write_text(
                json.dumps(
                    {
                        "schema": "zkf-post-soak-release-checks-v1",
                        "summary": {"passed": True},
                    }
                )
            )
            payload = self.module.validate_post_soak_checks_report(report_path)
        self.assertTrue(payload["summary"]["passed"])

    def test_wait_for_soak_report_rejects_stale_running_progress(self):
        with tempfile.TemporaryDirectory(prefix="zkf-finalizer-stale-soak-") as tempdir:
            report_path = Path(tempdir) / "strict-certification.json"
            progress_path = Path(tempdir) / "soak-progress.json"
            progress_path.write_text(
                json.dumps(
                    {
                        "phase": "running",
                        "updated_at_unix_ms": int((time.time() - 3600) * 1000),
                    }
                )
            )

            with self.assertRaisesRegex(RuntimeError, "stale"):
                self.module.wait_for_soak_report(
                    report_path,
                    progress_path,
                    poll_seconds=0,
                    stale_after_seconds=60,
                )

    def test_main_fails_fast_when_desktop_binary_is_missing(self):
        with tempfile.TemporaryDirectory(prefix="zkf-finalizer-missing-desktop-") as tempdir:
            root = Path(tempdir)
            bundle_dir = root / "bundle"
            source_binary = root / "source-zkf-cli"
            gate_report = root / "strict-gate.json"
            soak_report = root / "strict-soak.json"
            soak_progress = root / "soak-progress.json"
            installed_report = root / "installed.json"
            workspace_validation = root / "workspace_validation.json"
            post_soak_checks = root / "post_soak_release_checks.json"

            source_binary.write_text("same-binary")
            gate_report.write_text(json.dumps({"summary": {"final_pass": True}}))
            soak_report.write_text(json.dumps({"summary": {"final_pass": True}}))
            soak_progress.write_text(json.dumps({"phase": "completed"}))
            installed_report.write_text(json.dumps({"final_pass": True}))
            workspace_validation.write_text(
                json.dumps(
                    {
                        "schema": "zkf-workspace-validation-v1",
                        "summary": {"passed": True, "blocking_reasons": []},
                    }
                )
            )
            post_soak_checks.write_text(
                json.dumps(
                    {
                        "schema": "zkf-post-soak-release-checks-v1",
                        "summary": {"passed": True, "blocking_reasons": []},
                    }
                )
            )

            argv = [
                "finalize_no_dashboard_release.py",
                "--bundle-dir",
                str(bundle_dir),
                "--source-binary",
                str(source_binary),
                "--desktop-binary",
                str(root / "missing-desktop-zkf-cli"),
                "--gate-report",
                str(gate_report),
                "--soak-report",
                str(soak_report),
                "--soak-progress",
                str(soak_progress),
                "--installed-report",
                str(installed_report),
                "--workspace-validation-report",
                str(workspace_validation),
                "--post-soak-checks-report",
                str(post_soak_checks),
            ]

            with patch.object(sys, "argv", argv), patch.object(
                self.module,
                "wait_for_soak_report",
            ) as wait_for_soak_report:
                with self.assertRaisesRegex(RuntimeError, "desktop binary is missing"):
                    self.module.main()
                wait_for_soak_report.assert_not_called()

    def test_detect_release_benchmark_backends_prefers_production_ready(self):
        payload = [
            {
                "backend": "plonky3",
                "production_ready": True,
                "runtime_ready": True,
                "compiled_in": True,
                "implementation_type": "native",
            },
            {
                "backend": "halo2",
                "production_ready": False,
                "runtime_ready": True,
                "compiled_in": True,
                "implementation_type": "native",
            },
        ]
        with patch.object(self.module, "run_json", return_value=(0, payload)), patch.object(
            self.module, "probe_release_benchmark_backend"
        ) as probe:
            backends, selection = self.module.detect_release_benchmark_backends(Path("/tmp/zkf-cli"))
        self.assertEqual(backends, ["plonky3"])
        self.assertEqual(selection, "production-ready")
        probe.assert_not_called()

    def test_detect_release_benchmark_backends_probes_when_matrix_is_silent(self):
        with patch.object(self.module, "run_json", return_value=(0, [])), patch.object(
            self.module,
            "probe_release_benchmark_backend",
            side_effect=lambda _binary, backend: backend == "plonky3",
        ):
            backends, selection = self.module.detect_release_benchmark_backends(Path("/tmp/zkf-cli"))
        self.assertEqual(backends, ["plonky3"])
        self.assertEqual(selection, "probed-explicit")

    def test_main_writes_release_status_and_handoff_with_packaged_evidence(self):
        with tempfile.TemporaryDirectory(prefix="zkf-finalizer-test-") as tempdir:
            root = Path(tempdir)
            bundle_dir = root / "bundle"
            source_binary = root / "source-zkf-cli"
            desktop_binary = root / "desktop-zkf-cli"
            gate_report = root / "strict-gate.json"
            soak_report = root / "strict-soak.json"
            soak_progress = root / "soak-progress.json"
            installed_report = root / "installed.json"
            assistant_bundle = root / "knowledge_bundle.json"
            workspace_validation = root / "workspace_validation.json"
            post_soak_checks = root / "post_soak_release_checks.json"

            for path in (source_binary, desktop_binary):
                path.write_text("same-binary")
            gate_report.write_text(json.dumps({"summary": {"final_pass": True}}))
            soak_report.write_text(json.dumps({"summary": {"final_pass": True}}))
            soak_progress.write_text(json.dumps({"phase": "completed"}))
            installed_report.write_text(json.dumps({"final_pass": True}))
            assistant_bundle.write_text(json.dumps({"schema": "legacy"}))
            workspace_validation.write_text(
                json.dumps(
                    {
                        "schema": "zkf-workspace-validation-v1",
                        "summary": {"passed": True, "blocking_reasons": []},
                    }
                )
            )
            post_soak_checks.write_text(
                json.dumps(
                    {
                        "schema": "zkf-post-soak-release-checks-v1",
                        "summary": {"passed": True, "blocking_reasons": []},
                    }
                )
            )

            tool_source = root / "tool.py"
            fixture_source = root / "proof.json"
            benchmark_file = root / "benchmarks" / "manifest.json"
            benchmark_file.parent.mkdir(parents=True, exist_ok=True)
            snapshot_source = ROOT / "README.md"
            tool_source.write_text("#!/usr/bin/env python3\n")
            fixture_source.write_text("{}")
            benchmark_file.write_text("{}")

            def fake_build_bundle_assistant(bundle_path: Path):
                assistant_dir = bundle_path / "assistant"
                assistant_dir.mkdir(parents=True, exist_ok=True)
                bundle_path_json = assistant_dir / "knowledge_bundle.json"
                context_path = assistant_dir / "system_context.md"
                bundle_path_json.write_text(json.dumps({"schema": "zkf-assistant-bundle-v2"}))
                context_path.write_text("# context\n")
                return {
                    "bundle": str(bundle_path_json),
                    "context": str(context_path),
                    "schema": "zkf-assistant-bundle-v2",
                }

            def fake_build_bundle_competitive_report(
                bundle_path: Path,
                *,
                config_path,
                iterations,
                benchmark_backends,
            ):
                self.assertIsNone(config_path)
                self.assertEqual(iterations, 1)
                self.assertEqual(benchmark_backends, ["plonky3"])
                assistant_dir = bundle_path / "assistant"
                assistant_dir.mkdir(parents=True, exist_ok=True)
                report_path = assistant_dir / "competitive_harness.json"
                gate_path = assistant_dir / "competition_gate.json"
                toolchain_manifest_path = assistant_dir / "toolchain_manifest.json"
                report_path.write_text(
                    json.dumps(
                        {
                            "summary": {
                                "zkf_benchmark_status": "ok",
                                "zkf_wrap_status": "ok",
                                "zkf_self_check_passed": True,
                                "competitor_toolchains_ready": 10,
                                "external_evidence_complete": True,
                            }
                        }
                    )
                )
                gate_path.write_text(
                    json.dumps(
                        {
                            "schema": "zkf-competition-gate-v1",
                            "competition_gate_passed": True,
                            "required_toolchains_ready": True,
                            "mixed_corpus_complete": True,
                            "external_evidence_complete": True,
                        }
                    )
                )
                toolchain_manifest_path.write_text(
                    json.dumps(
                        {
                            "schema": "zkf-competition-toolchain-manifest-v1",
                            "summary": {"required_toolchains_ready": True},
                        }
                    )
                )
                return {
                    "report": str(report_path),
                    "gate": str(gate_path),
                    "toolchain_manifest": str(toolchain_manifest_path),
                    "schema": "zkf-competitive-harness-v2",
                }

            argv = [
                "finalize_no_dashboard_release.py",
                "--bundle-dir",
                str(bundle_dir),
                "--source-binary",
                str(source_binary),
                "--desktop-binary",
                str(desktop_binary),
                "--gate-report",
                str(gate_report),
                "--soak-report",
                str(soak_report),
                "--soak-progress",
                str(soak_progress),
                "--installed-report",
                str(installed_report),
                "--assistant-bundle",
                str(assistant_bundle),
                "--workspace-validation-report",
                str(workspace_validation),
                "--post-soak-checks-report",
                str(post_soak_checks),
                "--competitive-iterations",
                "1",
            ]

            with patch.object(
                self.module,
                "wait_for_soak_report",
                return_value={"summary": {"final_pass": True}},
            ), patch.object(
                self.module,
                "run_json",
                return_value=(
                    0,
                    {
                        "production_ready": True,
                        "strict_certification_present": True,
                        "strict_certification_match": True,
                    },
                ),
            ), patch.object(
                self.module,
                "detect_release_benchmark_backends",
                return_value=(["plonky3"], "probed-explicit"),
            ), patch.object(
                self.module,
                "build_bundle_assistant",
                side_effect=fake_build_bundle_assistant,
            ), patch.object(
                self.module,
                "build_bundle_competitive_report",
                side_effect=fake_build_bundle_competitive_report,
            ), patch.object(
                self.module,
                "RELEASE_TOOL_SOURCES",
                {"tool.py": tool_source},
            ), patch.object(
                self.module,
                "RELEASE_FIXTURE_ASSETS",
                {"proof.json": fixture_source},
            ), patch.object(
                self.module,
                "RELEASE_BENCHMARK_SNAPSHOT",
                benchmark_file.parent,
            ), patch.object(
                self.module,
                "RELEASE_SOURCE_SNAPSHOT",
                [snapshot_source],
            ), patch.object(
                self.module,
                "archive_bundle",
                return_value=root / "bundle.tar.gz",
            ), patch.object(sys, "argv", argv):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    exit_code = self.module.main()
                self.assertEqual(exit_code, 0)
                release_status = json.loads((bundle_dir / "RELEASE_STATUS.json").read_text())
                checksum_manifest = json.loads((bundle_dir / "SHA256SUMS.json").read_text())
                self.assertEqual(release_status["competitive_benchmark_backends"], ["plonky3"])
                self.assertEqual(
                    release_status["competitive_benchmark_backend_selection"],
                    "probed-explicit",
                )
                self.assertEqual(
                    release_status["assistant_bundle_schema"],
                    "zkf-assistant-bundle-v2",
                )
                self.assertEqual(
                    release_status["competitive_report_schema"],
                    "zkf-competitive-harness-v2",
                )
                self.assertEqual(
                    release_status["competition_gate_schema"],
                    "zkf-competition-gate-v1",
                )
                self.assertEqual(
                    release_status["toolchain_manifest_schema"],
                    "zkf-competition-toolchain-manifest-v1",
                )
                self.assertEqual(
                    release_status["workspace_validation_schema"],
                    "zkf-workspace-validation-v1",
                )
                self.assertEqual(
                    release_status["post_soak_checks_schema"],
                    "zkf-post-soak-release-checks-v1",
                )
                self.assertTrue(
                    (bundle_dir / "assistant" / "knowledge_bundle.prebuilt.json").exists()
                )
                self.assertTrue((bundle_dir / "assistant" / "workspace_validation.json").exists())
                self.assertTrue((bundle_dir / "assistant" / "post_soak_release_checks.json").exists())
                self.assertTrue((bundle_dir / "certification" / "soak-progress.json").exists())
                self.assertTrue((bundle_dir / "docs" / "M4_MAX_OPERATOR_HANDOFF.md").exists())
                self.assertIn("RELEASE_STATUS.json", checksum_manifest)
                self.assertIn("assistant/knowledge_bundle.json", checksum_manifest)
                self.assertIn("assistant/workspace_validation.json", checksum_manifest)
                self.assertIn("assistant/post_soak_release_checks.json", checksum_manifest)
                self.assertNotIn("SHA256SUMS.json", checksum_manifest)
                stdout_payload = json.loads(stdout.getvalue())
                self.assertEqual(stdout_payload["bundle"], str(bundle_dir))
                self.assertTrue(stdout_payload["archive"].endswith("bundle.tar.gz"))
                handoff = (bundle_dir / "docs" / "M4_MAX_OPERATOR_HANDOFF.md").read_text()
                self.assertIn("probed-explicit", handoff)
                self.assertIn("competition_gate.json", handoff)
                self.assertIn("workspace_validation.json", handoff)
                self.assertIn("post_soak_release_checks.json", handoff)


class AssistantBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("build_zfk_assistant_bundle")

    def test_collect_certification_state_uses_supplied_paths(self):
        with tempfile.TemporaryDirectory(prefix="zkf-assistant-cert-") as tempdir:
            tempdir_path = Path(tempdir)
            gate = tempdir_path / "gate.json"
            soak = tempdir_path / "soak.json"
            progress = tempdir_path / "progress.json"
            gate.write_text(json.dumps({"summary": {"final_pass": True}}))
            soak.write_text(json.dumps({"summary": {"final_pass": False}}))
            progress.write_text(json.dumps({"phase": "running"}))
            with patch.object(
                self.module,
                "run",
                return_value=subprocess.CompletedProcess(["ps"], 0, "", ""),
            ):
                state = self.module.collect_certification_state(
                    gate_report_path=gate,
                    soak_progress_path=progress,
                    soak_report_path=soak,
                )
        self.assertEqual(state["gate_report"]["path"], str(gate))
        self.assertTrue(state["gate_report"]["final_pass"])
        self.assertEqual(state["soak_report"]["path"], str(soak))
        self.assertFalse(state["soak_report"]["final_pass"])
        self.assertFalse(state["soak_running"])


class ValidateWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("validate_workspace")

    def test_validation_workspace_command_excludes_benches(self):
        commands = self.module.validation_commands()
        workspace_cmd = next(
            entry["cmd"] for entry in commands if entry["label"] == "cargo-test-workspace"
        )
        self.assertIn("--lib", workspace_cmd)
        self.assertIn("--bins", workspace_cmd)
        self.assertIn("--tests", workspace_cmd)
        self.assertNotIn("--all-targets", workspace_cmd)

    def test_validation_commands_include_python_build_and_import_on_macos(self):
        with patch.object(self.module.sys, "platform", "darwin"):
            commands = self.module.validation_commands()
        labels = [entry["label"] for entry in commands]
        self.assertIn("cargo-test-zkf-backends-recursive-hardening", labels)
        self.assertIn("cargo-test-zkf-metal-sha256", labels)
        self.assertIn("cargo-test-zkf-metal-keccak256", labels)
        self.assertIn("cargo-build-zkf-python", labels)
        self.assertIn("python-import-zkf", labels)

    def test_validation_commands_skip_python_binding_checks_off_macos(self):
        with patch.object(self.module.sys, "platform", "linux"):
            commands = self.module.validation_commands()
        labels = [entry["label"] for entry in commands]
        self.assertIn("cargo-test-zkf-backends-recursive-hardening", labels)
        self.assertNotIn("cargo-test-zkf-metal-sha256", labels)
        self.assertNotIn("cargo-test-zkf-metal-keccak256", labels)
        self.assertNotIn("cargo-build-zkf-python", labels)
        self.assertNotIn("python-import-zkf", labels)


class NeuralControlPlaneToolingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus_module = load_module("build_control_plane_corpus")
        cls.post_soak_module = load_module("run_post_soak_release_checks")

    @staticmethod
    def make_record(
        idx: int,
        *,
        job_kind: str,
        objective: str,
        backend: str,
        field: str,
        degraded: bool,
        fixture: bool,
    ) -> dict:
        source_path = (
            f"/repo/zkf-runtime/tests/fixtures/neural_engine/record-{idx}.json"
            if fixture
            else f"/tmp/live-telemetry-{idx}.json"
        )
        record = {
            "_source_path": source_path,
            "circuit_features": {
                "constraint_count": 1024 + idx,
                "signal_count": 256 + (idx % 32),
                "witness_size": 320 + (idx % 64),
                "max_constraint_degree": 2,
                "blackbox_op_distribution": {"sha256": 2, "poseidon2": 1},
            },
            "control_plane": {
                "decision": {
                    "dispatch_plan": {"candidate": "balanced"},
                    "features": {
                        "objective": objective,
                        "hardware_profile": "apple-silicon-m4-max-48gb",
                        "requested_jobs": 1,
                        "total_jobs": 2,
                        "ram_utilization": 0.3,
                        "memory_pressure_ratio": 0.3 if degraded else 0.08,
                        "thermal_pressure": 0.24 if degraded else 0.05,
                        "cpu_speed_limit": 0.93 if degraded else 1.0,
                        "unified_memory": 1.0,
                        "stage_node_counts": {"ntt": 2, "msm": 1, "sha256-batch": 1},
                    },
                }
            },
            "dispatch_config": {
                "dispatch_candidate": "balanced",
                "batch_sizes": {"ntt": 2, "msm": 1, "sha256-batch": 1},
            },
            "hardware_state": {
                "metal_available": True,
                "memory_pressure_bytes": 13_000_000_000 if degraded else 5_000_000_000,
                "thermal_pressure": 0.24 if degraded else 0.05,
                "cpu_speed_limit": 0.93 if degraded else 1.0,
            },
            "metadata": {
                "job_kind": job_kind,
                "backend_used": backend,
                "field_used": field,
                "optimization_objective": objective,
                "proof_size_bytes": 512 + idx,
            },
            "outcome": {"total_proving_time_ms": 200.0 + idx},
        }
        if fixture:
            record["metadata"]["fixture_scenario_id"] = f"scenario-{idx}"
        return record

    def test_build_control_plane_corpus_production_profile_rejects_sparse_fixture_corpus(self):
        with tempfile.TemporaryDirectory(prefix="zkf-corpus-sparse-") as tempdir:
            out_path = Path(tempdir) / "corpus.jsonl"
            summary_path = Path(tempdir) / "summary.json"
            records = [
                self.make_record(
                    idx=idx,
                    job_kind="prove",
                    objective="fastest-prove",
                    backend="arkworks-groth16",
                    field="bn254",
                    degraded=False,
                    fixture=True,
                )
                for idx in range(6)
            ]
            _, summary = self.corpus_module.write_corpus(
                records=records,
                out_path=out_path,
                summary_out=summary_path,
                profile="production",
                validation=self.corpus_module.PRODUCTION_REQUIREMENTS,
            )
        self.assertFalse(summary["validation"]["passed"])
        self.assertTrue(any("total_records" in reason for reason in summary["validation"]["reasons"]))
        self.assertTrue(any("live_records" in reason for reason in summary["validation"]["reasons"]))

    def test_build_control_plane_corpus_production_profile_accepts_broad_live_corpus(self):
        with tempfile.TemporaryDirectory(prefix="zkf-corpus-prod-") as tempdir:
            out_path = Path(tempdir) / "corpus.jsonl"
            summary_path = Path(tempdir) / "summary.json"
            backends = [
                "arkworks-groth16",
                "halo2",
                "plonky3",
                "nova",
                "hypernova",
                "sp1",
            ]
            fields = ["bn254", "goldilocks", "pasta-fp"]
            objectives = ["fastest-prove", "smallest-proof", "no-trusted-setup"]
            job_kinds = ["prove", "fold", "wrap"]
            records = []
            for idx in range(500):
                records.append(
                    self.make_record(
                        idx=idx,
                        job_kind=job_kinds[idx % len(job_kinds)],
                        objective=objectives[idx % len(objectives)],
                        backend=backends[idx % len(backends)],
                        field=fields[idx % len(fields)],
                        degraded=(idx % 5 == 0),
                        fixture=False,
                    )
                )
            _, summary = self.corpus_module.write_corpus(
                records=records,
                out_path=out_path,
                summary_out=summary_path,
                profile="production",
                validation=self.corpus_module.PRODUCTION_REQUIREMENTS,
            )
        self.assertTrue(summary["validation"]["passed"])
        self.assertEqual(summary["total_records"], 500)
        self.assertGreaterEqual(summary["live_records"], 500)
        self.assertGreaterEqual(summary["states"]["degraded"], 1)
        self.assertGreaterEqual(len(summary["backends"]), 6)

    def test_post_soak_validation_commands_include_release_critical_steps(self):
        commands = self.post_soak_module.validation_commands(
            source_binary=Path("/tmp/zkf-cli"),
            workspace_validation_report=Path("/tmp/workspace_validation.json"),
        )
        labels = [entry["label"] for entry in commands]
        self.assertIn("strict-metal-doctor", labels)
        self.assertIn("cargo-test-zkf-cli-wrapper-smoke", labels)
        self.assertIn("cargo-test-native-zkvm-sp1", labels)
        self.assertIn("cargo-test-native-zkvm-risc-zero", labels)
        self.assertIn("cargo-test-zkf-cli-featured", labels)
        self.assertIn("python-validate-workspace", labels)
        wrapper_smoke = next(
            entry for entry in commands if entry["label"] == "cargo-test-zkf-cli-wrapper-smoke"
        )
        self.assertIn(
            "cmd::runtime::tests::runtime_execute_native_wrapper_plan_end_to_end",
            wrapper_smoke["cmd"],
        )

    def test_validate_strict_doctor_result_rejects_non_ready_payload(self):
        result = self.post_soak_module.validate_strict_doctor_result(
            {
                "stdout_preview": json.dumps(
                    {
                        "production_ready": False,
                        "strict_certification_present": True,
                        "strict_certification_match": True,
                    }
                ),
                "ok": True,
            }
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["validation_error"], "production_ready=false")

    def test_validate_nonzero_test_execution_rejects_zero_test_result(self):
        result = self.post_soak_module.validate_nonzero_test_execution(
            {
                "stdout_preview": "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored;",
                "ok": True,
            },
            expected_test_count=1,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["validation_error"], "command ran zero tests")

    def test_validate_nonzero_test_execution_requires_expected_test_count(self):
        result = self.post_soak_module.validate_nonzero_test_execution(
            {
                "stdout_preview": "running 2 tests\n\ntest result: ok. 2 passed; 0 failed; 0 ignored;",
                "ok": True,
            },
            expected_test_count=1,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(
            result["validation_error"],
            "command did not run expected test count: 1",
        )

    def test_exclusive_output_lock_rejects_live_owner(self):
        with tempfile.TemporaryDirectory(prefix="zkf-post-soak-lock-") as tempdir:
            out_path = Path(tempdir) / "post_soak_release_checks.certified.json"
            lock_path = self.post_soak_module.lock_path_for(out_path)
            lock_path.write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "out_path": str(out_path),
                        "created_at": "2026-03-17T00:00:00Z",
                    }
                )
            )
            with self.assertRaisesRegex(RuntimeError, "already in use"):
                with self.post_soak_module.exclusive_output_lock(out_path):
                    self.fail("lock acquisition should have failed")

    def test_build_report_reuses_matching_ok_results_and_reruns_changed_commands(self):
        with tempfile.TemporaryDirectory(prefix="zkf-post-soak-reuse-") as tempdir:
            tempdir_path = Path(tempdir)
            prior_report = tempdir_path / "prior.json"
            out_path = tempdir_path / "out.json"
            workspace_validation = tempdir_path / "workspace_validation.json"
            workspace_validation.write_text(
                json.dumps(
                    {
                        "schema": "zkf-workspace-validation-v1",
                        "summary": {"passed": True},
                    }
                )
            )
            prior_report.write_text(
                json.dumps(
                    {
                        "schema": self.post_soak_module.SCHEMA,
                        "commands": [
                            {
                                "label": "strict-metal-doctor",
                                "command": ["/tmp/zkf-cli", "metal-doctor", "--strict", "--json"],
                                "ok": True,
                            },
                            {
                                "label": "cargo-test-zkf-cli-wrapper-smoke",
                                "command": [
                                    "cargo",
                                    "test",
                                    "-p",
                                    "zkf-cli",
                                    "runtime_execute_native_wrapper_plan_end_to_end",
                                ],
                                "ok": True,
                            },
                        ],
                    }
                )
            )
            commands = [
                {
                    "label": "strict-metal-doctor",
                    "cmd": ["/tmp/zkf-cli", "metal-doctor", "--strict", "--json"],
                },
                {
                    "label": "cargo-test-zkf-cli-wrapper-smoke",
                    "cmd": [
                        "cargo",
                        "test",
                        "-p",
                        "zkf-cli",
                        "--bin",
                        "zkf-cli",
                        "--features",
                        "metal-gpu,neural-engine",
                        "cmd::runtime::tests::runtime_execute_native_wrapper_plan_end_to_end",
                        "--",
                        "--ignored",
                        "--exact",
                        "--nocapture",
                    ],
                },
            ]
            observed_calls = []

            def fake_run_command(*, label, cmd, logs_dir, env=None):
                del logs_dir, env
                observed_calls.append((label, cmd))
                return {
                    "label": label,
                    "command": cmd,
                    "ok": True,
                    "returncode": 0,
                    "stdout_preview": "running 1 test",
                    "stderr_preview": None,
                }

            with patch.object(
                self.post_soak_module,
                "validation_commands",
                return_value=commands,
            ), patch.object(self.post_soak_module, "run_command", side_effect=fake_run_command):
                report = self.post_soak_module.build_report(
                    out_path=out_path,
                    source_binary=Path("/tmp/zkf-cli"),
                    workspace_validation_report=workspace_validation,
                    reuse_report=prior_report,
                )

        self.assertTrue(report["summary"]["passed"])
        self.assertEqual(report["summary"]["commands_reused"], 1)
        self.assertEqual(len(observed_calls), 1)
        self.assertEqual(observed_calls[0][0], "cargo-test-zkf-cli-wrapper-smoke")
        strict = next(
            entry for entry in report["commands"] if entry["label"] == "strict-metal-doctor"
        )
        self.assertEqual(strict["reused_from_report"], str(prior_report))


class SystemDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("system_dashboard")

    def test_refresh_assistant_bundle_uses_bundle_local_paths(self):
        with tempfile.TemporaryDirectory(prefix="zkf-dashboard-test-") as tempdir:
            bundle_root = Path(tempdir)
            (bundle_root / "bin").mkdir()
            (bundle_root / "bin" / "zkf-cli").write_text("")
            (bundle_root / "certification").mkdir()
            for name in ("strict-gate.json", "soak-progress.json", "strict-certification.json"):
                (bundle_root / "certification" / name).write_text("{}")
            with patch.object(self.module, "ROOT", bundle_root), patch.object(
                self.module,
                "run",
                return_value=subprocess.CompletedProcess(["python3"], 0, "{}", ""),
            ):
                result = self.module.refresh_assistant_bundle()
        self.assertTrue(result["ok"])
        command = result["command"]
        self.assertIn("--zfk-home", command)
        self.assertIn(str(bundle_root), command)
        self.assertIn(str(bundle_root / "certification" / "strict-gate.json"), command)
        self.assertIn(str(bundle_root / "certification" / "strict-certification.json"), command)


class ProductionSoakAgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("production_soak_agent")

    def test_build_plist_restarts_only_on_crash(self):
        with tempfile.TemporaryDirectory(prefix="zkf-soak-agent-") as tempdir:
            tempdir_path = Path(tempdir)
            plist = self.module.build_plist(
                proof=tempdir_path / "proof.json",
                compiled=tempdir_path / "compiled.json",
                out_dir=tempdir_path / "out",
                json_out=tempdir_path / "out" / "strict-certification.json",
                bin_path=tempdir_path / "zkf-cli",
                parallel_jobs="1",
                hours=12,
                cycles=20,
            )
        self.assertEqual(plist["KeepAlive"], {"Crashed": True})
        self.assertTrue(plist["RunAtLoad"])
        self.assertEqual(
            plist["ProgramArguments"][0],
            str(ROOT / "scripts" / "production_soak.sh"),
        )


class WorkflowContractTests(unittest.TestCase):
    def test_competition_workflow_declares_required_jobs_and_artifacts(self):
        workflow = (ROOT / ".github" / "workflows" / "competition-gate.yml").read_text()
        self.assertIn("competition-linux:", workflow)
        self.assertIn("competition-apple-silicon:", workflow)
        self.assertIn("make competition-gate", workflow)
        self.assertIn("target/competition/competitive_harness.json", workflow)
        self.assertIn("target/competition/competition_gate.json", workflow)
        self.assertIn("target/competition/toolchain_manifest.json", workflow)


if __name__ == "__main__":
    unittest.main()
