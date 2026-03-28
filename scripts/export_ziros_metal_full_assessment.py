#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = Path.home() / "Desktop" / "ZirOS_Metal_Full_Assessment_2026-03-25"
DEFAULT_ZIP = DEFAULT_BUNDLE.with_suffix(".zip")

TARGET_DIRS = [
    "target-codex-build",
    "target-gpu-export",
    "target-local",
    "target-month3-validation",
    "target-test-distributed",
    "target-verification-export",
]

PROOF_AND_ATTESTATION_SCRIPTS = [
    "scripts/proof_audit.py",
    "scripts/verify_gpu_proof_manifest.py",
    "scripts/verify_gpu_bundle_attestation.py",
    "scripts/run_lean_proofs.sh",
    "scripts/run_verus_gpu_checks.sh",
    "scripts/run_kani_gpu_checks.sh",
    "scripts/run_verus_runtime_execution_proofs.sh",
    "scripts/run_verus_buffer_proofs.sh",
    "scripts/run_shader_spirv_verification.sh",
    "scripts/run_formal_suite.sh",
    "scripts/bootstrap_spirv_toolchain.sh",
]

INLINE_TEST_SOURCES = [
    "zkf-metal/src/field_ops.rs",
    "zkf-metal/src/hash/mod.rs",
    "zkf-metal/src/poly.rs",
    "zkf-metal/src/fri.rs",
    "zkf-metal/src/constraint_eval.rs",
    "zkf-metal/src/ntt/p3_adapter.rs",
    "zkf-metal/src/ntt/bn254.rs",
    "zkf-metal/src/poseidon2/mod.rs",
    "zkf-metal/src/merkle.rs",
    "zkf-metal/src/msm/pippenger.rs",
    "zkf-metal/src/msm/pallas_pippenger.rs",
    "zkf-metal/src/msm/vesta_pippenger.rs",
    "zkf-metal/src/launch_contracts.rs",
    "zkf-metal/src/verification_kani.rs",
    "zkf-metal/src/device.rs",
    "zkf-metal/src/pipeline.rs",
    "zkf-metal/src/async_dispatch.rs",
    "zkf-metal/src/batch_prover.rs",
    "zkf-metal/src/verified_artifacts.rs",
    "zkf-runtime/tests/verification_prop.rs",
]


@dataclass
class ManifestRow:
    bundle_path: str
    source_path: str
    category: str
    provenance: str
    production_class: str
    notes: str


@dataclass
class CommandResult:
    index: int
    slug: str
    argv: list[str]
    cwd: str
    returncode: int
    started_at: float
    finished_at: float
    duration_seconds: float
    log_path: str

    def as_json(self) -> dict[str, object]:
        return {
            "index": self.index,
            "slug": self.slug,
            "argv": self.argv,
            "cwd": self.cwd,
            "returncode": self.returncode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "log_path": self.log_path,
        }


class Exporter:
    def __init__(self, bundle_dir: Path) -> None:
        self.bundle_dir = bundle_dir
        self.zip_path = bundle_dir.with_suffix(".zip")
        self.manifest_rows: list[ManifestRow] = []
        self._manifest_seen: set[str] = set()
        self.command_results: list[CommandResult] = []

    def write_partial_command_results(self) -> None:
        path = self.bundle_dir / "generated_session" / "command_results.partial.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps([result.as_json() for result in self.command_results], indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )

    def bundle_rel(self, path: Path) -> str:
        return path.relative_to(self.bundle_dir).as_posix()

    def record(
        self,
        bundle_path: Path,
        source_path: str,
        category: str,
        provenance: str,
        production_class: str,
        notes: str = "",
    ) -> None:
        rel = self.bundle_rel(bundle_path)
        if rel in self._manifest_seen:
            return
        self._manifest_seen.add(rel)
        self.manifest_rows.append(
            ManifestRow(
                bundle_path=rel,
                source_path=source_path,
                category=category,
                provenance=provenance,
                production_class=production_class,
                notes=notes,
            )
        )

    def ensure_clean_bundle(self) -> None:
        if self.bundle_dir.exists():
            shutil.rmtree(self.bundle_dir)
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        if self.zip_path.exists():
            self.zip_path.unlink()

    def copy_file(
        self,
        src: Path,
        dst: Path,
        category: str,
        provenance: str,
        production_class: str,
        notes: str = "",
    ) -> None:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        self.record(dst, str(src), category, provenance, production_class, notes)

    def should_skip_repo_path(self, rel: Path) -> bool:
        if not rel.parts:
            return False
        first = rel.parts[0]
        if first == ".git":
            return True
        if first == ".venv-coreml":
            return True
        if first.startswith(".tmp-fiat-fields"):
            return True
        if first.startswith("target"):
            return True
        return "__pycache__" in rel.parts

    def copy_tree(
        self,
        src_dir: Path,
        dst_dir: Path,
        category: str,
        provenance: str,
        production_class: str,
        notes: str = "",
        skip_repo_filters: bool = False,
    ) -> None:
        for current_root, dirs, files in os.walk(src_dir):
            current_path = Path(current_root)
            rel = current_path.relative_to(src_dir)
            if skip_repo_filters:
                dirs[:] = [
                    d
                    for d in dirs
                    if not self.should_skip_repo_path((rel / d) if rel != Path(".") else Path(d))
                ]
            else:
                dirs[:] = [d for d in dirs if d != "__pycache__"]
            for file_name in files:
                rel_file = rel / file_name if rel != Path(".") else Path(file_name)
                if skip_repo_filters and self.should_skip_repo_path(rel_file):
                    continue
                src_file = current_path / file_name
                dst_file = dst_dir / rel_file
                self.copy_file(
                    src_file,
                    dst_file,
                    category=category,
                    provenance=provenance,
                    production_class=production_class,
                    notes=notes,
                )

    def copy_root_artifacts(self) -> None:
        existing_dir = self.bundle_dir / "existing_artifacts" / "repo_root"
        allowed_suffixes = {".json", ".log", ".sol"}
        for path in sorted(ROOT.iterdir()):
            if path.is_dir():
                continue
            if path.suffix not in allowed_suffixes:
                continue
            self.copy_file(
                path,
                existing_dir / path.name,
                category="existing_artifacts",
                provenance="existing",
                production_class="mixed",
                notes="repo-root proof/log/sol artifact",
            )

    def copy_selected_build_artifacts(self) -> None:
        build_root = self.bundle_dir / "build_artifacts"
        for target_name in TARGET_DIRS:
            target_root = ROOT / target_name
            if not target_root.exists():
                continue
            for out_dir in sorted(target_root.rglob("zkf-metal-*/out")):
                if not out_dir.is_dir():
                    continue
                relative = out_dir.relative_to(target_root)
                self.copy_tree(
                    out_dir,
                    build_root / target_name / relative,
                    category="build_artifacts",
                    provenance="existing",
                    production_class="generated-build-output",
                    notes="selected zkf-metal build out directory",
                )

    def run_command(
        self,
        index: int,
        slug: str,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> CommandResult:
        logs_dir = self.bundle_dir / "generated_session" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = logs_dir / f"{index:02d}-{slug}.log"
        effective_env = os.environ.copy()
        if env:
            effective_env.update(env)
        effective_cwd = cwd or ROOT
        started = time.time()
        with log_path.open("w", encoding="utf-8") as handle:
            handle.write(f"$ {' '.join(argv)}\n")
            handle.write(f"cwd={effective_cwd}\n\n")
            handle.flush()
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=effective_cwd,
                    env=effective_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                assert process.stdout is not None
                for line in process.stdout:
                    handle.write(line)
                    handle.flush()
                returncode = process.wait()
            except OSError as error:
                returncode = 127
                handle.write(f"[spawn-error] {error}\n")
                handle.flush()
            finished = time.time()
            handle.write(
                f"\n[exit] returncode={returncode} duration_seconds={finished - started:.3f}\n"
            )
            handle.flush()
        result = CommandResult(
            index=index,
            slug=slug,
            argv=argv,
            cwd=str(effective_cwd),
            returncode=returncode,
            started_at=started,
            finished_at=finished,
            duration_seconds=finished - started,
            log_path=str(log_path),
        )
        self.command_results.append(result)
        self.record(
            log_path,
            "generated by export_ziros_metal_full_assessment.py",
            category="generated_session",
            provenance="generated-this-session",
            production_class="session-log",
            notes=f"command log for {' '.join(argv)}",
        )
        self.write_partial_command_results()
        return result

    def copy_telemetry_paths_from_runtime_trace(self, trace_path: Path, bundle_name: str) -> None:
        try:
            payload = json.loads(trace_path.read_text(encoding="utf-8"))
        except Exception:
            return
        telemetry_paths = payload.get("telemetry_paths", [])
        if not isinstance(telemetry_paths, list):
            return
        telemetry_root = self.bundle_dir / "generated_session" / "telemetry" / bundle_name
        for item in telemetry_paths:
            if not isinstance(item, str):
                continue
            src = Path(item)
            if not src.is_file():
                continue
            dst = telemetry_root / src.name
            self.copy_file(
                src,
                dst,
                category="generated_session",
                provenance="generated-this-session",
                production_class="telemetry-json",
                notes=f"referenced by runtime trace {trace_path.name}",
            )

    def scan_generated_session(self) -> None:
        generated_root = self.bundle_dir / "generated_session"
        if not generated_root.exists():
            return
        for path in sorted(generated_root.rglob("*")):
            if not path.is_file():
                continue
            if self.bundle_rel(path) in self._manifest_seen:
                continue
            self.record(
                path,
                "generated inside bundle during export commands",
                category="generated_session",
                provenance="generated-this-session",
                production_class="generated-output",
                notes="captured post-command file",
            )

    def write_json(self, path: Path, payload: object, notes: str = "") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.record(
            path,
            "generated by export_ziros_metal_full_assessment.py",
            category="generated_session",
            provenance="generated-this-session",
            production_class="generated-json",
            notes=notes,
        )

    def write_text(self, path: Path, content: str, category: str, notes: str = "") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self.record(
            path,
            "generated by export_ziros_metal_full_assessment.py",
            category=category,
            provenance="generated-this-session",
            production_class="generated-doc",
            notes=notes,
        )

    def command_result(self, slug: str) -> CommandResult | None:
        for result in self.command_results:
            if result.slug == slug:
                return result
        return None

    def build_start_here(self) -> str:
        bundle = self.bundle_dir
        best_gpu = bundle / "existing_artifacts" / "my_circuit" / "proof_plonky3.json"
        most_complete = bundle / "existing_artifacts" / "zkf_test_suite_full"
        satellite_trace = (
            bundle
            / "generated_session"
            / "private_satellite_bundle"
            / "private_satellite.runtime_trace.json"
        )
        nbody_trace = (
            bundle
            / "generated_session"
            / "private_nbody_bundle"
            / "private_nbody.runtime_trace.json"
        )
        benchmark_log = bundle / "generated_session" / "logs" / "12-metal_gpu_benchmark.log"
        bench_json = bundle / "tests_and_benchmarks" / "bench.json"
        return "\n".join(
            [
                "ZirOS Metal Full Assessment Export",
                "",
                f"This package lives at: {bundle}",
                f"Zip archive: {self.zip_path}",
                "",
                "What this package is:",
                "- A maximal Metal/GPU assessment handoff for ZirOS/ZKF.",
                "- It includes source, shaders, host runtime wiring, proof surfaces, manifests, build outputs, tests, benchmarks, existing artifacts, and fresh session-generated logs and showcase bundles.",
                "",
                "What is production:",
                f"- Production shader inventory is the set compiled by {bundle / 'repo_snapshot' / ROOT.name / 'zkf-metal' / 'build.rs'}.",
                "- Production runtime dispatch and fail-closed behavior are implemented in the copied runtime and metal host files under repo_snapshot/ and proofs_and_attestation/.",
                "",
                "What is experimental or unshipped:",
                f"- {bundle / 'repo_snapshot' / ROOT.name / 'zkf-metal' / 'src' / 'shaders' / 'msm_sort.metal'} is the clearest unshipped shader candidate.",
                "- SPIR-V mirror kernels and benchmark/example-only surfaces are included for assessment but should not be read as verified-pinned production runtime coverage.",
                "",
                "Best command to reproduce fresh evidence in this package:",
                f"- See {bundle / 'generated_session' / 'logs'} for the exact commands and outputs.",
                "- Strongest end-to-end bundle commands are the private satellite and private n-body showcase example runs.",
                "",
                "Best file proving GPU execution most directly:",
                f"- {best_gpu}",
                "- It is the strongest checked-in GPU-positive artifact and reports metal_gpu_busy_ratio=1 with no CPU fallback for the required stages.",
                "",
                "Most complete existing artifact folder:",
                f"- {most_complete}",
                "",
                "Fresh runtime trace files generated in this session:",
                f"- {satellite_trace}",
                f"- {nbody_trace}",
                "",
                "Fresh benchmark / validation logs generated in this session:",
                f"- {benchmark_log}",
                f"- {bench_json}",
                "",
                "Critical honesty notes:",
                "- VerifiedPinned runtime coverage is narrower than the broader code/proof inventory.",
                "- batch_field_ops.metal, poly_ops.metal, fri.metal, and constraint_eval.metal are compiled production code but not covered by the current four GPU manifests / shipped attestation set.",
                "- CodegenSoundness.lean is weaker than some ledger prose; exact digest equality is enforced in Rust runtime attestation.",
                "- There was no checked-in live runtime_trace.json in the repo snapshot; runtime traces in this package were generated during this session.",
                "",
                "Primary guidance for the reviewer:",
                "- Read ANSWERS.md first.",
                "- Use MANIFEST.csv to trace every copied/generated file back to its source and classification.",
                "- Use generated_session/logs/ to review failures and successes verbatim.",
            ]
        ) + "\n"

    def build_answers(self) -> str:
        bundle = self.bundle_dir
        root_snapshot = bundle / "repo_snapshot" / ROOT.name
        return "\n".join(
            [
                "# Metal Assessment Answers",
                "",
                "## Production Shaders",
                f"- Production shaders are the files compiled by {root_snapshot / 'zkf-metal' / 'build.rs'}.",
                f"- Main library inputs live under {root_snapshot / 'zkf-metal' / 'src' / 'shaders'} and include the field, NTT, Poseidon2, hash, FRI, poly, and constraint-eval sources selected by build.rs.",
                "",
                "## Experimental Or Unshipped",
                f"- {root_snapshot / 'zkf-metal' / 'src' / 'shaders' / 'msm_sort.metal'} is included for review but is not selected by build.rs and has no confirmed production dispatch path.",
                f"- {root_snapshot / 'zkf-metal' / 'benches' / 'metal_bench.rs'} and {root_snapshot / 'zkf-metal' / 'examples' / 'bench_naf.rs'} are benchmark/example surfaces, not production runtime surfaces.",
                f"- {bundle / 'proofs_and_attestation' / 'zkf-metal' / 'proofs' / 'spirv'} is a validation mirror lane, not the verified-pinned runtime lane.",
                "",
                "## VerifiedPinned Runtime Lane",
                f"- The strict verified lane is defined by {root_snapshot / 'zkf-runtime' / 'src' / 'metal_dispatch_macos.rs'}.",
                "- It is narrower than the broader manifest and proof inventory.",
                "- Treat BN254 classic MSM, BN254/Goldilocks NTT, strict Poseidon batch, and SHA-256 as the pinned admitted lane for the purposes of an honest assessment.",
                "",
                "## Broader Inventory Not Fully Admitted In VerifiedPinned",
                "- Keccak, BabyBear Poseidon2 and NTT, and Pallas/Vesta MSM have source and proof/manifests present, but they are not all admitted in the current strict runtime whitelist.",
                "- FRI and Merkle have real Metal paths in code and tests, but they are not all part of the pinned verified lane described by the runtime whitelist.",
                "",
                "## Strongest GPU Evidence",
                f"- Strongest checked-in GPU-positive artifact: {bundle / 'existing_artifacts' / 'my_circuit' / 'proof_plonky3.json'}",
                f"- Most complete existing artifact folder: {bundle / 'existing_artifacts' / 'zkf_test_suite_full'}",
                f"- Strongest fresh runtime traces: {bundle / 'generated_session' / 'private_satellite_bundle' / 'private_satellite.runtime_trace.json'} and {bundle / 'generated_session' / 'private_nbody_bundle' / 'private_nbody.runtime_trace.json'}",
                f"- Strongest fresh end-to-end Metal benchmark log: {bundle / 'generated_session' / 'logs' / '12-metal_gpu_benchmark.log'}",
                "",
                "## Fail-Closed Evidence",
                f"- Runtime fail-closed behavior is implemented in {root_snapshot / 'zkf-runtime' / 'src' / 'metal_driver.rs'} and {root_snapshot / 'zkf-runtime' / 'src' / 'metal_dispatch_macos.rs'}.",
                f"- Scheduler handling is in {root_snapshot / 'zkf-runtime' / 'src' / 'scheduler.rs'}.",
                f"- Runtime proof surface is in {bundle / 'proofs_and_attestation' / 'zkf-runtime' / 'proofs' / 'verus' / 'runtime_execution_scheduler_verus.rs'}.",
                "",
                "## Determinism Evidence",
                f"- Determinism-related tests and references are in {bundle / 'tests_and_benchmarks' / 'inline_sources' / 'zkf-metal' / 'src' / 'poseidon2' / 'mod.rs'}, {bundle / 'tests_and_benchmarks' / 'inline_sources' / 'zkf-metal' / 'src' / 'poseidon2' / 'goldilocks.rs'}, and the Metal integration validation test file.",
                "",
                "## CPU Reference Correctness Evidence",
                f"- The strongest parity file is {bundle / 'tests_and_benchmarks' / 'zkf-integration-tests' / 'tests' / 'metal_accelerator_validation.rs'}.",
                "- Additional parity coverage exists in the copied inline NTT, hash, Poseidon2, MSM, and Merkle source files under tests_and_benchmarks/inline_sources/.",
                "",
                "## Attestation Enforcement Evidence",
                f"- Runtime attestation logic is in {root_snapshot / 'zkf-metal' / 'src' / 'device.rs'} and {root_snapshot / 'zkf-metal' / 'src' / 'verified_artifacts.rs'}.",
                f"- Committed attestation manifests are in {bundle / 'proofs_and_attestation' / 'zkf-metal' / 'proofs' / 'manifests'}.",
                f"- Manifest regeneration and attestation gates are logged in {bundle / 'generated_session' / 'logs'}.",
                "",
                "## Unfinished Or Narrower-Than-Claimed Surfaces",
                "- batch_field_ops.metal, poly_ops.metal, fri.metal, and constraint_eval.metal are compiled production sources but not covered by the current four GPU manifests / shipped attestation set.",
                "- CodegenSoundness.lean is weaker than some ledger prose. Exact digest equality is enforced in Rust runtime attestation rather than fully proved in Lean.",
                "- There was no checked-in live runtime_trace.json in the repo snapshot; fresh traces were generated in this export session.",
            ]
        ) + "\n"

    def write_manifest_csv(self) -> None:
        manifest_path = self.bundle_dir / "MANIFEST.csv"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.manifest_rows.sort(key=lambda row: row.bundle_path)
        with manifest_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "bundle_path",
                    "source_path",
                    "category",
                    "provenance",
                    "production_class",
                    "notes",
                ]
            )
            for row in self.manifest_rows:
                writer.writerow(
                    [
                        row.bundle_path,
                        row.source_path,
                        row.category,
                        row.provenance,
                        row.production_class,
                        row.notes,
                    ]
                )
        self.record(
            manifest_path,
            "generated by export_ziros_metal_full_assessment.py",
            category="docs",
            provenance="generated-this-session",
            production_class="generated-doc",
            notes="bundle manifest",
        )

    def zip_bundle(self) -> None:
        archive_base = str(self.zip_path.with_suffix(""))
        made = shutil.make_archive(archive_base, "zip", self.bundle_dir)
        if Path(made) != self.zip_path:
            shutil.move(made, self.zip_path)

    def write_docs(self) -> None:
        self.write_text(
            self.bundle_dir / "START_HERE.txt",
            self.build_start_here(),
            category="docs",
            notes="top-level reviewer guidance",
        )
        self.write_text(
            self.bundle_dir / "ANSWERS.md",
            self.build_answers(),
            category="docs",
            notes="plain-English audit answers",
        )

    def export(self) -> int:
        self.ensure_clean_bundle()

        self.copy_tree(
            ROOT,
            self.bundle_dir / "repo_snapshot" / ROOT.name,
            category="repo_snapshot",
            provenance="existing",
            production_class="mixed",
            notes="full repo snapshot with requested exclusions",
            skip_repo_filters=True,
        )

        self.copy_selected_build_artifacts()

        self.copy_tree(
            ROOT / "zkf-metal" / "proofs",
            self.bundle_dir / "proofs_and_attestation" / "zkf-metal" / "proofs",
            category="proofs_and_attestation",
            provenance="existing",
            production_class="proof-surface",
        )
        self.copy_tree(
            ROOT / "zkf-runtime" / "proofs",
            self.bundle_dir / "proofs_and_attestation" / "zkf-runtime" / "proofs",
            category="proofs_and_attestation",
            provenance="existing",
            production_class="proof-surface",
        )
        for rel in [
            "zkf-ir-spec/verification-ledger.json",
            ".zkf-completion-status.json",
            "support-matrix.json",
            "docs/CANONICAL_TRUTH.md",
        ] + PROOF_AND_ATTESTATION_SCRIPTS:
            src = ROOT / rel
            if src.exists():
                self.copy_file(
                    src,
                    self.bundle_dir / "proofs_and_attestation" / rel,
                    category="proofs_and_attestation",
                    provenance="existing",
                    production_class="proof-attestation-support",
                )

        self.copy_file(
            ROOT / "zkf-integration-tests" / "tests" / "metal_accelerator_validation.rs",
            self.bundle_dir
            / "tests_and_benchmarks"
            / "zkf-integration-tests"
            / "tests"
            / "metal_accelerator_validation.rs",
            category="tests_and_benchmarks",
            provenance="existing",
            production_class="test-source",
        )
        self.copy_file(
            ROOT / "zkf-integration-tests" / "tests" / "metal_gpu_benchmark.rs",
            self.bundle_dir
            / "tests_and_benchmarks"
            / "zkf-integration-tests"
            / "tests"
            / "metal_gpu_benchmark.rs",
            category="tests_and_benchmarks",
            provenance="existing",
            production_class="benchmark-source",
        )
        self.copy_file(
            ROOT / "zkf-integration-tests" / "tests" / "production_benchmark.rs",
            self.bundle_dir
            / "tests_and_benchmarks"
            / "zkf-integration-tests"
            / "tests"
            / "production_benchmark.rs",
            category="tests_and_benchmarks",
            provenance="existing",
            production_class="benchmark-source",
        )
        self.copy_file(
            ROOT / "zkf-metal" / "benches" / "metal_bench.rs",
            self.bundle_dir / "tests_and_benchmarks" / "zkf-metal" / "benches" / "metal_bench.rs",
            category="tests_and_benchmarks",
            provenance="existing",
            production_class="benchmark-source",
        )
        self.copy_file(
            ROOT / "zkf-metal" / "examples" / "bench_naf.rs",
            self.bundle_dir / "tests_and_benchmarks" / "zkf-metal" / "examples" / "bench_naf.rs",
            category="tests_and_benchmarks",
            provenance="existing",
            production_class="benchmark-source",
        )
        self.copy_file(
            ROOT / "bench.json",
            self.bundle_dir / "tests_and_benchmarks" / "bench.json",
            category="tests_and_benchmarks",
            provenance="existing",
            production_class="benchmark-artifact",
        )
        self.copy_tree(
            ROOT / "benchmarks",
            self.bundle_dir / "tests_and_benchmarks" / "benchmarks",
            category="tests_and_benchmarks",
            provenance="existing",
            production_class="benchmark-tree",
        )
        for rel in INLINE_TEST_SOURCES:
            src = ROOT / rel
            if src.exists():
                self.copy_file(
                    src,
                    self.bundle_dir / "tests_and_benchmarks" / "inline_sources" / rel,
                    category="tests_and_benchmarks",
                    provenance="existing",
                    production_class="inline-test-source",
                )

        self.copy_tree(
            ROOT / "zkf_test_suite_full",
            self.bundle_dir / "existing_artifacts" / "zkf_test_suite_full",
            category="existing_artifacts",
            provenance="existing",
            production_class="existing-artifact-tree",
        )
        self.copy_tree(
            ROOT / "my_circuit",
            self.bundle_dir / "existing_artifacts" / "my_circuit",
            category="existing_artifacts",
            provenance="existing",
            production_class="existing-artifact-tree",
        )
        self.copy_root_artifacts()

        self.copy_tree(
            ROOT / "docs",
            self.bundle_dir / "docs" / "repo_docs",
            category="docs",
            provenance="existing",
            production_class="repo-docs",
        )

        command_specs: list[tuple[str, list[str], dict[str, str] | None]] = [
            ("metal-doctor-json", ["cargo", "run", "-p", "zkf-cli", "--", "metal-doctor", "--json"], None),
            ("metal-doctor-strict-json", ["cargo", "run", "-p", "zkf-cli", "--", "metal-doctor", "--strict", "--json"], None),
            (
                "export-gpu-proof-artifacts",
                [
                    "cargo",
                    "run",
                    "-p",
                    "zkf-metal",
                    "--example",
                    "export_gpu_proof_artifacts",
                    "--",
                    "--out-dir",
                    str(self.bundle_dir / "generated_session" / "gpu_manifests"),
                    "--lean-dir",
                    str(self.bundle_dir / "generated_session" / "lean_generated"),
                ],
                None,
            ),
            ("verify-gpu-proof-manifest", ["python3", "scripts/verify_gpu_proof_manifest.py"], None),
            ("verify-gpu-bundle-attestation", ["python3", "scripts/verify_gpu_bundle_attestation.py"], None),
            ("run-lean-proofs", ["./scripts/run_lean_proofs.sh"], None),
            ("run-verus-gpu-checks", ["./scripts/run_verus_gpu_checks.sh"], None),
            ("run-verus-runtime-execution-proofs", ["./scripts/run_verus_runtime_execution_proofs.sh"], None),
            ("run-verus-buffer-proofs", ["./scripts/run_verus_buffer_proofs.sh"], None),
            ("run-kani-gpu-checks", ["./scripts/run_kani_gpu_checks.sh"], None),
            (
                "metal-accelerator-validation",
                [
                    "cargo",
                    "test",
                    "-p",
                    "zkf-integration-tests",
                    "--test",
                    "metal_accelerator_validation",
                    "--features",
                    "metal-gpu",
                    "--",
                    "--nocapture",
                    "--test-threads=1",
                ],
                None,
            ),
            (
                "metal-gpu-benchmark",
                [
                    "cargo",
                    "test",
                    "-p",
                    "zkf-integration-tests",
                    "--test",
                    "metal_gpu_benchmark",
                    "--features",
                    "metal-gpu",
                    "--",
                    "--nocapture",
                    "--test-threads=1",
                ],
                None,
            ),
            ("metal-bench", ["cargo", "bench", "-p", "zkf-metal", "--bench", "metal_bench"], None),
            ("bench-naf", ["cargo", "run", "-p", "zkf-metal", "--example", "bench_naf"], None),
            (
                "private-nbody-bundle",
                [
                    "cargo",
                    "run",
                    "-p",
                    "zkf-lib",
                    "--example",
                    "private_nbody_orbital_showcase",
                    "--",
                    str(self.bundle_dir / "generated_session" / "private_nbody_bundle"),
                ],
                {"ZKF_PRIVATE_NBODY_FULL_AUDIT": "1"},
            ),
            (
                "private-satellite-bundle",
                [
                    "cargo",
                    "run",
                    "-p",
                    "zkf-lib",
                    "--example",
                    "private_satellite_conjunction_showcase",
                    "--",
                    str(self.bundle_dir / "generated_session" / "private_satellite_bundle"),
                ],
                {"ZKF_PRIVATE_SATELLITE_FULL_AUDIT": "1"},
            ),
        ]

        for index, (slug, argv, env) in enumerate(command_specs, start=1):
            self.run_command(index, slug, argv, env=env)

        for trace_path, name in [
            (
                self.bundle_dir
                / "generated_session"
                / "private_nbody_bundle"
                / "private_nbody.runtime_trace.json",
                "private_nbody",
            ),
            (
                self.bundle_dir
                / "generated_session"
                / "private_satellite_bundle"
                / "private_satellite",
                "private_satellite",
            ),
        ]:
            if trace_path.is_file():
                self.copy_telemetry_paths_from_runtime_trace(trace_path, name)

        self.scan_generated_session()
        self.write_json(
            self.bundle_dir / "generated_session" / "command_results.json",
            [result.as_json() for result in self.command_results],
            notes="summary of export command executions",
        )
        self.write_docs()
        self.write_manifest_csv()
        self.zip_bundle()

        print(self.bundle_dir)
        print(self.zip_path)
        return 0


def main(argv: Iterable[str]) -> int:
    argv_list = list(argv)
    bundle_dir = Path(argv_list[0]) if argv_list else DEFAULT_BUNDLE
    exporter = Exporter(bundle_dir)
    return exporter.export()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
