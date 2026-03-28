#!/usr/bin/env python3
"""Regenerate the checked-in Neural Engine fixture models."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from zkf_control_plane_common import (
    control_plane_feature_labels,
    corpus_hash,
    security_feature_labels,
    schema_fingerprint,
    tool_versions,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "zkf-runtime" / "tests" / "fixtures" / "neural_engine"
FIXTURE_CORPUS = FIXTURE_ROOT / "control_plane_fixture_corpus.jsonl"
MODELS_DIR = FIXTURE_ROOT / "models"
MANIFEST_PATH = FIXTURE_ROOT / "fixture_manifest.json"
REQUIREMENTS_PATH = ROOT / "scripts" / "neural_engine_requirements.txt"
SCHEMA = "zkf-neural-fixture-models-v1"

LANES = {
    "scheduler": {
        "package": "scheduler_v1.mlpackage",
        "output_name": "predicted_duration_ms",
        "trainer": ROOT / "scripts" / "train_scheduler_model.py",
    },
    "backend": {
        "package": "backend_recommender_v1.mlpackage",
        "output_name": "backend_score",
        "trainer": ROOT / "scripts" / "train_backend_recommender.py",
    },
    "duration": {
        "package": "duration_estimator_v1.mlpackage",
        "output_name": "predicted_duration_ms",
        "trainer": ROOT / "scripts" / "train_duration_estimator.py",
    },
    "anomaly": {
        "package": "anomaly_detector_v1.mlpackage",
        "output_name": "anomaly_score",
        "trainer": ROOT / "scripts" / "train_anomaly_detector.py",
    },
    "security": {
        "package": "security_detector_v1.mlpackage",
        "output_name": "risk_score",
        "trainer": ROOT / "scripts" / "train_security_detector.py",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the committed fixtures match a fresh regeneration",
    )
    return parser.parse_args()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def stable_package_uuid(model_hash: str) -> str:
    value = model_hash[:32].upper()
    return "-".join(
        [value[:8], value[8:12], value[12:16], value[16:20], value[20:32]]
    )


def normalize_mlpackage(package_path: Path) -> None:
    from coremltools.proto import Model_pb2

    model_path = package_path / "Data" / "com.apple.CoreML" / "model.mlmodel"
    message = Model_pb2.Model()
    message.ParseFromString(model_path.read_bytes())
    deterministic_bytes = message.SerializeToString(deterministic=True)
    model_path.write_bytes(deterministic_bytes)

    package_uuid = stable_package_uuid(sha256_bytes(deterministic_bytes))
    manifest = {
        "fileFormatVersion": "1.0.0",
        "itemInfoEntries": {
            package_uuid: {
                "author": "com.apple.CoreML",
                "description": "CoreML Model Specification",
                "name": "model.mlmodel",
                "path": "com.apple.CoreML/model.mlmodel",
            }
        },
        "rootModelIdentifier": package_uuid,
    }
    manifest_path = package_path / "Manifest.json"
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")


def directory_tree_hash(path: Path) -> str:
    digest = hashlib.sha256()
    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file():
            continue
        digest.update(candidate.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(candidate.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def run_trainer(script: Path, out_path: Path) -> None:
    proc = subprocess.run(
        [
            "python3",
            str(script),
            "--input",
            str(FIXTURE_CORPUS),
            "--out",
            str(out_path),
            "--feature-schema",
            "v1",
        ],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"{script.name} failed with exit code {proc.returncode}\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )
    normalize_mlpackage(out_path)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_sidecar(lane: str, sidecar_path: Path, expected_corpus_hash: str) -> dict[str, Any]:
    payload = load_json(sidecar_path)
    expected = LANES[lane]
    feature_labels = security_feature_labels("v1") if lane == "security" else control_plane_feature_labels("v1")
    if payload.get("lane") != lane:
        raise SystemExit(f"{sidecar_path} lane mismatch: {payload.get('lane')} != {lane}")
    if payload.get("version") != "v1":
        raise SystemExit(f"{sidecar_path} version mismatch: {payload.get('version')}")
    if payload.get("schema_fingerprint") != schema_fingerprint(feature_labels):
        raise SystemExit(
            f"{sidecar_path} schema fingerprint drift: {payload.get('schema_fingerprint')}"
        )
    if payload.get("output_name") != expected["output_name"]:
        raise SystemExit(
            f"{sidecar_path} output name drift: {payload.get('output_name')} != {expected['output_name']}"
        )
    if payload.get("corpus_hash") != expected_corpus_hash:
        raise SystemExit(
            f"{sidecar_path} corpus hash drift: {payload.get('corpus_hash')} != {expected_corpus_hash}"
        )
    if payload.get("input_shape") != len(feature_labels):
        raise SystemExit(f"{sidecar_path} input shape drift: {payload.get('input_shape')}")
    quality_gate = payload.get("quality_gate")
    if not isinstance(quality_gate, dict):
        raise SystemExit(f"{sidecar_path} is missing quality_gate metadata")
    if quality_gate.get("passed") is not True:
        raise SystemExit(f"{sidecar_path} failed its fixture quality gate")
    return payload


def build_manifest(staging_dir: Path) -> dict[str, Any]:
    corpus_digest = corpus_hash([str(FIXTURE_CORPUS)])
    manifest = {
        "schema": SCHEMA,
        "schema_fingerprint": schema_fingerprint(control_plane_feature_labels("v1")),
        "fixture_corpus": {
            "path": str(FIXTURE_CORPUS.relative_to(ROOT)),
            "sha256": sha256_path(FIXTURE_CORPUS),
            "corpus_hash": corpus_digest,
        },
        "requirements_file": {
            "path": str(REQUIREMENTS_PATH.relative_to(ROOT)),
            "sha256": sha256_path(REQUIREMENTS_PATH),
        },
        "tool_versions": tool_versions(),
        "lanes": {},
    }

    for lane, config in LANES.items():
        package_path = staging_dir / config["package"]
        sidecar_path = Path(f"{package_path}.json")
        sidecar = validate_sidecar(lane, sidecar_path, corpus_digest)
        manifest["lanes"][lane] = {
            "lane": sidecar.get("lane"),
            "version": sidecar.get("version"),
            "schema": sidecar.get("schema"),
            "schema_fingerprint": sidecar.get("schema_fingerprint"),
            "package": f"models/{config['package']}",
            "package_tree_sha256": directory_tree_hash(package_path),
            "sidecar": f"models/{config['package']}.json",
            "sidecar_sha256": sha256_path(sidecar_path),
            "trainer_script": sidecar.get("trainer_script"),
            "output_name": sidecar.get("output_name"),
            "input_shape": sidecar.get("input_shape"),
            "metrics": sidecar.get("metrics"),
            "quality_gate": sidecar.get("quality_gate"),
            "lane_semantics": sidecar.get("lane_semantics"),
            "corpus_hash": sidecar.get("corpus_hash"),
            "tool_versions": sidecar.get("tool_versions"),
        }
    return manifest


def validate_fixture_invariants(staging_dir: Path) -> None:
    scheduler_hash = directory_tree_hash(staging_dir / LANES["scheduler"]["package"])
    duration_hash = directory_tree_hash(staging_dir / LANES["duration"]["package"])
    if scheduler_hash == duration_hash:
        raise SystemExit(
            "scheduler and duration fixtures are still byte-identical; expected distinct models"
        )


def copy_generated_models(staging_dir: Path) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    for config in LANES.values():
        package_name = config["package"]
        source_package = staging_dir / package_name
        source_sidecar = Path(f"{source_package}.json")
        dest_package = MODELS_DIR / package_name
        dest_sidecar = Path(f"{dest_package}.json")
        if dest_package.exists():
            shutil.rmtree(dest_package)
        shutil.copytree(source_package, dest_package)
        shutil.copy2(source_sidecar, dest_sidecar)


def main() -> int:
    args = parse_args()
    if not FIXTURE_CORPUS.exists():
        raise SystemExit(f"missing fixture corpus: {FIXTURE_CORPUS}")
    if not REQUIREMENTS_PATH.exists():
        raise SystemExit(f"missing neural-engine requirements file: {REQUIREMENTS_PATH}")

    with tempfile.TemporaryDirectory(prefix="zkf-neural-fixtures-") as temp_root:
        staging_root = Path(temp_root)
        staging_models = staging_root / "models"
        staging_models.mkdir(parents=True, exist_ok=True)
        for config in LANES.values():
            run_trainer(config["trainer"], staging_models / config["package"])

        validate_fixture_invariants(staging_models)
        manifest = build_manifest(staging_models)
        manifest_text = canonical_json(manifest)

        if args.check:
            if not MANIFEST_PATH.exists():
                raise SystemExit(f"missing committed fixture manifest: {MANIFEST_PATH}")
            existing_manifest = canonical_json(load_json(MANIFEST_PATH))
            if existing_manifest != manifest_text:
                raise SystemExit(
                    "fixture manifest drift detected; regenerate with "
                    "`python3 scripts/build_fixture_neural_models.py`"
                )
            for config in LANES.values():
                package_name = config["package"]
                committed_package = MODELS_DIR / package_name
                committed_sidecar = Path(f"{committed_package}.json")
                generated_package = staging_models / package_name
                generated_sidecar = Path(f"{generated_package}.json")
                if directory_tree_hash(committed_package) != directory_tree_hash(generated_package):
                    raise SystemExit(f"package drift detected for {package_name}")
                if sha256_path(committed_sidecar) != sha256_path(generated_sidecar):
                    raise SystemExit(f"sidecar drift detected for {committed_sidecar.name}")
            print("fixture neural models are up to date")
            return 0

        copy_generated_models(staging_models)
        MANIFEST_PATH.write_text(manifest_text, encoding="utf-8")
        print("wrote fixture neural models:")
        for config in LANES.values():
            print(MODELS_DIR / config["package"])
        print(MANIFEST_PATH)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
