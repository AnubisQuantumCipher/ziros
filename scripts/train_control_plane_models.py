#!/usr/bin/env python3
"""Build a validated Neural Engine model bundle from telemetry."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import build_control_plane_corpus as corpus_builder
from zkf_control_plane_common import (
    DEFAULT_MODEL_DIR,
    control_plane_feature_labels,
    control_plane_schema_name,
    corpus_hash,
    load_telemetry_records,
    security_feature_labels,
    schema_fingerprint,
    tool_versions,
)

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS_PATH = ROOT / "scripts" / "neural_engine_requirements.txt"
SCHEMA = "zkf-neural-model-bundle-v2"

LANES = {
    "scheduler": {
        "package": "scheduler_v2.mlpackage",
        "output_name": "predicted_duration_ms",
        "trainer": ROOT / "scripts" / "train_scheduler_model.py",
    },
    "backend": {
        "package": "backend_recommender_v2.mlpackage",
        "output_name": "backend_score",
        "trainer": ROOT / "scripts" / "train_backend_recommender.py",
    },
    "duration": {
        "package": "duration_estimator_v2.mlpackage",
        "output_name": "predicted_duration_ms",
        "trainer": ROOT / "scripts" / "train_duration_estimator.py",
    },
    "anomaly": {
        "package": "anomaly_detector_v2.mlpackage",
        "output_name": "anomaly_score",
        "trainer": ROOT / "scripts" / "train_anomaly_detector.py",
    },
    "security": {
        "package": "security_detector_v2.mlpackage",
        "output_name": "risk_score",
        "trainer": ROOT / "scripts" / "train_security_detector.py",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", default=[], help="Telemetry file, glob, or directory")
    parser.add_argument(
        "--profile",
        choices=["production", "fixture"],
        default="production",
        help="Corpus and quality profile to enforce before publishing models",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=DEFAULT_MODEL_DIR,
        help="Output directory for the trained model packages",
    )
    parser.add_argument(
        "--corpus-out",
        type=Path,
        default=DEFAULT_MODEL_DIR / "control_plane_corpus.jsonl",
        help="Normalized corpus output path",
    )
    parser.add_argument(
        "--summary-out",
        type=Path,
        default=DEFAULT_MODEL_DIR / "control_plane_corpus.summary.json",
        help="Corpus summary output path",
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        default=DEFAULT_MODEL_DIR / "control_plane_models_manifest.json",
        help="Bundle manifest output path",
    )
    return parser.parse_args()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def stable_package_uuid(model_hash: str) -> str:
    value = model_hash[:32].upper()
    return "-".join([value[:8], value[8:12], value[12:16], value[16:20], value[20:32]])


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


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
    (package_path / "Manifest.json").write_text(canonical_json(manifest), encoding="utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def run_trainer(
    script: Path,
    input_paths: list[str],
    out_path: Path,
    profile: str,
    feature_schema: str,
) -> None:
    command = [
        "python3",
        str(script),
        "--out",
        str(out_path),
        "--quality-profile",
        profile,
        "--feature-schema",
        feature_schema,
    ]
    for input_path in input_paths:
        command.extend(["--input", input_path])
    proc = subprocess.run(
        command,
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


def validate_sidecar(
    lane: str,
    sidecar_path: Path,
    *,
    expected_corpus_hash: str,
    profile: str,
    feature_schema: str,
) -> dict[str, Any]:
    payload = load_json(sidecar_path)
    expected = LANES[lane]
    if payload.get("lane") != lane:
        raise SystemExit(f"{sidecar_path} lane mismatch: {payload.get('lane')} != {lane}")
    expected_version = "v2" if feature_schema == "v2" else "v1"
    if payload.get("version") != expected_version:
        raise SystemExit(f"{sidecar_path} version mismatch: {payload.get('version')}")
    expected_labels = (
        security_feature_labels(feature_schema)
        if lane == "security"
        else control_plane_feature_labels(feature_schema)
    )
    if payload.get("schema_fingerprint") != schema_fingerprint(expected_labels):
        raise SystemExit(
            f"{sidecar_path} schema fingerprint drift: {payload.get('schema_fingerprint')}"
        )
    if payload.get("schema") != control_plane_schema_name(feature_schema):
        raise SystemExit(f"{sidecar_path} schema drift: {payload.get('schema')}")
    if payload.get("output_name") != expected["output_name"]:
        raise SystemExit(
            f"{sidecar_path} output name drift: {payload.get('output_name')} != {expected['output_name']}"
        )
    if payload.get("corpus_hash") != expected_corpus_hash:
        raise SystemExit(
            f"{sidecar_path} corpus hash drift: {payload.get('corpus_hash')} != {expected_corpus_hash}"
        )
    if payload.get("input_shape") != len(expected_labels):
        raise SystemExit(f"{sidecar_path} input shape drift: {payload.get('input_shape')}")
    quality_gate = payload.get("quality_gate")
    if not isinstance(quality_gate, dict):
        raise SystemExit(f"{sidecar_path} is missing quality_gate metadata")
    if quality_gate.get("passed") is not True:
        raise SystemExit(f"{sidecar_path} failed its {profile} quality gate")
    if profile != "fixture" and payload.get("quality_profile") != profile:
        raise SystemExit(
            f"{sidecar_path} quality profile drift: {payload.get('quality_profile')} != {profile}"
        )
    return payload


def build_manifest(
    *,
    model_dir: Path,
    corpus_path: Path,
    summary_path: Path,
    manifest_path: Path,
    input_paths: list[str],
    profile: str,
    feature_schema: str,
) -> dict[str, Any]:
    corpus_digest = corpus_hash(input_paths)
    summary = load_json(summary_path)
    if not (summary.get("validation") or {}).get("passed"):
        raise SystemExit(f"corpus summary did not pass validation: {summary_path}")
    manifest = {
        "schema": SCHEMA,
        "schema_fingerprint": schema_fingerprint(control_plane_feature_labels(feature_schema)),
        "feature_schema": feature_schema,
        "profile": profile,
        "corpus": {
            "path": str(corpus_path),
            "sha256": sha256_path(corpus_path),
            "corpus_hash": corpus_digest,
        },
        "corpus_summary": {
            "path": str(summary_path),
            "sha256": sha256_path(summary_path),
            "summary": summary,
        },
        "requirements_file": {
            "path": str(REQUIREMENTS_PATH),
            "sha256": sha256_path(REQUIREMENTS_PATH),
        },
        "tool_versions": tool_versions(),
        "lanes": {},
    }
    for lane, config in LANES.items():
        package_path = model_dir / config["package"]
        sidecar_path = Path(f"{package_path}.json")
        sidecar = validate_sidecar(
            lane,
            sidecar_path,
            expected_corpus_hash=corpus_digest,
            profile=profile,
            feature_schema=feature_schema,
        )
        manifest["lanes"][lane] = {
            "lane": sidecar.get("lane"),
            "version": sidecar.get("version"),
            "schema": sidecar.get("schema"),
            "schema_fingerprint": sidecar.get("schema_fingerprint"),
            "package": str(package_path),
            "package_tree_sha256": directory_tree_hash(package_path),
            "sidecar": str(sidecar_path),
            "sidecar_sha256": sha256_path(sidecar_path),
            "trainer_script": sidecar.get("trainer_script"),
            "output_name": sidecar.get("output_name"),
            "input_shape": sidecar.get("input_shape"),
            "metrics": sidecar.get("metrics"),
            "quality_gate": sidecar.get("quality_gate"),
            "quality_profile": sidecar.get("quality_profile", "fixture"),
            "lane_semantics": sidecar.get("lane_semantics"),
            "corpus_hash": sidecar.get("corpus_hash"),
            "tool_versions": sidecar.get("tool_versions"),
        }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
    return manifest


def main() -> int:
    args = parse_args()
    if not REQUIREMENTS_PATH.exists():
        raise SystemExit(f"missing neural-engine requirements file: {REQUIREMENTS_PATH}")

    records = load_telemetry_records(args.input)
    trainer_inputs = list(args.input)
    validation = {}
    if args.profile == "production":
        validation.update(corpus_builder.PRODUCTION_REQUIREMENTS)
    args.corpus_out.parent.mkdir(parents=True, exist_ok=True)
    args.summary_out.parent.mkdir(parents=True, exist_ok=True)
    args.model_dir.mkdir(parents=True, exist_ok=True)

    _, summary = corpus_builder.write_corpus(
        records=records,
        out_path=args.corpus_out,
        summary_out=args.summary_out,
        profile=args.profile,
        validation=validation,
        feature_schema="v2",
    )
    if not summary["validation"]["passed"]:
        raise SystemExit(
            "control-plane corpus does not satisfy the requested coverage profile:\n- "
            + "\n- ".join(summary["validation"]["reasons"])
        )

    with tempfile.TemporaryDirectory(prefix="zkf-control-plane-models-") as temp_root:
        staging_root = Path(temp_root)
        staging_models = staging_root / "models"
        staging_models.mkdir(parents=True, exist_ok=True)
        for config in LANES.values():
            run_trainer(
                config["trainer"],
                trainer_inputs,
                staging_models / config["package"],
                args.profile,
                "v2",
            )

        for config in LANES.values():
            package_name = config["package"]
            source_package = staging_models / package_name
            source_sidecar = Path(f"{source_package}.json")
            dest_package = args.model_dir / package_name
            dest_sidecar = Path(f"{dest_package}.json")
            if dest_package.exists():
                shutil.rmtree(dest_package)
            shutil.copytree(source_package, dest_package)
            shutil.copy2(source_sidecar, dest_sidecar)

    manifest = build_manifest(
        model_dir=args.model_dir,
        corpus_path=args.corpus_out,
        summary_path=args.summary_out,
        manifest_path=args.manifest_out,
        input_paths=trainer_inputs,
        profile=args.profile,
        feature_schema="v2",
    )
    print("wrote control-plane model bundle:")
    for config in LANES.values():
        print(args.model_dir / config["package"])
    print(args.manifest_out)
    print(json.dumps({"profile": args.profile, "corpus_records": summary["total_records"], "manifest": str(args.manifest_out)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
