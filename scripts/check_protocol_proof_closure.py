#!/usr/bin/env python3

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

from lean_toolchain import lake_cmd_prefix


ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "zkf-ir-spec" / "verification-ledger.json"
GOALS_PATH = ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "ProtocolGoals.lean"
PROTOCOL_WORKSPACE = ROOT / "zkf-protocol-proofs"
PROTOCOL_LIBRARY = "ZkfProtocolProofs"
PROTOCOL_LIBRARY_OLEAN = (
    PROTOCOL_WORKSPACE / ".lake" / "build" / "lib" / "lean" / f"{PROTOCOL_LIBRARY}.olean"
)
VENDOR_SOURCES_PATH = PROTOCOL_WORKSPACE / "vendor" / "sources.json"
APPROVED_AXIOMS = {"Classical.choice", "Quot.sound", "propext"}
FORBIDDEN_PROTOCOL_IMPORTS: dict[Path, list[str]] = {
    ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "Groth16Exact.lean": [
        "import ZkfProtocolProofs.Groth16TypeIII",
        "import ZkfProtocolProofs.Groth16TypeIIIZeroKnowledge",
    ],
    ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "FriExact.lean": [
        "import ZkfProtocolProofs.FriProximityModel",
    ],
    ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "NovaExact.lean": [
        "import ZkfProtocolProofs.NovaFoldingModel",
    ],
    ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "HyperNovaExact.lean": [
        "import ZkfProtocolProofs.HyperNovaCcsModel",
    ],
}

THEOREM_GATES: dict[str, list[tuple[Path, str]]] = {
    "protocol.groth16_completeness": [
        (
            ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "Groth16Exact.lean",
            "groth16_exact_completeness",
        ),
    ],
    "protocol.groth16_knowledge_soundness": [
        (
            ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "Groth16Exact.lean",
            "groth16_exact_knowledge_soundness",
        ),
    ],
    "protocol.groth16_zero_knowledge": [
        (
            ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "Groth16Exact.lean",
            "groth16_exact_zero_knowledge",
        ),
    ],
    "protocol.fri_completeness": [
        (
            ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "FriExact.lean",
            "fri_exact_completeness",
        ),
    ],
    "protocol.fri_proximity_soundness": [
        (
            ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "FriExact.lean",
            "fri_exact_proximity_soundness",
        ),
    ],
    "protocol.nova_completeness": [
        (
            ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "NovaExact.lean",
            "nova_exact_completeness",
        ),
    ],
    "protocol.nova_folding_soundness": [
        (
            ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "NovaExact.lean",
            "nova_exact_folding_sound",
        ),
    ],
    "protocol.hypernova_completeness": [
        (
            ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "HyperNovaExact.lean",
            "hypernova_exact_completeness",
        ),
    ],
    "protocol.hypernova_folding_soundness": [
        (
            ROOT / "zkf-protocol-proofs" / "ZkfProtocolProofs" / "HyperNovaExact.lean",
            "hypernova_exact_folding_sound",
        ),
    ],
}

GOAL_DEFS = [
    "def groth16CompletenessObligation",
    "def groth16KnowledgeSoundnessObligation",
    "def groth16ZeroKnowledgeObligation",
    "def friCompletenessObligation",
    "def friProximitySoundnessObligation",
    "def novaCompletenessObligation",
    "def novaFoldingSoundnessObligation",
    "def hypernovaCompletenessObligation",
    "def hypernovaFoldingSoundnessObligation",
]

THEOREM_SHAPE_REQUIREMENTS = {
    "groth16_exact_completeness": [
        "ZkfProtocolProofs.groth16ImportedCrsValidityHypothesis",
        "ZkfProtocolProofs.groth16ExactCompletenessHypothesis",
        "ZkfProtocolProofs.shippedGroth16CompiledContext",
        "ZkfProtocolProofs.shippedGroth16VerifierGuardsHold",
        "ZkfProtocolProofs.exactGroth16VerifierAccepts",
    ],
    "groth16_exact_knowledge_soundness": [
        "ZkfProtocolProofs.groth16ImportedCrsValidityHypothesis",
        "ZkfProtocolProofs.groth16KnowledgeOfExponentHypothesis",
        "ZkfProtocolProofs.shippedGroth16CompiledContext",
        "ZkfProtocolProofs.exactGroth16VerifierAccepts",
    ],
    "groth16_exact_zero_knowledge": [
        "ZkfProtocolProofs.groth16ImportedCrsValidityHypothesis",
        "ZkfProtocolProofs.groth16ExactZeroKnowledgeHypothesis",
        "ZkfProtocolProofs.shippedGroth16Artifact",
        "ZkfProtocolProofs.exactGroth16PublicView",
    ],
    "fri_exact_completeness": [
        "ZkfProtocolProofs.friExactCompletenessHypothesis",
        "ZkfProtocolProofs.shippedFriCompiledContext",
        "ZkfProtocolProofs.shippedFriVerifierGuardsHold",
        "ZkfProtocolProofs.exactFriVerifierAccepts",
    ],
    "fri_exact_proximity_soundness": [
        "ZkfProtocolProofs.friReedSolomonProximitySoundnessHypothesis",
        "ZkfProtocolProofs.shippedFriCompiledContext",
        "ZkfProtocolProofs.exactFriVerifierAccepts",
    ],
    "nova_exact_completeness": [
        "ZkfProtocolProofs.novaExactCompletenessHypothesis",
        "ZkfProtocolProofs.completeClassicNovaIvcMetadata",
        "ZkfProtocolProofs.shippedNovaCompiledContext",
        "ZkfProtocolProofs.shippedNovaVerifierGuardsHold",
        "ZkfProtocolProofs.exactNovaVerifierAccepts",
    ],
    "nova_exact_folding_sound": [
        "ZkfProtocolProofs.novaExactFoldingSoundnessHypothesis",
        "ZkfProtocolProofs.shippedNovaCompiledContext",
        "ZkfProtocolProofs.exactNovaVerifierAccepts",
    ],
    "hypernova_exact_completeness": [
        "ZkfProtocolProofs.hypernovaExactCompletenessHypothesis",
        "ZkfProtocolProofs.shippedHyperNovaCompiledContext",
        "ZkfProtocolProofs.shippedHyperNovaVerifierGuardsHold",
        "ZkfProtocolProofs.exactHyperNovaVerifierAccepts",
    ],
    "hypernova_exact_folding_sound": [
        "ZkfProtocolProofs.hypernovaExactFoldingSoundnessHypothesis",
        "ZkfProtocolProofs.shippedHyperNovaCompiledContext",
        "ZkfProtocolProofs.exactHyperNovaVerifierAccepts",
    ],
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def file_contains(path: Path, needle: str) -> bool:
    return needle in path.read_text(encoding="utf-8")


def theorem_marker(decl_name: str) -> str:
    return f"theorem {decl_name}"


def validate_protocol_exact_imports() -> None:
    for path, forbidden_imports in FORBIDDEN_PROTOCOL_IMPORTS.items():
        text = path.read_text(encoding="utf-8")
        for forbidden_import in forbidden_imports:
            require(
                forbidden_import not in text,
                f"{path} still imports blocked abstract transport layer `{forbidden_import}`",
            )


def validate_vendor_sources() -> None:
    require(VENDOR_SOURCES_PATH.exists(), "missing protocol vendor manifest")
    vendor_manifest = json.loads(VENDOR_SOURCES_PATH.read_text(encoding="utf-8"))
    require(
        vendor_manifest.get("schema") == "zkf-protocol-vendor-v1",
        "unexpected protocol vendor manifest schema",
    )
    sources = vendor_manifest.get("sources")
    require(isinstance(sources, list) and sources, "protocol vendor manifest has no sources")
    sources_by_id = {source["id"]: source for source in sources}

    required_source_ids = {
        "formal-snarks-project",
        "arklib",
        "vcvio",
        "comp-poly",
        "ext-tree-map-lemmas",
        "doc-gen4",
        "checkdecls",
        "groth16-2016-260",
        "fri-2017-602",
        "nova-security-2024-232",
        "nova-2021-370",
        "hypernova-2023-573",
    }
    require(
        set(sources_by_id).issuperset(required_source_ids),
        "protocol vendor manifest is missing one or more required source ids",
    )

    for source in sources:
        require("id" in source, "protocol vendor source entry is missing `id`")
        require("kind" in source, f"protocol vendor source `{source.get('id')}` is missing `kind`")
        require(
            "origin" in source,
            f"protocol vendor source `{source.get('id')}` is missing `origin`",
        )
        local_path = source.get("local_path")
        if local_path:
            resolved_path = ROOT / local_path
            require(
                resolved_path.exists(),
                f"protocol vendor source `{source['id']}` path does not exist: {resolved_path}",
            )
            lock_path = resolved_path / "SOURCE.lock.json"
            require(
                lock_path.exists(),
                f"protocol vendor source `{source['id']}` is missing {lock_path}",
            )
            lock_data = json.loads(lock_path.read_text(encoding="utf-8"))
            require(
                lock_data.get("id") == source["id"],
                f"{lock_path} does not match source id `{source['id']}`",
            )
            require(
                lock_data.get("origin") == source["origin"],
                f"{lock_path} origin does not match `{source['origin']}`",
            )
            if "revision" in source:
                require(
                    lock_data.get("revision") == source["revision"],
                    f"{lock_path} revision does not match `{source['revision']}`",
                )

    formal_source = sources_by_id["formal-snarks-project"]
    require(
        formal_source.get("status") == "vendored",
        "formal-snarks-project must be vendored locally",
    )
    require(
        formal_source.get("revision") == "dcfc78d456882087d4e592e090e8d6d6df83e560",
        "formal-snarks-project revision drifted from the pinned source lock",
    )

    arklib_source = sources_by_id["arklib"]
    require(
        arklib_source.get("status") == "vendored",
        "ArkLib must be vendored locally",
    )
    require(
        arklib_source.get("revision") == "74f8ca485e9072fba82ba6a78debe50c5b7feb06",
        "ArkLib revision drifted from the pinned source lock",
    )

    vcvio_source = sources_by_id["vcvio"]
    require(
        vcvio_source.get("status") == "vendored",
        "VCV-io must be vendored locally",
    )
    require(
        vcvio_source.get("revision") == "d37e586bbe481ea3925eeb800d5b6fb1e8b829fe",
        "VCV-io revision drifted from the pinned source lock",
    )

    comp_poly_source = sources_by_id["comp-poly"]
    require(
        comp_poly_source.get("status") == "vendored",
        "CompPoly must be vendored locally",
    )
    require(
        comp_poly_source.get("revision") == "d7b9f987496841b066d4958b72f774f545ce907b",
        "CompPoly revision drifted from the pinned source lock",
    )

    ext_tree_map_source = sources_by_id["ext-tree-map-lemmas"]
    require(
        ext_tree_map_source.get("status") == "vendored",
        "ExtTreeMapLemmas must be vendored locally",
    )
    require(
        ext_tree_map_source.get("revision") == "82d5763c08b020fc38898a4fd59a5213059a5f87",
        "ExtTreeMapLemmas revision drifted from the pinned source lock",
    )


def ensure_protocol_library_built() -> None:
    result = subprocess.run(
        [*lake_cmd_prefix(), "build", PROTOCOL_LIBRARY],
        cwd=PROTOCOL_WORKSPACE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    require(
        result.returncode == 0,
        f"failed to rebuild {PROTOCOL_LIBRARY} before protocol closure audit:\n{result.stdout}",
    )


def audit_theorem_axioms(decl_names: list[str]) -> None:
    if not decl_names:
        return

    ensure_protocol_library_built()

    with tempfile.NamedTemporaryFile(
        "w",
        suffix=".lean",
        prefix="ProtocolAxiomAudit.",
        dir=PROTOCOL_WORKSPACE,
        delete=False,
        encoding="utf-8",
    ) as temp_file:
        temp_path = Path(temp_file.name)
        temp_file.write(f"import {PROTOCOL_LIBRARY}\n")
        for decl_name in decl_names:
            temp_file.write(f"#print axioms {PROTOCOL_LIBRARY}.{decl_name}\n")

    try:
        result = subprocess.run(
            [*lake_cmd_prefix(), "env", "lean", temp_path.name],
            cwd=PROTOCOL_WORKSPACE,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    finally:
        temp_path.unlink(missing_ok=True)

    require(
        result.returncode == 0,
        f"protocol axiom audit failed:\n{result.stdout}",
    )

    audit_output = result.stdout
    for decl_name in decl_names:
        full_name = f"{PROTOCOL_LIBRARY}.{decl_name}"
        pattern = re.compile(
            rf"'{re.escape(full_name)}' "
            rf"(does not depend on any axioms|depends on axioms: (?P<axioms>[^\n]+))"
        )
        match = pattern.search(audit_output)
        require(
            match is not None,
            f"protocol axiom audit did not report `{full_name}`",
        )

        axioms_str = match.group("axioms")
        if axioms_str is None:
            continue

        axioms = {
            axiom.strip().strip("[]")
            for axiom in axioms_str.split(",")
            if axiom.strip().strip("[]")
        }
        require(
            "Lean.sorryAx" not in axioms,
            f"{full_name} still depends on Lean.sorryAx",
        )
        disallowed_axioms = sorted(axiom for axiom in axioms if axiom not in APPROVED_AXIOMS)
        require(
            not disallowed_axioms,
            f"{full_name} depends on disallowed axioms: {', '.join(disallowed_axioms)}",
        )


def audit_theorem_shapes(decl_names: list[str]) -> None:
    if not decl_names:
        return

    ensure_protocol_library_built()

    with tempfile.NamedTemporaryFile(
        "w",
        suffix=".lean",
        prefix="ProtocolShapeAudit.",
        dir=PROTOCOL_WORKSPACE,
        delete=False,
        encoding="utf-8",
    ) as temp_file:
        temp_path = Path(temp_file.name)
        temp_file.write(f"import {PROTOCOL_LIBRARY}\n")
        for decl_name in decl_names:
            required = THEOREM_SHAPE_REQUIREMENTS.get(decl_name, [])
            if required:
                required_args = ", ".join(required)
                temp_file.write(
                    f"#protocol_closure_audit "
                    f"{PROTOCOL_LIBRARY}.{decl_name} requires [{required_args}]\n"
                )
            else:
                temp_file.write(f"#protocol_closure_audit {PROTOCOL_LIBRARY}.{decl_name}\n")

    try:
        result = subprocess.run(
            [*lake_cmd_prefix(), "env", "lean", temp_path.name],
            cwd=PROTOCOL_WORKSPACE,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    finally:
        temp_path.unlink(missing_ok=True)

    require(
        result.returncode == 0,
        f"protocol theorem-shape audit failed:\n{result.stdout}",
    )


def main() -> None:
    validate_vendor_sources()
    validate_protocol_exact_imports()

    ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    entries = {
        entry["theorem_id"]: entry
        for entry in ledger["entries"]
        if entry["theorem_id"] in THEOREM_GATES
    }
    require(
        set(entries) == set(THEOREM_GATES),
        "protocol closure gate could not find all tracked protocol ledger entries",
    )

    goals_text = GOALS_PATH.read_text(encoding="utf-8")
    for marker in GOAL_DEFS:
        require(marker in goals_text, f"missing protocol proof obligation marker: {marker}")

    mechanized_decls: list[str] = []
    for theorem_id, theorem_markers in THEOREM_GATES.items():
        trusted_assumptions = entries[theorem_id].get("trusted_assumptions", [])
        status = entries[theorem_id]["status"]
        assurance_class = entries[theorem_id].get("assurance_class")
        if status == "assumed_external":
            continue
        if status != "mechanized_local":
            raise SystemExit(
                f"unexpected protocol ledger status for {theorem_id}: {status}"
            )
        require(
            assurance_class == "hypothesis_carried_theorem",
            f"{theorem_id} should be classified as hypothesis_carried_theorem",
        )
        evidence_path = entries[theorem_id].get("evidence_path", "")
        require(
            "vendor/" not in evidence_path.replace("\\", "/"),
            f"{theorem_id} is marked mechanized_local but still points at vendored evidence",
        )
        require(
            trusted_assumptions == [],
            f"{theorem_id} is marked mechanized_local but still carries trusted assumptions",
        )
        for path, decl_name in theorem_markers:
            require(
                file_contains(path, theorem_marker(decl_name)),
                f"{theorem_id} is marked mechanized_local but {path} lacks `theorem {decl_name}`",
            )
            mechanized_decls.append(decl_name)

    audit_theorem_shapes(mechanized_decls)
    audit_theorem_axioms(mechanized_decls)


if __name__ == "__main__":
    main()
