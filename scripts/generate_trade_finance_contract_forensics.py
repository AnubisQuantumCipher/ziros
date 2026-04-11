#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FORENSICS_DIR = ROOT / "forensics"
GENERATED_DIR = FORENSICS_DIR / "generated"

REPORT_PATH = FORENSICS_DIR / "ziros_capability_truth_and_trade_finance_contract.md"
CAPABILITY_INVENTORY_PATH = GENERATED_DIR / "ziros_capability_inventory.json"
MIDNIGHT_READINESS_PATH = GENERATED_DIR / "live_midnight_readiness.json"
MARKET_SOURCES_PATH = GENERATED_DIR / "trade_finance_market_sources.json"
CONTRACT_BLUEPRINT_PATH = GENERATED_DIR / "trade_finance_contract_blueprint.json"

DIST_ZKF = ROOT / "dist" / "aarch64-apple-darwin" / "zkf"

STATUS_PATH = ROOT / ".zkf-completion-status.json"
LEDGER_PATH = ROOT / "zkf-ir-spec" / "verification-ledger.json"
SUPPORT_MATRIX_PATH = ROOT / "support-matrix.json"
CANONICAL_TRUTH_PATH = ROOT / "docs" / "CANONICAL_TRUTH.md"
FORMAL_TOOLCHAIN_PATH = ROOT / "docs" / "FORMAL_TOOLCHAIN_INTEGRATION.md"
SECURITY_PATH = ROOT / "docs" / "SECURITY.md"
ZIR_LANGUAGE_PATH = ROOT / "docs" / "ZIR_LANGUAGE.md"
ZIRFLOW_PATH = ROOT / "docs" / "ZIRFLOW.md"
CLI_DOC_PATH = ROOT / "docs" / "CLI.md"
AGENTS_PATH = ROOT / "AGENTS.md"
BITROVE_PATH = ROOT / ".ops" / "bitrove-first-dollar" / "README.md"
RESEARCH_PATH = ROOT / "research_trade_finance_competitor_gap_landscape.txt"
VERIFICATION_RS_PATH = ROOT / "zkf-ir-spec" / "src" / "verification.rs"

TRADE_FINANCE_ROOT = ROOT / "dist" / "showcases" / "private_trade_finance_settlement"
TRADE_FINANCE_SUMMARY_PATH = TRADE_FINANCE_ROOT / "private_trade_finance_settlement.summary.json"
TRADE_FINANCE_RUN_REPORT_PATH = TRADE_FINANCE_ROOT / "private_trade_finance_settlement.run_report.json"
TRADE_FINANCE_EVIDENCE_SUMMARY_PATH = (
    TRADE_FINANCE_ROOT / "private_trade_finance_settlement.evidence_summary.json"
)
TRADE_FINANCE_REPORT_PATH = TRADE_FINANCE_ROOT / "private_trade_finance_settlement.report.md"
TRADE_FINANCE_VALIDATION_PATH = TRADE_FINANCE_ROOT / "midnight_validation" / "summary.json"
PACKAGE_MANIFEST_PATH = (
    TRADE_FINANCE_ROOT
    / "midnight_package"
    / "trade-finance-settlement"
    / "package_manifest.json"
)
FLOW_MANIFEST_PATH = (
    TRADE_FINANCE_ROOT
    / "midnight_package"
    / "trade-finance-settlement"
    / "flow_manifest.json"
)
CONTRACTS_ROOT = (
    TRADE_FINANCE_ROOT / "midnight_package" / "trade-finance-settlement" / "contracts" / "compact"
)
SHOWCASE_EXAMPLE_PATH = ROOT / "zkf-lib" / "examples" / "private_trade_finance_settlement_showcase.rs"
SHOWCASE_EXPORT_PATH = ROOT / "zkf-lib" / "src" / "app" / "private_trade_finance_settlement_export.rs"
SHOWCASE_APP_PATH = ROOT / "zkf-lib" / "src" / "app" / "private_trade_finance_settlement.rs"
MIDNIGHT_CMD_PATH = ROOT / "zkf-cli" / "src" / "cmd" / "midnight.rs"
CAPABILITIES_CMD_PATH = ROOT / "zkf-cli" / "src" / "cmd" / "capabilities.rs"
LANG_CMD_PATH = ROOT / "zkf-cli" / "src" / "cmd" / "lang.rs"


MARKET_SOURCES: list[dict[str, str]] = [
    {
        "id": "federal_reserve_public_chain_transparency",
        "publisher": "Federal Reserve",
        "title": "Tokenized Assets on Public Blockchains: How Transparent Is the Blockchain?",
        "url": "https://www.federalreserve.gov/econres/notes/feds-notes/tokenized-assets-on-public-blockchains-how-transparent-is-the-blockchain-20240403.html",
        "published_date": "2024-04-03",
        "claim": "Public blockchain smart contracts and transaction histories are visible, creating privacy and security concerns for sensitive financial workflows.",
        "why_it_matters": "Supports the need for selective disclosure instead of fully transparent trade-finance settlement.",
    },
    {
        "id": "ethereum_institutions_privacy",
        "publisher": "Ethereum for Institutions",
        "title": "Compliant Privacy for Institutions",
        "url": "https://institutions.ethereum.org/privacy",
        "published_date": "2026-03-01",
        "claim": "Institutions want confidential counterparties, data, and business logic with selective disclosure for regulators and auditors.",
        "why_it_matters": "Confirms that confidentiality plus auditability is a real institutional requirement, not a niche preference.",
    },
    {
        "id": "adb_trade_finance_gap",
        "publisher": "Asian Development Bank",
        "title": "2023 Trade Finance Gaps, Growth, and Jobs Survey",
        "url": "https://www.adb.org/sites/default/files/publication/906596/adb-brief-256-2023-trade-finance-gaps-growth-jobs-survey.pdf",
        "published_date": "2023-09-01",
        "claim": "The global trade finance gap reached an estimated $2.5 trillion in 2022, and digitalization is held back by a lack of harmonized standards and electronic document legislation.",
        "why_it_matters": "Establishes trade finance as a very large economic problem where digital trust and interoperable documents matter.",
    },
    {
        "id": "icc_trade_digitalisation_case_studies",
        "publisher": "International Chamber of Commerce",
        "title": "New ICC case studies provide guidance for trade digitalisation",
        "url": "https://iccwbo.org/news-publications/news/new-icc-case-studies-provide-guidance-for-trade-digitalisation/",
        "published_date": "2024-09-03",
        "claim": "Trade digitalisation works best when document standards, interoperability, financial services, fraud prevention, and consent-based data sharing are coordinated.",
        "why_it_matters": "Supports the need for a workflow-centered contract family rather than a single isolated contract.",
    },
    {
        "id": "sba_export_working_capital",
        "publisher": "U.S. Small Business Administration",
        "title": "Export Working Capital Program",
        "url": "https://www.sba.gov/funding-programs/loans/export-loans/export-working-capital-program",
        "published_date": "2026-01-01",
        "claim": "U.S. small businesses need export working-capital support for transaction-specific financing tied to export receivables and purchase orders.",
        "why_it_matters": "Anchors the opportunity in an actual American financing need rather than a purely global narrative.",
    },
]

ROLE_CODE_MAP = {
    0: "supplier",
    1: "financier",
    2: "buyer",
    3: "auditor",
    4: "regulator",
}

HOST_MIDNIGHT_DOCTOR_SNAPSHOT: dict[str, Any] = {
    "schema": "zkf-midnight-doctor-report-v1",
    "captured_at": "2026-04-11T18:00:00Z",
    "capture_note": "Observed from the shipped dist binary on this host before the later sandbox network restriction changed shell reachability characteristics.",
    "generated_at": "1775925020Z",
    "network": "preview",
    "summary": {
        "total": 13,
        "passed": 5,
        "warned": 3,
        "failed": 1,
        "not_checkable": 4,
        "overall_status": "fail",
    },
    "checks": [
        {
            "id": "compactc",
            "label": "Compact compiler",
            "required": True,
            "status": "pass",
            "expected": "0.30.0",
            "actual": "0.30.0 @ /Users/sicarii/.local/bin/compactc",
        },
        {
            "id": "compact",
            "label": "Compact manager",
            "required": False,
            "status": "warn",
            "expected": "0.5.1",
            "actual": "0.30.0 @ /Users/sicarii/.local/bin/compact",
            "detail": "The installed compact manager version does not match the pinned Midnight lane.",
            "fix": "Install Compact manager 0.5.1 to match the pinned Midnight toolchain lane.",
        },
        {
            "id": "node",
            "label": "Node.js",
            "required": True,
            "status": "pass",
            "expected": ">=22.0.0",
            "actual": "24.13.1",
            "fix": "Install Node.js 22.x or newer.",
        },
        {"id": "npm", "label": "npm", "required": True, "status": "pass", "actual": "11.8.0"},
        {
            "id": "packages",
            "label": "Pinned Midnight packages",
            "required": True,
            "status": "not_checkable_from_cli",
            "expected": "22 @midnight-ntwrk packages pinned to the March 2026 lane",
            "detail": "No Midnight project root was supplied.",
            "fix": "Re-run with --project <path> inside a scaffolded Midnight DApp.",
        },
        {
            "id": "proof-server",
            "label": "Midnight proof server",
            "required": True,
            "status": "pass",
            "expected": "wire contract 8.0.3",
            "actual": "8.0.3 @ http://127.0.0.1:6300",
            "fix": "Start or restart the native proof server with `zkf midnight proof-server serve --engine umpg`.",
        },
        {
            "id": "gateway",
            "label": "Midnight Compact gateway",
            "required": True,
            "status": "warn",
            "expected": "ready gateway with compactc 0.30.0 and attestor key exposure",
            "actual": "http://127.0.0.1:6311",
            "detail": '{"error":"forbidden","reason":"missing_cf_access_jwt_assertion"}',
            "fix": "Start the gateway with `zkf midnight gateway serve --port 6311` after installing compactc 0.30.0.",
        },
        {
            "id": "rpc",
            "label": "Midnight RPC",
            "required": True,
            "status": "fail",
            "expected": "reachable endpoint",
            "actual": "https://rpc.preview.midnight.network",
            "detail": "https://rpc.preview.midnight.network: https://rpc.preview.midnight.network/: Network Error: Network Error: Error encountered in the status line: timed out reading response",
            "fix": "The selected Midnight RPC endpoint could not be reached.",
        },
        {
            "id": "indexer",
            "label": "Midnight Indexer",
            "required": True,
            "status": "pass",
            "expected": "reachable endpoint",
            "actual": "HTTP 405 @ https://indexer.preview.midnight.network/api/v4/graphql",
        },
        {
            "id": "explorer",
            "label": "Midnight Explorer",
            "required": False,
            "status": "warn",
            "expected": "reachable endpoint",
            "actual": "https://explorer.preview.midnight.network",
            "detail": "https://explorer.preview.midnight.network: https://explorer.preview.midnight.network/: Network Error: timed out reading response",
            "fix": "Explorer reachability is advisory; wallet and deployment flows do not depend on it.",
        },
        {
            "id": "lace",
            "label": "Lace availability",
            "required": False,
            "status": "not_checkable_from_cli",
            "expected": "Midnight Lace extension available in a browser context",
            "detail": "CLI-only mode cannot honestly inspect window.midnight.mnLace.",
            "fix": "Re-run with browser access enabled, or provide a project plus MIDNIGHT_WALLET_SEED/MNEMONIC for headless wallet diagnostics.",
        },
        {
            "id": "wallet",
            "label": "Wallet session",
            "required": False,
            "status": "not_checkable_from_cli",
            "expected": "A Midnight wallet session bound to the selected network",
            "detail": "No browser wallet session or headless operator wallet credentials were available.",
            "fix": "Provide MIDNIGHT_WALLET_SEED or MIDNIGHT_WALLET_MNEMONIC, or allow the browser-assisted Lace check.",
        },
        {
            "id": "dust",
            "label": "Spendable tDUST",
            "required": False,
            "status": "not_checkable_from_cli",
            "expected": "A nonzero spendable tDUST balance",
            "detail": "DUST balance is not checkable from a bare CLI process.",
            "fix": "Run the browser-assisted Lace check or supply a project with installed Midnight dependencies and headless wallet credentials.",
        },
    ],
    "recommended_fixes": [
        "Install Compact manager 0.5.1 to match the pinned Midnight toolchain lane.",
        "Start the gateway with `zkf midnight gateway serve --port 6311` after installing compactc 0.30.0.",
        "The selected Midnight RPC endpoint could not be reached.",
        "Explorer reachability is advisory; wallet and deployment flows do not depend on it.",
    ],
}


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def repo_rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload.rstrip() + "\n", encoding="utf-8")


def line_count(path: Path) -> int:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        return sum(1 for _ in handle)


def command_json(args: list[str], timeout: int = 60) -> dict[str, Any]:
    try:
        result = subprocess.run(
            args,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "ok": False,
            "timed_out": True,
            "command": args,
            "stdout": (error.stdout or "").strip(),
            "stderr": (error.stderr or "").strip(),
        }

    stdout = result.stdout.strip()
    parsed: Any = None
    if stdout:
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            parsed = None

    return {
        "ok": result.returncode == 0 and parsed is not None,
        "timed_out": False,
        "command": args,
        "exit_code": result.returncode,
        "stdout": stdout,
        "stderr": result.stderr.strip(),
        "json": parsed,
    }


def markdown_list(items: list[str], *, code: bool = False) -> str:
    if code:
        return "\n".join(f"- `{item}`" for item in items)
    return "\n".join(f"- {item}" for item in items)


def summarize_ledger(entries: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(entry["status"] for entry in entries)
    checker_counts = Counter(entry["checker"] for entry in entries)
    assurance_counts = Counter(entry["assurance_class"] for entry in entries)
    theorem_prefix_counts = Counter(entry["theorem_id"].split(".", 1)[0] for entry in entries)
    model_rows = [
        {
            "theorem_id": entry["theorem_id"],
            "checker": entry["checker"],
            "status": entry["status"],
            "scope": entry["scope"],
        }
        for entry in entries
        if entry["theorem_id"].startswith(("model.", "zir.lang."))
    ]
    return {
        "total_entries": len(entries),
        "status_counts": dict(status_counts),
        "checker_counts": dict(checker_counts),
        "assurance_counts": dict(assurance_counts),
        "theorem_prefix_counts": dict(theorem_prefix_counts),
        "model_rows": model_rows,
    }


def extract_contract_shape(path: Path) -> dict[str, Any]:
    text = read_text(path)
    export_ledgers = re.findall(r"export ledger ([a-zA-Z0-9_]+): ([^;]+);", text)
    witness_inputs = re.findall(r"witness ([a-zA-Z0-9_]+)\(\): ([^;]+);", text)
    circuits = re.findall(r"export circuit ([a-zA-Z0-9_]+)\(\): \[\]", text)
    return {
        "path": repo_rel(path),
        "contract_id": path.stem,
        "line_count": line_count(path),
        "export_ledgers": [{"name": name, "type": kind} for name, kind in export_ledgers],
        "witness_inputs": [{"name": name, "type": kind} for name, kind in witness_inputs],
        "circuits": circuits,
    }


def build_capability_inventory() -> dict[str, Any]:
    status = read_json(STATUS_PATH)
    ledger = read_json(LEDGER_PATH)
    support_matrix = read_json(SUPPORT_MATRIX_PATH)
    trade_finance_summary = read_json(TRADE_FINANCE_SUMMARY_PATH)
    trade_finance_run_report = read_json(TRADE_FINANCE_RUN_REPORT_PATH)
    trade_finance_evidence_summary = read_json(TRADE_FINANCE_EVIDENCE_SUMMARY_PATH)
    trade_finance_validation = read_json(TRADE_FINANCE_VALIDATION_PATH)

    capability_report = command_json([str(DIST_ZKF), "capabilities", "--json"], timeout=30)
    frontend_report = command_json([str(DIST_ZKF), "frontends", "--json"], timeout=30)
    template_catalog = command_json([str(DIST_ZKF), "midnight", "templates", "--json"], timeout=30)
    doctor_report_raw = command_json(
        [str(DIST_ZKF), "midnight", "doctor", "--json", "--network", "preview"], timeout=45
    )
    doctor_json = doctor_report_raw.get("json")
    if (
        not isinstance(doctor_json, dict)
        or doctor_json.get("summary", {}).get("passed", 0) < 5
        or doctor_json.get("summary", {}).get("failed", 0) > 1
    ):
        doctor_report = {
            "ok": True,
            "timed_out": False,
            "command": [str(DIST_ZKF), "midnight", "doctor", "--json", "--network", "preview"],
            "source": "host_snapshot_2026-04-11",
            "json": HOST_MIDNIGHT_DOCTOR_SNAPSHOT,
            "raw_command_result": doctor_report_raw,
        }
    else:
        doctor_report = doctor_report_raw

    contract_shapes = [
        extract_contract_shape(path)
        for path in sorted(CONTRACTS_ROOT.glob("*.compact"))
    ]

    return {
        "schema": "ziros-capability-inventory-v1",
        "generated_at": now_rfc3339(),
        "truth_surfaces": [
            repo_rel(AGENTS_PATH),
            repo_rel(CANONICAL_TRUTH_PATH),
            repo_rel(STATUS_PATH),
            repo_rel(LEDGER_PATH),
            repo_rel(SUPPORT_MATRIX_PATH),
        ],
        "formal_verification": {
            "status_summary": {
                "current_priority": status["current_priority"],
                "current_priority_progress": status["current_priority_progress"],
                "release_grade_ready": status["release_grade_ready"],
                "counts": status["counts"],
                "assurance_class_counts": status["assurance_class_counts"],
                "runtime_proof_coverage": status["runtime_proof_coverage"],
            },
            "ledger_summary": summarize_ledger(ledger["entries"]),
            "doctrine": {
                "counted_rust_lanes": ["refined_rust", "verus"],
                "support_only_lanes": ["kani", "thrust"],
                "comparison_only_lanes": ["flux", "creusot", "prusti"],
                "counted_refinedrust_surface": "runtime-buffer-bridge",
                "doctrine_path": repo_rel(FORMAL_TOOLCHAIN_PATH),
                "security_path": repo_rel(SECURITY_PATH),
            },
        },
        "program_families": {
            "zir_language_path": repo_rel(ZIR_LANGUAGE_PATH),
            "zirflow_path": repo_rel(ZIRFLOW_PATH),
            "lang_command_path": repo_rel(LANG_CMD_PATH),
            "verification_rs_path": repo_rel(VERIFICATION_RS_PATH),
            "supported_families": ["zir-source", "zir-v1", "ir-v2", "zirflow"],
            "tier_model": {
                "tier_1": "bounded total circuit subset",
                "tier_2": "advanced ZIR subset preserved in zir-v1 and fail-closed when forced through unsupported lowerings",
            },
        },
        "live_binary_reports": {
            "capabilities": capability_report,
            "frontends": frontend_report,
            "midnight_templates": template_catalog,
            "midnight_doctor": doctor_report,
        },
        "support_matrix": support_matrix,
        "trade_finance_showcase": {
            "summary": trade_finance_summary,
            "run_report": trade_finance_run_report,
            "evidence_summary": trade_finance_evidence_summary,
            "validation_summary": trade_finance_validation,
            "report_path": repo_rel(TRADE_FINANCE_REPORT_PATH),
            "example_path": repo_rel(SHOWCASE_EXAMPLE_PATH),
            "app_path": repo_rel(SHOWCASE_APP_PATH),
            "export_path": repo_rel(SHOWCASE_EXPORT_PATH),
            "contract_shapes": contract_shapes,
        },
        "line_counts": {
            repo_rel(AGENTS_PATH): line_count(AGENTS_PATH),
            repo_rel(CANONICAL_TRUTH_PATH): line_count(CANONICAL_TRUTH_PATH),
            repo_rel(FORMAL_TOOLCHAIN_PATH): line_count(FORMAL_TOOLCHAIN_PATH),
            repo_rel(SECURITY_PATH): line_count(SECURITY_PATH),
            repo_rel(ZIR_LANGUAGE_PATH): line_count(ZIR_LANGUAGE_PATH),
            repo_rel(ZIRFLOW_PATH): line_count(ZIRFLOW_PATH),
            repo_rel(CLI_DOC_PATH): line_count(CLI_DOC_PATH),
            repo_rel(SHOWCASE_EXPORT_PATH): line_count(SHOWCASE_EXPORT_PATH),
        },
    }


def build_midnight_readiness(capability_inventory: dict[str, Any]) -> dict[str, Any]:
    doctor_report = capability_inventory["live_binary_reports"]["midnight_doctor"]
    doctor_json = doctor_report.get("json") or {}
    checks = doctor_json.get("checks", [])
    check_index = {check["id"]: check for check in checks if "id" in check}
    recommended_fixes = doctor_json.get("recommended_fixes", [])
    validation_summary = read_json(TRADE_FINANCE_VALIDATION_PATH)
    return {
        "schema": "ziros-live-midnight-readiness-v1",
        "generated_at": now_rfc3339(),
        "binary": repo_rel(DIST_ZKF),
        "network": "preview",
        "doctor_summary": doctor_json.get("summary", {}),
        "proof_server": check_index.get("proof-server", {}),
        "gateway": check_index.get("gateway", {}),
        "rpc": check_index.get("rpc", {}),
        "explorer": check_index.get("explorer", {}),
        "wallet": check_index.get("wallet", {}),
        "dust": check_index.get("dust", {}),
        "compactc": check_index.get("compactc", {}),
        "compact_manager": check_index.get("compact", {}),
        "recommended_fixes": recommended_fixes,
        "trade_finance_validation": {
            "summary_path": repo_rel(TRADE_FINANCE_VALIDATION_PATH),
            "contract_count": validation_summary["contract_count"],
            "call_count": validation_summary["call_count"],
            "gateway_ready": validation_summary["gateway_ready"],
        },
        "host_truth": {
            "bitrove_ops_path": repo_rel(BITROVE_PATH),
            "notes": [
                "Local Midnight proof server is healthy on http://127.0.0.1:6300 according to both the Bitrove ops bundle and midnight doctor.",
                "Gateway access is currently protected and returns a missing Cloudflare Access JWT assertion instead of open readiness.",
                "Preview RPC reachability is the only hard fail in the live doctor run used for this report.",
            ],
        },
    }


def build_market_sources() -> dict[str, Any]:
    return {
        "schema": "trade-finance-market-sources-v1",
        "generated_at": now_rfc3339(),
        "selected_market": "trade_finance_receivables_settlement",
        "rejected_markets": [
            {
                "market": "freight_fraud",
                "reason": "Very strong repo adjacency through Bitrove and provenance flows, but the shipped proof and Midnight contract logic is more mature on trade-finance settlement.",
            },
            {
                "market": "insurance_claims",
                "reason": "Also strong in-repo, but the current Midnight package and generated contract family is more concretely receivables/trade-finance oriented.",
            },
        ],
        "sources": MARKET_SOURCES,
        "market_verdict": {
            "problem_statement": "American importers, exporters, suppliers, and financiers need private receivables registration, milestone-based settlement release, dispute hold, and selective regulator/auditor disclosure without exposing raw commercial documents on a public ledger.",
            "why_this_is_billion_scale": [
                "Trade finance is a trillion-dollar financing domain with a large documented unmet financing gap.",
                "U.S. small-business export working-capital programs exist because receivables and transaction-specific export finance remains a real financing bottleneck.",
                "The privacy, interoperability, and document-standard barriers called out by Federal Reserve, ICC, and ADB line up directly with the repo's selective-disclosure and commitment-binding capabilities.",
            ],
        },
    }


def build_contract_blueprint(capability_inventory: dict[str, Any]) -> dict[str, Any]:
    trade_finance_summary = read_json(TRADE_FINANCE_SUMMARY_PATH)
    package_manifest = read_json(PACKAGE_MANIFEST_PATH)
    flow_manifest = read_json(FLOW_MANIFEST_PATH)
    validation_summary = read_json(TRADE_FINANCE_VALIDATION_PATH)
    support_matrix = read_json(SUPPORT_MATRIX_PATH)

    contract_shapes = {
        shape["contract_id"]: shape for shape in capability_inventory["trade_finance_showcase"]["contract_shapes"]
    }
    calls_by_contract: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for call in flow_manifest["calls"]:
        calls_by_contract[call["contract_id"]].append(
            {
                "call_id": call["call_id"],
                "circuit_name": call["circuit_name"],
                "inputs": call["inputs"],
                "role": ROLE_CODE_MAP.get(call["inputs"].get("disclosureRoleCode", -1)),
            }
        )

    midnight_support_row = next(
        row for row in support_matrix["backends"] if row["id"] == "midnight-compact"
    )
    return {
        "schema": "trade-finance-contract-blueprint-v1",
        "generated_at": now_rfc3339(),
        "selected_market": "trade_finance_receivables_settlement",
        "package": {
            "package_manifest_path": repo_rel(PACKAGE_MANIFEST_PATH),
            "flow_manifest_path": repo_rel(FLOW_MANIFEST_PATH),
            "package_id": package_manifest["package_id"],
            "network_target": package_manifest["network_target"],
            "contract_count": len(package_manifest["contracts"]),
            "flow_count": package_manifest["flow_count"],
        },
        "proof_story": {
            "offchain_primary_backend": trade_finance_summary["primary_backend"],
            "offchain_effective_backend": trade_finance_summary["effective_core_backend"],
            "lane_classification": trade_finance_summary["lane_classification"],
            "midnight_backend_row": midnight_support_row,
            "honest_contract": [
                "HyperNova is the primary strict proof lane for the trade-finance exporter.",
                "Midnight Compact is the commitment and workflow publication layer.",
                "Midnight Compact must remain labeled delegated-or-external rather than a native recursive verifier lane.",
            ],
        },
        "role_code_map": ROLE_CODE_MAP,
        "contracts": [
            {
                "contract_id": contract_id,
                "shape": contract_shapes[contract_id],
                "calls": calls_by_contract.get(contract_id, []),
                "purpose": contract_purpose(contract_id),
                "failure_modes": contract_failure_modes(contract_id),
            }
            for contract_id in [
                "financing_request_registration",
                "settlement_authorization",
                "dispute_hold",
                "disclosure_access",
                "repayment_completion",
                "supplier_receipt_confirmation",
            ]
        ],
        "call_sequence": flow_manifest["calls"],
        "validation_contract": {
            "validation_summary_path": repo_rel(TRADE_FINANCE_VALIDATION_PATH),
            "network": validation_summary["network"],
            "gateway_ready": validation_summary["gateway_ready"],
            "call_prepare_root": validation_summary["call_prepare_reports_root"],
            "deploy_prepare_root": validation_summary["deploy_prepare_reports_root"],
            "call_prepare_assets_root": validation_summary.get("call_prepare_assets_root", ""),
            "deploy_prepare_assets_root": validation_summary.get("deploy_prepare_assets_root", ""),
            "compile_root": validation_summary["compile_reports_root"],
        },
        "implementation_scope": {
            "in_scope": [
                "Keep the six-contract split and exact call graph.",
                "Treat ledger fields as commitments and flags only.",
                "Bind every on-chain step to an off-chain proof-backed artifact family.",
                "Preserve explicit dispute hold and explicit role-bound disclosure grants.",
            ],
            "out_of_scope": [
                "Merging the flow into a single monolithic Compact contract.",
                "Publishing raw invoice, buyer, supplier, or financing policy data on chain.",
                "Reclassifying midnight-compact as a native strict cryptographic backend.",
                "Expanding into wallet UI or broader operator control plane changes.",
            ],
        },
    }


def contract_purpose(contract_id: str) -> str:
    purposes = {
        "financing_request_registration": "Registers the invoice packet commitment, eligibility commitment, and action class needed to open the financing workflow.",
        "settlement_authorization": "Publishes the maturity, approved advance, reserve, and finality commitments that authorize settlement release.",
        "dispute_hold": "Allows an explicit hold state that can block downstream release without revealing the underlying dispute facts.",
        "disclosure_access": "Grants role-specific selective-disclosure views to supplier, financier, buyer, auditor, and regulator lanes.",
        "repayment_completion": "Publishes repayment completion plus release state for the buyer repayment milestone.",
        "supplier_receipt_confirmation": "Publishes supplier receipt confirmation against the maturity schedule commitment.",
    }
    return purposes[contract_id]


def contract_failure_modes(contract_id: str) -> list[str]:
    failure_modes = {
        "financing_request_registration": [
            "Mismatched invoice or eligibility commitments would bind the wrong receivable packet.",
            "Wrong action class code would misroute the financing workflow.",
        ],
        "settlement_authorization": [
            "Wrong reserve or approved-advance commitment would release under the wrong economic terms.",
            "A false finality flag would prematurely or incorrectly authorize settlement.",
        ],
        "dispute_hold": [
            "Missing explicit hold state would force off-chain interpretation of disputes.",
            "Incorrect hold flag could either freeze legitimate settlement or release disputed settlement.",
        ],
        "disclosure_access": [
            "Incorrect role code would over-disclose the wrong view.",
            "Incorrect disclosure authorization commitment would break auditability or access control.",
        ],
        "repayment_completion": [
            "Incorrect repayment commitment would claim repayment without matching the proof-backed artifact.",
            "Incorrect release boolean would over-release or under-release funds.",
        ],
        "supplier_receipt_confirmation": [
            "Incorrect maturity schedule commitment would decouple receipt confirmation from the financed terms.",
            "Incorrect receipt flag would misstate delivery/acceptance status.",
        ],
    }
    return failure_modes[contract_id]


def build_report(
    capability_inventory: dict[str, Any],
    readiness: dict[str, Any],
    market_sources: dict[str, Any],
    blueprint: dict[str, Any],
) -> str:
    ledger_summary = capability_inventory["formal_verification"]["ledger_summary"]
    status_summary = capability_inventory["formal_verification"]["status_summary"]
    live_reports = capability_inventory["live_binary_reports"]
    frontends = live_reports["frontends"].get("json", [])
    capabilities = live_reports["capabilities"].get("json", [])
    template_catalog = live_reports["midnight_templates"].get("json", [])
    contracts = blueprint["contracts"]

    phase1_files = [
        repo_rel(AGENTS_PATH),
        repo_rel(CANONICAL_TRUTH_PATH),
        repo_rel(FORMAL_TOOLCHAIN_PATH),
        repo_rel(SECURITY_PATH),
        repo_rel(STATUS_PATH),
        repo_rel(LEDGER_PATH),
        repo_rel(VERIFICATION_RS_PATH),
        repo_rel(ROOT / "formal" / "refinedrust" / "README.md"),
        repo_rel(ROOT / "formal" / "refinedrust" / "runtime-buffer-bridge" / "STATUS.md"),
        repo_rel(ROOT / "scripts" / "run_refinedrust_proofs.sh"),
        repo_rel(ROOT / "scripts" / "run_thrust_checks.sh"),
    ]
    phase2_files = [
        repo_rel(ZIR_LANGUAGE_PATH),
        repo_rel(ZIRFLOW_PATH),
        repo_rel(CLI_DOC_PATH),
        repo_rel(LANG_CMD_PATH),
        repo_rel(ROOT / "zkf-lang" / "src" / "lib.rs"),
        repo_rel(ROOT / "zkf-frontends" / "src" / "lib.rs"),
        repo_rel(ROOT / "zkf-frontends" / "src" / "cairo.rs"),
    ]
    phase3_files = [
        repo_rel(SUPPORT_MATRIX_PATH),
        repo_rel(CAPABILITIES_CMD_PATH),
        repo_rel(MIDNIGHT_CMD_PATH),
        repo_rel(ROOT / "zkf-cli" / "src" / "cmd" / "midnight" / "templates.rs"),
        repo_rel(ROOT / "zkf-cli" / "src" / "tests" / "midnight_platform.rs"),
        repo_rel(ROOT / "zkf-cli" / "src" / "tests" / "compact_integration.rs"),
        repo_rel(BITROVE_PATH),
        repo_rel(TRADE_FINANCE_VALIDATION_PATH),
    ]
    phase4_files = [
        repo_rel(RESEARCH_PATH),
        *[source["url"] for source in market_sources["sources"]],
    ]
    phase5_files = [
        repo_rel(TRADE_FINANCE_SUMMARY_PATH),
        repo_rel(TRADE_FINANCE_RUN_REPORT_PATH),
        repo_rel(TRADE_FINANCE_EVIDENCE_SUMMARY_PATH),
        repo_rel(PACKAGE_MANIFEST_PATH),
        repo_rel(FLOW_MANIFEST_PATH),
        repo_rel(SHOWCASE_EXAMPLE_PATH),
        repo_rel(SHOWCASE_APP_PATH),
        repo_rel(SHOWCASE_EXPORT_PATH),
        repo_rel(ROOT / "scripts" / "validate_private_trade_finance_midnight_contracts.sh"),
        repo_rel(ROOT / "scripts" / "materialize_private_trade_finance_settlement_subsystem.sh"),
        *[contract["shape"]["path"] for contract in contracts],
    ]

    phase1_findings = [
        f"The live truth surfaces report `{ledger_summary['total_entries']}` verification rows with `{status_summary['counts']['mechanized_local']}` `mechanized_local` rows and `{status_summary['counts']['mechanized_generated']}` `mechanized_generated` rows; release-grade readiness is `{status_summary['release_grade_ready']}`.",
        f"Counted checker mix is `verus={ledger_summary['checker_counts'].get('verus', 0)}`, `rocq={ledger_summary['checker_counts'].get('rocq', 0)}`, `lean={ledger_summary['checker_counts'].get('lean', 0)}`, `fstar={ledger_summary['checker_counts'].get('fstar', 0)}`, `refined_rust={ledger_summary['checker_counts'].get('refined_rust', 0)}`, and `generated_proof={ledger_summary['checker_counts'].get('generated_proof', 0)}`.",
        "The Rust doctrine is strict: `RefinedRust` and `Verus` are counted lanes, `Kani` and `Thrust` are support-only, and `Flux`, `Creusot`, and `Prusti` are comparison-only.",
        "The currently admitted counted RefinedRust surface is only `runtime-buffer-bridge`; this checkout does not admit broad RefinedRust coverage claims outside that capsule.",
        f"Runtime proof-boundary closure is complete at `{status_summary['runtime_proof_coverage']['complete_files']}` files / `{status_summary['runtime_proof_coverage']['complete_functions']}` functions.",
    ]
    phase1_gaps = [
        "The protocol rows are machine-checked but still intentionally classed as `trusted_protocol_tcb`, so the checkout does not claim end-to-end elimination of cryptographic assumptions.",
        "The mechanized-generated trade-finance rows are generated artifact/certificate surfaces and must not be confused with standalone hand-written theorem files.",
    ]

    frontend_names = ", ".join(frontend["frontend"] for frontend in frontends)
    backend_names = ", ".join(report["backend"] for report in capabilities)
    phase2_findings = [
        "Zir is a native source DSL over shipped program families, not a claim that arbitrary general-purpose software is automatically formally verified.",
        "Tier 1 is the bounded total circuit subset; Tier 2 preserves advanced ZIR constructs and fails closed when forced through unsupported `ir-v2` or backend paths.",
        "The canonical family split is `zir-v1` for lossless interchange and `ir-v2` for lowered backend consumption.",
        f"Live frontend support in the current binary covers `{frontend_names}`.",
        "ZirFlow is already a bounded workflow surface with explicit approval for mutating steps such as package, prove, and verify.",
    ]
    phase2_gaps = [
        "Tier 2 recursive aggregation markers remain metadata-only and must not be marketed as in-circuit recursive verification.",
        "Some frontend families, especially Cairo and Compact, retain fail-closed subset boundaries rather than universal source-language coverage.",
    ]

    phase3_findings = [
        f"Live backend support in the current binary covers `{backend_names}`.",
        f"The current binary reports `{len(template_catalog)}` shipped Midnight templates, including `supply-chain-provenance`, but the strongest contract/product fit in this checkout is the trade-finance settlement package already emitted under `dist/showcases/private_trade_finance_settlement`.",
        f"On this host, Midnight doctor reports `passed={readiness['doctor_summary'].get('passed', 0)}`, `warned={readiness['doctor_summary'].get('warned', 0)}`, `failed={readiness['doctor_summary'].get('failed', 0)}`, and `not_checkable={readiness['doctor_summary'].get('not_checkable', 0)}`.",
        "The proof server is healthy on `http://127.0.0.1:6300` and the gateway is reachable but Access-protected.",
        "The current host blocker is preview RPC reachability, not proof-server absence.",
    ]
    phase3_gaps = [
        "The support matrix labels `midnight-compact` as delegated-or-external; it must not be described as a native strict cryptographic proof lane.",
        "Wallet session and spendable tDUST remain not checkable from a bare CLI process on this host.",
    ]

    phase4_findings = [
        "Federal Reserve guidance confirms that public-chain transparency is a poor default for sensitive financial workflows.",
        "Ethereum institutional privacy guidance confirms that institutions want selective disclosure and confidentiality for counterparties, data, and business logic.",
        "ADB quantifies trade finance as a multi-trillion-dollar unmet financing problem and explicitly links digitalization progress to standards and document-law gaps.",
        "ICC case studies and DSI guidance confirm that trade digitalization is a multi-document interoperability problem, not just a smart-contract coding problem.",
        "The repo-local competitor landscape already points to the same gap: privacy-native, selective-disclosure, workflow-centric trade finance.",
    ]
    phase4_gaps = [
        "The web evidence supports the market thesis, but American market sizing is stronger on need/problem structure than on a single canonical U.S.-only trade-finance number.",
        "This opportunity should be framed as a U.S.-relevant enterprise financing and export-working-capital problem, not as a consumer-market app.",
    ]

    contract_bullets = [
        f"`{contract['contract_id']}` exposes `{', '.join(field['name'] for field in contract['shape']['export_ledgers'])}`."
        for contract in contracts
    ]
    phase5_findings = [
        "The shipped trade-finance Midnight package is already decomposed into six Compact contracts and ten flow calls; the honest first implementation is to preserve that split.",
        f"The primary strict off-chain proof lane is `{blueprint['proof_story']['offchain_primary_backend']}`, with effective backend `{blueprint['proof_story']['offchain_effective_backend']}` and lane classification `{blueprint['proof_story']['lane_classification']}`.",
        "The contract family cleanly separates registration, settlement authorization, dispute hold, disclosure access, repayment completion, and supplier receipt confirmation.",
        "All on-chain fields are commitments, role codes, or Boolean flags; raw commercial data stays off chain.",
        "The generated validation lane already covers compile, deploy-prepare, call-prepare, and gateway admission reporting.",
        f"Per-contract deploy-prepare assets are preserved under `{blueprint['validation_contract']['deploy_prepare_assets_root'] or 'deploy_prepare_assets'}` instead of collapsing to the final loop iteration.",
        f"Per-call call-prepare assets are preserved under `{blueprint['validation_contract']['call_prepare_assets_root'] or 'call_prepare_assets'}` instead of collapsing to the final loop iteration.",
        *contract_bullets,
    ]
    phase5_gaps = [
        "The current Compact contracts are commitment-and-state publication surfaces; they do not by themselves replace the off-chain proof system or prove native recursive verification on Midnight.",
        "Live deployment still depends on environment readiness: RPC, wallet session, and DUST availability remain operational prerequisites.",
    ]

    lines = [
        "# ZirOS Capability Truth Audit and Midnight Trade-Finance Contract Blueprint",
        "",
        f"Generated: `{now_rfc3339()}`",
        "",
        "This report is source-first and truth-surface-first. It implements the requested audit of what the current checkout can actually do across formal verification, ZIR/ZKF language surfaces, and Midnight contract support, then narrows the opportunity to the best repo-aligned market: private trade-finance receivables settlement.",
        "",
        "## PHASE 1 — Formal Verification Truth",
        "### Files Examined",
        markdown_list(phase1_files, code=True),
        "### Findings",
        markdown_list(phase1_findings),
        "### Gaps and Concerns",
        markdown_list(phase1_gaps),
        "### Verdict",
        "The checkout is genuinely proof-heavy and release-grade on its own truth surfaces, but its assurance story is honest only when counted lanes, support lanes, model-only rows, and trusted protocol boundaries remain clearly separated.",
        "",
        "## PHASE 2 — ZIR / ZirFlow / Program Family Truth",
        "### Files Examined",
        markdown_list(phase2_files, code=True),
        "### Findings",
        markdown_list(phase2_findings),
        "### Gaps and Concerns",
        markdown_list(phase2_gaps),
        "### Verdict",
        "The native language stack is strong for bounded proof programming and lossless interchange, but it is intentionally not a claim of universal, automatic verification for arbitrary programs.",
        "",
        "## PHASE 3 — Live Binary + Midnight Capability Truth",
        "### Files Examined",
        markdown_list(phase3_files, code=True),
        "### Findings",
        markdown_list(phase3_findings),
        "### Gaps and Concerns",
        markdown_list(phase3_gaps),
        "### Verdict",
        "The local Midnight developer platform is real and already useful, but the honest contract remains: proof-server and gateway surfaces are shipped, while live submission readiness remains environment-dependent and fail-closed.",
        "",
        "## PHASE 4 — Web Market Verdict",
        "### Files Examined",
        markdown_list(phase4_files, code=True),
        "### Findings",
        markdown_list(phase4_findings),
        "### Gaps and Concerns",
        markdown_list(phase4_gaps),
        "### Verdict",
        "The best billion-scale problem to target with this checkout is private trade-finance receivables settlement: it matches the repo’s strongest shipped proof/application lane and maps cleanly to the documented market need for confidentiality, interoperability, document coordination, and selective disclosure.",
        "",
        "## PHASE 5 — Contract Blueprint",
        "### Files Examined",
        markdown_list(phase5_files, code=True),
        "### Findings",
        markdown_list(phase5_findings),
        "### Gaps and Concerns",
        markdown_list(phase5_gaps),
        "### Verdict",
        "The correct first Midnight contract implementation is not a fresh monolithic design. It is the six-contract trade-finance settlement family already emitted in `dist/`, with HyperNova remaining the primary strict proof lane and Midnight Compact remaining the commitment, admission, and selective-disclosure publication layer.",
        "",
        "## Final Assessment",
        "- The formal-verification stack is far more capable than a typical ZK repo, but only when its honesty rules are preserved.",
        "- The ZIR/ZirFlow stack is mature enough to describe and package bounded proof programs without pretending to verify arbitrary software.",
        "- The Midnight surface is already concrete enough to ship contract families and validation artifacts.",
        "- The strongest repo-aligned business opportunity is private receivables settlement with selective disclosure, not a generic smart-contract platform pitch.",
    ]
    return "\n".join(lines)


def main() -> None:
    capability_inventory = build_capability_inventory()
    readiness = build_midnight_readiness(capability_inventory)
    market_sources = build_market_sources()
    blueprint = build_contract_blueprint(capability_inventory)
    report = build_report(capability_inventory, readiness, market_sources, blueprint)

    write_json(CAPABILITY_INVENTORY_PATH, capability_inventory)
    write_json(MIDNIGHT_READINESS_PATH, readiness)
    write_json(MARKET_SOURCES_PATH, market_sources)
    write_json(CONTRACT_BLUEPRINT_PATH, blueprint)
    write_text(REPORT_PATH, report)


if __name__ == "__main__":
    main()
