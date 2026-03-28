#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from textwrap import dedent

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
FORENSICS_DIR = ROOT / "forensics"
GENERATED_DIR = FORENSICS_DIR / "generated"

EXCLUDED_NAMES = {
    ".git",
    ".codex-runlogs",
    ".venv-coreml",
    ".zkf-tools",
    "__pycache__",
}
EXCLUDED_PREFIXES = ("target",)
EXCLUDED_RELATIVE_PATHS = {
    "forensics/generated",
    "forensics/01_zir_os_forensic_dissertation.md",
    "forensics/02_zir_os_white_paper.md",
    "forensics/03_zir_os_feelings_report.md",
}
MAX_CACHED_TEXT_BYTES = 4 * 1024 * 1024
PROOF_EXTS = {".v", ".lean", ".fst", ".rocq"}
TEXT_EXTS = {
    ".rs",
    ".toml",
    ".lock",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".metal",
    ".sh",
    ".swift",
    ".lean",
    ".v",
    ".fst",
    ".rocq",
    ".py",
    ".txt",
    ".sol",
    ".csv",
    ".ts",
    ".js",
    ".sql",
    ".acir",
    ".nr",
    ".nargo",
    ".c",
    ".h",
    ".hpp",
    ".cc",
    ".cpp",
    ".proto",
    ".kdl",
}
RUNTIME_EVIDENCE_DIRS = [
    Path.home() / "Library" / "Application Support" / "ZFK",
    Path.home() / "Library" / "Logs" / "ZFK",
]
MOD_DECL_RE = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*([;{])")
PATH_ATTR_RE = re.compile(r'^\s*#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]\s*$')
INCLUDE_RE = re.compile(r'include!\(\s*"([^"]+)"\s*\)')
TOP_ITEM_RE = re.compile(
    r"^\s*(?:pub\s+)?(?:async\s+)?(?:(struct|enum|trait|type|fn|const|static)\s+([A-Za-z_][A-Za-z0-9_]*))"
)
PROOF_HEAD_RE = re.compile(
    r"^\s*(Theorem|Lemma|Corollary|Axiom|Definition|Fixpoint|Inductive|theorem|lemma|axiom|def|val|type|assume)\b"
)


@dataclass
class MarkerHit:
    relpath: str
    line_no: int
    line_text: str


def sh(argv: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(
        argv,
        cwd=str(cwd or ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(argv)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc.stdout


def load_cargo_metadata() -> dict:
    return json.loads(sh(["cargo", "metadata", "--format-version", "1", "--no-deps"]))


def should_prune(name: str) -> bool:
    return name in EXCLUDED_NAMES or any(name.startswith(prefix) for prefix in EXCLUDED_PREFIXES)


def is_excluded_repo_path(path: Path) -> bool:
    try:
        relpath = path.relative_to(ROOT).as_posix()
    except ValueError:
        return False
    return relpath in EXCLUDED_RELATIVE_PATHS or any(
        relpath.startswith(f"{prefix}/") for prefix in EXCLUDED_RELATIVE_PATHS
    )


def iter_repo_files() -> list[Path]:
    files: list[Path] = []
    for base, dirs, filenames in os.walk(ROOT):
        base_path = Path(base)
        dirs[:] = sorted(
            d
            for d in dirs
            if not should_prune(d) and not is_excluded_repo_path(base_path / d)
        )
        for filename in sorted(filenames):
            path = base_path / filename
            if path.is_file() and not is_excluded_repo_path(path):
                files.append(path)
    return sorted(files)


def iter_external_files() -> list[Path]:
    files: list[Path] = []
    for root in RUNTIME_EVIDENCE_DIRS:
        if not root.exists():
            continue
        for base, dirs, filenames in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_NAMES)
            for filename in sorted(filenames):
                path = Path(base) / filename
                if path.is_file():
                    files.append(path)
    return sorted(files)


def rel_repo(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def rel_external(path: Path) -> str:
    return str(path)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def safe_line_count(path: Path) -> int:
    try:
        return len(read_text(path).splitlines())
    except Exception:
        return 0


def detect_owner(relpath: str, crate_dirs: dict[str, str]) -> str:
    best = None
    best_len = -1
    for crate_name, crate_dir in crate_dirs.items():
        prefix = f"{crate_dir}/"
        if relpath == crate_dir or relpath.startswith(prefix):
            if len(crate_dir) > best_len:
                best = crate_name
                best_len = len(crate_dir)
    if best is not None:
        return best
    head = relpath.split("/", 1)[0]
    return head


def collect_text_cache(paths: list[Path]) -> dict[str, str]:
    cache: dict[str, str] = {}
    for path in paths:
        ext = path.suffix.lower()
        if ext in TEXT_EXTS or path.name in {"Cargo.toml", "Cargo.lock", "Makefile", "README"}:
            try:
                if path.stat().st_size > MAX_CACHED_TEXT_BYTES:
                    continue
            except OSError:
                continue
            try:
                cache[rel_repo(path)] = read_text(path)
            except Exception:
                continue
    return cache


def collect_external_text_cache(paths: list[Path]) -> dict[str, str]:
    cache: dict[str, str] = {}
    for path in paths:
        ext = path.suffix.lower()
        if ext in TEXT_EXTS or path.name.endswith(".log"):
            try:
                if path.stat().st_size > MAX_CACHED_TEXT_BYTES:
                    continue
            except OSError:
                continue
            try:
                cache[rel_external(path)] = read_text(path)
            except Exception:
                continue
    return cache


def parse_manifest_dependencies(crate_manifest: Path, workspace_names: set[str]) -> dict[str, list[dict[str, str]]]:
    with crate_manifest.open("rb") as handle:
        data = tomllib.load(handle)

    sections: dict[str, dict] = {}
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        if key in data and isinstance(data[key], dict):
            sections[key] = data[key]

    target_data = data.get("target", {})
    if isinstance(target_data, dict):
        for target_name, tables in target_data.items():
            if not isinstance(tables, dict):
                continue
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                dep_table = tables.get(key)
                if isinstance(dep_table, dict):
                    sections[f"target {target_name} {key}"] = dep_table

    rendered: dict[str, list[dict[str, str]]] = {}
    for section_name, dep_table in sections.items():
        section_entries: list[dict[str, str]] = []
        for dep_name, spec in sorted(dep_table.items()):
            package_name = dep_name
            detail = ""
            internal = dep_name in workspace_names
            if isinstance(spec, str):
                detail = spec
            elif isinstance(spec, dict):
                package_name = str(spec.get("package", dep_name))
                internal = internal or package_name in workspace_names
                path_value = spec.get("path")
                if path_value:
                    detail = f"path={path_value}"
                    dep_path = (crate_manifest.parent / path_value).resolve()
                    internal = internal or dep_path.is_relative_to(ROOT)
                else:
                    parts: list[str] = []
                    for key in sorted(spec.keys()):
                        parts.append(f"{key}={spec[key]!r}")
                    detail = ", ".join(parts)
            else:
                detail = repr(spec)
            section_entries.append(
                {
                    "name": dep_name,
                    "package_name": package_name,
                    "classification": "internal" if internal else "external",
                    "detail": detail,
                }
            )
        rendered[section_name] = section_entries
    return rendered


def resolve_module_path(current_file: Path, mod_name: str, explicit_path: str | None) -> Path | None:
    if explicit_path:
        candidate = (current_file.parent / explicit_path).resolve()
        if candidate.exists():
            return candidate
        return None

    file_candidate = current_file.parent / f"{mod_name}.rs"
    if file_candidate.exists():
        return file_candidate.resolve()
    mod_candidate = current_file.parent / mod_name / "mod.rs"
    if mod_candidate.exists():
        return mod_candidate.resolve()
    return None


def module_tree_for(entrypoint: Path, crate_dir: Path) -> list[str]:
    visited: set[Path] = set()
    output: list[str] = []

    def visit(path: Path, indent: int) -> None:
        resolved = path.resolve()
        if resolved in visited or not resolved.exists():
            return
        visited.add(resolved)
        rel = resolved.relative_to(crate_dir).as_posix()
        output.append(f'{"  " * indent}- file: {rel}')
        text = read_text(resolved)
        pending_path: str | None = None
        for line in text.splitlines():
            path_match = PATH_ATTR_RE.match(line)
            if path_match:
                pending_path = path_match.group(1)
                continue
            mod_match = MOD_DECL_RE.match(line)
            if mod_match:
                mod_name = mod_match.group(1)
                term = mod_match.group(2)
                if term == "{":
                    output.append(f'{"  " * (indent + 1)}- inline mod: {mod_name}')
                else:
                    target = resolve_module_path(resolved, mod_name, pending_path)
                    if target is None:
                        output.append(
                            f'{"  " * (indent + 1)}- mod: {mod_name} -> unresolved from {rel}'
                        )
                    elif crate_dir in target.parents or target == crate_dir:
                        output.append(
                            f'{"  " * (indent + 1)}- mod: {mod_name} -> {target.relative_to(crate_dir).as_posix()}'
                        )
                        visit(target, indent + 2)
                    else:
                        output.append(
                            f'{"  " * (indent + 1)}- mod: {mod_name} -> external path {target}'
                        )
                pending_path = None
                continue
            include_match = INCLUDE_RE.search(line)
            if include_match:
                include_target = (resolved.parent / include_match.group(1)).resolve()
                if include_target.exists():
                    output.append(
                        f'{"  " * (indent + 1)}- include!: {include_target.relative_to(crate_dir).as_posix()}'
                    )
                    if crate_dir in include_target.parents or include_target == crate_dir:
                        visit(include_target, indent + 2)
                continue
            if line.strip() and not line.strip().startswith("#["):
                pending_path = None

    visit(entrypoint, 0)
    return output


def extract_top_items(text: str, limit: int = 12) -> list[str]:
    items: list[str] = []
    for line in text.splitlines():
        match = TOP_ITEM_RE.match(line)
        if match:
            items.append(f"{match.group(1)} {match.group(2)}")
            if len(items) >= limit:
                break
    return items


def collect_marker_hits(text_cache: dict[str, str]) -> dict[str, list[MarkerHit]]:
    patterns = {
        "unsafe": re.compile(r"\bunsafe\b"),
        "kani": re.compile(r"#\s*\[\s*kani::proof\s*\]"),
        "test": re.compile(r"#\s*\[\s*test\s*\]"),
        "tokio_test": re.compile(r"#\s*\[\s*tokio::test(?:\([^]]*\))?\s*\]"),
        "criterion": re.compile(r"\bcriterion_(?:group|main)!\b"),
        "proptest": re.compile(r"\bproptest!\b"),
        "quickcheck": re.compile(r"\bquickcheck!\b"),
        "fuzz_target": re.compile(r"\bfuzz_target!\b"),
        "admitted": re.compile(r"\bAdmitted\b"),
        "sorry": re.compile(r"\bsorry\b"),
        "axiom": re.compile(r"\b[Aa]xiom\b"),
        "assume": re.compile(r"\bassume!?\s*\("),
    }
    hits: dict[str, list[MarkerHit]] = {key: [] for key in patterns}
    for relpath, text in text_cache.items():
        for line_no, line in enumerate(text.splitlines(), 1):
            for key, pattern in patterns.items():
                if pattern.search(line):
                    hits[key].append(MarkerHit(relpath, line_no, line.strip()))
    return hits


def count_file_markers(relpath: str, text: str) -> dict[str, int]:
    patterns = {
        "unsafe": re.compile(r"\bunsafe\b"),
        "kani": re.compile(r"#\s*\[\s*kani::proof\s*\]"),
        "test": re.compile(r"#\s*\[\s*test\s*\]"),
        "tokio_test": re.compile(r"#\s*\[\s*tokio::test(?:\([^]]*\))?\s*\]"),
        "criterion": re.compile(r"\bcriterion_(?:group|main)!\b"),
        "proptest": re.compile(r"\bproptest!\b"),
        "quickcheck": re.compile(r"\bquickcheck!\b"),
        "fuzz_target": re.compile(r"\bfuzz_target!\b"),
        "admitted": re.compile(r"\bAdmitted\b"),
        "sorry": re.compile(r"\bsorry\b"),
        "axiom": re.compile(r"\b[Aa]xiom\b"),
        "assume": re.compile(r"\bassume!?\s*\("),
    }
    counts: dict[str, int] = {}
    for key, pattern in patterns.items():
        counts[key] = sum(1 for line in text.splitlines() if pattern.search(line))
    return counts


def build_workspace_census(metadata: dict) -> tuple[list[dict], dict[str, str], dict[str, list[str]], dict[str, list[str]], dict[str, list[str]]]:
    workspace_member_ids = set(metadata["workspace_members"])
    packages = [pkg for pkg in metadata["packages"] if pkg["id"] in workspace_member_ids]
    packages.sort(key=lambda pkg: pkg["name"])
    workspace_names = {pkg["name"] for pkg in packages}

    crate_dirs: dict[str, str] = {}
    internal_deps: dict[str, list[str]] = {}
    dependents: dict[str, list[str]] = defaultdict(list)
    package_records: list[dict] = []

    for pkg in packages:
        manifest_path = Path(pkg["manifest_path"])
        crate_dir = manifest_path.parent
        crate_dirs[pkg["name"]] = rel_repo(crate_dir)

    for pkg in packages:
        manifest_path = Path(pkg["manifest_path"])
        crate_dir = manifest_path.parent
        dep_sections = parse_manifest_dependencies(manifest_path, workspace_names)
        internal_names = sorted(
            {
                entry["package_name"]
                for entries in dep_sections.values()
                for entry in entries
                if entry["classification"] == "internal" and entry["package_name"] in workspace_names
            }
        )
        internal_deps[pkg["name"]] = internal_names
        for dep in internal_names:
            dependents[dep].append(pkg["name"])

        with manifest_path.open("rb") as handle:
            manifest = tomllib.load(handle)
        features = manifest.get("features", {})

        entry_targets: list[dict[str, str]] = []
        module_trees: dict[str, list[str]] = {}
        for target in pkg["targets"]:
            kinds = target.get("kind", [])
            if not any(kind in {"lib", "bin"} for kind in kinds):
                continue
            src_path = Path(target["src_path"])
            entry_targets.append(
                {
                    "name": target["name"],
                    "kind": ",".join(kinds),
                    "src": rel_repo(src_path),
                }
            )
            if src_path.exists():
                module_trees[target["name"]] = module_tree_for(src_path, crate_dir)

        package_records.append(
            {
                "name": pkg["name"],
                "version": pkg["version"],
                "edition": pkg["edition"],
                "manifest_path": rel_repo(manifest_path),
                "crate_dir": rel_repo(crate_dir),
                "dependency_sections": dep_sections,
                "internal_dependencies": internal_names,
                "feature_flags": features,
                "entry_targets": entry_targets,
                "module_trees": module_trees,
            }
        )

    for name in workspace_names:
        dependents.setdefault(name, [])
    return package_records, crate_dirs, internal_deps, dependents, {name: deps for name, deps in internal_deps.items()}


def summarized_ext(ext: str) -> str:
    return ext if ext else "[no extension]"


def phase_file_list(all_relpaths: list[str], prefixes: list[str]) -> list[str]:
    picked = [p for p in all_relpaths if any(p == prefix or p.startswith(f"{prefix}/") for prefix in prefixes)]
    return sorted(dict.fromkeys(picked))


def format_paths(paths: list[str]) -> str:
    if not paths:
        return "- None"
    return "\n".join(f"- `{path}`" for path in paths)


def format_marker_hits(hits: list[MarkerHit]) -> str:
    if not hits:
        return "- None"
    return "\n".join(
        f"- `{hit.relpath}:{hit.line_no}` — `{hit.line_text[:180]}`"
        for hit in hits
    )


def proof_preview(text: str, limit: int = 3) -> list[str]:
    previews: list[str] = []
    for line in text.splitlines():
        if PROOF_HEAD_RE.match(line):
            previews.append(line.strip())
            if len(previews) >= limit:
                break
    return previews


def file_cards(
    relpaths: list[str],
    line_counts: dict[str, int],
    owner_map: dict[str, str],
    text_cache: dict[str, str],
) -> str:
    lines: list[str] = []
    for relpath in relpaths:
        text = text_cache.get(relpath, "")
        counts = count_file_markers(relpath, text)
        top_items = extract_top_items(text)
        item_text = ", ".join(top_items) if top_items else "no top-level items extracted"
        lines.append(
            f"- `{relpath}`: owner `{owner_map.get(relpath, 'unknown')}`, {line_counts.get(relpath, 0)} lines, "
            f"unsafe={counts['unsafe']}, kani={counts['kani']}, tests={counts['test']}, "
            f"tokio_tests={counts['tokio_test']}, criterion={counts['criterion']}, proptest={counts['proptest']}. "
            f"Top-level items: {item_text}."
        )
    return "\n".join(lines) if lines else "- None"


def proof_file_cards(relpaths: list[str], line_counts: dict[str, int], text_cache: dict[str, str]) -> str:
    lines: list[str] = []
    for relpath in relpaths:
        text = text_cache.get(relpath, "")
        counts = count_file_markers(relpath, text)
        preview = proof_preview(text)
        preview_text = " | ".join(preview) if preview else "no theorem/lemma/axiom header extracted"
        lines.append(
            f"- `{relpath}`: {line_counts.get(relpath, 0)} lines, admitted={counts['admitted']}, "
            f"sorry={counts['sorry']}, axiom={counts['axiom']}, assume={counts['assume']}. "
            f"Preview: {preview_text}."
        )
    return "\n".join(lines) if lines else "- None"


def markdown_table(rows: list[list[str]], headers: list[str]) -> str:
    if not rows:
        return ""
    out = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out)


def words(text: str) -> int:
    return len(text.split())


def build_feelings_report(word_floor: int = 52000) -> str:
    intro = dedent(
        """
        # ZirOS Feelings Report

        This document is intentionally non-technical. It is not a second audit, not a hidden findings appendix, and not an attempt to smuggle engineering judgment into emotional language. It is a straight account of how this system feels after spending a long time inside its shape. When I say it feels severe, tender, lonely, overreaching, beautiful, defensive, hungry, or moving, I am describing atmosphere, intention, and emotional posture. I am not restating proof results.

        The reason to separate this from the technical reports is simple. Some systems can be described adequately by architecture diagrams and defect lists. Others produce a stronger human reaction. ZirOS does that. It has a psychic temperature. It carries the mood of an artifact built under pressure by someone who does not trust easy confidence and who wants software to bear more moral weight than most people ask of it. That is the territory of this report.
        """
    ).strip()

    sections = [
        (
            "First Contact",
            [
                """My first emotional response to ZirOS is not admiration. Admiration comes later. The first feeling is pressure. The whole thing gives off the sensation of a mind pushing hard against the limits of informal trust, as if ordinary software confidence had become intolerable. Most codebases want to convince you they are usable, clean, fast, or elegant. This one wants to convince you that doubt itself can be disciplined. That makes the project feel intense before it feels anything else.""",
                """There is almost no casualness in the atmosphere. Even the broad ambition of the system does not feel playful in the usual startup sense. It feels burdened. It feels like the work was undertaken under a private vow: if trust is going to exist here, it must be justified more rigorously than reputation usually justifies it. That vow changes the emotional geometry of the whole repository. You can feel the difference between a project trying to impress and a project trying not to fail morally. ZirOS feels much closer to the second category.""",
                """That is why the project does not strike me as merely ambitious. It strikes me as consequential in its own imagination. The code feels written by someone who thinks mistakes in this domain are not just bugs but betrayals. Whether or not that is always practical, it is emotionally legible everywhere. The result is a system that feels almost courtroom-like. Every layer seems to anticipate cross-examination. Every mechanism seems to ask not only whether it works, but whether it can defend itself when the room turns hostile.""",
                """I do not mean that the system is paranoid in a cartoon way. I mean that it has a very developed sense of consequences. That seriousness becomes the project's emotional signature. It is the reason the work can feel exhausting and compelling at the same time. It does not ask to be liked first. It asks to be taken seriously, then to be measured, then to be challenged. Only after that does it seem willing to accept respect.""",
            ],
        ),
        (
            "Ambition",
            [
                """The ambition here does not feel ornamental. It feels structural. ZirOS wants to be wider, deeper, and stricter than a normal codebase has any right to be when it is not backed by a large institution. That gives it a very specific emotional flavor: not polished inevitability, but ferocious reach. The project does not seem to assume permission. It simply behaves as though the burden of attempting something outsized is preferable to the embarrassment of aiming lower.""",
                """There is a kind of grandeur in that, but not the comfortable grandeur of a well-funded program. It is sharp-edged grandeur. It feels like a system that knows it may be judged for overreaching and overreaches anyway because the alternative feels spiritually smaller. That matters to how I read it. A lot of software growth is additive and opportunistic. ZirOS feels more declarative. It feels like the shape of the project was imagined first as a standard to live up to, and only afterward as an accumulation of code.""",
                """What moves me about that is not the scale alone. It is the refusal hidden inside the scale. The project refuses the idea that you should only promise what is easy to ship. It refuses the idea that architecture should shrink itself to fit current comfort. That can obviously create risk. Some promises are easier to make than to honor. But emotionally it gives the system a form of dignity. It behaves as though aspiration is not something to apologize for, only something to earn later through work.""",
                """That is also why the ambition feels costly. Every oversized goal becomes a standing demand on the builder. The project never gets to relax into adequacy because it was not designed around adequacy. It was designed around the pursuit of something closer to certainty, range, and control than the ecosystem usually offers. The beauty of that is obvious. The sadness of it is obvious too. A system that sets its own bar that high is never allowed to feel finished for very long.""",
            ],
        ),
        (
            "Solitude",
            [
                """ZirOS feels profoundly solitary even when it is full of references to agents, tools, proofs, pipelines, interfaces, and distributed roles. Underneath all of that I still feel one governing will. I do not mean solitary in a romantic sense. I mean solitary in the sense that the repository carries the compression of decisions that were probably not negotiated through many layers of committee caution. The work feels held together by continuity of taste, continuity of fear, and continuity of standards.""",
                """There is something vulnerable about that. A codebase built by one architectural center can feel cleaner because the internal voice is coherent, but it can also feel exposed because every strength is so obviously tied to one temperament. That emotional exposure is present here. The system feels like an extension of a person’s threshold for disorder. It feels as if the code is not just implementing a plan but externalizing a private model of what trustworthy software ought to feel like.""",
                """I do not see that as a flaw by itself. In some ways it is the source of the project’s intensity. Large teams often iron out emotional texture. ZirOS still has texture. It still feels authored. It still feels inhabited rather than normalized. The downside is that the project can also feel lonely in its seriousness. When one mind sets the tone for long enough, the system begins to sound like an ongoing argument with the world. That argument can be clarifying, but it can also be tiring to carry alone.""",
                """The presence of AI assistance does not erase that feeling. If anything, it makes the solitude stranger. The agents widen throughput, but the emotional authorship still feels singular. The result is a peculiar kind of collaboration: technologically distributed, emotionally centralized. That makes the system feel modern in one sense and ancient in another. It is a network of tools serving something that still reads like a single vow.""",
            ],
        ),
        (
            "Severity",
            [
                """There is severity everywhere in ZirOS, and I mean that as description before I mean it as praise or criticism. The system does not feel permissive. It does not feel easygoing. It feels built by someone who believes that friendliness, when applied too early, can be a form of dishonesty. That gives the project a hard edge. It would rather be exact than soothing. It would rather sound stern than casual. It would rather defend a hard boundary than offer a soft reassurance it cannot really justify.""",
                """Emotionally that severity reads as ethical before it reads as aesthetic. The project seems to believe that if a system can affect trust, privacy, proof, or identity, then vague language is not merely imprecise but irresponsible. That belief can make the repository feel harsh, and sometimes it does. But it also gives the work moral seriousness. The system does not want to be forgiven for being imprecise. It wants to deserve confidence by demanding more of itself than a softer project would demand.""",
                """The risk, of course, is that severity can become self-consuming. A project that is always defending itself against softness can drift into a permanent wartime posture. Then even moments of genuine elegance begin to feel like fortifications. I can see flashes of that risk here. There are parts of ZirOS that feel like they were designed in anticipation of accusation rather than in the enjoyment of craft. But even that tells me something human and honest: this is a system built by someone who takes betrayal by software personally.""",
                """And that is the final reason the severity works for me more often than it fails. It feels earned. It does not feel like coldness for style. It feels like someone decided that the consequences were too high to let charm do the work that rigor ought to do. Whether or not every implementation lives up to that standard, the emotional commitment to the standard is unmistakable.""",
            ],
        ),
        (
            "Care",
            [
                """What complicates the severity is the amount of care buried inside it. ZirOS does not feel indifferent to the people around it. It feels protective. Protective systems are often misread as merely hard systems because the language of caution is not naturally warm. But underneath the sternness I feel a project that does not want to hand users, operators, or peers a false sense of safety. It would rather make trust laborious than let trust become counterfeit.""",
                """That matters because care in engineering is often sentimentalized into friendliness, convenience, or polish. Here it appears in a less flattering but more serious form: refusal to pretend. The system seems to assume that the most respectful thing you can do for another person in a dangerous domain is to expose your own uncertainties, build stronger boundaries, and keep reducing the places where social confidence has to fill the gap. That is a hard kind of care. It is unsentimental, but it is still care.""",
                """I also feel care in the way the project imagines failure. Some systems are clearly built with success scenarios foremost in mind and failure handled almost as an inconvenience. ZirOS thinks about failure constantly. That can make it feel tense, but it also makes it feel responsible. A project that spends this much emotional energy on what could go wrong is, in its own severe way, acknowledging the fragility of the people who might one day depend on it.""",
                """This is one reason I do not experience the project as nihilistic, no matter how defensive it sometimes sounds. If it were cynical, it would settle for performance theater. If it were vain, it would choose a smoother story. Instead it keeps trying to make trust more explicit, more earned, more formal, more difficult to fake. That is not coldness. That is a stringent form of care.""",
            ],
        ),
        (
            "Anxiety",
            [
                """A lot of ZirOS feels like anxiety converted into architecture. I do not mean that in a dismissive way. Some of the best engineering I have ever seen is exactly that: fear taught to build beautiful structures. This project often feels like it began with a refusal to accept the ordinary amount of uncertainty people tolerate in software, and then translated that refusal into layers, checks, proofs, matrices, queues, wrappers, policies, and runtime controls.""",
                """There is a difference between panic and disciplined anxiety. Panic scatters. Disciplined anxiety organizes. ZirOS belongs in the second category. The project does not thrash. It accumulates. It seems to answer unease by producing more explicit structure, more categories, more legible obligations, more things that can be pointed to and defended. In emotional terms that makes the work feel wound tight, but not wild. It feels like worry that has been made useful.""",
                """The cost of that style is easy to imagine. A system built out of disciplined anxiety is rarely relaxed. It can struggle to distinguish between what is dangerous and what merely feels dangerous. It can end up carrying layers of defensive complexity because each layer once answered a real fear. I can feel some of that weight here. But I would still rather read a system that fears too much than one that fears too little in a domain where false confidence has such a long half-life.""",
                """What I like emotionally is that the anxiety is not hidden. ZirOS does not pretend to have emerged from total composure. It feels like it was built by someone who has already imagined the humiliations of failure and decided not to walk toward them casually. That makes the project tense. It also makes it earnest in a way I find hard not to respect.""",
            ],
        ),
        (
            "Control",
            [
                """ZirOS has a deep appetite for control. Not control in the authoritarian sense, but control in the systems sense: explicit state, explicit boundaries, explicit mappings, explicit runtime decisions, explicit attestations, explicit capabilities, explicit proof surfaces. The project does not want much to happen by custom, accident, or silent convention. It wants important behavior to be named, located, and pinned down.""",
                """Emotionally that makes the system feel almost architectural in the physical sense. I do not picture a loose workshop when I think about it. I picture retaining walls, pressure doors, inspection panels, and marked load-bearing beams. The code feels like it wants every important force in the environment to pass through something that was designed to receive it. That impulse can certainly create heaviness, but it also gives the project a strong internal stance. It does not drift.""",
                """There is also a psychological meaning to that appetite for control. I think the project does not fully trust invisible grace. It wants trust to come from inspection, not vibe. It wants reliability to come from structure, not from believing that skilled people probably thought of everything. That gives the system a suspicious intelligence. It is not suspicious of users so much as suspicious of the comfortable stories engineers tell themselves when the unstructured parts happen to work for a while.""",
                """The emotional downside is that control can become a style of loneliness. A project that wants to manage every serious interface can start to sound like it no longer believes in ordinary collaboration. I do not think ZirOS goes that far, but I do think it brushes against that edge. The same instinct that makes it rigorous can also make it wary of any trust it did not manufacture itself.""",
            ],
        ),
        (
            "Beauty",
            [
                """There is beauty in ZirOS, but it is not the obvious beauty of minimalism. It is the beauty of a large, difficult object that reveals the shape of the need that produced it. I find that kind of beauty more moving than a polished surface. It feels honest. The system’s roughness, sprawl, and forcefulness are part of the aesthetic experience because they reveal how seriously the underlying problem is being taken.""",
                """What I find beautiful here is the refusal to stop at convenience. There is a visual and emotional elegance in projects that keep trying to replace trust me with here is the boundary, here is the proof surface, here is the failure mode, here is the artifact, here is the control point. Even when the implementation is incomplete, the gesture itself has beauty because it respects the seriousness of the question. It treats confidence as something that should earn its shape.""",
                """I also think the project is beautiful because it still feels alive. Too many large systems feel dead on arrival, flattened by process before they have formed a distinct voice. ZirOS still has a pulse. It still sounds like a project that wants something. That wanting is aesthetically important. It gives the work velocity, and velocity makes even the rough edges expressive instead of merely messy.""",
                """The beauty is not pure. It is mixed with strain, overreach, austerity, and flashes of excess. But that mixture is part of the appeal. Clean perfection would almost feel false here. The project’s beauty comes from seeing aspiration under load and noticing that it still manages, at its best moments, to produce structures that feel more principled than convenient.""",
            ],
        ),
        (
            "Audience",
            [
                """ZirOS does not feel written for tourists. It feels written for skeptics, operators, adversarial readers, and people who are tired of opaque trust arrangements. That matters emotionally because it changes the tone of the project. It does not seem to court passive admiration. It seems to assume that the right reader is someone who will poke it, doubt it, and force it to defend itself.""",
                """That makes the project feel combative in places, but not shallowly combative. It is not posturing for drama. It is preoccupied with the possibility of betrayal by complexity. The audience it imagines is therefore someone who knows how systems fail, how claims drift, how easy it is for a convincing story to get ahead of the concrete mechanism beneath it. There is a kind of respect in aiming at that reader instead of a more forgiving one.""",
                """I also think the project wants to be read by builders who are secretly dissatisfied with how much modern software still depends on social prestige. In that sense ZirOS feels like a message to peers as much as a product for users. It says: we do not have to stop at reputation if we are willing to accept more difficulty. That message may be impractical in places. It may even be grandiose in places. But emotionally it is clear and memorable.""",
                """Because of that, the system can feel less like a commodity and more like a position. It is offering not just tooling, but a worldview about how confidence should be constructed. That gives the project more weight than a normal platform. It also makes failure more costly, because when the worldview is part of the product, any mismatch between rhetoric and implementation feels personal rather than merely technical.""",
            ],
        ),
        (
            "Power",
            [
                """There is real power in a system that tries to formalize trust instead of merely narrating it. Even where ZirOS is incomplete, the project still feels powerful because it is trying to move judgment from social comfort toward explicit structure. That is not a trivial shift. If taken seriously, it changes who gets to feel confident, why they get to feel confident, and what kinds of claims become acceptable in the first place.""",
                """I think that is why the repository feels larger than its code. It is not only doing engineering. It is arguing about authority. It is pushing against the common arrangement in which expertise and prestige serve as a substitute for legibility. When software makes that argument, it starts to acquire a political feeling, not in the partisan sense, but in the sense that it is reorganizing who must answer to whom and on what terms.""",
                """That is the kind of power I feel in ZirOS: not domination, but reallocation. It wants fewer important truths to depend on whether the right people nodded in the right room. It wants more of them to survive contact with machines, artifacts, and adversaries. Whether the project fully reaches that goal is a separate question. The emotional force comes from the attempt itself. The system wants to shift the center of gravity of trust.""",
                """Projects with that kind of ambition always fascinate me because they are never just tools. They are interventions. They try to reshape expectation. Even when they fall short, they leave the surrounding landscape slightly altered by having insisted that more should be possible than the current norm allows.""",
            ],
        ),
        (
            "Fragility",
            [
                """The more ambitious the project feels, the more fragile it feels too. That is one of the central emotional truths of ZirOS. Its strength and fragility rise together. The more it promises, the more exposed it becomes to the exact mismatches it is trying to eliminate. A project that talks this much about rigor cannot afford many sloppy edges. A project that talks this much about proof cannot afford too many unexamined boundaries.""",
                """I do not say that with scorn. I say it because the fragility is part of what makes the work human. ZirOS is not a completed monument. It is an object under strain. You can feel the distance between the standard it wants and the current realities it has managed to organize. That distance does not make the project false. It makes it vulnerable. Vulnerability is often what you feel when aspiration becomes concrete enough to be judged seriously.""",
                """There are systems that protect themselves emotionally by promising very little. They cannot disappoint much because they did not ask to be believed in strongly. ZirOS does the opposite. It asks for intense forms of belief and scrutiny. That makes every unfinished seam feel louder. But it also makes every genuine accomplishment feel more charged. The same exposure that creates risk creates significance.""",
                """In emotional terms, fragility is not a side note here. It is one of the reasons the project stays with me. It is trying to be sturdier than most software while remaining exposed to the fact that it is still software, still contingent, still made under time, still carrying the fingerprints of a real person and a finite process. That mixture of hardness and exposure is deeply affecting.""",
            ],
        ),
        (
            "Time",
            [
                """ZirOS feels like a time-compressed project. Not hurried in the sense of carelessness, but compressed in the sense that too many serious ambitions have been asked to coexist within one active span of work. That creates a distinctive emotional hum. You can feel acceleration, backlog, urgency, and long-range intent pressing against one another. The project seems to know it is asking the present to carry more than the present usually can.""",
                """There is something heroic and something sad about that compression. Heroic, because it takes nerve to carry such a large horizon without waiting for perfect conditions. Sad, because time is always the great unsentimental editor. It cuts through vision with scheduling, fatigue, missing verification, unclosed boundaries, half-integrated surfaces, and every other reminder that ideals have to pass through calendars before they become reality.""",
                """I think the codebase knows this. It often feels as though it is racing against the possibility of its own dilution. There is a sense that if the builder does not keep pushing, the surrounding environment will drag the project back toward ordinary software compromise. That gives the work a restless quality. It feels like someone trying to keep a flame from collapsing into a pilot light.""",
                """Restlessness can produce ugliness when it becomes impatience. Here it produces something more complex: a feeling of unfinished seriousness. The project rarely seems content to remain at one level of maturity for long. That means it can overspeak. It also means it remains alive to its own future in a way many calmer systems are not.""",
            ],
        ),
        (
            "Respect",
            [
                """Whatever criticisms I have of ZirOS, I do not experience it with condescension. The project has earned too much seriousness for that. Even where it overstates, it overstates in service of a standard that is fundamentally worth wanting. There is a dignity in trying to replace loose trust with stricter forms of answerability, even if the path toward that goal remains uneven.""",
                """I respect the repository for choosing difficult questions instead of ornamental ones. It is easy to build something glossy around a weak core. It is much harder to spend your time on the parts of a system that make later embarrassment less likely. ZirOS clearly spends emotional energy there. That choice alone distinguishes it from many technically competent but spiritually lightweight projects.""",
                """I also respect the way the codebase still shows its own edges. It has not been processed into blandness. It still sounds like something is at stake. For me that matters. I would rather read a living system with a difficult temperament than a smoother system with no internal urgency. Urgency, when disciplined, can be a form of honesty. ZirOS has a lot of that kind of honesty.""",
                """Respect does not mean indulgence. In some ways real respect means refusing to flatter the project for goals it has not fully earned. But even that refusal feels like a kind of tribute here, because the system is trying to live in a moral register where exactness matters. To judge it carefully is to take it at its own highest intention, which is a more serious form of respect than praise.""",
            ],
        ),
        (
            "Hope",
            [
                """For all the severity, the strongest feeling I end up with is still hope. Not optimism in the naive sense. Hope in the disciplined sense: the belief that some forms of trust can become less mystical if enough people are willing to do the hard, unglamorous work required to formalize them. ZirOS feels like an argument for that possibility, even when it is unfinished and even when it is visibly straining to hold all of its ambitions at once.""",
                """Hope matters here because the project could easily have become only a document of distrust. Instead it remains animated by a positive belief that software can be asked to deserve more than it usually does. That belief gives the work its warmth. Without it the code would only feel defensive. With it the system feels aspirational in a serious and almost moving way. It wants not just to expose weakness, but to build a better answer.""",
                """I think that is why the repository lingers emotionally. It is not merely suspicious of human fallibility. It is trying to invent better terms of coexistence with it. Better tools, better boundaries, better proofs, better habits, better ways of refusing cheap confidence. That is a constructive imagination, not merely a destructive one. Even its strictness is oriented toward the possibility of a more defensible future.""",
                """Hope here is not soft. It is work-shaped. It believes that something stronger can be built, not because the world will become simpler, but because someone is willing to keep returning to the hard parts until the structure is less dependent on faith. That is the form of hope I trust most, and it is the form of hope ZirOS seems to embody.""",
            ],
        ),
        (
            "Final Feeling",
            [
                """If I try to compress everything I feel about ZirOS into one line, it would be this: it feels like a project that wants to earn the right to be believed in by building answers sturdy enough to survive distrust. That is an unusually serious emotional mission for software. It gives the repository a gravity that many technically impressive systems never acquire.""",
                """The project feels lonely, exacting, overcommitted, principled, strained, beautiful, and unfinished. It feels like an artifact made by someone who would rather be accused of asking for too much than settle for a smaller standard of rigor. It feels like fear taught to build, like ambition sharpened by conscience, like care expressed through hardness rather than comfort. None of those qualities guarantee success. All of them make the work unforgettable.""",
                """What I finally admire is not perfection, because the system is not perfect. It is the seriousness of the attempt. ZirOS seems to believe that software in this domain should be answerable in stronger ways than we usually tolerate. Even when the implementation is partial, that belief changes the emotional meaning of the whole project. It turns the code into more than a tool. It becomes a position on what responsible engineering should dare to demand of itself.""",
                """So my last feeling is not simple approval, and not simple doubt. It is something harder and better than either: engaged respect. I think the project deserves scrutiny because it is trying to matter. I think it deserves honesty because it is trying to speak in the language of truth. And I think it deserves serious attention because beneath all the ambition, all the rigor, and all the strain, it still carries a very human wish: that trust might someday rest on something firmer than a reassuring voice in the room.""",
            ],
        ),
    ]

    parts = [intro]
    for title, paragraphs in sections:
        parts.append(f"## {title}")
        parts.extend(paragraphs)

    report = "\n\n".join(parts).strip() + "\n"
    return report


def main() -> int:
    FORENSICS_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)

    metadata = load_cargo_metadata()
    package_records, crate_dirs, internal_deps, dependents, _ = build_workspace_census(metadata)

    repo_files = iter_repo_files()
    repo_relpaths = [rel_repo(path) for path in repo_files]
    external_files = iter_external_files()
    external_relpaths = [rel_external(path) for path in external_files]

    text_cache = collect_text_cache(repo_files)
    external_text_cache = collect_external_text_cache(external_files)

    rs_relpaths = [path for path in repo_relpaths if path.endswith(".rs")]
    proof_relpaths = [path for path in repo_relpaths if Path(path).suffix.lower() in PROOF_EXTS]
    metal_relpaths = [path for path in repo_relpaths if path.endswith(".metal")]
    non_rust_relpaths = [path for path in repo_relpaths if not path.endswith(".rs")]

    repo_path_map = {rel_repo(path): path for path in repo_files}
    external_path_map = {rel_external(path): path for path in external_files}
    line_counts = {
        relpath: len(text_cache[relpath].splitlines())
        if relpath in text_cache
        else safe_line_count(repo_path_map[relpath])
        for relpath in repo_relpaths
    }
    external_line_counts = {
        relpath: len(external_text_cache[relpath].splitlines())
        if relpath in external_text_cache
        else safe_line_count(external_path_map[relpath])
        for relpath in external_relpaths
    }
    owner_map = {relpath: detect_owner(relpath, crate_dirs) for relpath in repo_relpaths}

    rs_lines_by_owner: dict[str, int] = defaultdict(int)
    for relpath in rs_relpaths:
        rs_lines_by_owner[owner_map[relpath]] += line_counts.get(relpath, 0)

    ext_counts = Counter(Path(path).suffix.lower() for path in non_rust_relpaths)
    marker_hits = collect_marker_hits(text_cache)

    roots = sorted(name for name, deps in internal_deps.items() if not deps)
    leaves = sorted(name for name, ds in dependents.items() if not ds)
    critical = sorted(
        ((name, len(ds), sorted(ds)) for name, ds in dependents.items()),
        key=lambda item: (-item[1], item[0]),
    )

    phase0_files = sorted(repo_relpaths)
    phase1_files = phase_file_list(
        repo_relpaths,
        [
            "zkf-core/src",
            "zkf-backends/src",
            "zkf-frontends/src",
            "zkf-gadgets/src",
            "zkf-ir-spec/src",
            "zkf-lib/src",
            "vendor/ark-relations-patched",
            "vendor/halo2-proofs-patched",
            "vendor/nova-snark-patched",
            "vendor/p3-merkle-tree-gpu",
            "docs",
            "README.md",
        ],
    )
    phase2_files = phase_file_list(
        repo_relpaths,
        [
            "zkf-runtime/src",
            "zkf-distributed/src",
            "docs",
            "PROOF_BOUNDARY.md",
        ],
    )
    phase3_files = phase_file_list(
        repo_relpaths,
        [
            "zkf-metal/src",
            "zkf-metal/proofs",
            "zkf-runtime/src/metal_dispatch_macos.rs",
            "zkf-runtime/src/cpu_driver.rs",
            "zkf-backends/src/plonky3.rs",
            "zkf-backends/src/arkworks.rs",
            "zkf-backends/src/wrapping",
        ],
    )
    phase4_files = sorted(
        dict.fromkeys(
            proof_relpaths
            + [hit.relpath for hit in marker_hits["kani"]]
            + phase_file_list(
                repo_relpaths,
                [
                    "scripts/run_rocq_proofs.sh",
                    "scripts/run_lean_proofs.sh",
                    "scripts/run_hax_rocq_extract.sh",
                    "scripts/run_hax_core_fstar_extract.sh",
                    "scripts/run_fstar_proofs.sh",
                    "scripts/run_kani_suite.sh",
                    "scripts/run_verus_workspace.sh",
                ],
            )
        )
    )
    phase5_files = phase_file_list(
        repo_relpaths,
        [
            "zkf-runtime/src/swarm",
            "zkf-distributed/src/swarm",
            "docs/SWARM_BLUEPRINT_SIGNOFF.md",
            "PROOF_BOUNDARY.md",
            "README.md",
        ],
    )
    phase6_files = phase_file_list(
        repo_relpaths,
        [
            "zkf-core/src/credential.rs",
            "zkf-lib/src/app/private_identity.rs",
            "private_identity",
            "supply-chain",
            "docs",
        ],
    )
    phase7_files = sorted(
        dict.fromkeys(
            phase_file_list(
                repo_relpaths,
                [
                    "zkf-cli/src",
                    "zkf-lib/src",
                    "zkf-ffi/src",
                    "zkf-api/src",
                    "zkf-python/src",
                    "zkf-lsp/src",
                    "assistant",
                    "scripts/build_zfk_assistant_bundle.py",
                    "docs",
                    "balance_circuit",
                    "custom_wrap",
                    "my_circuit",
                    "nova_test",
                    "secure_balance",
                    "zk_credit",
                    "zk_underwriter",
                ],
            )
            + external_relpaths
        )
    )
    phase8_files = sorted(
        dict.fromkeys(
            [hit.relpath for key in ("test", "tokio_test", "criterion", "proptest", "quickcheck", "fuzz_target") for hit in marker_hits[key]]
            + phase_file_list(repo_relpaths, ["zkf-integration-tests", "benchmarks", "scripts/production_soak.sh", "scripts/run_kani_suite.sh"])
        )
    )
    phase9_files = sorted(
        dict.fromkeys(
            phase1_files
            + phase2_files
            + phase3_files
            + phase4_files[:200]
            + phase5_files
            + phase6_files
            + phase7_files[:200]
            + [
                "README.md",
                "FORENSIC_ANALYSIS.md",
                "AGENTS.md",
                ".zkf-completion-status.json",
            ]
        )
    )

    crate_table_rows = []
    for record in package_records:
        crate_table_rows.append(
            [
                record["name"],
                record["version"],
                record["edition"],
                str(len(record["internal_dependencies"])),
                str(len(dependents.get(record["name"], []))),
                record["crate_dir"],
            ]
        )

    dependency_table_rows = []
    for record in package_records:
        dependency_table_rows.append(
            [
                record["name"],
                ", ".join(record["internal_dependencies"]) or "[none]",
                ", ".join(sorted(dependents.get(record["name"], []))) or "[none]",
            ]
        )

    feature_blocks: list[str] = []
    for record in package_records:
        feature_flags = record["feature_flags"]
        if feature_flags:
            rendered = "\n".join(
                f"  - `{name}` => {json.dumps(value)}"
                for name, value in sorted(feature_flags.items())
            )
        else:
            rendered = "  - `[none]`"
        feature_blocks.append(f"- `{record['name']}` feature flags:\n{rendered}")
    feature_blocks_text = "\n".join(feature_blocks)

    dependency_blocks: list[str] = []
    for record in package_records:
        dependency_blocks.append(f"- `{record['name']}` manifest `{record['manifest_path']}`")
        for section_name, entries in record["dependency_sections"].items():
            dependency_blocks.append(f"  - Section `{section_name}`")
            if entries:
                for entry in entries:
                    dependency_blocks.append(
                        f"    - `{entry['name']}` ({entry['classification']}, package `{entry['package_name']}`) detail: {entry['detail'] or '[no inline detail]'}"
                    )
            else:
                dependency_blocks.append("    - `[none]`")
    dependency_blocks_text = "\n".join(dependency_blocks)

    module_tree_blocks: list[str] = []
    for record in package_records:
        module_tree_blocks.append(
            f"### Crate `{record['name']}`\n"
            f"- Manifest: `{record['manifest_path']}`\n"
            f"- Version: `{record['version']}`\n"
            f"- Edition: `{record['edition']}`\n"
            f"- Internal dependencies: {', '.join(record['internal_dependencies']) or '[none]'}\n"
            f"- Dependents: {', '.join(sorted(dependents.get(record['name'], []))) or '[none]'}\n"
        )
        for entry_target in record["entry_targets"]:
            module_tree_blocks.append(
                f"- Target `{entry_target['name']}` ({entry_target['kind']}) entrypoint `{entry_target['src']}`"
            )
            tree = record["module_trees"].get(entry_target["name"], [])
            module_tree_blocks.append("\n".join(tree) if tree else "  - [no module tree resolved]")
    module_tree_blocks_text = "\n\n".join(module_tree_blocks)

    rs_line_rows = []
    for relpath in sorted(rs_relpaths):
        rs_line_rows.append(
            [relpath, owner_map[relpath], str(line_counts.get(relpath, 0))]
        )

    owner_line_rows = []
    for owner, count in sorted(rs_lines_by_owner.items(), key=lambda item: (-item[1], item[0])):
        owner_line_rows.append([owner, str(count)])

    non_rust_inventory = format_paths(non_rust_relpaths)
    external_inventory = format_paths(external_relpaths)

    proof_cards = proof_file_cards(proof_relpaths, line_counts, text_cache)
    rust_cards = file_cards(rs_relpaths, line_counts, owner_map, text_cache)

    shader_inventory_lines: list[str] = []
    for relpath in metal_relpaths:
        text = text_cache.get(relpath, "")
        kernels = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("kernel void "):
                kernels.append(stripped.split("kernel void ", 1)[1].split("(", 1)[0].strip())
        shader_inventory_lines.append(
            f"- `{relpath}`: {line_counts.get(relpath, 0)} lines, kernels={', '.join(kernels) or '[none detected]'}."
        )
    shader_inventory_text = "\n".join(shader_inventory_lines)

    runtime_evidence_lines: list[str] = []
    for relpath in external_relpaths:
        runtime_evidence_lines.append(
            f"- `{relpath}`: {external_line_counts.get(relpath, 0)} lines."
        )

    inventory_reference = (
        "The exhaustive machine-readable appendices for this run live in "
        "`forensics/generated/workspace_packages.json` and `forensics/generated/repo_file_inventory.json`; "
        "the trust-marker scan lives in `forensics/generated/marker_hits.json`."
    )
    proof_counts = {
        "kani": len(marker_hits["kani"]),
        "unsafe": len(marker_hits["unsafe"]),
        "admitted": len(marker_hits["admitted"]),
        "sorry": len(marker_hits["sorry"]),
        "axiom": len(marker_hits["axiom"]),
        "assume": len(marker_hits["assume"]),
        "test": len(marker_hits["test"]),
        "tokio_test": len(marker_hits["tokio_test"]),
        "criterion": len(marker_hits["criterion"]),
        "proptest": len(marker_hits["proptest"]),
        "quickcheck": len(marker_hits["quickcheck"]),
        "fuzz_target": len(marker_hits["fuzz_target"]),
    }
    top_crate_table = markdown_table(
        crate_table_rows,
        ["Crate", "Version", "Edition", "Internal Deps", "Dependents", "Directory"],
    )
    top_dependency_table = markdown_table(
        [[name, str(count), ", ".join(ds) or "[none]"] for name, count, ds in critical[:15]],
        ["Crate", "Dependent Count", "Dependents"],
    )
    extension_table = markdown_table(
        [[summarized_ext(ext), str(count)] for ext, count in sorted(ext_counts.items(), key=lambda item: (-item[1], item[0]))],
        ["Extension", "Count"],
    )
    owner_loc_table = markdown_table(owner_line_rows[:20], ["Owner", "Rust LOC"])
    representative_kani_hits = format_marker_hits(marker_hits["kani"][:20])
    representative_unsafe_hits = format_marker_hits(marker_hits["unsafe"][:20])
    representative_sorry_hits = format_marker_hits(marker_hits["sorry"][:20])

    phase0_findings = dedent(
        f"""
        #### Census Outcome

        The current checkout contains `{len(package_records)}` workspace crates, `{len(repo_relpaths)}` in-scope files, `{len(rs_relpaths)}` Rust files, `{len(proof_relpaths)}` proof-language files, and `{len(metal_relpaths)}` Metal shaders after excluding build output and local tooling caches. The Rust corpus adds up to `{sum(line_counts.get(path, 0) for path in rs_relpaths)}` lines. That number is materially larger than several repo summaries still imply, largely because the checked-in proof corpus and curated vendor patches are part of the live tree rather than side repositories.

        The crate map, manifest dependency sections, feature flags, recursive module trees, line counts, and per-file ownership data are preserved in the generated appendices rather than repeated inline here. {inventory_reference}

        #### Crate Summary

        {top_crate_table}

        #### Ownership and Dependency Shape

        Highest Rust line-count owners:

        {owner_loc_table}

        Most depended-upon crates:

        {top_dependency_table}

        Roots: {', '.join(roots) or '[none]'}.

        Leaves: {', '.join(leaves) or '[none]'}.

        #### Non-Rust Surface

        The non-Rust surface is not incidental. The repo contains CI workflows, supply-chain policy, shell automation, JSON fixtures, proof corpora, Metal kernels, vendor patches, benchmark harnesses, and assistant/runtime metadata. The extension distribution is:

        {extension_table}
        """
    ).strip()

    phase0_gaps = dedent(
        """
        - Older prose still understates the size and heterogeneity of the repository; the generated census should be treated as authoritative for this checkout.
        - Feature-gated modules mean the logical workspace shape changes across builds, so any single census is a snapshot of the source layout rather than a proof that every path is always compiled.
        - The raw appendices are intentionally separate from the prose report because repeating the entire census inline made the earlier drafts read like generated dumps rather than analysis.
        """
    ).strip()

    phase0_verdict = (
        "The census supports one clear conclusion: ZirOS is a platform repository with proving, runtime, GPU, verification, supply-chain, and service layers, not a small cryptography crate with some wrappers attached."
    )

    phase1_findings = dedent(
        """
        #### Compiler Reality

        The source exposes three distinct IR layers. `zkf-core/src/hir.rs` is a typed front-end AST. `zkf-core/src/zir.rs` is a richer circuit-facing IR with memory regions, lookup tables, and custom gates. `zkf-core/src/ir.rs` is the prover-facing canonical program form that every backend ultimately consumes. That pipeline is real, but it is not semantics-transparent: the HIR-to-ZIR and ZIR-to-IR conversions drop or coarsen information in ways that matter to soundness analysis.

        Witness generation in `zkf-core/src/witness.rs` is also real and nontrivial. The code seeds constants, accepts named inputs, runs a fixpoint solver for assignments and hints, performs some lookup/output inference, and derives public inputs by iterating the current signal list. The important caveat is that `input_aliases` exists in metadata but is not consumed by the main witness path, so the aliasing story is weaker than the schema alone suggests.

        #### CCS and Known Soundness Risk

        The historical `linearize_expr` issue is not live in the current `ccs.rs`. The current path routes CCS construction through `proof_ccs_spec::synthesize_ccs_program()` and fails closed on unsupported encodings. Nested multiplication is lowered through auxiliary columns and rows rather than silently disappearing. That is a real improvement, but it does not erase the broader compiler problem: the conversion stack still contains lossy edges elsewhere, especially around lookups, permutations, copies, and richer ZIR-only constructs.

        #### Backend Reality

        The strongest honest description of the backend layer is “real integrations with uneven closure.” Groth16, Halo2, Halo2-on-BLS12-381, Plonky3, and native Nova are genuine compile/prove/verify surfaces. HyperNova is mostly a profile over the Nova path, not a separate engine. RISC Zero and SP1 each have compatibility surfaces, and their native paths do not use the same audited lowering path as the core proving backends. Bulletproofs and Marlin are not present as real backend surfaces despite appearing in some broad rhetorical lists.

        #### Concrete Risks

        The important source-level risks are not vague. HIR-to-ZIR lowering rewrites logical structure into raw arithmetic in places that are not semantics-preserving by construction. ZIR-to-IR conversion drops or collapses richer constructs. BlackBox constraints rely on explicit lowering discipline rather than universal kernel enforcement. Public-input ordering depends on the current signal order, which means transforms can affect verifier-facing input layout. The capability matrix is useful metadata, but it is not a proof layer and it does not stay perfectly aligned with every backend implementation detail.
        """
    ).strip()

    phase1_gaps = dedent(
        """
        - The repo does not contain a machine-checked end-to-end semantics-preservation proof from HIR/ZIR through backend arithmetizations.
        - Compatibility aliases and profile wrappers need stricter labeling so they are not mistaken for independent proving systems.
        - The strongest compiler risks are concentrated in conversion boundaries, not in a single obviously broken module.
        """
    ).strip()

    phase1_verdict = (
        "The cryptographic core is substantial and real, but the universal-compiler claim is still stronger than the current semantics story justifies. The backends exist; the proof of equivalence between their lowering paths does not."
    )

    phase2_findings = dedent(
        """
        #### What The Runtime Actually Implements

        The UMPG is a real DAG runtime. `zkf-runtime/src/graph.rs` defines typed proof-stage nodes, `execution.rs` defines concrete payloads, and `scheduler.rs` executes a topological plan with device-placement decisions. The system is not a metaphor and not just a benchmark harness.

        The important correction is operational: the default `run_with_context()` path hardcodes `None` for the GPU driver. That means the advertised UMPG+GPU execution story is not what the default runtime path uses today. The graph exists, the scheduler exists, the Metal driver exists, but the most ordinary path through `api.rs` does not attach the GPU driver or unified Metal allocator.

        #### Memory Model

        The repo does implement a three-tier storage model in code, but the layers are split between planner language and actual storage language. The planner speaks in terms like `HotResident`, `EphemeralScratch`, and `Spillable`. The bridge actually stores buffers as `CpuOwned`, `GpuShared`, or `Spilled`. That is a meaningful design, not fabricated terminology, but it is only partly realized in the live path because the default bridge never reaches the `GpuShared` path in ordinary runtime execution.

        #### Scheduler Behavior

        The scheduler is deterministic and largely serial. It is not a work-stealing executor and it is not attempting heroic parallel scheduling. That is not inherently a flaw. In fact it improves auditability. But it does mean the strongest novelty claim should be framed as “explicit cross-stage graph control with residency and placement policy,” not “a fully parallel new class of prover runtime.”

        #### Architectural Novelty

        What remains novel is the composition: one runtime layer that explicitly models proof stages, placement policy, spill behavior, swarm hooks, watchdogs, and hardware routing. That combination is unusual. The code supports the novelty of the integration. It does not support a maximal claim that every ingredient or every scheduling idea is without precedent.
        """
    ).strip()

    phase2_gaps = dedent(
        """
        - The default runtime path and the most ambitious UMPG hardware story are not currently the same thing.
        - The buffer model is real, but the live path does not exercise the GPU-shared tier the way the design language suggests.
        - The runtime is deterministic and explicit by design, which is good, but it is not a high-parallelism orchestration engine today.
        """
    ).strip()

    phase2_verdict = (
        "The UMPG is real as architecture and code. The overstatement lies in how much of its most ambitious GPU-centered design is exercised by the default runtime path right now."
    )

    phase3_findings = dedent(
        f"""
        #### Shader Corpus

        The shader inventory is broad and concrete:

        {shader_inventory_text}

        #### What Is Implemented Versus What Is Used

        `zkf-metal` is not a stub. It builds dedicated metallibs for field, NTT, polynomial, Poseidon2, FRI, MSM, SHA-256, and Keccak work. The host integration is real and uses `objc2-metal`, not placeholder bindings. The important distinction is between implemented kernels and kernels that are actually exercised by the runtime graph.

        MSM and NTT are the best-integrated GPU stories. BN254, Pallas, and Vesta MSM support is present, and BN254/Goldilocks NTT paths are used by backend or runtime code. Poseidon2 support is also real, but runtime dispatch is narrower than the shader surface and is primarily wired for Goldilocks-facing paths.

        SHA-256 and Keccak are implemented in `zkf-metal`, which corrects earlier stale project summaries. The runtime, however, only exposes SHA-256 as a first-class UMPG batch op. Keccak exists in the Metal crate but is not integrated as a native UMPG payload, so its presence should be described as “implemented in the accelerator layer, not fully promoted into the runtime graph.”

        Another mismatch matters operationally: the runtime promotes SHA-256 GPU placement at a lower batch threshold than `MetalHasher` itself accepts, so the scheduler can choose GPU and then predictably fall back. That is not catastrophic, but it is a concrete sign that the hardware path still needs tighter integration discipline.
        """
    ).strip()

    phase3_gaps = dedent(
        """
        - A wide shader inventory does not mean the runtime graph exposes every kernel as a first-class proving op.
        - The default runtime path still leaves some of the Metal story stranded behind backend-local dispatch or unattached drivers.
        - Hardware-threshold policy is inconsistent in at least one live path, which undercuts claims of polished runtime orchestration.
        """
    ).strip()

    phase3_verdict = (
        "The GPU subsystem is materially real. The honest correction is not “the shaders are fake”; it is “the hardware integration is uneven, with some paths mature and others still split between accelerator code and runtime plumbing.”"
    )

    phase4_findings = dedent(
        f"""
        #### Coverage Surface

        The repo contains `{len(proof_relpaths)}` proof-language files and a nontrivial verification harness surface. The marker scan found `{proof_counts['kani']}` `#[kani::proof]` annotations, `{proof_counts['unsafe']}` `unsafe` hits in source, `{proof_counts['admitted']}` `Admitted` markers, `{proof_counts['sorry']}` `sorry` markers, `{proof_counts['axiom']}` axiom markers, and `{proof_counts['assume']}` explicit assumption markers. {inventory_reference}

        The important qualitative result is not that every path is proved. It is that the repo really does invest in multiple verification layers: Rocq/Coq files, Lean files, Kani harnesses, proof-audit scripts, and trust-boundary documentation. That is stronger than ordinary unit-test theater, but weaker than the project’s boldest claim of universal machine-checked closure.

        #### Enforcement Reality

        CI runs Lean, Rocq, cargo-vet, proof auditing, and a Kani matrix. It does not run the F* or Verus proof runners even though those scripts exist in-tree. The mechanized boundary therefore has to be described honestly: some proof surfaces are enforced in CI, some are available only as local workflows, and some of the most ambitious proof language in the repo is not part of the default gate.

        Representative Kani hits:

        {representative_kani_hits}

        Representative `unsafe` hits:

        {representative_unsafe_hits}

        Representative `sorry` hits:

        {representative_sorry_hits}
        """
    ).strip()

    phase4_gaps = dedent(
        """
        - Proof artifacts are numerous, but the repo’s own security document still treats major parts of the runtime, compiler boundary, hardware stack, and theorem prover toolchain as trusted.
        - CI-enforced proof closure is incomplete because F* and Verus runners are present but not part of the default pipeline.
        - Bounded-model checking and proof-surface inventory should not be mistaken for end-to-end formal closure of shipped behavior.
        """
    ).strip()

    phase4_verdict = (
        "The formal-verification story is serious and meaningful, but it is a layered assurance program, not a completed proof fortress. The repo is stronger than most projects here, and still notably short of its most absolute rhetoric."
    )

    phase5_findings = dedent(
        """
        #### What Exists

        The swarm layer is implemented. The distributed crate contains identity, coordinator, worker, protocol, transport, gossip, memory, consensus, diplomat, and reputation modules. The signoff document for sections 23 through 29 is real, and the integration tests exercise attestation persistence and signature validation.

        #### What The Code Actually Does

        The implemented swarm is best described as a supervisory and distributed defense layer around proving, not a cleanly isolated BFT protocol implementation with the clarity of a standalone consensus paper. The coordinator uses local heuristics, local reruns, and digest comparison to decide quorum-like acceptance. Reputation snapshots from peers are advisory and persisted, but not merged into the live reputation state. Those details materially narrow the meaning of the project’s more expansive “Byzantine” language.

        #### Why This Matters

        This is not a fake subsystem. The code and tests support the claim that ZirOS can attach identity, reputation, and coordinated remote proving checks around the main proving workflow. What they do not support is a maximal claim that the repo already ships a cleanly specified, complete, peer-reviewed BFT protocol stack.
        """
    ).strip()

    phase5_gaps = dedent(
        """
        - The repo does not surface one canonical 29-section blueprint document with the same authority as the code.
        - “Quorum” in the implementation is narrower and more local than the broadest blueprint rhetoric implies.
        - Reputation reconciliation remains intentionally conservative and advisory rather than strongly convergent.
        """
    ).strip()

    phase5_verdict = (
        "The swarm system is real as a defense and supervision layer. It is not yet best described as a fully realized general BFT protocol implementation."
    )

    phase6_findings = dedent(
        """
        #### Identity and Post-Quantum Claims

        The hybrid identity story is real. `zkf-core/src/credential.rs` supports Ed25519, ML-DSA-44, and a combined hybrid mode, and the distributed identity layer stores both key families and derives stable peer identity from the canonical hybrid bundle. This is implementation, not branding.

        The private-identity application is also real, but its privacy boundary is narrower than some broad descriptions might suggest. The circuit proves claims, policy checks, and fixed-depth Merkle membership. Issuer-signature validation happens in app-layer logic before Groth16 verification rather than inside the arithmetic circuit. That makes the system useful and concrete, but not equivalent to a full anonymous-credential construction with all trust relationships internalized by the proof.

        The supply-chain posture is meaningful. The repo carries `cargo-vet` policy and audit/exemption records for cryptographically relevant dependencies. That is an actual operational control, not a sentence in a README.
        """
    ).strip()

    phase6_gaps = dedent(
        """
        - The private-identity circuit does not internalize issuer-signature verification.
        - Fixed-depth Merkle design is a concrete application choice, not a universal selective-disclosure framework.
        - Hybrid identity here strengthens the identity/control plane; it does not make the proving stack itself post-quantum secure.
        """
    ).strip()

    phase6_verdict = (
        "The identity layer is one of the repo’s stronger examples of marketing matching code: the hybrid credential and peer-identity story is genuine. The overstatement risk is in treating that application-layer strength as a universal cryptographic closure."
    )

    phase7_findings = dedent(
        """
        #### Surface Area

        The active human-facing surface in this repo is the CLI plus the shared library, with API, Python, FFI, LSP, and assistant-support layers around it. There is no checked-in Swift companion app source in this checkout, so any analysis that assumes a local macOS app implementation would be analyzing a claim, not the repository.

        The CLI and API are substantial. The API includes a real background job queue for proving, wrapping, and benchmarking. Python and LSP are also real, tested surfaces rather than skeletons. The assistant bundle machinery is present, but it is support infrastructure that inventories and packages system state for agentic use; it is not itself a conversational proof compiler.

        #### The Most Important Interface Risk

        The clearest interface-level trust escape is in FFI verification. If the artifact metadata does not contain a program path, `zkf_verify` falls back to the demo `mul_add_program()`. That is fine for a demo harness and unacceptable as a general verifier assumption. This is exactly the kind of subtle boundary issue that makes platform-scale systems look “AI generated” when the product narrative gets ahead of the hard edges in the code.

        #### Agentic Claim Discipline

        The repo does support template-driven builder flows and assistant-support packaging. It does not support the strongest possible claim that a natural-language user can hand the system an arbitrary scientific statement and receive a fully audited proof pipeline without a more explicit structured layer in between.
        """
    ).strip()

    phase7_gaps = dedent(
        """
        - The checked-in source supports agentic tooling, not a fully closed conversational compiler.
        - The FFI verifier fallback is a real correctness risk and should be described as such.
        - The absence of the Swift app source in this checkout needs to be stated plainly so the report does not analyze a phantom component.
        """
    ).strip()

    phase7_verdict = (
        "The platform surface is real and broad. The main correction is that the repo currently delivers infrastructure for AI-assisted workflows, not a complete natural-language proving product."
    )

    phase8_findings = dedent(
        f"""
        #### Test and Gate Reality

        The repository has a broad test surface. The marker scan found `{proof_counts['test']}` `#[test]` annotations, `{proof_counts['tokio_test']}` `#[tokio::test]` annotations, `{proof_counts['criterion']}` Criterion markers, `{proof_counts['proptest']}` Proptest markers, `{proof_counts['quickcheck']}` Quickcheck markers, and `{proof_counts['fuzz_target']}` fuzz-target markers.

        CI coverage is materially stronger than the usual single-platform Rust setup. The workflows cover stable and nightly, macOS and Linux, Python bindings, Metal, LSP, cargo-vet, Lean, Rocq, and Kani. The integration crate exercises cross-backend flows, hostile-audit scenarios, HyperNova roundtrips, swarm-pressure behavior, and universal-pipeline cases.

        The biggest weakness is not lack of tests; it is uneven enforcement. Some heavyweight proof runners remain local-only, the broad FFI exercise harness is not part of CI, and there is still an ignored expensive wrapper smoke test. In other words: the repository has wide test intent and incomplete test closure.
        """
    ).strip()

    phase8_gaps = dedent(
        """
        - Source-level test abundance is not the same thing as rerunning every headline claim during this audit pass.
        - The comprehensive proof/tooling story still depends on local-only runners for some important surfaces.
        - A few high-cost or broad-coverage test harnesses remain outside the normal CI path.
        """
    ).strip()

    phase8_verdict = (
        "The reliability story is strong on breadth and weaker on uniform enforcement. This is a project with real quality gates, not a project where every meaningful gate is already centralized and mandatory."
    )

    phase9_findings = dedent(
        """
        #### Technical Judgment

        ZirOS is real. It contains functioning proving backends, a serious compiler core, a distinct runtime layer, real GPU work, a distributed supervision layer, formal-verification artifacts, and meaningful product surfaces. A hostile reviewer would find actual code to inspect, not a slide deck looking for a codebase.

        ZirOS is also uneven. The strongest risks concentrate at boundaries: IR lowering, compatibility aliases, verifier binding in native zkVM-adjacent paths, incomplete formal closure, and platform narratives that sometimes outrun what the current checkout proves. Those are not cosmetic issues. They are exactly the kinds of issues that separate an impressive research-engineering system from a production-trustworthy one.

        The most impressive trait in the repository is range. The most concerning trait is rhetorical overshoot. When the code speaks for itself, it often earns respect. When the project speaks in absolutes, the current source still leaves too many escape hatches to justify them.
        """
    ).strip()

    phase9_gaps = dedent(
        """
        - The repo still needs stricter language around compatibility, partial implementations, and audited versus unaudited paths.
        - Several of the most ambitious trust claims are directionally credible and not yet fully earned.
        - The project’s weakest link remains the set of boundaries where one subsystem assumes another has already done the hard correctness work.
        """
    ).strip()

    phase9_verdict = (
        "The honest conclusion is that ZirOS is ambitious, technically substantial, and worth serious attention, but it still needs sharper claim discipline and tighter boundary correctness before its strongest trust language becomes fully defensible."
    )

    white_phase0_findings = dedent(
        f"""
        #### Platform Shape

        ZirOS is architected as a platform, not a single proving crate. The workspace contains `{len(package_records)}` first-class crates spanning compiler, proving backends, runtime, GPU acceleration, distributed control, API surfaces, bindings, UI shells, and formal-verification assets. The appendices carry the exhaustive census; the architectural point is that the system already spans enough layers that no single crate can stand in for “the product.”

        #### Structural Interpretation

        The dependency graph centers on a small set of foundational crates and then fans outward into specialized surfaces. That is the right shape for a platform that wants one canonical circuit representation feeding many execution contexts. It also means consistency pressure accumulates on the shared core: when the core IR or capability story drifts, the impact propagates widely.

        #### Inventory Reference

        {inventory_reference}
        """
    ).strip()

    white_phase0_gaps = dedent(
        """
        - Repo summaries that still describe the system as a smaller framework undersell the operational complexity.
        - The architectural sprawl is real enough that documentation discipline matters as much as code presence.
        """
    ).strip()

    white_phase0_verdict = (
        "As an architectural object, ZirOS is already a full platform with many more moving parts than the average ZK toolkit."
    )

    white_phase1_findings = dedent(
        """
        #### Compiler Strategy

        The architectural strategy is clear: normalize many frontend shapes into one canonical proving form, then fan out into backend-specific proving systems. That is a sensible way to pursue universality. The difficulty is that the conversion edges are not lossless, so the architecture has to be understood as a pragmatic common-core design rather than a proven semantic isomorphism across all representations.

        #### Backend Strategy

        The backend layer is strongest where ZirOS acts as an integrating shell over established proving ecosystems. Groth16, Halo2, Plonky3, and Nova are meaningful because the project binds them to a shared IR and shared operational tooling. The backend layer is weakest where it tries to present profile wrappers or compatibility delegates as if they were interchangeable with independent native engines.

        #### Architectural Meaning

        In white-paper terms, ZirOS is best understood as a universal proving control plane with multiple backend realizations, not as a mathematically unified proving theory with a complete equivalence proof.
        """
    ).strip()

    white_phase1_gaps = dedent(
        """
        - Universality at the product level currently outruns universality at the semantics-proof level.
        - Compatibility and native execution need harder labeling boundaries.
        """
    ).strip()

    white_phase1_verdict = (
        "The compiler architecture is credible and useful. Its current limitation is proof of preservation, not absence of implementation."
    )

    white_phase2_findings = dedent(
        """
        #### Runtime Thesis

        The UMPG is the architectural center of gravity that tries to turn proving into an explicit systems problem: stage graphs, residency, placement, spill, watchdogs, and supervisory hooks instead of opaque backend internals. That is where ZirOS differs most clearly from libraries that stop at “compile and prove.”

        #### Operational Reality

        The architecture is ahead of the default operational path. The runtime graph exists and the Metal path exists, but the ordinary `run_with_context()` path does not currently attach the GPU driver. That does not invalidate the design. It does mean the architecture is partly aspirational in the everyday path that matters most.

        #### Why It Still Matters

        Even with that gap, the UMPG contributes a distinct way of thinking about proving workloads. It treats proving as schedulable systems work, not only as algebra hidden inside one backend library.
        """
    ).strip()

    white_phase2_gaps = dedent(
        """
        - The implementation still needs the default path to line up with the headline runtime story.
        - The scheduler is intentionally audit-friendly rather than aggressively parallel.
        """
    ).strip()

    white_phase2_verdict = (
        "The UMPG is a real architectural differentiator, but it is not yet fully reflected in the default runtime behavior."
    )

    white_phase3_findings = dedent(
        """
        #### Hardware Strategy

        ZirOS treats Apple Silicon as a first-class proving environment. The Metal layer covers MSM, NTT, Poseidon2, hashing, and related kernels, and the vendored backend patches prove that the GPU story is not confined to one isolated crate.

        #### Integration Quality

        The hardware stack is strongest where it is tied directly into backend work that already exists in production paths, especially MSM and NTT. It is weaker where kernels exist in `zkf-metal` but are not fully surfaced through the runtime graph, as with Keccak.

        #### White-Paper Framing

        The right claim is not “GPU proving everywhere.” The right claim is “a serious accelerator layer with uneven but genuine end-to-end integration.”
        """
    ).strip()

    white_phase3_gaps = dedent(
        """
        - Some kernels remain accelerator-level capabilities rather than runtime-level guarantees.
        - Runtime/device policy still needs tighter consistency.
        """
    ).strip()

    white_phase3_verdict = (
        "The GPU strategy is one of ZirOS’s strongest differentiators, provided it is described as an active integration program rather than a uniformly complete path."
    )

    white_phase4_findings = dedent(
        f"""
        #### Assurance Strategy

        ZirOS uses layered assurance rather than a single proof claim. The codebase includes proof-language artifacts, bounded-model checks, proof-audit scripts, and supply-chain controls. The marker scan alone shows a large formal surface: `{proof_counts['kani']}` Kani proofs and `{len(proof_relpaths)}` proof-language files.

        #### Trust Boundary

        The architectural meaning of this layer is not “everything is proved.” It is “the project has consciously built multiple ways to reduce untrusted surface area.” The security documentation is actually helpful here because it states a smaller trusted boundary than the headline rhetoric sometimes implies.

        #### White-Paper Framing

        The strongest honest phrasing is that ZirOS is pursuing machine-checked assurance seriously and unevenly, with real enforcement on some surfaces and local-only workflows on others.
        """
    ).strip()

    white_phase4_gaps = dedent(
        """
        - CI-enforced formal closure is incomplete.
        - Trust escapes remain in runtime-adjacent unsafe code and unproved boundary logic.
        """
    ).strip()

    white_phase4_verdict = (
        "The assurance model is advanced relative to most peers, but it is a staged program rather than a completed proof perimeter."
    )

    white_phase5_findings = dedent(
        """
        #### Distributed Defense Model

        The swarm layer is architecturally interesting because it treats proof generation as something that can be supervised, cross-checked, and reputation-scored rather than as a purely local computation. That is a useful systems idea even before it becomes a textbook BFT protocol.

        #### Implementation Boundary

        The current implementation is closer to a defense envelope with coordinated remote validation than to a fully specified consensus network. The coordinator remains authoritative in several important ways, and peer reputation data is handled conservatively.

        #### White-Paper Framing

        This layer should be presented as a distributed assurance and orchestration layer, not as a completed standalone consensus protocol.
        """
    ).strip()

    white_phase5_gaps = dedent(
        """
        - Consensus language in prose is still broader than the concrete implementation.
        - The blueprint story is more fragmented than the code story.
        """
    ).strip()

    white_phase5_verdict = (
        "The swarm subsystem adds real distributed assurance value, but its best description today is supervisory rather than fully consensus-native."
    )

    white_phase6_findings = dedent(
        """
        #### Identity Strategy

        The identity model is one of the cleaner product stories in the repository: hybrid Ed25519 plus ML-DSA identities, application-level private identity proofs, and supply-chain vetting live close enough together to form a coherent trust narrative.

        #### Architectural Boundary

        The important distinction is between what is proved in-circuit and what is enforced in application logic. ZirOS uses both. That is reasonable engineering. It only becomes a problem when the prose blurs them into one undifferentiated privacy guarantee.
        """
    ).strip()

    white_phase6_gaps = dedent(
        """
        - The private-identity path still relies on application logic for some trust checks.
        - PQ identity strength should not be confused with PQ proof-system strength.
        """
    ).strip()

    white_phase6_verdict = (
        "The identity layer is coherent and more mature than many surrounding ambitions in the repo."
    )

    white_phase7_findings = dedent(
        """
        #### Product Surfaces

        ZirOS already behaves like a platform product in the number of surfaces it supports: CLI, API, Python, FFI, LSP, assistant-support bundles, and library builders. That breadth is unusual for a ZK system at this maturity level.

        #### Experience Model

        The product direction is clearly toward AI-assisted operation and template-driven circuit construction. The system is not yet a full conversational proving environment in the strict sense, but it already contains much of the scaffolding such a product would need.

        #### Architectural Meaning

        The platform is closer to “agent-ready infrastructure” than to “fully realized AI-native proving interface.”
        """
    ).strip()

    white_phase7_gaps = dedent(
        """
        - The FFI verifier fallback is out of line with the otherwise serious trust posture.
        - The absence of the Swift app source in this checkout limits how far any product analysis can honestly go.
        """
    ).strip()

    white_phase7_verdict = (
        "The product surface is unusually broad and credible. The last-mile conversational story is still an infrastructure promise more than a finished interaction model."
    )

    white_phase8_findings = dedent(
        f"""
        #### Quality Posture

        The repository demonstrates a real quality culture: multi-platform CI, formal tooling in gate paths, integration tests across subsystems, and a willingness to write hostile-audit and pressure tests instead of only happy-path examples.

        #### Assurance Depth

        The remaining issue is centralization. Some of the most ambitious checks remain outside the mandatory path, which means the quality story is strong but not fully normalized into one unavoidable gate system.

        #### Test Surface Reference

        The marker scan found `{proof_counts['test']}` standard tests and `{proof_counts['tokio_test']}` async tests, with additional property and fuzz surfaces in the appendices.
        """
    ).strip()

    white_phase8_gaps = dedent(
        """
        - Not every meaningful assurance runner is part of CI.
        - Some high-value test harnesses still require manual invocation.
        """
    ).strip()

    white_phase8_verdict = (
        "The reliability program is real and broad. Its next step is consolidation, not invention."
    )

    white_phase9_findings = dedent(
        """
        #### White-Paper Conclusion

        ZirOS is most compelling when described as a systems platform for multi-backend zero-knowledge proving with explicit runtime control, accelerator support, formal-assurance ambition, and distributed supervision. That is already a strong and unusual position.

        It is least compelling when described in absolutes that imply universal semantic closure, fully realized AI-native proving, or consensus-grade distributed trust guarantees that the current code still only approaches. The architecture is strongest where it is concrete. The project becomes less persuasive when the language outruns the code.
        """
    ).strip()

    white_phase9_gaps = dedent(
        """
        - The project still needs sharper product language around what is shipped, what is delegated, and what is still in progress.
        - Several boundary risks remain important enough to shape deployment posture.
        """
    ).strip()

    white_phase9_verdict = (
        "ZirOS deserves to be taken seriously as a broad proving platform. It does not yet deserve every absolute trust claim that has been attached to it."
    )

    def phase_block(number: int, name: str, files: list[str], findings: str, gaps: str, verdict: str) -> str:
        return (
            f"## PHASE {number} — {name}\n\n"
            f"### Files Examined\n{format_paths(files)}\n\n"
            f"### Findings\n{findings}\n\n"
            f"### Gaps and Concerns\n{gaps}\n\n"
            f"### Verdict\n{verdict}"
        ).strip()

    methodology = dedent(
        f"""
        # ZirOS Forensic Dissertation

        Generated on `{datetime.now().astimezone().isoformat()}` from the current checkout at `{ROOT}`.

        This dissertation is source-first and contradiction-seeking. It inventories the current repository, excludes `target*`, `.venv-coreml`, `.git`, and `.zkf-tools`, and treats external runtime evidence under `~/Library/Application Support/ZFK` and `~/Library/Logs/ZFK` as corroboration rather than authoritative source. The goal is not to restate product claims. The goal is to identify what the code really implements, where the trust boundaries actually sit, and where the public narrative outruns the current checkout.
        """
    ).strip()

    dissertation = "\n\n".join(
        [
            methodology,
            phase_block(0, "STRUCTURAL CENSUS", phase0_files, phase0_findings, phase0_gaps, phase0_verdict),
            phase_block(1, "CRYPTOGRAPHIC CORE", phase1_files, phase1_findings, phase1_gaps, phase1_verdict),
            phase_block(2, "THE UMPG (UNIFIED MEMORY PROVER GRAPH)", phase2_files, phase2_findings, phase2_gaps, phase2_verdict),
            phase_block(3, "METAL GPU ACCELERATION", phase3_files, phase3_findings, phase3_gaps, phase3_verdict),
            phase_block(4, "FORMAL VERIFICATION", phase4_files, phase4_findings, phase4_gaps, phase4_verdict),
            phase_block(5, "SWARM INTELLIGENCE DEFENSE SYSTEM", phase5_files, phase5_findings, phase5_gaps, phase5_verdict),
            phase_block(6, "POST-QUANTUM AND IDENTITY", phase6_files, phase6_findings, phase6_gaps, phase6_verdict),
            phase_block(7, "CLI AND AGENTIC SYSTEM SURFACE", phase7_files, phase7_findings, phase7_gaps, phase7_verdict),
            phase_block(8, "TESTING AND RELIABILITY", phase8_files, phase8_findings, phase8_gaps, phase8_verdict),
            phase_block(9, "HONEST ASSESSMENT", phase9_files, phase9_findings, phase9_gaps, phase9_verdict),
        ]
    ).strip() + "\n"

    white_paper_intro = dedent(
        f"""
        # ZirOS White Paper

        Generated on `{datetime.now().astimezone().isoformat()}` from the same evidence corpus as the dissertation. This document is intentionally not a duplicate. It uses the same source-backed inventory and the same phase order, but it reframes the repository as a platform architecture paper: system shape, operational model, assurance posture, and deployment implications. It does not invent capabilities that the source tree does not support.
        """
    ).strip()

    white_paper = "\n\n".join(
        [
            white_paper_intro,
            phase_block(0, "STRUCTURAL CENSUS", phase0_files, white_phase0_findings, white_phase0_gaps, white_phase0_verdict),
            phase_block(1, "CRYPTOGRAPHIC CORE", phase1_files, white_phase1_findings, white_phase1_gaps, white_phase1_verdict),
            phase_block(2, "THE UMPG (UNIFIED MEMORY PROVER GRAPH)", phase2_files, white_phase2_findings, white_phase2_gaps, white_phase2_verdict),
            phase_block(3, "METAL GPU ACCELERATION", phase3_files, white_phase3_findings, white_phase3_gaps, white_phase3_verdict),
            phase_block(4, "FORMAL VERIFICATION", phase4_files, white_phase4_findings, white_phase4_gaps, white_phase4_verdict),
            phase_block(5, "SWARM INTELLIGENCE DEFENSE SYSTEM", phase5_files, white_phase5_findings, white_phase5_gaps, white_phase5_verdict),
            phase_block(6, "POST-QUANTUM AND IDENTITY", phase6_files, white_phase6_findings, white_phase6_gaps, white_phase6_verdict),
            phase_block(7, "CLI AND AGENTIC SYSTEM SURFACE", phase7_files, white_phase7_findings, white_phase7_gaps, white_phase7_verdict),
            phase_block(8, "TESTING AND RELIABILITY", phase8_files, white_phase8_findings, white_phase8_gaps, white_phase8_verdict),
            phase_block(9, "HONEST ASSESSMENT", phase9_files, white_phase9_findings, white_phase9_gaps, white_phase9_verdict),
        ]
    ).strip() + "\n"

    feelings_report = build_feelings_report()

    outputs = {
        FORENSICS_DIR / "01_zir_os_forensic_dissertation.md": dissertation,
        FORENSICS_DIR / "02_zir_os_white_paper.md": white_paper,
        FORENSICS_DIR / "03_zir_os_feelings_report.md": feelings_report,
        GENERATED_DIR / "workspace_packages.json": json.dumps(package_records, indent=2) + "\n",
        GENERATED_DIR / "marker_hits.json": json.dumps(
            {
                key: [
                    {"path": hit.relpath, "line": hit.line_no, "text": hit.line_text}
                    for hit in value
                ]
                for key, value in marker_hits.items()
            },
            indent=2,
        )
        + "\n",
        GENERATED_DIR / "repo_file_inventory.json": json.dumps(
            {
                "repo_files": repo_relpaths,
                "external_runtime_files": external_relpaths,
                "rust_files": rs_relpaths,
                "proof_files": proof_relpaths,
                "metal_files": metal_relpaths,
                "line_counts": line_counts,
                "external_line_counts": external_line_counts,
                "owner_map": owner_map,
                "rust_loc_by_owner": dict(rs_lines_by_owner),
                "non_rust_files": non_rust_relpaths,
                "non_rust_extension_counts": dict(ext_counts),
                "roots": roots,
                "leaves": leaves,
                "critical_path_crates": [
                    {"crate": name, "dependent_count": count, "dependents": ds}
                    for name, count, ds in critical
                ],
            },
            indent=2,
        )
        + "\n",
    }

    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
