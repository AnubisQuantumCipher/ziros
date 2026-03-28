#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fiat_commit="bc35fd783f33ac69027364c683a4c24401ffcab7"
fiat_repo_url="https://github.com/mit-plv/fiat-crypto.git"
fiat_cache_root="${ZKF_FIAT_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/zkf/fiat-crypto/${fiat_commit}}"
fiat_repo="${ZKF_FIAT_REPO:-${fiat_cache_root}/repo}"
fiat_switch="${ZKF_FIAT_OPAM_SWITCH:-hax-5.1.1}"

generated_dir="${repo_root}/zkf-core/src/fiat_generated"
manifest_path="${repo_root}/zkf-core/fiat-crypto-manifest.json"

ops=(
  mul
  square
  add
  sub
  opp
  from_montgomery
  to_montgomery
  nonzero
  selectznz
  to_bytes
  from_bytes
  one
  msat
  divstep
  divstep_precomp
)

field_ids=(
  "bn254"
  "bls12-381"
  "pasta-fp"
  "pasta-fq"
)

module_names=(
  "bn254_scalar"
  "bls12_381_scalar"
  "pasta_fp"
  "pasta_fq"
)

moduli=(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
  "52435875175126190479447740508185965837690552500527637822603658699938581184513"
  "28948022309329048855892746252171976963363056481941560715954676764349967630337"
  "28948022309329048855892746252171976963363056481941647379679742748393362948097"
)

module_files=(
  "bn254_scalar_64.rs"
  "bls12_381_scalar_64.rs"
  "pasta_fp_64.rs"
  "pasta_fq_64.rs"
)

word_size="64"

usage() {
  cat >&2 <<'EOF'
Usage:
  bash scripts/regenerate_fiat_fields.sh
  bash scripts/regenerate_fiat_fields.sh --check

Environment:
  ZKF_FIAT_CACHE_ROOT   Override the cache root used for the pinned Fiat-Crypto checkout.
  ZKF_FIAT_REPO         Override the Fiat-Crypto checkout path directly.
  ZKF_FIAT_OPAM_SWITCH  Override the opam switch used to build the standalone generator.
EOF
}

log() {
  printf '[fiat-fields] %s\n' "$*" >&2
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    log "Missing required command: ${command_name}"
    exit 1
  fi
}

ensure_repo() {
  if [[ ! -d "${fiat_repo}/.git" ]]; then
    log "Cloning Fiat-Crypto ${fiat_commit} into ${fiat_repo}"
    mkdir -p "$(dirname "${fiat_repo}")"
    git clone --recursive "${fiat_repo_url}" "${fiat_repo}"
  fi

  local current_commit
  current_commit="$(git -C "${fiat_repo}" rev-parse HEAD)"
  if [[ "${current_commit}" != "${fiat_commit}" ]]; then
    log "Checking out Fiat-Crypto ${fiat_commit}"
    git -C "${fiat_repo}" fetch --tags origin
    git -C "${fiat_repo}" checkout "${fiat_commit}"
  fi

  git -C "${fiat_repo}" submodule update --init --recursive
}

ensure_generator() {
  local generator_path="${fiat_repo}/src/ExtractionOCaml/fiat_crypto"
  if [[ -x "${generator_path}" ]]; then
    printf '%s\n' "${generator_path}"
    return
  fi

  require_command opam
  log "Building pinned Fiat-Crypto standalone generator with opam switch ${fiat_switch}"
  opam exec --switch="${fiat_switch}" -- sh -lc \
    "ulimit -S -s 1048576 >/dev/null 2>&1 || true; cd '${fiat_repo}' && make SKIP_BEDROCK2=1 standalone-unified-ocaml -j1"

  if [[ ! -x "${generator_path}" ]]; then
    log "Expected generator was not produced at ${generator_path}"
    exit 1
  fi

  printf '%s\n' "${generator_path}"
}

generate_field_module() {
  local generator_path="$1"
  local module_name="$2"
  local modulus="$3"
  local output_path="$4"
  local generator_relpath="src/ExtractionOCaml/fiat_crypto"

  log "Generating ${module_name} -> ${output_path}"
  (
    cd "${fiat_repo}"
    "${generator_relpath}" \
      word-by-word-montgomery \
      --lang Rust \
      --inline \
      "${module_name}" \
      "${word_size}" \
      "${modulus}" \
      "${ops[@]}" \
      > "${output_path}"
  )
}

format_generated_module() {
  local output_path="$1"
  rustfmt --edition 2021 "${output_path}"
  perl -0pi -e 's/\.([0-9]+) \.([0-9]+)/.$1.$2/g' "${output_path}"
}

write_manifest() {
  local manifest_out="$1"
  local generator_path="$2"
  python3 - "${manifest_out}" "${generator_path}" "${fiat_commit}" "${fiat_repo_url}" "${fiat_switch}" "${generated_dir}" "${repo_root}" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

manifest_out = pathlib.Path(sys.argv[1])
generator_path = pathlib.Path(sys.argv[2])
fiat_commit = sys.argv[3]
fiat_repo_url = sys.argv[4]
fiat_switch = sys.argv[5]
generated_dir = pathlib.Path(sys.argv[6])
repo_root = pathlib.Path(sys.argv[7])
generator_relpath = "src/ExtractionOCaml/fiat_crypto"

field_ids = [
    "bn254",
    "bls12-381",
    "pasta-fp",
    "pasta-fq",
]
module_names = [
    "bn254_scalar",
    "bls12_381_scalar",
    "pasta_fp",
    "pasta_fq",
]
moduli = [
    "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    "52435875175126190479447740508185965837690552500527637822603658699938581184513",
    "28948022309329048855892746252171976963363056481941560715954676764349967630337",
    "28948022309329048855892746252171976963363056481941647379679742748393362948097",
]
module_files = [
    "bn254_scalar_64.rs",
    "bls12_381_scalar_64.rs",
    "pasta_fp_64.rs",
    "pasta_fq_64.rs",
]
ops = [
    "mul",
    "square",
    "add",
    "sub",
    "opp",
    "from_montgomery",
    "to_montgomery",
    "nonzero",
    "selectznz",
    "to_bytes",
    "from_bytes",
    "one",
    "msat",
    "divstep",
    "divstep_precomp",
]

entries = []
for field_id, module_name, modulus, module_file in zip(field_ids, module_names, moduli, module_files):
    module_path = generated_dir / module_file
    data = module_path.read_bytes()
    entries.append(
        {
            "field_id": field_id,
            "module_name": module_name,
            "word_size": 64,
            "modulus_decimal": modulus,
            "module_path": os.path.relpath(module_path, start=repo_root),
            "sha256": hashlib.sha256(data).hexdigest(),
            "generator_command": [
                generator_relpath,
                "word-by-word-montgomery",
                "--lang",
                "Rust",
                "--inline",
                module_name,
                "64",
                modulus,
                *ops,
            ],
        }
    )

manifest = {
    "schema": "zkf-fiat-crypto-manifest-v1",
    "upstream_repo": fiat_repo_url,
    "upstream_commit": fiat_commit,
    "generator": {
        "opam_switch": fiat_switch,
        "standalone_binary": generator_relpath,
        "strategy": "word-by-word-montgomery",
        "language": "Rust",
        "word_size": 64,
        "extra_args": ["--inline"],
        "operations": ops,
    },
    "fields": entries,
}

manifest_out.write_text(json.dumps(manifest, indent=2) + "\n")
PY
}

check_or_install() {
  local candidate="$1"
  local target="$2"
  local label="$3"
  if ! cmp -s "${candidate}" "${target}"; then
    log "Mismatch detected for ${label}: ${target}"
    diff -u --label "expected:${target}" --label "generated:${label}" "${target}" "${candidate}" || true
    return 1
  fi
}

main() {
  local check_mode=0
  if [[ "${1:-}" == "--check" ]]; then
    check_mode=1
    shift
  fi

  if [[ $# -ne 0 ]]; then
    usage
    exit 1
  fi

  require_command git
  require_command python3
  require_command diff
  require_command rustfmt

  ensure_repo
  local generator_path
  generator_path="$(ensure_generator)"

  mkdir -p "${generated_dir}"

  local tmpdir
  tmpdir="$(mktemp -d "${repo_root}/.tmp-fiat-fields.XXXXXX")"
  trap 'rm -rf -- "'"${tmpdir}"'"' EXIT

  local failures=0
  local i
  for i in "${!field_ids[@]}"; do
    local tmp_output="${tmpdir}/${module_files[i]}"
    local target_output="${generated_dir}/${module_files[i]}"
    generate_field_module "${generator_path}" "${module_names[i]}" "${moduli[i]}" "${tmp_output}"
    format_generated_module "${tmp_output}"

    if [[ ${check_mode} -eq 1 ]]; then
      if [[ ! -f "${target_output}" ]]; then
        log "Missing checked-in generated module: ${target_output}"
        failures=1
      elif ! check_or_install "${tmp_output}" "${target_output}" "${module_names[i]}"; then
        failures=1
      fi
    else
      cp "${tmp_output}" "${target_output}"
    fi
  done

  local manifest_tmp="${tmpdir}/fiat-crypto-manifest.json"
  write_manifest "${manifest_tmp}" "${generator_path}"

  if [[ ${check_mode} -eq 1 ]]; then
    if [[ ! -f "${manifest_path}" ]]; then
      log "Missing checked-in manifest: ${manifest_path}"
      failures=1
    elif ! check_or_install "${manifest_tmp}" "${manifest_path}" "fiat-crypto-manifest"; then
      failures=1
    fi
  else
    cp "${manifest_tmp}" "${manifest_path}"
  fi

  if [[ ${failures} -ne 0 ]]; then
    log "Fiat-Crypto regeneration check failed"
    exit 1
  fi

  if [[ ${check_mode} -eq 1 ]]; then
    log "Checked-in Fiat-Crypto modules and manifest match regenerated output"
  else
    log "Updated Fiat-Crypto generated modules and manifest"
  fi
}

main "$@"
