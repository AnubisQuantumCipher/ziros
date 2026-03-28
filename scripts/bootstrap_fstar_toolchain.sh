#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tool_bin="$repo_root/.zkf-tools/fstar/bin"
env_file="$repo_root/.zkf-tools/fstar/fstar.env"
pin_file="$repo_root/zkf-core/proofs/fstar/HAX_PIN.toml"
z3_fetch_url="https://raw.githubusercontent.com/FStarLang/FStar/master/.scripts/get_fstar_z3.sh"
user_bin="${HOME}/.local/bin"

pin_value() {
  local key="$1"
  awk -F '"' -v key="$key" '$1 ~ "^" key " = " { print $2; exit }' "$pin_file"
}

if ! command -v opam >/dev/null 2>&1; then
  echo "opam is required to install the local F* toolchain" >&2
  exit 1
fi

if [ ! -f "$pin_file" ]; then
  echo "missing F* pin metadata at $pin_file" >&2
  exit 1
fi

switch_name="$(pin_value opam_switch)"
ocaml_version="$(pin_value ocaml_version)"

if [ -z "$switch_name" ] || [ -z "$ocaml_version" ]; then
  echo "failed to read pinned F* switch metadata from $pin_file" >&2
  exit 1
fi

mkdir -p "$tool_bin"
mkdir -p "$user_bin"

if ! opam switch list --short | grep -Fxq "$switch_name"; then
  opam switch create "$switch_name" "ocaml-base-compiler.$ocaml_version" --yes
fi

if ! opam exec --switch="$switch_name" -- sh -c 'command -v fstar.exe >/dev/null 2>&1 || command -v fstar >/dev/null 2>&1'; then
  opam install --switch="$switch_name" -y fstar
fi

opam_bin="$(opam var --switch="$switch_name" bin)"
if [ -x "$opam_bin/fstar.exe" ]; then
  ln -sf "$opam_bin/fstar.exe" "$tool_bin/fstar.exe"
  ln -sf "$opam_bin/fstar.exe" "$tool_bin/fstar"
elif [ -x "$opam_bin/fstar" ]; then
  cat >"$tool_bin/fstar.exe" <<EOF
#!/usr/bin/env bash
exec "$opam_bin/fstar" "\$@"
EOF
  chmod +x "$tool_bin/fstar.exe"
  ln -sf "$tool_bin/fstar.exe" "$tool_bin/fstar"
else
  echo "failed to locate F* binary in pinned opam switch '$switch_name'" >&2
  exit 1
fi

cat >"$user_bin/fstar.exe" <<EOF
#!/usr/bin/env bash
exec "$tool_bin/fstar.exe" "\$@"
EOF
chmod +x "$user_bin/fstar.exe"
ln -sf "$user_bin/fstar.exe" "$user_bin/fstar"

if [ ! -x "$tool_bin/z3-4.8.5" ] || [ ! -x "$tool_bin/z3-4.13.3" ]; then
  tmp_script="$(mktemp)"
  trap 'rm -f "$tmp_script"' EXIT
  curl -fsSL "$z3_fetch_url" -o "$tmp_script"
  bash "$tmp_script" "$tool_bin"
fi

if command -v z3 >/dev/null 2>&1; then
  ln -sf "$(command -v z3)" "$tool_bin/z3"
fi

mkdir -p "$(dirname "$env_file")"
cat >"$env_file" <<EOF
#!/usr/bin/env bash
export ZKF_FSTAR_SWITCH="$switch_name"
if command -v opam >/dev/null 2>&1; then
  eval "\$(opam env --switch=\$ZKF_FSTAR_SWITCH --set-switch)"
fi
export PATH="$tool_bin:\$PATH"
EOF
chmod +x "$env_file"

echo "$tool_bin"
