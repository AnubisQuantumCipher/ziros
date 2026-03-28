#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$repo_root/zkf-core/proofs/rocq/HAX_PIN.toml"
tools_root="$repo_root/.zkf-tools/hax"
checkout_dir="$tools_root/src/hax"
env_file="$tools_root/hax.env"

pin_value() {
  local key="$1"
  awk -F '"' -v key="$key" '$1 ~ "^" key " = " { print $2; exit }' "$pin_file"
}

require_binary() {
  local binary="$1"
  if ! command -v "$binary" >/dev/null 2>&1; then
    echo "required binary '$binary' was not found in PATH" >&2
    exit 1
  fi
}

hax_repo="$(pin_value repo)"
hax_rev="$(pin_value rev)"
switch_name="$(pin_value opam_switch)"
ocaml_version="$(pin_value ocaml_version)"

if [ -z "$hax_repo" ] || [ -z "$hax_rev" ] || [ -z "$switch_name" ] || [ -z "$ocaml_version" ]; then
  echo "failed to read pinned hax settings from $pin_file" >&2
  exit 1
fi

for binary in cargo git jq node opam rustup; do
  require_binary "$binary"
done

mkdir -p "$tools_root/src"

if [ ! -d "$checkout_dir/.git" ]; then
  git clone "$hax_repo" "$checkout_dir"
fi

git -C "$checkout_dir" fetch --tags --force origin
git -C "$checkout_dir" checkout --force "$hax_rev"

if ! opam switch list --short | grep -Fxq "$switch_name"; then
  opam switch create "$switch_name" "ocaml-base-compiler.$ocaml_version" --yes
fi

# shellcheck disable=SC1090
eval "$(opam env --switch="$switch_name" --set-switch)"
export PATH="$HOME/.cargo/bin:$PATH"

if ! cargo hax --version >/dev/null 2>&1 || ! command -v hax-engine >/dev/null 2>&1; then
  (
    cd "$checkout_dir"
    ./setup.sh
  )
fi

mkdir -p "$(dirname "$env_file")"
cat >"$env_file" <<EOF
#!/usr/bin/env bash
export ZKF_HAX_SWITCH="$switch_name"
export ZKF_HAX_REPO="$checkout_dir"
if command -v opam >/dev/null 2>&1; then
  eval "\$(opam env --switch=\$ZKF_HAX_SWITCH --set-switch)"
fi
export PATH="\$HOME/.cargo/bin:\$PATH"
EOF
chmod +x "$env_file"

cargo hax --version >/dev/null
command -v hax-engine >/dev/null 2>&1

echo "Bootstrapped pinned hax toolchain at $checkout_dir using opam switch $switch_name"
