#!/usr/bin/env bash

rocq_tool_home_bin() {
  local tool="$1"
  local candidate=""
  for switch in default hax-5.1.1; do
    candidate="${HOME}/.opam/${switch}/bin/${tool}"
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

rocq_tool_opam_bin_dir() {
  if command -v opam >/dev/null 2>&1; then
    local bin_dir=""
    bin_dir="$(opam var bin 2>/dev/null || true)"
    if [[ -n "$bin_dir" ]]; then
      printf '%s\n' "$bin_dir"
      return 0
    fi
  fi
  return 1
}

rocq_tool_bin() {
  local tool="$1"
  if command -v "$tool" >/dev/null 2>&1; then
    command -v "$tool"
    return 0
  fi

  local bin_dir=""
  if bin_dir="$(rocq_tool_opam_bin_dir)"; then
    if [[ -x "$bin_dir/$tool" ]]; then
      printf '%s\n' "$bin_dir/$tool"
      return 0
    fi
  fi

  rocq_tool_home_bin "$tool"
}

prepend_rocq_toolchain_path() {
  local coqc_bin=""
  if coqc_bin="$(rocq_tool_bin coqc)"; then
    export PATH="$(dirname "$coqc_bin"):$PATH"
    return 0
  fi
  return 1
}
