#!/usr/bin/env bash

lean_toolchain_target="${LEAN_TOOLCHAIN_TARGET:-leanprover/lean4:v4.28.0}"

lean_tool_home_bin() {
  local tool="$1"
  local candidate="${HOME}/.elan/bin/${tool}"
  if [[ -x "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  return 1
}

lean_tool_elan_bin() {
  if command -v elan >/dev/null 2>&1; then
    command -v elan
    return 0
  fi
  lean_tool_home_bin elan
}

run_lean_tool() {
  local tool="$1"
  shift

  if command -v "$tool" >/dev/null 2>&1; then
    "$(command -v "$tool")" "$@"
    return 0
  fi

  local direct_bin=""
  if direct_bin="$(lean_tool_home_bin "$tool")"; then
    "$direct_bin" "$@"
    return 0
  fi

  local elan_bin=""
  if elan_bin="$(lean_tool_elan_bin)"; then
    "$elan_bin" run "$lean_toolchain_target" "$tool" "$@"
    return 0
  fi

  printf '%s\n' \
    "Lean 4.28.0 ${tool} is required; expected \`${tool}\` on PATH, \`$HOME/.elan/bin/${tool}\`, or an \`elan\` launcher" >&2
  return 1
}

run_lean() {
  run_lean_tool lean "$@"
}

run_lake() {
  run_lean_tool lake "$@"
}
