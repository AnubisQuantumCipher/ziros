#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEADER_TEXT='// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0'

while IFS= read -r -d '' file_path; do
  if rg -q "Business Source License" "$file_path"; then
    continue
  fi

  temp_file="$(mktemp)"
  {
    printf '%s\n\n' "$HEADER_TEXT"
    cat "$file_path"
  } >"$temp_file"
  mv "$temp_file" "$file_path"
done < <(
  find "$ROOT_DIR" \
    \( \
      -path "$ROOT_DIR/.git" -o \
      -path "$ROOT_DIR/vendor" -o \
      -path "$ROOT_DIR/target" -o \
      -path "$ROOT_DIR/target-public" -o \
      -path "$ROOT_DIR/target-local" -o \
      -path "$ROOT_DIR/.tmp" \
    \) -prune -o \
    -type f -name '*.rs' -print0
)
