#!/usr/bin/env bash
set -euo pipefail
cd /Users/sicarii/Desktop/ZirOS
mkdir -p forensics/generated

# All non-target tracked files
rg --files | grep -Ev '(^target-public/|^target/|^\.git/)' | sort > forensics/generated/all_files.tsv
wc -l forensics/generated/all_files.tsv > forensics/generated/summary.txt

# Top-level counts by dir
awk -F/ 'NF==1{print "."; next} {print $1}' forensics/generated/all_files.tsv | sort | uniq -c | sort -nr > forensics/generated/top_level_counts.tsv

# Extension and line inventory
awk -F. 'function ext(n,   i,p){i=split(n,a,"/"); p=a[i]; if (p ~ /\./){n=split(p,b,"."); if (n>1) print tolower(b[n]); else print "[no_ext]"} else print "[no_ext]"}' forensics/generated/all_files.tsv | sort | uniq -c | sort -nr > forensics/generated/extension_counts.tsv

while IFS= read -r f; do
  if [ -f "$f" ]; then
    lines=$(wc -l < "$f")
    size=$(stat -f %z "$f")
    printf '%8s\t%s\t%s\n' "$lines" "$size" "$f"
  fi
 done < forensics/generated/all_files.tsv > forensics/generated/file_inventory_lines.tsv

sort -nr forensics/generated/file_inventory_lines.tsv | head -n 200 > forensics/generated/file_inventory_top200_lines.tsv

# Crate inventory from workspace
rg --files -g 'Cargo.toml' | grep -v '/vendor/' | grep -v '/target/' | sort > forensics/generated/crate_manifests.txt

> forensics/generated/crate_source_map.tsv
while IFS= read -r cm; do
  dir=$(dirname "$cm")
  name=$(grep -m1 '^name =' "$cm" | sed 's/name = "\([^"]*\)"/\1/')
  printf '%s\t%s\n' "$dir" "$name" >> forensics/generated/crate_source_map.tsv
  # collect source files
  rg --files "$dir/src" "$dir/examples" "$dir/tests" "$dir/benches" "$dir/build.rs" 2>/dev/null | sort > /tmp/tmp_crate_files
  c=$(wc -l < /tmp/tmp_crate_files)
  l=0
  while IFS= read -r sf; do
    [ -f "$sf" ] && l=$((l + $(wc -l < "$sf")))
  done < /tmp/tmp_crate_files
  printf '%s\t%s\t%s\n' "$name" "$c" "$l" >> forensics/generated/crate_volume.tsv
  rm -f /tmp/tmp_crate_files
 done < forensics/generated/crate_manifests.txt

# Proof/server/ops critical files
printf '== Midnight proof-server surface ==\n' > forensics/generated/critical_index.md
printf 'zkf-cli/src/cmd/midnight.rs\n' >> forensics/generated/critical_index.md
printf 'zkf-cli/src/cmd/runtime.rs\n' >> forensics/generated/critical_index.md
printf 'zkf-runtime/src/api.rs\n' >> forensics/generated/critical_index.md
printf 'zkf-runtime/src/lib.rs\n' >> forensics/generated/critical_index.md
printf 'zkf-runtime/src/control_plane.rs\n' >> forensics/generated/critical_index.md
printf 'zkf-metal/src/lib.rs\n' >> forensics/generated/critical_index.md
printf 'zkf-metal/src/proof_ir.rs\n' >> forensics/generated/critical_index.md
printf 'zkf-wallet/src/lib.rs\n' >> forensics/generated/critical_index.md

# Generate quick forensics report
{
  echo '# Forensic Corpus Snapshot'
  echo
  echo '## File Universe'
  echo "- Total files (excludes .git,target,target-public): $(wc -l < forensics/generated/all_files.tsv)"
  echo
  echo '## Top-level folder concentrations'
  head -n 60 forensics/generated/top_level_counts.tsv
  echo
  echo '## Extension counts'
  head -n 80 forensics/generated/extension_counts.tsv
  echo
  echo '## Largest 50 in-repo files by line count'
  head -n 50 forensics/generated/file_inventory_lines.tsv | sort -nr
  echo
  echo '## Workspace crates'
  awk '{print "- "$1" -> "$2}' forensics/generated/crate_source_map.tsv
} > forensics/generated/README.md
