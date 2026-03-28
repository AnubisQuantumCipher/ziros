#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
zkf_core_rocq_dir="$repo_root/zkf-core/proofs/rocq"
zkf_backends_rocq_dir="$repo_root/zkf-backends/proofs/rocq"
zkf_frontends_rocq_dir="$repo_root/zkf-frontends/proofs/rocq"
zkf_runtime_rocq_dir="$repo_root/zkf-runtime/proofs/rocq"
zkf_lib_rocq_dir="$repo_root/zkf-lib/proofs/rocq"
zkf_distributed_rocq_dir="$repo_root/zkf-distributed/proofs/rocq"
hax_env="$repo_root/.zkf-tools/hax/hax.env"
hax_core_dir="$repo_root/.zkf-tools/hax/src/hax/hax-lib/proof-libs/coq/coq/generated-core"
vendor_record_update_dir="$zkf_core_rocq_dir/vendor/RecordUpdate"
source "$repo_root/scripts/rocq_toolchain.sh"
record_update_dir=""

if [ -f "$hax_env" ]; then
  # shellcheck disable=SC1090
  source "$hax_env"
fi

prepend_rocq_toolchain_path || true

coq_lib_dir="$(coqc -where 2>/dev/null || true)"

if [ -f "$vendor_record_update_dir/RecordSet.v" ] && [ -f "$vendor_record_update_dir/RecordEta.v" ]; then
  record_update_dir="$vendor_record_update_dir"
elif [ -n "$coq_lib_dir" ] && [ -d "$coq_lib_dir/user-contrib/RecordUpdate" ]; then
  record_update_dir="$coq_lib_dir/user-contrib/RecordUpdate"
fi

if command -v coqc >/dev/null 2>&1; then
  coqc -q "$repo_root/zkf-ir-spec/proofs/rocq/Normalization.v"
  (
    cd "$zkf_core_rocq_dir"
    if [ -n "$record_update_dir" ] && [ -f "$record_update_dir/RecordSet.v" ] && [ -f "$record_update_dir/RecordEta.v" ]; then
      coqc -q -Q "$record_update_dir" RecordUpdate "$record_update_dir/RecordEta.v"
      coqc -q -Q "$record_update_dir" RecordUpdate "$record_update_dir/RecordSet.v"
    fi

    needs_hax_core_rebuild=0
    if [ ! -f "$hax_core_dir/src/Core.vo" ]; then
      needs_hax_core_rebuild=1
    fi

    if [ -d "$hax_core_dir" ] && [ "$needs_hax_core_rebuild" -eq 1 ]; then
      (
        cd "$hax_core_dir"
        find src spec phase_library -type f \
          \( -name '*.vo' -o -name '*.vos' -o -name '*.vok' -o -name '*.glob' -o -name '*.aux' \) \
          -delete
        coq_makefile_args=(-f _CoqProject -o Makefile)
        if [ -n "$record_update_dir" ]; then
          coq_makefile_args=(-f _CoqProject -Q "$record_update_dir" RecordUpdate -o Makefile)
        fi
        coq_makefile "${coq_makefile_args[@]}"
        make -j1 COQC=coqc COQDEP=coqdep COQTOP=coqtop COQCHK=coqchk
      )
    fi

    coq_flags=(
      -q
      -Q ./extraction ZkfCoreExtraction
      -Q "$hax_core_dir/src" Core
      -Q "$hax_core_dir/spec" Core
      -Q "$hax_core_dir/phase_library" Core
    )

    if [ -n "$record_update_dir" ]; then
      coq_flags+=(-Q "$record_update_dir" RecordUpdate)
    fi

    generated_files=()
    preferred_generated_files=(
      "./extraction/Zkf_core_Field.v"
      "./extraction/Zkf_core_Proof_kernel_spec_Bundle.v"
      "./extraction/Zkf_core_Proof_kernel_spec.v"
      "./extraction/Zkf_core_Proof_kernel_spec_Spec_field_ops.v"
    )

    for generated_file in "${preferred_generated_files[@]}"; do
      if [ -f "$generated_file" ]; then
        generated_files+=("$generated_file")
      fi
    done

    while IFS= read -r generated_file; do
      skip_file=0
      for preferred_file in "${preferred_generated_files[@]}"; do
        if [ "$generated_file" = "$preferred_file" ]; then
          skip_file=1
          break
        fi
      done
      if [ "$skip_file" -eq 0 ]; then
        generated_files+=("$generated_file")
      fi
    done < <(find ./extraction -type f -name '*.v' ! -name '_CoqProject' | sort)

    coqc "${coq_flags[@]}" KernelCompat.v
    coqc -q KernelArithmetic.v
    if [ -f KernelGenerated.v ]; then
      for generated_file in "${generated_files[@]}"; do
        coqc "${coq_flags[@]}" "$generated_file"
      done
      coqc "${coq_flags[@]}" KernelGenerated.v
      if [ -f KernelSemantics.v ]; then
        coqc "${coq_flags[@]}" KernelSemantics.v
      fi
      if [ -f KernelFieldEncodingProofs.v ]; then
        coqc "${coq_flags[@]}" KernelFieldEncodingProofs.v
      fi
      if [ -f FieldGenerationProvenance.v ]; then
        coqc "${coq_flags[@]}" FieldGenerationProvenance.v
      fi
      if [ -f Bn254MontgomeryStrictLane.v ]; then
        coqc "${coq_flags[@]}" Bn254MontgomeryStrictLane.v
      fi
      coqc "${coq_flags[@]}" KernelProofs.v
      if [ -f WitnessAdapterSemantics.v ]; then
        coqc "${coq_flags[@]}" WitnessAdapterSemantics.v
      fi
      if [ -f WitnessAdapterProofs.v ]; then
        coqc "${coq_flags[@]}" WitnessAdapterProofs.v
      fi
      if [ -f WitnessGenerationSemantics.v ]; then
        coqc "${coq_flags[@]}" WitnessGenerationSemantics.v
      fi
      if [ -f WitnessGenerationProofs.v ]; then
        coqc "${coq_flags[@]}" WitnessGenerationProofs.v
      fi
      if [ -f CcsSemantics.v ]; then
        coqc "${coq_flags[@]}" CcsSemantics.v
      fi
      if [ -f CcsProofs.v ]; then
        coqc "${coq_flags[@]}" CcsProofs.v
      fi
      if [ -f TransformSemantics.v ]; then
        coqc "${coq_flags[@]}" TransformSemantics.v
      fi
      if [ -f TransformProofs.v ]; then
        coqc "${coq_flags[@]}" TransformProofs.v
      fi
      if [ -f PipelineComposition.v ]; then
        coqc "${coq_flags[@]}" PipelineComposition.v
      fi
      if [ -f OrbitalDynamicsProofs.v ]; then
        coqc "${coq_flags[@]}" OrbitalDynamicsProofs.v
      fi
      if [ -f SatelliteConjunctionProofs.v ]; then
        coqc "${coq_flags[@]}" SatelliteConjunctionProofs.v
      fi
    fi
  )
  if [ -d "$zkf_backends_rocq_dir" ]; then
    (
      cd "$zkf_backends_rocq_dir"
      backend_coq_flags=(
        -q
        -Q ./extraction ZkfBackendsExtraction
        -Q "$hax_core_dir/src" Core
        -Q "$hax_core_dir/spec" Core
        -Q "$hax_core_dir/phase_library" Core
      )

      if [ -n "$record_update_dir" ]; then
        backend_coq_flags+=(-Q "$record_update_dir" RecordUpdate)
      fi

      backend_generated_files=()
      while IFS= read -r generated_file; do
        backend_generated_files+=("$generated_file")
      done < <(find ./extraction -type f -name '*.v' ! -name '_CoqProject' | sort)

      if [ "${#backend_generated_files[@]}" -gt 0 ]; then
        if [ -f BackendCompat.v ]; then
          coqc "${backend_coq_flags[@]}" BackendCompat.v
        fi
        for generated_file in "${backend_generated_files[@]}"; do
          coqc "${backend_coq_flags[@]}" "$generated_file"
        done
      fi

      for proof_file in \
        Plonky3Semantics.v \
        Plonky3Proofs.v \
        LookupLoweringSemantics.v \
        LookupLoweringProofs.v \
        BlackboxHashSemantics.v \
        BlackboxHashProofs.v \
        BlackboxEcdsaSemantics.v \
        BlackboxEcdsaProofs.v \
        BlackboxRuntimeProofs.v
      do
        if [ -f "$proof_file" ]; then
          coqc "${backend_coq_flags[@]}" "$proof_file"
        fi
      done
    )
  fi
  if [ -d "$zkf_runtime_rocq_dir" ]; then
    (
      cd "$zkf_runtime_rocq_dir"
      runtime_coq_flags=(
        -q
        -R "$zkf_core_rocq_dir" ""
        -Q "$zkf_core_rocq_dir/extraction" ZkfCoreExtraction
        -Q ./extraction ZkfRuntimeExtraction
        -Q "$hax_core_dir/src" Core
        -Q "$hax_core_dir/spec" Core
        -Q "$hax_core_dir/phase_library" Core
      )

      if [ -n "$record_update_dir" ]; then
        runtime_coq_flags+=(-Q "$record_update_dir" RecordUpdate)
      fi

      runtime_generated_files=()
      while IFS= read -r generated_file; do
        runtime_generated_files+=("$generated_file")
      done < <(find ./extraction -type f -name '*.v' ! -name '_CoqProject' | sort)

      for generated_file in "${runtime_generated_files[@]}"; do
        coqc "${runtime_coq_flags[@]}" "$generated_file"
      done

      for proof_file in RuntimePipelineComposition.v SwarmProofs.v; do
        if [ -f "$proof_file" ]; then
          coqc "${runtime_coq_flags[@]}" "$proof_file"
        fi
      done
    )
  fi
  if [ -d "$zkf_frontends_rocq_dir" ]; then
    (
      cd "$zkf_frontends_rocq_dir"
      frontend_coq_flags=(-q)

      if [ -n "$record_update_dir" ]; then
        frontend_coq_flags+=(-Q "$record_update_dir" RecordUpdate)
      fi

      if [ -d ./extraction ]; then
        frontend_coq_flags+=(-Q ./extraction ZkfFrontendsExtraction)
        frontend_generated_files=()
        while IFS= read -r generated_file; do
          frontend_generated_files+=("$generated_file")
        done < <(find ./extraction -type f -name '*.v' ! -name '_CoqProject' | sort)

        for generated_file in "${frontend_generated_files[@]}"; do
          coqc "${frontend_coq_flags[@]}" "$generated_file"
        done
      fi

      if [ -f NoirRecheckSemantics.v ]; then
        coqc "${frontend_coq_flags[@]}" NoirRecheckSemantics.v
      fi
      if [ -f NoirRecheckProofs.v ]; then
        coqc "${frontend_coq_flags[@]}" NoirRecheckProofs.v
      fi
    )
  fi
  if [ -d "$zkf_lib_rocq_dir" ]; then
    (
      cd "$zkf_lib_rocq_dir"
      lib_coq_flags=(
        -q
        -R "$zkf_core_rocq_dir" ""
        -Q "$zkf_core_rocq_dir/extraction" ZkfCoreExtraction
        -Q ./extraction ZkfLibExtraction
        -Q "$hax_core_dir/src" Core
        -Q "$hax_core_dir/spec" Core
        -Q "$hax_core_dir/phase_library" Core
      )

      if [ -n "$record_update_dir" ]; then
        lib_coq_flags+=(-Q "$record_update_dir" RecordUpdate)
      fi

      lib_generated_files=()
      while IFS= read -r generated_file; do
        lib_generated_files+=("$generated_file")
      done < <(find ./extraction -type f -name '*.v' ! -name '_CoqProject' | sort)

      for generated_file in "${lib_generated_files[@]}"; do
        coqc "${lib_coq_flags[@]}" "$generated_file"
      done

      if [ -f EmbeddedPipelineComposition.v ]; then
        coqc "${lib_coq_flags[@]}" EmbeddedPipelineComposition.v
      fi
    )
  fi
  if [ -d "$zkf_distributed_rocq_dir" ]; then
    (
      cd "$zkf_distributed_rocq_dir"
      distributed_coq_flags=(
        -q
        -R "$zkf_core_rocq_dir" ""
        -Q "$zkf_core_rocq_dir/extraction" ZkfCoreExtraction
        -Q ./extraction ZkfDistributedExtraction
        -Q "$hax_core_dir/src" Core
        -Q "$hax_core_dir/spec" Core
        -Q "$hax_core_dir/phase_library" Core
      )

      if [ -n "$record_update_dir" ]; then
        distributed_coq_flags+=(-Q "$record_update_dir" RecordUpdate)
      fi

      distributed_generated_files=()
      while IFS= read -r generated_file; do
        distributed_generated_files+=("$generated_file")
      done < <(find ./extraction -type f -name '*.v' ! -name '_CoqProject' | sort)

      if [ "${#distributed_generated_files[@]}" -gt 0 ]; then
        for generated_file in "${distributed_generated_files[@]}"; do
          coqc "${distributed_coq_flags[@]}" "$generated_file"
        done
      fi

      if [ -f SwarmReputationProofs.v ]; then
        coqc "${distributed_coq_flags[@]}" SwarmReputationProofs.v
      fi
      if [ -f SwarmEpochProofs.v ]; then
        coqc "${distributed_coq_flags[@]}" SwarmEpochProofs.v
      fi
    )
  fi
  python3 "$repo_root/scripts/check_strict_montgomery_exclusion.py"
  exit 0
fi

echo "coqc (Rocq 9.1) is required to check the Rocq proof files in zkf-ir-spec and zkf-core" >&2
exit 1
