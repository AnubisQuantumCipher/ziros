import CodegenSoundness
import HashReference

namespace ZkfMetalProofs

theorem sha256_round_sound : ProgramRefinesKernelSpec batch_sha256 sha256Spec := by
  simp [ProgramRefinesKernelSpec, batch_sha256, sha256Spec]

theorem batch_sha256_kernel_refines_spec : LoweringMatchesProgram batch_sha256 := by
  simp [LoweringMatchesProgram, Program.stepCount, batch_sha256]

theorem keccak_round_sound : ProgramRefinesKernelSpec batch_keccak256 keccakSpec := by
  simp [ProgramRefinesKernelSpec, batch_keccak256, keccakSpec]

theorem batch_keccak_kernel_refines_spec : LoweringMatchesProgram batch_keccak256 := by
  simp [LoweringMatchesProgram, Program.stepCount, batch_keccak256]

theorem hash_family_exact_digest_sound :
    (∀ env, HashAcceptedLaunchSurface batch_sha256 env ->
      ProgramImplementsHashDigestSemantics batch_sha256 sha256ExactDigestSemantics)
      ∧
    (∀ env, HashAcceptedLaunchSurface batch_keccak256 env ->
      ProgramImplementsHashDigestSemantics batch_keccak256 keccakExactDigestSemantics) := by
  refine ⟨?_, ?_⟩
  · intro env _accepted
    simp [ProgramImplementsHashDigestSemantics, sha256ExactDigestSemantics, batch_sha256]
  · intro env _accepted
    simp [ProgramImplementsHashDigestSemantics, keccakExactDigestSemantics, batch_keccak256]

end ZkfMetalProofs
