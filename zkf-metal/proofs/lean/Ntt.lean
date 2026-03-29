import CodegenSoundness
import Bn254NttArithmetic
import NttReference

namespace ZkfMetalProofs

theorem butterfly_sound :
    ProgramRefinesKernelSpec ntt_butterfly_goldilocks goldilocksButterflySpec
      ∧ ProgramRefinesKernelSpec ntt_butterfly_goldilocks_batch goldilocksBatchSpec
      ∧ ProgramRefinesKernelSpec ntt_butterfly_babybear babybearButterflySpec
      ∧ ProgramRefinesKernelSpec ntt_butterfly_babybear_batch babybearBatchSpec
      ∧ ProgramRefinesKernelSpec ntt_butterfly_bn254 bn254ButterflySpec := by
  exact ⟨
    by
      simp [ProgramRefinesKernelSpec, ntt_butterfly_goldilocks, goldilocksButterflySpec,
        nttButterflySpec],
    by
      simp [ProgramRefinesKernelSpec, ntt_butterfly_goldilocks_batch, goldilocksBatchSpec,
        nttButterflySpec],
    by
      simp [ProgramRefinesKernelSpec, ntt_butterfly_babybear, babybearButterflySpec,
        nttButterflySpec],
    by
      simp [ProgramRefinesKernelSpec, ntt_butterfly_babybear_batch, babybearBatchSpec,
        nttButterflySpec],
    by
      simp [ProgramRefinesKernelSpec, ntt_butterfly_bn254, bn254ButterflySpec, nttButterflySpec]
  ⟩

theorem twiddle_schedule_sound :
    ProgramRefinesKernelSpec ntt_small_goldilocks goldilocksSmallSpec
      ∧ ProgramRefinesKernelSpec ntt_hybrid_goldilocks goldilocksHybridSpec
      ∧ ProgramRefinesKernelSpec ntt_small_bn254 bn254SmallSpec
      ∧ ProgramRefinesKernelSpec ntt_hybrid_bn254 bn254HybridSpec := by
  exact ⟨
    by simp [ProgramRefinesKernelSpec, ntt_small_goldilocks, goldilocksSmallSpec, nttSmallSpec],
    by simp [ProgramRefinesKernelSpec, ntt_hybrid_goldilocks, goldilocksHybridSpec, nttHybridSpec],
    by simp [ProgramRefinesKernelSpec, ntt_small_bn254, bn254SmallSpec, nttSmallSpec],
    by simp [ProgramRefinesKernelSpec, ntt_hybrid_bn254, bn254HybridSpec, nttHybridSpec]
  ⟩

theorem small_ntt_refines_stage_semantics :
    LoweringMatchesProgram ntt_small_goldilocks ∧ LoweringMatchesProgram ntt_small_bn254 := by
  exact ⟨
    by simp [LoweringMatchesProgram, Program.stepCount, ntt_small_goldilocks],
    by simp [LoweringMatchesProgram, Program.stepCount, ntt_small_bn254]
  ⟩

theorem hybrid_ntt_refines_full_ntt :
    LoweringMatchesProgram ntt_hybrid_goldilocks ∧ LoweringMatchesProgram ntt_hybrid_bn254 := by
  exact ⟨
    by simp [LoweringMatchesProgram, Program.stepCount, ntt_hybrid_goldilocks],
    by simp [LoweringMatchesProgram, Program.stepCount, ntt_hybrid_bn254]
  ⟩

theorem large_ntt_refines_full_ntt :
    LoweringMatchesProgram ntt_butterfly_goldilocks_batch
      ∧ LoweringMatchesProgram ntt_butterfly_babybear_batch := by
  exact ⟨
    by simp [LoweringMatchesProgram, Program.stepCount, ntt_butterfly_goldilocks_batch],
    by simp [LoweringMatchesProgram, Program.stepCount, ntt_butterfly_babybear_batch]
  ⟩

theorem bn254_ntt_refines_full_ntt :
    LoweringMatchesProgram ntt_butterfly_bn254
      ∧ LoweringMatchesProgram ntt_small_bn254
      ∧ LoweringMatchesProgram ntt_hybrid_bn254 := by
  exact ⟨
    by simp [LoweringMatchesProgram, Program.stepCount, ntt_butterfly_bn254],
    by simp [LoweringMatchesProgram, Program.stepCount, ntt_small_bn254],
    by simp [LoweringMatchesProgram, Program.stepCount, ntt_hybrid_bn254]
  ⟩

theorem ntt_family_exact_transform_sound :
    (∀ env, NttAcceptedLaunchSurface ntt_butterfly_goldilocks env ->
      ProgramImplementsNttTransformSemantics
        ntt_butterfly_goldilocks goldilocksButterflyTransformSemantics)
      ∧
    (∀ env, NttAcceptedLaunchSurface ntt_butterfly_goldilocks_batch env ->
      ProgramImplementsNttTransformSemantics
        ntt_butterfly_goldilocks_batch goldilocksBatchTransformSemantics)
      ∧
    (∀ env, NttAcceptedLaunchSurface ntt_small_goldilocks env ->
      ProgramImplementsNttTransformSemantics
        ntt_small_goldilocks goldilocksSmallTransformSemantics)
      ∧
    (∀ env, NttAcceptedLaunchSurface ntt_hybrid_goldilocks env ->
      ProgramImplementsNttTransformSemantics
        ntt_hybrid_goldilocks goldilocksHybridTransformSemantics)
      ∧
    (∀ env, NttAcceptedLaunchSurface ntt_butterfly_babybear env ->
      ProgramImplementsNttTransformSemantics
        ntt_butterfly_babybear babybearButterflyTransformSemantics)
      ∧
    (∀ env, NttAcceptedLaunchSurface ntt_butterfly_babybear_batch env ->
      ProgramImplementsNttTransformSemantics
        ntt_butterfly_babybear_batch babybearBatchTransformSemantics)
      ∧
    (∀ env, NttAcceptedLaunchSurface ntt_butterfly_bn254 env ->
      ProgramImplementsNttTransformSemantics
        ntt_butterfly_bn254 bn254ButterflyTransformSemantics)
      ∧
    (∀ env, NttAcceptedLaunchSurface ntt_small_bn254 env ->
      ProgramImplementsNttTransformSemantics
        ntt_small_bn254 bn254SmallTransformSemantics)
      ∧
    (∀ env, NttAcceptedLaunchSurface ntt_hybrid_bn254 env ->
      ProgramImplementsNttTransformSemantics
        ntt_hybrid_bn254 bn254HybridTransformSemantics)
      ∧
    NttLargeScheduleSurface
      ntt_butterfly_goldilocks
      ntt_butterfly_goldilocks_batch
      FieldFamily.goldilocks
      8
      ∧
    NttStagedTransformSurface
      ntt_butterfly_goldilocks
      ntt_small_goldilocks
      ntt_hybrid_goldilocks
      FieldFamily.goldilocks
      8
      false
      ∧
    NttLargeScheduleSurface
      ntt_butterfly_babybear
      ntt_butterfly_babybear_batch
      FieldFamily.babyBear
      4
      ∧
    NttStagedTransformSurface
      ntt_butterfly_bn254
      ntt_small_bn254
      ntt_hybrid_bn254
      FieldFamily.bn254Scalar
      8
      true := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro env _accepted
    simp [
      ProgramImplementsNttTransformSemantics,
      goldilocksButterflyTransformSemantics,
      nttTransformSemantics,
      ntt_butterfly_goldilocks,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsNttTransformSemantics,
      goldilocksBatchTransformSemantics,
      nttTransformSemantics,
      ntt_butterfly_goldilocks_batch,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsNttTransformSemantics,
      goldilocksSmallTransformSemantics,
      goldilocksButterflyTransformSemantics,
      nttTransformSemantics,
      ntt_small_goldilocks,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsNttTransformSemantics,
      goldilocksHybridTransformSemantics,
      goldilocksButterflyTransformSemantics,
      nttTransformSemantics,
      ntt_hybrid_goldilocks,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsNttTransformSemantics,
      babybearButterflyTransformSemantics,
      goldilocksButterflyTransformSemantics,
      nttTransformSemantics,
      ntt_butterfly_babybear,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsNttTransformSemantics,
      babybearBatchTransformSemantics,
      goldilocksBatchTransformSemantics,
      nttTransformSemantics,
      ntt_butterfly_babybear_batch,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsNttTransformSemantics,
      bn254ButterflyTransformSemantics,
      nttTransformSemantics,
      ntt_butterfly_bn254,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsNttTransformSemantics,
      bn254SmallTransformSemantics,
      bn254ButterflyTransformSemantics,
      nttTransformSemantics,
      ntt_small_bn254,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsNttTransformSemantics,
      bn254HybridTransformSemantics,
      bn254ButterflyTransformSemantics,
      nttTransformSemantics,
      ntt_hybrid_bn254,
    ]
  · simp [NttLargeScheduleSurface, ntt_butterfly_goldilocks, ntt_butterfly_goldilocks_batch]
  · simp [
      NttStagedTransformSurface,
      ntt_butterfly_goldilocks,
      ntt_small_goldilocks,
      ntt_hybrid_goldilocks,
    ]
  · simp [NttLargeScheduleSurface, ntt_butterfly_babybear, ntt_butterfly_babybear_batch]
  · simp [NttStagedTransformSurface, ntt_butterfly_bn254, ntt_small_bn254, ntt_hybrid_bn254]

theorem gpu_bn254_ntt_butterfly_arithmetic_sound :
    ProgramImplementsBn254ButterflyArithmetic ntt_butterfly_bn254
      ∧
    (∀ stage n tid lhs rhs twiddle,
      Bn254ButterflyBranchActive stage n tid ->
      Bn254Canonical lhs ->
      Bn254Canonical rhs ->
      Bn254Canonical twiddle ->
      Bn254Canonical (bn254MontMul twiddle rhs)
        ∧ Bn254Canonical (bn254ButterflyOut0 lhs rhs twiddle)
        ∧ Bn254Canonical (bn254ButterflyOut1 lhs rhs twiddle)
        ∧ bn254ButterflyOut0 lhs rhs twiddle
            = bn254Normalize (lhs + bn254MontMul twiddle rhs)
        ∧ bn254ButterflyOut1 lhs rhs twiddle
            = bn254Normalize (lhs + bn254Modulus - bn254MontMul twiddle rhs)
        ∧ bn254ButterflyTwiddleIndex stage tid
            = bn254ButterflyHalfN stage + bn254ButterflyPos stage tid) := by
  exact bn254ButterflyArithmeticSurfaceSound

end ZkfMetalProofs
