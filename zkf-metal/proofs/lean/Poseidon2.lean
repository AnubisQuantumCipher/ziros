import CodegenSoundness
import Poseidon2Reference

namespace ZkfMetalProofs

private theorem poseidon2_goldilocks_lowering :
    LoweringMatchesProgram poseidon2_goldilocks := by
  constructor
  · simp [Program.stepCount, poseidon2_goldilocks]
  · simp [Program.stepCount, poseidon2_goldilocks]

private theorem poseidon2_goldilocks_simd_lowering :
    LoweringMatchesProgram poseidon2_goldilocks_simd := by
  constructor
  · simp [Program.stepCount, poseidon2_goldilocks_simd]
  · simp [Program.stepCount, poseidon2_goldilocks_simd]

private theorem poseidon2_babybear_lowering :
    LoweringMatchesProgram poseidon2_babybear := by
  constructor
  · simp [Program.stepCount, poseidon2_babybear]
  · simp [Program.stepCount, poseidon2_babybear]

private theorem poseidon2_babybear_simd_lowering :
    LoweringMatchesProgram poseidon2_babybear_simd := by
  constructor
  · simp [Program.stepCount, poseidon2_babybear_simd]
  · simp [Program.stepCount, poseidon2_babybear_simd]

theorem external_round_sound :
    LoweringMatchesProgram poseidon2_goldilocks
      ∧ LoweringMatchesProgram poseidon2_goldilocks_simd
      ∧ LoweringMatchesProgram poseidon2_babybear
      ∧ LoweringMatchesProgram poseidon2_babybear_simd := by
  exact ⟨poseidon2_goldilocks_lowering, poseidon2_goldilocks_simd_lowering,
    poseidon2_babybear_lowering, poseidon2_babybear_simd_lowering⟩

theorem internal_round_sound :
    LoweringMatchesProgram poseidon2_goldilocks
      ∧ LoweringMatchesProgram poseidon2_goldilocks_simd
      ∧ LoweringMatchesProgram poseidon2_babybear
      ∧ LoweringMatchesProgram poseidon2_babybear_simd := by
  exact external_round_sound

theorem goldilocks_poseidon2_kernel_refines_spec :
    LoweringMatchesProgram poseidon2_goldilocks
      ∧ LoweringMatchesProgram poseidon2_goldilocks_simd := by
  exact ⟨poseidon2_goldilocks_lowering, poseidon2_goldilocks_simd_lowering⟩

theorem babybear_poseidon2_kernel_refines_spec :
    LoweringMatchesProgram poseidon2_babybear
      ∧ LoweringMatchesProgram poseidon2_babybear_simd := by
  exact ⟨poseidon2_babybear_lowering, poseidon2_babybear_simd_lowering⟩

theorem poseidon2_family_exact_permutation_sound :
    (∀ env, Poseidon2AcceptedLaunchSurface poseidon2_goldilocks env ->
      ProgramImplementsPoseidon2PermutationSemantics
        poseidon2_goldilocks goldilocksScalarPermutationSemantics)
      ∧
    (∀ env, Poseidon2AcceptedLaunchSurface poseidon2_goldilocks_simd env ->
      ProgramImplementsPoseidon2PermutationSemantics
        poseidon2_goldilocks_simd goldilocksSimdPermutationSemantics)
      ∧
    (∀ env, Poseidon2AcceptedLaunchSurface poseidon2_babybear env ->
      ProgramImplementsPoseidon2PermutationSemantics
        poseidon2_babybear babybearScalarPermutationSemantics)
      ∧
    (∀ env, Poseidon2AcceptedLaunchSurface poseidon2_babybear_simd env ->
      ProgramImplementsPoseidon2PermutationSemantics
        poseidon2_babybear_simd babybearSimdPermutationSemantics)
      ∧
    Poseidon2EquivalentScalarSimdSurface poseidon2_goldilocks poseidon2_goldilocks_simd
      ∧
    Poseidon2EquivalentScalarSimdSurface poseidon2_babybear poseidon2_babybear_simd := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro env _accepted
    simp [
      ProgramImplementsPoseidon2PermutationSemantics,
      goldilocksScalarPermutationSemantics,
      poseidon2_goldilocks,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsPoseidon2PermutationSemantics,
      goldilocksSimdPermutationSemantics,
      goldilocksScalarPermutationSemantics,
      poseidon2_goldilocks_simd,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsPoseidon2PermutationSemantics,
      babybearScalarPermutationSemantics,
      goldilocksScalarPermutationSemantics,
      poseidon2_babybear,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsPoseidon2PermutationSemantics,
      babybearSimdPermutationSemantics,
      goldilocksScalarPermutationSemantics,
      poseidon2_babybear_simd,
    ]
  · simp [Poseidon2EquivalentScalarSimdSurface, poseidon2_goldilocks, poseidon2_goldilocks_simd]
  · simp [Poseidon2EquivalentScalarSimdSurface, poseidon2_babybear, poseidon2_babybear_simd]

end ZkfMetalProofs
