import CodegenSoundness
import MsmReference

namespace ZkfMetalProofs

theorem bucket_assignment_sound :
    ProgramRefinesKernelSpec msm_bn254_classic_assign bn254ClassicAssignSpec
      ∧ ProgramRefinesKernelSpec msm_pallas_classic_assign pallasClassicAssignSpec
      ∧ ProgramRefinesKernelSpec msm_vesta_classic_assign vestaClassicAssignSpec := by
  exact ⟨
    by simp [ProgramRefinesKernelSpec, msm_bn254_classic_assign, bn254ClassicAssignSpec, msmSpec],
    by simp [ProgramRefinesKernelSpec, msm_pallas_classic_assign, pallasClassicAssignSpec, msmSpec],
    by simp [ProgramRefinesKernelSpec, msm_vesta_classic_assign, vestaClassicAssignSpec, msmSpec]
  ⟩

theorem bucket_accumulation_sound :
    ProgramRefinesKernelSpec msm_bn254_classic_accumulate bn254ClassicAccumulateSpec
      ∧ ProgramRefinesKernelSpec msm_pallas_classic_accumulate pallasClassicAccumulateSpec
      ∧ ProgramRefinesKernelSpec msm_pallas_naf_accumulate pallasNafAccumulateSpec
      ∧ ProgramRefinesKernelSpec msm_vesta_classic_accumulate vestaClassicAccumulateSpec
      ∧ ProgramRefinesKernelSpec msm_vesta_naf_accumulate vestaNafAccumulateSpec := by
  exact ⟨
    by
      simp [ProgramRefinesKernelSpec, msm_bn254_classic_accumulate, bn254ClassicAccumulateSpec,
        msmSpec],
    by
      simp [ProgramRefinesKernelSpec, msm_pallas_classic_accumulate, pallasClassicAccumulateSpec,
        msmSpec],
    by simp [ProgramRefinesKernelSpec, msm_pallas_naf_accumulate, pallasNafAccumulateSpec, msmSpec],
    by
      simp [ProgramRefinesKernelSpec, msm_vesta_classic_accumulate, vestaClassicAccumulateSpec,
        msmSpec],
    by simp [ProgramRefinesKernelSpec, msm_vesta_naf_accumulate, vestaNafAccumulateSpec, msmSpec]
  ⟩

theorem bucket_reduce_sound :
    ProgramRefinesKernelSpec msm_bn254_classic_reduce bn254ClassicReduceSpec := by
  simp [ProgramRefinesKernelSpec, msm_bn254_classic_reduce, bn254ClassicReduceSpec, msmSpec]

theorem combine_windows_sound :
    ProgramRefinesKernelSpec msm_bn254_classic_combine bn254ClassicCombineSpec := by
  simp [ProgramRefinesKernelSpec, msm_bn254_classic_combine, bn254ClassicCombineSpec, msmSpec]

theorem bn254_msm_refines_pippenger :
    LoweringMatchesProgram msm_bn254_classic_assign
      ∧ LoweringMatchesProgram msm_bn254_classic_accumulate
      ∧ LoweringMatchesProgram msm_bn254_classic_reduce
      ∧ LoweringMatchesProgram msm_bn254_classic_combine := by
  exact ⟨
    by simp [LoweringMatchesProgram, Program.stepCount, msm_bn254_classic_assign],
    by simp [LoweringMatchesProgram, Program.stepCount, msm_bn254_classic_accumulate],
    by simp [LoweringMatchesProgram, Program.stepCount, msm_bn254_classic_reduce],
    by simp [LoweringMatchesProgram, Program.stepCount, msm_bn254_classic_combine]
  ⟩

theorem pallas_msm_refines_pippenger :
    LoweringMatchesProgram msm_pallas_classic_assign
      ∧ LoweringMatchesProgram msm_pallas_classic_accumulate
      ∧ LoweringMatchesProgram msm_pallas_naf_accumulate := by
  exact ⟨
    by simp [LoweringMatchesProgram, Program.stepCount, msm_pallas_classic_assign],
    by simp [LoweringMatchesProgram, Program.stepCount, msm_pallas_classic_accumulate],
    by simp [LoweringMatchesProgram, Program.stepCount, msm_pallas_naf_accumulate]
  ⟩

theorem vesta_msm_refines_pippenger :
    LoweringMatchesProgram msm_vesta_classic_assign
      ∧ LoweringMatchesProgram msm_vesta_classic_accumulate
      ∧ LoweringMatchesProgram msm_vesta_naf_accumulate := by
  exact ⟨
    by simp [LoweringMatchesProgram, Program.stepCount, msm_vesta_classic_assign],
    by simp [LoweringMatchesProgram, Program.stepCount, msm_vesta_classic_accumulate],
    by simp [LoweringMatchesProgram, Program.stepCount, msm_vesta_naf_accumulate]
  ⟩

theorem msm_family_exact_pippenger_sound :
    (∀ env, MsmAcceptedLaunchSurface msm_bn254_classic_assign env ->
      ProgramImplementsMsmPippengerSemantics
        msm_bn254_classic_assign bn254ClassicAssignSemantics)
      ∧
    (∀ env, MsmAcceptedLaunchSurface msm_bn254_classic_accumulate env ->
      ProgramImplementsMsmPippengerSemantics
        msm_bn254_classic_accumulate bn254ClassicAccumulateSemantics)
      ∧
    (∀ env, MsmAcceptedLaunchSurface msm_bn254_classic_reduce env ->
      ProgramImplementsMsmPippengerSemantics
        msm_bn254_classic_reduce bn254ClassicReduceSemantics)
      ∧
    (∀ env, MsmAcceptedLaunchSurface msm_bn254_classic_combine env ->
      ProgramImplementsMsmPippengerSemantics
        msm_bn254_classic_combine bn254ClassicCombineSemantics)
      ∧
    (∀ env, MsmAcceptedLaunchSurface msm_pallas_classic_assign env ->
      ProgramImplementsMsmPippengerSemantics
        msm_pallas_classic_assign pallasClassicAssignSemantics)
      ∧
    (∀ env, MsmAcceptedLaunchSurface msm_pallas_classic_accumulate env ->
      ProgramImplementsMsmPippengerSemantics
        msm_pallas_classic_accumulate pallasClassicAccumulateSemantics)
      ∧
    (∀ env, MsmAcceptedLaunchSurface msm_pallas_naf_accumulate env ->
      ProgramImplementsMsmPippengerSemantics
        msm_pallas_naf_accumulate pallasNafAccumulateSemantics)
      ∧
    (∀ env, MsmAcceptedLaunchSurface msm_vesta_classic_assign env ->
      ProgramImplementsMsmPippengerSemantics
        msm_vesta_classic_assign vestaClassicAssignSemantics)
      ∧
    (∀ env, MsmAcceptedLaunchSurface msm_vesta_classic_accumulate env ->
      ProgramImplementsMsmPippengerSemantics
        msm_vesta_classic_accumulate vestaClassicAccumulateSemantics)
      ∧
    (∀ env, MsmAcceptedLaunchSurface msm_vesta_naf_accumulate env ->
      ProgramImplementsMsmPippengerSemantics
        msm_vesta_naf_accumulate vestaNafAccumulateSemantics)
      ∧
    Bn254ClassicChainSurface
      msm_bn254_classic_assign
      msm_bn254_classic_accumulate
      msm_bn254_classic_reduce
      msm_bn254_classic_combine
      ∧
    CurveClassicOrNafSurface
      msm_pallas_classic_assign
      msm_pallas_classic_accumulate
      msm_pallas_naf_accumulate
      CurveFamily.pallas
      "pallas_msm_library"
      ∧
    CurveClassicOrNafSurface
      msm_vesta_classic_assign
      msm_vesta_classic_accumulate
      msm_vesta_naf_accumulate
      CurveFamily.vesta
      "vesta_msm_library" := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro env _accepted
    simp [
      ProgramImplementsMsmPippengerSemantics,
      bn254ClassicAssignSemantics,
      msmSemantics,
      bn254SourcePaths,
      msm_bn254_classic_assign,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsMsmPippengerSemantics,
      bn254ClassicAccumulateSemantics,
      msmSemantics,
      bn254SourcePaths,
      msm_bn254_classic_accumulate,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsMsmPippengerSemantics,
      bn254ClassicReduceSemantics,
      msmSemantics,
      bn254ReduceSourcePaths,
      msm_bn254_classic_reduce,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsMsmPippengerSemantics,
      bn254ClassicCombineSemantics,
      msmSemantics,
      bn254ReduceSourcePaths,
      msm_bn254_classic_combine,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsMsmPippengerSemantics,
      pallasClassicAssignSemantics,
      msmSemantics,
      pallasSourcePaths,
      msm_pallas_classic_assign,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsMsmPippengerSemantics,
      pallasClassicAccumulateSemantics,
      msmSemantics,
      pallasSourcePaths,
      msm_pallas_classic_accumulate,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsMsmPippengerSemantics,
      pallasNafAccumulateSemantics,
      msmSemantics,
      pallasSourcePaths,
      msm_pallas_naf_accumulate,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsMsmPippengerSemantics,
      vestaClassicAssignSemantics,
      msmSemantics,
      vestaSourcePaths,
      msm_vesta_classic_assign,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsMsmPippengerSemantics,
      vestaClassicAccumulateSemantics,
      msmSemantics,
      vestaSourcePaths,
      msm_vesta_classic_accumulate,
    ]
  · intro env _accepted
    simp [
      ProgramImplementsMsmPippengerSemantics,
      vestaNafAccumulateSemantics,
      msmSemantics,
      vestaSourcePaths,
      msm_vesta_naf_accumulate,
    ]
  · simp [
      Bn254ClassicChainSurface,
      msm_bn254_classic_assign,
      msm_bn254_classic_accumulate,
      msm_bn254_classic_reduce,
      msm_bn254_classic_combine,
    ]
  · simp [
      CurveClassicOrNafSurface,
      msm_pallas_classic_assign,
      msm_pallas_classic_accumulate,
      msm_pallas_naf_accumulate,
    ]
  · simp [
      CurveClassicOrNafSurface,
      msm_vesta_classic_assign,
      msm_vesta_classic_accumulate,
      msm_vesta_naf_accumulate,
    ]

end ZkfMetalProofs
