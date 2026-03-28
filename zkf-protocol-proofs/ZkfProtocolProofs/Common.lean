namespace ZkfProtocolProofs

structure RustFileSnapshot where
  path : String
  sha256 : String
deriving Repr, DecidableEq

structure Groth16SurfaceSnapshot where
  surface : String
  backend : String
  field : String
  curve : String
  scheme : String
  setupBlobVersion : Nat
  setupProvenance : String
  securityBoundary : String
  developmentBoundary : String
  requiredCompiledMetadata : List String
  requiredProofMetadata : List String
  verifierChecks : List String
  rustFiles : List RustFileSnapshot
deriving Repr, DecidableEq

structure FriSurfaceSnapshot where
  surface : String
  backend : String
  scheme : String
  pcs : String
  plonky3Version : String
  seedDerivation : String
  wrapperSurface : String
  wrapperStatuses : List String
  wrapperStrategies : List String
  wrapperSemantics : List String
  sourceVerificationSemantics : List String
  requiredProofMetadata : List String
  rustFiles : List RustFileSnapshot
deriving Repr, DecidableEq

structure NovaSurfaceSnapshot where
  surface : String
  backend : String
  compileScheme : String
  foldScheme : String
  nativeMode : String
  profiles : List String
  primaryCurve : String
  secondaryCurve : String
  curveCycle : String
  stepArity : Nat
  compressedFoldSupportedProfiles : List String
  requiredCompiledMetadata : List String
  requiredSingleStepProofMetadata : List String
  requiredFoldProofMetadata : List String
  rustFiles : List RustFileSnapshot
deriving Repr, DecidableEq

structure BilinearGroupSurface where
  backend : String
  curve : String
  scalarField : String
  scheme : String
  setupBlobVersion : Nat
  setupProvenance : String
  securityBoundary : String
  developmentBoundary : String
  requiredCompiledMetadata : List String
  requiredProofMetadata : List String
  verifierChecks : List String
  rustFiles : List RustFileSnapshot
deriving Repr, DecidableEq

structure FriTranscriptSurface where
  backend : String
  scheme : String
  pcs : String
  plonky3Version : String
  seedDerivation : String
  wrapperSurface : String
  wrapperStatuses : List String
  wrapperStrategies : List String
  wrapperSemantics : List String
  sourceVerificationSemantics : List String
  requiredProofMetadata : List String
  rustFiles : List RustFileSnapshot
deriving Repr, DecidableEq

structure ReedSolomonDomainSurface where
  backend : String
  pcs : String
  wrapperSurface : String
  transcriptSeed : String
  wrapperStrategies : List String
  wrapperStatuses : List String
  rustFiles : List RustFileSnapshot
deriving Repr, DecidableEq

structure RelaxedR1CSSurface where
  backend : String
  profile : String
  compileScheme : String
  foldScheme : String
  nativeMode : String
  primaryCurve : String
  secondaryCurve : String
  curveCycle : String
  stepArity : Nat
  requiredCompiledMetadata : List String
  requiredSingleStepProofMetadata : List String
  requiredFoldProofMetadata : List String
  rustFiles : List RustFileSnapshot
deriving Repr, DecidableEq

structure HyperNovaCcsSurface where
  backend : String
  profile : String
  compileScheme : String
  nativeMode : String
  primaryCurve : String
  secondaryCurve : String
  curveCycle : String
  stepArity : Nat
  requiredCompiledMetadata : List String
  requiredSingleStepProofMetadata : List String
  rustFiles : List RustFileSnapshot
deriving Repr, DecidableEq

structure ProtocolProofObligation where
  theoremName : String
  ledgerTheoremId : String
  scope : String
  targetSurface : String
  statementSummary : String
  blockingAssumptions : List String
deriving Repr, DecidableEq

end ZkfProtocolProofs
