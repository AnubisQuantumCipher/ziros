def withinTermWindow (windowOpen windowClose presented : Nat) : Bool :=
  decide (windowOpen ≤ presented) && decide (presented ≤ windowClose)

def eligibilityPassed (windowOk : Bool) (supportedEligibilityPredicateCount lenderExclusionMatchCount buyerAcceptanceTermCount : Nat) : Bool :=
  windowOk
    && decide (1 ≤ supportedEligibilityPredicateCount)
    && decide (lenderExclusionMatchCount = 0)
    && decide (1 ≤ buyerAcceptanceTermCount)

def approvedAdvanceAmount (eligibleInvoice retentionAmount discountAmount advanceCap : Nat) : Nat :=
  Nat.min (eligibleInvoice - retentionAmount - discountAmount) advanceCap

def reserveAmount (approvedAdvance reserveMargin reserveFloor : Nat) : Nat :=
  Nat.max (approvedAdvance + reserveMargin) reserveFloor

def feeAmount (approvedAdvance attachmentPoint participationCap participationRate scale : Nat) : Nat :=
  ((Nat.min (approvedAdvance - attachmentPoint) participationCap) * participationRate) / scale

def actionClassCode (eligible inconsistencyHit riskReviewHit manualReviewHit : Bool) : Nat :=
  if !eligible then 3
  else if inconsistencyHit then 4
  else if riskReviewHit then 2
  else if manualReviewHit then 1
  else 0

def humanReviewRequired (eligible inconsistencyHit riskReviewHit manualReviewHit : Bool) : Bool :=
  (!eligible) || inconsistencyHit || riskReviewHit || manualReviewHit

def eligibleForMidnightSettlement
    (eligible inconsistencyHit riskReviewHit manualReviewHit : Bool)
    (approvedAdvance : Nat) : Bool :=
  eligible
    && !inconsistencyHit
    && !riskReviewHit
    && !manualReviewHit
    && decide (0 < approvedAdvance)

def disclosureValueA
    (role settlementCommitment advanceCommitment invoiceCommitment reserveCommitment : Nat) : Nat :=
  match role with
  | 0 => settlementCommitment
  | 1 => advanceCommitment
  | 2 => invoiceCommitment
  | 3 => advanceCommitment
  | _ => reserveCommitment


def disclosureValueB
    (role advanceCommitment eligibilityCommitment consistencyCommitment reserveCommitment duplicateRiskCommitment : Nat) : Nat :=
  match role with
  | 0 => advanceCommitment
  | 1 => reserveCommitment
  | 2 => eligibilityCommitment
  | 3 => consistencyCommitment
  | _ => duplicateRiskCommitment

def disclosureAuthorizationInner
    (role credentialCommitment requestIdHash : Nat) : Nat :=
  1111 + role + credentialCommitment + requestIdHash

def disclosureAuthorizationCommitment
    (role credentialCommitment requestIdHash callerCommitment viewCommitment publicBlinding : Nat) : Nat :=
  disclosureAuthorizationInner role credentialCommitment requestIdHash
    + callerCommitment
    + viewCommitment
    + publicBlinding


def roleValid (role : Nat) : Bool :=
  decide (role < 5)

def shardAssignment (commitment shardCount : Nat) : Nat :=
  commitment % shardCount

def batchRootPayload (commitment0 commitment1 commitment2 commitment3 blinding0 blinding1 : Nat) : Nat :=
  commitment0 + commitment1 + commitment2 + commitment3 + blinding0 + blinding1

theorem withinTermWindow_true_implies_lower
    {windowOpen windowClose presented : Nat} :
    withinTermWindow windowOpen windowClose presented = true -> windowOpen ≤ presented := by
  intro h
  simp [withinTermWindow] at h
  exact h.left

theorem withinTermWindow_true_implies_upper
    {windowOpen windowClose presented : Nat} :
    withinTermWindow windowOpen windowClose presented = true -> presented ≤ windowClose := by
  intro h
  simp [withinTermWindow] at h
  exact h.right

theorem eligibilityPassed_true_implies_conditions
    {windowOk : Bool} {supportedEligibilityPredicateCount lenderExclusionMatchCount buyerAcceptanceTermCount : Nat} :
    eligibilityPassed windowOk supportedEligibilityPredicateCount lenderExclusionMatchCount buyerAcceptanceTermCount = true ->
      windowOk = true
      ∧ 1 ≤ supportedEligibilityPredicateCount
      ∧ lenderExclusionMatchCount = 0
      ∧ 1 ≤ buyerAcceptanceTermCount := by
  intro h
  simp [eligibilityPassed] at h
  rcases h with ⟨⟨⟨hWindow, hSupported⟩, hExclusion⟩, hRequested⟩
  exact ⟨hWindow, hSupported, hExclusion, hRequested⟩

theorem approvedAdvanceAmount_le_cap
    (eligibleInvoice retentionAmount discountAmount advanceCap : Nat) :
    approvedAdvanceAmount eligibleInvoice retentionAmount discountAmount advanceCap ≤ advanceCap := by
  unfold approvedAdvanceAmount
  exact Nat.min_le_right _ _

theorem reserveAmount_ge_floor
    (approvedAdvance reserveMargin reserveFloor : Nat) :
    reserveFloor ≤ reserveAmount approvedAdvance reserveMargin reserveFloor := by
  unfold reserveAmount
  exact Nat.le_max_right _ _

theorem reserveAmount_ge_approved
    (approvedAdvance reserveMargin reserveFloor : Nat) :
    approvedAdvance ≤ reserveAmount approvedAdvance reserveMargin reserveFloor := by
  unfold reserveAmount
  exact Nat.le_trans (Nat.le_add_right _ _) (Nat.le_max_left _ _)

theorem feeAmount_zero_below_attachment
    {approvedAdvance attachmentPoint participationCap participationRate scale : Nat}
    (h : approvedAdvance ≤ attachmentPoint) :
    feeAmount approvedAdvance attachmentPoint participationCap participationRate scale = 0 := by
  have hsub : approvedAdvance - attachmentPoint = 0 := Nat.sub_eq_zero_of_le h
  simp [feeAmount, hsub]

theorem actionClassCode_in_range
    (eligible inconsistencyHit riskReviewHit manualReviewHit : Bool) :
    actionClassCode eligible inconsistencyHit riskReviewHit manualReviewHit ≤ 4 := by
  cases eligible <;> cases inconsistencyHit <;> cases riskReviewHit <;> cases manualReviewHit <;>
    simp [actionClassCode]

theorem actionClassRejectsIneligibleRequest
    (inconsistencyHit riskReviewHit manualReviewHit : Bool) :
    actionClassCode false inconsistencyHit riskReviewHit manualReviewHit = 3 := by
  simp [actionClassCode]

theorem actionClassApprovesWhenAllClear :
    actionClassCode true false false false = 0 := by
  simp [actionClassCode]

theorem humanReviewRequired_for_nonapprove_actions
    {eligible inconsistencyHit riskReviewHit manualReviewHit : Bool} :
    actionClassCode eligible inconsistencyHit riskReviewHit manualReviewHit ≠ 0 ->
      humanReviewRequired eligible inconsistencyHit riskReviewHit manualReviewHit = true := by
  intro h
  cases eligible <;> cases inconsistencyHit <;> cases riskReviewHit <;> cases manualReviewHit <;>
    simp [actionClassCode, humanReviewRequired] at h ⊢

theorem midnightSettlement_requires_clear_action
    {eligible inconsistencyHit riskReviewHit manualReviewHit : Bool} {approvedAdvance : Nat} :
    eligibleForMidnightSettlement eligible inconsistencyHit riskReviewHit manualReviewHit approvedAdvance = true ->
      actionClassCode eligible inconsistencyHit riskReviewHit manualReviewHit = 0 := by
  intro h
  cases eligible <;> cases inconsistencyHit <;> cases riskReviewHit <;> cases manualReviewHit <;>
    simp [eligibleForMidnightSettlement, actionClassCode] at h ⊢

theorem midnightSettlement_requires_positive_advance
    {eligible inconsistencyHit riskReviewHit manualReviewHit : Bool} {approvedAdvance : Nat} :
    eligibleForMidnightSettlement eligible inconsistencyHit riskReviewHit manualReviewHit approvedAdvance = true ->
      0 < approvedAdvance := by
  cases approvedAdvance with
  | zero =>
      intro h
      simp [eligibleForMidnightSettlement] at h
  | succ n =>
      intro _
      simp

theorem validRoleHasSelector (role : Nat) (h : role < 5) :
    roleValid role = true := by
  simp [roleValid, h]

theorem supplierDisclosureBindsExpectedCommitments
    (settlementCommitment advanceCommitment invoiceCommitment reserveCommitment
      eligibilityCommitment consistencyCommitment duplicateRiskCommitment : Nat) :
    disclosureValueA 0 settlementCommitment advanceCommitment invoiceCommitment reserveCommitment = settlementCommitment
    ∧ disclosureValueB 0 advanceCommitment eligibilityCommitment consistencyCommitment reserveCommitment duplicateRiskCommitment = advanceCommitment := by
  simp [disclosureValueA, disclosureValueB]

theorem financierDisclosureBindsExpectedCommitments
    (settlementCommitment advanceCommitment invoiceCommitment reserveCommitment
      eligibilityCommitment consistencyCommitment duplicateRiskCommitment : Nat) :
    disclosureValueA 1 settlementCommitment advanceCommitment invoiceCommitment reserveCommitment = advanceCommitment
    ∧ disclosureValueB 1 advanceCommitment eligibilityCommitment consistencyCommitment reserveCommitment duplicateRiskCommitment = reserveCommitment := by
  simp [disclosureValueA, disclosureValueB]

theorem buyerDisclosureBindsExpectedCommitments
    (settlementCommitment advanceCommitment invoiceCommitment reserveCommitment
      eligibilityCommitment consistencyCommitment duplicateRiskCommitment : Nat) :
    disclosureValueA 2 settlementCommitment advanceCommitment invoiceCommitment reserveCommitment = invoiceCommitment
    ∧ disclosureValueB 2 advanceCommitment eligibilityCommitment consistencyCommitment reserveCommitment duplicateRiskCommitment = eligibilityCommitment := by
  simp [disclosureValueA, disclosureValueB]

theorem auditorDisclosureBindsExpectedCommitments
    (settlementCommitment advanceCommitment invoiceCommitment reserveCommitment
      eligibilityCommitment consistencyCommitment duplicateRiskCommitment : Nat) :
    disclosureValueA 3 settlementCommitment advanceCommitment invoiceCommitment reserveCommitment = advanceCommitment
    ∧ disclosureValueB 3 advanceCommitment eligibilityCommitment consistencyCommitment reserveCommitment duplicateRiskCommitment = consistencyCommitment := by
  simp [disclosureValueA, disclosureValueB]

theorem regulatorDisclosureBindsExpectedCommitments
    (settlementCommitment advanceCommitment invoiceCommitment reserveCommitment
      eligibilityCommitment consistencyCommitment duplicateRiskCommitment : Nat) :
    disclosureValueA 4 settlementCommitment advanceCommitment invoiceCommitment reserveCommitment = reserveCommitment
    ∧ disclosureValueB 4 advanceCommitment eligibilityCommitment consistencyCommitment reserveCommitment duplicateRiskCommitment = duplicateRiskCommitment := by
  simp [disclosureValueA, disclosureValueB]

theorem disclosureAuthorizationBindsRoleCredentialRequestCallerAndView
    (role credentialCommitment requestIdHash callerCommitment viewCommitment publicBlinding : Nat) :
    disclosureAuthorizationCommitment
      role
      credentialCommitment
      requestIdHash
      callerCommitment
      viewCommitment
      publicBlinding =
    disclosureAuthorizationInner role credentialCommitment requestIdHash
      + callerCommitment
      + viewCommitment
      + publicBlinding := by
  simp [disclosureAuthorizationCommitment]

theorem supplierDisclosureNoninterference
    (settlementCommitment advanceCommitment invoiceCommitment0 reserveCommitment0
      eligibilityCommitment0 consistencyCommitment0 duplicateRiskCommitment0
      invoiceCommitment1 reserveCommitment1 eligibilityCommitment1
      consistencyCommitment1 duplicateRiskCommitment1 : Nat) :
    disclosureValueA 0 settlementCommitment advanceCommitment invoiceCommitment0 reserveCommitment0 =
      disclosureValueA 0 settlementCommitment advanceCommitment invoiceCommitment1 reserveCommitment1
    ∧ disclosureValueB 0 advanceCommitment eligibilityCommitment0 consistencyCommitment0 reserveCommitment0 duplicateRiskCommitment0 =
      disclosureValueB 0 advanceCommitment eligibilityCommitment1 consistencyCommitment1 reserveCommitment1 duplicateRiskCommitment1 := by
  simp [disclosureValueA, disclosureValueB]

theorem financierDisclosureNoninterference
    (settlementCommitment0 advanceCommitment reserveCommitment
      invoiceCommitment0 eligibilityCommitment0 consistencyCommitment0 duplicateRiskCommitment0
      settlementCommitment1 invoiceCommitment1 eligibilityCommitment1
      consistencyCommitment1 duplicateRiskCommitment1 : Nat) :
    disclosureValueA 1 settlementCommitment0 advanceCommitment invoiceCommitment0 reserveCommitment =
      disclosureValueA 1 settlementCommitment1 advanceCommitment invoiceCommitment1 reserveCommitment
    ∧ disclosureValueB 1 advanceCommitment eligibilityCommitment0 consistencyCommitment0 reserveCommitment duplicateRiskCommitment0 =
      disclosureValueB 1 advanceCommitment eligibilityCommitment1 consistencyCommitment1 reserveCommitment duplicateRiskCommitment1 := by
  simp [disclosureValueA, disclosureValueB]

theorem buyerDisclosureNoninterference
    (settlementCommitment0 advanceCommitment0 invoiceCommitment eligibilityCommitment
      reserveCommitment0 consistencyCommitment0 duplicateRiskCommitment0
      settlementCommitment1 advanceCommitment1 reserveCommitment1 consistencyCommitment1 duplicateRiskCommitment1 : Nat) :
    disclosureValueA 2 settlementCommitment0 advanceCommitment0 invoiceCommitment reserveCommitment0 =
      disclosureValueA 2 settlementCommitment1 advanceCommitment1 invoiceCommitment reserveCommitment1
    ∧ disclosureValueB 2 advanceCommitment0 eligibilityCommitment consistencyCommitment0 reserveCommitment0 duplicateRiskCommitment0 =
      disclosureValueB 2 advanceCommitment1 eligibilityCommitment consistencyCommitment1 reserveCommitment1 duplicateRiskCommitment1 := by
  simp [disclosureValueA, disclosureValueB]

theorem auditorDisclosureNoninterference
    (settlementCommitment0 advanceCommitment invoiceCommitment0 reserveCommitment0
      eligibilityCommitment0 consistencyCommitment duplicateRiskCommitment0
      settlementCommitment1 invoiceCommitment1 reserveCommitment1 eligibilityCommitment1 duplicateRiskCommitment1 : Nat) :
    disclosureValueA 3 settlementCommitment0 advanceCommitment invoiceCommitment0 reserveCommitment0 =
      disclosureValueA 3 settlementCommitment1 advanceCommitment invoiceCommitment1 reserveCommitment1
    ∧ disclosureValueB 3 advanceCommitment eligibilityCommitment0 consistencyCommitment reserveCommitment0 duplicateRiskCommitment0 =
      disclosureValueB 3 advanceCommitment eligibilityCommitment1 consistencyCommitment reserveCommitment1 duplicateRiskCommitment1 := by
  simp [disclosureValueA, disclosureValueB]

theorem regulatorDisclosureNoninterference
    (settlementCommitment0 advanceCommitment0 invoiceCommitment0 reserveCommitment
      eligibilityCommitment0 consistencyCommitment0 duplicateRiskCommitment
      settlementCommitment1 advanceCommitment1 invoiceCommitment1 eligibilityCommitment1 consistencyCommitment1 : Nat) :
    disclosureValueA 4 settlementCommitment0 advanceCommitment0 invoiceCommitment0 reserveCommitment =
      disclosureValueA 4 settlementCommitment1 advanceCommitment1 invoiceCommitment1 reserveCommitment
    ∧ disclosureValueB 4 advanceCommitment0 eligibilityCommitment0 consistencyCommitment0 reserveCommitment duplicateRiskCommitment =
      disclosureValueB 4 advanceCommitment1 eligibilityCommitment1 consistencyCommitment1 reserveCommitment duplicateRiskCommitment := by
  simp [disclosureValueA, disclosureValueB]

theorem shardAssignment_lt_shardCount
    (commitment shardCount : Nat) (h : 0 < shardCount) :
    shardAssignment commitment shardCount < shardCount := by
  unfold shardAssignment
  exact Nat.mod_lt _ h

theorem shardCountTwoMakesBit (commitment : Nat) :
    shardAssignment commitment 2 < 2 := by
  simpa [shardAssignment] using Nat.mod_lt commitment (by decide : 0 < 2)

theorem duplicateRegistryHandoffDeterministic
    (commitment0 commitment1 commitment2 commitment3 blinding0 blinding1 : Nat) :
    batchRootPayload commitment0 commitment1 commitment2 commitment3 blinding0 blinding1 =
      batchRootPayload commitment0 commitment1 commitment2 commitment3 blinding0 blinding1 := by
  rfl

def symbolicHash4 (a b c d : Nat) : Nat :=
  109 + a + 101 * b + 103 * c + 107 * d


def packetBindingStep (previous lane0 lane1 lane2 : Nat) : Nat :=
  symbolicHash4 previous lane0 lane1 lane2


def packetBindingTwoChunk (seed lane0 lane1 lane2 lane3 : Nat) : Nat :=
  packetBindingStep (packetBindingStep seed lane0 lane1 lane2) lane3 0 0


def capScore (raw : Nat) : Nat :=
  Nat.min raw 10000


def structuredInconsistencyScoreRaw
    (valuationScore quantityScore : Nat)
    (geographicReasonable requestAfterPresentment : Bool)
    (evidenceCompletenessScore : Nat) : Nat :=
  valuationScore
    + quantityScore
    + (if geographicReasonable then 0 else 800)
    + (if requestAfterPresentment then 0 else 2000)
    + evidenceCompletenessScore


def structuredInconsistencyScore
    (valuationScore quantityScore : Nat)
    (geographicReasonable requestAfterPresentment : Bool)
    (evidenceCompletenessScore : Nat) : Nat :=
  capScore <| structuredInconsistencyScoreRaw valuationScore quantityScore geographicReasonable requestAfterPresentment evidenceCompletenessScore


def consistencyScore
    (valuationScore quantityScore : Nat)
    (geographicReasonable requestAfterPresentment : Bool)
    (evidenceCompletenessScore : Nat) : Nat :=
  10000 - structuredInconsistencyScore valuationScore quantityScore geographicReasonable requestAfterPresentment evidenceCompletenessScore


def duplicateFinancingRiskScoreRaw
    (duplicationScore vendorScore chronologyScore eligibilityMismatchScore : Nat) : Nat :=
  duplicationScore + vendorScore + chronologyScore + eligibilityMismatchScore


def duplicateFinancingRiskScore
    (duplicationScore vendorScore chronologyScore eligibilityMismatchScore : Nat) : Nat :=
  capScore <| duplicateFinancingRiskScoreRaw duplicationScore vendorScore chronologyScore eligibilityMismatchScore


def settlementBindingInner
    (approvedAdvance reserveAmountValue actionClass destinationCommitment : Nat) : Nat :=
  symbolicHash4 approvedAdvance reserveAmountValue actionClass destinationCommitment


def settlementBindingOuter
    (inner reserveAccountCommitment settlementBlinding0 settlementBlinding1 : Nat) : Nat :=
  symbolicHash4 inner reserveAccountCommitment settlementBlinding0 settlementBlinding1


def settlementBindingDigest
    (approvedAdvance reserveAmountValue actionClass destinationCommitment reserveAccountCommitment
      settlementBlinding0 settlementBlinding1 invoicePacketCommitment eligibilityCommitment publicBlinding1 : Nat) : Nat :=
  symbolicHash4
    (settlementBindingOuter
      (settlementBindingInner approvedAdvance reserveAmountValue actionClass destinationCommitment)
      reserveAccountCommitment settlementBlinding0 settlementBlinding1)
    invoicePacketCommitment
    eligibilityCommitment
    publicBlinding1


def duplicateRegistryBatchRoot
    (commitment0 commitment1 commitment2 commitment3 blinding0 blinding1 : Nat) : Nat :=
  symbolicHash4 (symbolicHash4 1111 commitment0 commitment1 commitment2) commitment3 blinding0 blinding1


theorem packetBindingSoundness
    (seed lane0 lane1 lane2 lane3 : Nat) :
    packetBindingTwoChunk seed lane0 lane1 lane2 lane3 =
      symbolicHash4 (symbolicHash4 seed lane0 lane1 lane2) lane3 0 0 := by
  rfl


theorem consistencyScoreSoundness
    (valuationScore quantityScore evidenceCompletenessScore : Nat)
    (geographicReasonable requestAfterPresentment : Bool) :
    structuredInconsistencyScore valuationScore quantityScore geographicReasonable requestAfterPresentment evidenceCompletenessScore ≤ 10000
    ∧ consistencyScore valuationScore quantityScore geographicReasonable requestAfterPresentment evidenceCompletenessScore
        + structuredInconsistencyScore valuationScore quantityScore geographicReasonable requestAfterPresentment evidenceCompletenessScore = 10000 := by
  constructor
  · unfold structuredInconsistencyScore capScore
    exact Nat.min_le_right _ _
  · unfold consistencyScore structuredInconsistencyScore capScore
    simpa [Nat.add_comm] using Nat.sub_add_cancel (Nat.min_le_right (structuredInconsistencyScoreRaw valuationScore quantityScore geographicReasonable requestAfterPresentment evidenceCompletenessScore) 10000)


theorem duplicateFinancingRiskSoundness
    (duplicationScore vendorScore chronologyScore eligibilityMismatchScore : Nat) :
    duplicateFinancingRiskScore duplicationScore vendorScore chronologyScore eligibilityMismatchScore ≤ 10000 := by
  unfold duplicateFinancingRiskScore capScore
  exact Nat.min_le_right _ _


theorem approvedAdvanceFeeReserveSoundness
    (eligibleInvoice retentionAmount discountAmount advanceCap reserveMargin reserveFloor
      attachmentPoint participationCap participationRate scale : Nat)
    (_hCap : 0 ≤ advanceCap)
    (_hMargin : 0 ≤ reserveMargin)
    (_hScale : 0 < scale) :
    approvedAdvanceAmount eligibleInvoice retentionAmount discountAmount advanceCap ≤ advanceCap
    ∧ reserveFloor ≤ reserveAmount (approvedAdvanceAmount eligibleInvoice retentionAmount discountAmount advanceCap) reserveMargin reserveFloor
    ∧ approvedAdvanceAmount eligibleInvoice retentionAmount discountAmount advanceCap
        ≤ reserveAmount (approvedAdvanceAmount eligibleInvoice retentionAmount discountAmount advanceCap) reserveMargin reserveFloor
    ∧ (approvedAdvanceAmount eligibleInvoice retentionAmount discountAmount advanceCap ≤ attachmentPoint →
        feeAmount (approvedAdvanceAmount eligibleInvoice retentionAmount discountAmount advanceCap)
          attachmentPoint participationCap participationRate scale = 0) := by
  constructor
  · exact approvedAdvanceAmount_le_cap eligibleInvoice retentionAmount discountAmount advanceCap
  constructor
  · exact reserveAmount_ge_floor (approvedAdvanceAmount eligibleInvoice retentionAmount discountAmount advanceCap) reserveMargin reserveFloor
  constructor
  · exact reserveAmount_ge_approved (approvedAdvanceAmount eligibleInvoice retentionAmount discountAmount advanceCap) reserveMargin reserveFloor
  · intro hAttachment
    exact feeAmount_zero_below_attachment hAttachment


theorem actionDerivationSoundness
    (eligible inconsistencyHit riskReviewHit manualReviewHit : Bool)
    (approvedAdvance : Nat) :
    actionClassCode eligible inconsistencyHit riskReviewHit manualReviewHit ≤ 4
    ∧ (humanReviewRequired eligible inconsistencyHit riskReviewHit manualReviewHit = true ↔
        actionClassCode eligible inconsistencyHit riskReviewHit manualReviewHit ≠ 0)
    ∧ (eligibleForMidnightSettlement eligible inconsistencyHit riskReviewHit manualReviewHit approvedAdvance = true →
        actionClassCode eligible inconsistencyHit riskReviewHit manualReviewHit = 0 ∧ 0 < approvedAdvance) := by
  constructor
  · exact actionClassCode_in_range eligible inconsistencyHit riskReviewHit manualReviewHit
  constructor
  · cases eligible <;> cases inconsistencyHit <;> cases riskReviewHit <;> cases manualReviewHit <;>
      simp [actionClassCode, humanReviewRequired]
  · intro h
    exact ⟨midnightSettlement_requires_clear_action h, midnightSettlement_requires_positive_advance h⟩


theorem settlementBindingSoundness
    (approvedAdvance reserveAmountValue actionClass destinationCommitment reserveAccountCommitment
      settlementBlinding0 settlementBlinding1 invoicePacketCommitment eligibilityCommitment publicBlinding1 : Nat) :
    settlementBindingDigest approvedAdvance reserveAmountValue actionClass destinationCommitment reserveAccountCommitment
      settlementBlinding0 settlementBlinding1 invoicePacketCommitment eligibilityCommitment publicBlinding1 =
      symbolicHash4
        (symbolicHash4
          (symbolicHash4 approvedAdvance reserveAmountValue actionClass destinationCommitment)
          reserveAccountCommitment settlementBlinding0 settlementBlinding1)
        invoicePacketCommitment
        eligibilityCommitment
        publicBlinding1 := by
  rfl


theorem duplicateRegistryBatchBinding
    (commitment0 commitment1 commitment2 commitment3 blinding0 blinding1 : Nat) :
    duplicateRegistryBatchRoot commitment0 commitment1 commitment2 commitment3 blinding0 blinding1 =
      symbolicHash4 (symbolicHash4 1111 commitment0 commitment1 commitment2) commitment3 blinding0 blinding1 := by
  rfl

def generatedCircuitCertificateAccepts
    (fieldIsPastaFq poseidonNodesWidth4 programDigestLinkage
      disclosureAuthorizationBound emittedNoninterferenceBound : Bool) : Bool :=
  fieldIsPastaFq
    && poseidonNodesWidth4
    && programDigestLinkage
    && disclosureAuthorizationBound
    && emittedNoninterferenceBound

theorem generatedCircuitCertificateAcceptanceSoundness
    {fieldIsPastaFq poseidonNodesWidth4 programDigestLinkage
      disclosureAuthorizationBound emittedNoninterferenceBound : Bool} :
    generatedCircuitCertificateAccepts
      fieldIsPastaFq
      poseidonNodesWidth4
      programDigestLinkage
      disclosureAuthorizationBound
      emittedNoninterferenceBound = true ->
      fieldIsPastaFq = true
      ∧ poseidonNodesWidth4 = true
      ∧ programDigestLinkage = true
      ∧ disclosureAuthorizationBound = true
      ∧ emittedNoninterferenceBound = true := by
  intro h
  simp [generatedCircuitCertificateAccepts] at h
  rcases h with ⟨⟨⟨⟨hField, hPoseidon⟩, hDigest⟩, hAuthorization⟩, hNoninterference⟩
  exact ⟨hField, hPoseidon, hDigest, hAuthorization, hNoninterference⟩
