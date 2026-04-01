export const ATTESTATION_CONTRACT = {
  key: 'ziros-attestation',
  artifactDirectory: 'ziros_attestation',
  compactSource: 'ziros_attestation.compact',
  displayName: 'ZirOS Code Attestation',
  circuitIds: [
    'prove_backend_correctness',
    'prove_formal_coverage',
    'prove_audit_clean',
  ] as const,
};

export type AttestationCircuitId = (typeof ATTESTATION_CONTRACT.circuitIds)[number];
