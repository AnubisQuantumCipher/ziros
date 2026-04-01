export type ContractKey = 'backend' | 'formal' | 'audit';

export interface ContractDefinition {
  key: ContractKey;
  artifactDirectory: string;
  compactSource: string;
  displayName: string;
  description: string;
  circuitId: string;
  ledgerSummaryFields: string[];
}

export const CONTRACTS: ContractDefinition[] = [
  {
    key: 'backend',
    artifactDirectory: 'ziros_attestation_backend',
    compactSource: 'ziros_attestation_backend.compact',
    displayName: 'ZirOS Backend Conformance Attestation',
    description: 'Publishes the attestation commitment, passed-test count, and backend compliance bit.',
    circuitId: 'prove_backend_correctness',
    ledgerSummaryFields: ['attestation_commitment', 'verification_count', 'compliance_bit'],
  },
  {
    key: 'formal',
    artifactDirectory: 'ziros_attestation_formal',
    compactSource: 'ziros_attestation_formal.compact',
    displayName: 'ZirOS Formal Coverage Attestation',
    description: 'Publishes theorem count and formal-coverage compliance for the current ledger snapshot.',
    circuitId: 'prove_formal_coverage',
    ledgerSummaryFields: ['attestation_commitment', 'theorem_count', 'compliance_bit'],
  },
  {
    key: 'audit',
    artifactDirectory: 'ziros_attestation_audit',
    compactSource: 'ziros_attestation_audit.compact',
    displayName: 'ZirOS Audit Rollup Attestation',
    description: 'Consumes backend/formal commitments and audit evidence to publish the final compliance bit.',
    circuitId: 'prove_audit_clean',
    ledgerSummaryFields: ['attestation_commitment', 'verification_count', 'theorem_count', 'compliance_bit'],
  },
];

export const CONTRACTS_BY_KEY: Record<ContractKey, ContractDefinition> = Object.fromEntries(
  CONTRACTS.map((contract) => [contract.key, contract]),
) as Record<ContractKey, ContractDefinition>;

export function getContractDefinition(contractKey: ContractKey): ContractDefinition {
  return CONTRACTS_BY_KEY[contractKey];
}
