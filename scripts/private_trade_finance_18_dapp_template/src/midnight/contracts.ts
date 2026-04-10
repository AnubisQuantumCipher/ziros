export type ContractKey =
  | 'financing_request_registration'
  | 'settlement_authorization'
  | 'dispute_hold'
  | 'disclosure_access'
  | 'repayment_completion'
  | 'supplier_receipt_confirmation';

export interface ContractDefinition {
  key: ContractKey;
  artifactDirectory: string;
  compactSource: string;
  displayName: string;
  description: string;
  defaultDeployCallId: string;
}

export const CONTRACTS: ContractDefinition[] = [
  {
    key: 'financing_request_registration',
    artifactDirectory: 'financing_request_registration',
    compactSource: './contracts/compact/financing_request_registration.compact',
    displayName: 'Financing Request Registration',
    description: 'Registers the financing request commitment on Midnight.',
    defaultDeployCallId: 'register_financing_request',
  },
  {
    key: 'settlement_authorization',
    artifactDirectory: 'settlement_authorization',
    compactSource: './contracts/compact/settlement_authorization.compact',
    displayName: 'Settlement Authorization',
    description: 'Binds approved advance, reserve, and maturity schedule to settlement authorization.',
    defaultDeployCallId: 'authorize_settlement',
  },
  {
    key: 'dispute_hold',
    artifactDirectory: 'dispute_hold',
    compactSource: './contracts/compact/dispute_hold.compact',
    displayName: 'Dispute Hold',
    description: 'Captures dispute-hold state changes.',
    defaultDeployCallId: 'place_dispute_hold',
  },
  {
    key: 'disclosure_access',
    artifactDirectory: 'disclosure_access',
    compactSource: './contracts/compact/disclosure_access.compact',
    displayName: 'Disclosure Access',
    description: 'Manages role-coded selective disclosure views.',
    defaultDeployCallId: 'grant_disclosure_view_supplier',
  },
  {
    key: 'repayment_completion',
    artifactDirectory: 'repayment_completion',
    compactSource: './contracts/compact/repayment_completion.compact',
    displayName: 'Repayment Completion',
    description: 'Anchors buyer repayment completion.',
    defaultDeployCallId: 'complete_buyer_repayment',
  },
  {
    key: 'supplier_receipt_confirmation',
    artifactDirectory: 'supplier_receipt_confirmation',
    compactSource: './contracts/compact/supplier_receipt_confirmation.compact',
    displayName: 'Supplier Receipt Confirmation',
    description: 'Confirms supplier receipt against the maturity schedule commitment.',
    defaultDeployCallId: 'confirm_supplier_receipt',
  },
];

export const CONTRACTS_BY_KEY: Record<ContractKey, ContractDefinition> = Object.fromEntries(
  CONTRACTS.map((contract) => [contract.key, contract]),
) as Record<ContractKey, ContractDefinition>;

export function isContractKey(value: string): value is ContractKey {
  return value in CONTRACTS_BY_KEY;
}

export function getContractDefinition(contractKey: ContractKey): ContractDefinition {
  return CONTRACTS_BY_KEY[contractKey];
}
