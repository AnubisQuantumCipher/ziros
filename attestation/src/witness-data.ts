import { readFile } from 'node:fs/promises';

import type { ContractKey } from './contracts.js';
import { asBoolean } from './util.js';

export interface BackendWitnessData {
  present: bigint;
  testsRun: bigint;
  testsPassed: bigint;
}

type ContractSnapshots = Partial<Record<ContractKey, Record<string, unknown>>>;

export interface AttestationWitnessPayload {
  schema: 'ziros-code-attestation-witness-v1';
  generatedAt: string;
  version: {
    string: string;
    major: number;
    minor: number;
    patch: number;
  };
  attestationHash: string;
  attestationRootLimbs: [string, string, string, string];
  conformance: Record<
    string,
    {
      present: boolean;
      testsRun: number;
      testsPassed: number;
      testsFailed: number;
      passRate: number;
      sourcePath: string;
    }
  >;
  audit: {
    totalChecks: number;
    failedChecks: number;
    underconstrainedSignals: number;
    sourcePath: string;
  };
  ledger: {
    totalEntries: number;
    mechanizedEntries: number;
    pendingEntries: number;
    sourcePath: string;
  };
}

function backendKey(input: string): string {
  return input.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function parseBigInt(value: string | number | bigint): bigint {
  if (typeof value === 'bigint') {
    return value;
  }
  if (typeof value === 'number') {
    return BigInt(value);
  }
  return BigInt(value);
}

export async function loadWitnessPayload(pathname: string): Promise<AttestationWitnessPayload> {
  const raw = await readFile(pathname, 'utf-8');
  return JSON.parse(raw) as AttestationWitnessPayload;
}

export function backendWitness(
  payload: AttestationWitnessPayload,
  name: string,
): BackendWitnessData {
  const entry = payload.conformance[backendKey(name)];
  if (!entry) {
    return {
      present: 0n,
      testsRun: 0n,
      testsPassed: 0n,
    };
  }
  return {
    present: entry.present ? 1n : 0n,
    testsRun: BigInt(entry.testsRun),
    testsPassed: BigInt(entry.testsPassed),
  };
}

export function totalPassedCount(payload: AttestationWitnessPayload): bigint {
  return (
    backendWitness(payload, 'plonky3').testsPassed +
    backendWitness(payload, 'halo2').testsPassed +
    backendWitness(payload, 'nova').testsPassed +
    backendWitness(payload, 'hyper-nova').testsPassed
  );
}

export function theoremCount(payload: AttestationWitnessPayload): bigint {
  return BigInt(payload.ledger.totalEntries);
}

function fixed(value: bigint): (context: { privateState: undefined }) => [undefined, bigint] {
  return ({ privateState }) => [privateState, value] as [undefined, bigint];
}

function snapshotComplianceBit(
  snapshot: Record<string, unknown> | undefined,
  fallback: boolean,
): bigint {
  const value = snapshot?.compliance_bit;
  if (value == null) {
    return fallback ? 1n : 0n;
  }
  return asBoolean(value) ? 1n : 0n;
}

function snapshotCommitmentValue(
  snapshot: Record<string, unknown> | undefined,
): string | null {
  const value = snapshot?.attestation_commitment;
  return typeof value === 'string' && value.length > 0 ? value.toLowerCase() : null;
}

export function buildCompactWitnesses(
  contractKey: ContractKey,
  payload: AttestationWitnessPayload,
  options: {
    contractSnapshots?: ContractSnapshots;
  } = {},
): Record<string, (context: { privateState: undefined }) => [undefined, bigint]> {
  const [root0, root1, root2, root3] = payload.attestationRootLimbs.map(parseBigInt) as [
    bigint,
    bigint,
    bigint,
    bigint,
  ];
  const plonky3 = backendWitness(payload, 'plonky3');
  const halo2 = backendWitness(payload, 'halo2');
  const nova = backendWitness(payload, 'nova');
  const hyperNova = backendWitness(payload, 'hyper-nova');

  const common = {
    attestationRoot0: fixed(root0),
    attestationRoot1: fixed(root1),
    attestationRoot2: fixed(root2),
    attestationRoot3: fixed(root3),
  };
  const expectations = expectedComplianceBits(payload);

  switch (contractKey) {
    case 'backend':
      return {
        ...common,
        plonky3Present: fixed(plonky3.present),
        plonky3TestsRun: fixed(plonky3.testsRun),
        plonky3TestsPassed: fixed(plonky3.testsPassed),
        halo2Present: fixed(halo2.present),
        halo2TestsRun: fixed(halo2.testsRun),
        halo2TestsPassed: fixed(halo2.testsPassed),
        novaPresent: fixed(nova.present),
        novaTestsRun: fixed(nova.testsRun),
        novaTestsPassed: fixed(nova.testsPassed),
        hyperNovaPresent: fixed(hyperNova.present),
        hyperNovaTestsRun: fixed(hyperNova.testsRun),
        hyperNovaTestsPassed: fixed(hyperNova.testsPassed),
      };

    case 'formal':
      return {
        ...common,
        ledgerTotalEntries: fixed(BigInt(payload.ledger.totalEntries)),
        ledgerMechanizedEntries: fixed(BigInt(payload.ledger.mechanizedEntries)),
        ledgerPendingEntries: fixed(BigInt(payload.ledger.pendingEntries)),
      };

    case 'audit': {
      const backendSnapshot = options.contractSnapshots?.backend;
      const formalSnapshot = options.contractSnapshots?.formal;
      const backendCommitment = snapshotCommitmentValue(backendSnapshot);
      const formalCommitment = snapshotCommitmentValue(formalSnapshot);
      const upstreamCommitmentsAgree =
        backendCommitment != null &&
        formalCommitment != null &&
        backendCommitment === formalCommitment;

      return {
        ...common,
        verificationCount: fixed(totalPassedCount(payload)),
        theoremCount: fixed(theoremCount(payload)),
        backendCompliance: fixed(snapshotComplianceBit(backendSnapshot, expectations.backend)),
        formalCompliance: fixed(snapshotComplianceBit(formalSnapshot, expectations.formal)),
        upstreamCommitmentsAgree: fixed(upstreamCommitmentsAgree ? 1n : 0n),
        auditUnderconstrainedSignals: fixed(BigInt(payload.audit.underconstrainedSignals)),
        auditTotalChecks: fixed(BigInt(payload.audit.totalChecks)),
        auditFailedChecks: fixed(BigInt(payload.audit.failedChecks)),
      };
    }
  }
}

export function expectedComplianceBits(
  payload: AttestationWitnessPayload,
): Record<ContractKey | 'overall', boolean> {
  const plonky3 = backendWitness(payload, 'plonky3');
  const halo2 = backendWitness(payload, 'halo2');
  const nova = backendWitness(payload, 'nova');
  const hyperNova = backendWitness(payload, 'hyper-nova');

  const backendOk =
    plonky3.present === 1n &&
    halo2.present === 1n &&
    nova.present === 1n &&
    hyperNova.present === 1n &&
    plonky3.testsRun === plonky3.testsPassed &&
    halo2.testsRun === halo2.testsPassed &&
    nova.testsRun === nova.testsPassed &&
    hyperNova.testsRun === hyperNova.testsPassed;
  const formalOk =
    payload.ledger.pendingEntries === 0 &&
    payload.ledger.mechanizedEntries === payload.ledger.totalEntries;
  const auditOk =
    payload.audit.underconstrainedSignals === 0 &&
    payload.audit.failedChecks === 0 &&
    payload.audit.totalChecks > 0;

  return {
    backend: backendOk,
    formal: formalOk,
    audit: auditOk,
    overall: backendOk && formalOk && auditOk,
  };
}
