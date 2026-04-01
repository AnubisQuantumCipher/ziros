import { readFile } from 'node:fs/promises';

import type { AttestationCircuitId } from './contracts.js';

export interface BackendWitnessData {
  present: bigint;
  testsRun: bigint;
  testsPassed: bigint;
}

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

function asBigInt(value: string | number | bigint): bigint {
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

export function buildCompactWitnesses(payload: AttestationWitnessPayload): Record<string, (context: { privateState: undefined }) => [undefined, bigint]> {
  const [root0, root1, root2, root3] = payload.attestationRootLimbs.map(asBigInt) as [
    bigint,
    bigint,
    bigint,
    bigint,
  ];
  const plonky3 = backendWitness(payload, 'plonky3');
  const halo2 = backendWitness(payload, 'halo2');
  const nova = backendWitness(payload, 'nova');
  const hyperNova = backendWitness(payload, 'hyper-nova');

  const fixed = (value: bigint) => ({ privateState }: { privateState: undefined }) =>
    [privateState, value] as [undefined, bigint];

  return {
    attestationRoot0: fixed(root0),
    attestationRoot1: fixed(root1),
    attestationRoot2: fixed(root2),
    attestationRoot3: fixed(root3),
    timestampUnix: fixed(BigInt(Math.floor(Date.parse(payload.generatedAt) / 1000))),
    versionMajor: fixed(BigInt(payload.version.major)),
    versionMinor: fixed(BigInt(payload.version.minor)),
    versionPatch: fixed(BigInt(payload.version.patch)),
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
    ledgerTotalEntries: fixed(BigInt(payload.ledger.totalEntries)),
    ledgerMechanizedEntries: fixed(BigInt(payload.ledger.mechanizedEntries)),
    ledgerPendingEntries: fixed(BigInt(payload.ledger.pendingEntries)),
    auditUnderconstrainedSignals: fixed(BigInt(payload.audit.underconstrainedSignals)),
    auditTotalChecks: fixed(BigInt(payload.audit.totalChecks)),
    auditFailedChecks: fixed(BigInt(payload.audit.failedChecks)),
  };
}

export function expectedComplianceBits(payload: AttestationWitnessPayload): Record<AttestationCircuitId | 'overall', boolean> {
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
    prove_backend_correctness: backendOk,
    prove_formal_coverage: formalOk,
    prove_audit_clean: auditOk,
    overall: backendOk && formalOk && auditOk,
  };
}
