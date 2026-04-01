import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

import type { MidnightNetwork } from './config.js';
import { stringifyJson } from './util.js';

export type MidnightStackMatrixId = 'v4-stable' | 'v4-pre' | 'v3-compat';
export type MidnightSubmitStrategyId =
  | 'wallet-sdk'
  | 'metadata-midnight-extrinsic'
  | 'compat-node-client';
export type ProbeOutcome = 'accepted' | 'rejected' | 'panic' | 'error' | 'skipped';

export interface RuntimeWeightValue {
  refTime: string;
  proofSize: string;
}

export interface CompatibilityProfile {
  observedAt: string;
  network: MidnightNetwork;
  rpcUrl: string;
  indexerUrl: string;
  specVersion: string;
  transactionVersion: string;
  signedExtensions: string[];
  rawLedgerVersion: string;
  configurableTransactionSizeWeight: RuntimeWeightValue | null;
  txPause: {
    pausedCalls: number;
  };
  throttle: {
    palletKeys: string[];
    accountUsage: string | null;
  };
}

export interface ProbeValidationResult {
  source: 'External' | 'Local' | 'InBlock';
  outcome: ProbeOutcome;
  detail: string;
  raw?: unknown;
}

export interface ProbeSubmitResult {
  strategy: MidnightSubmitStrategyId;
  outcome: ProbeOutcome;
  txHash?: string | null;
  detail: string;
  raw?: unknown;
}

export interface ProbeResult {
  probeId: string;
  network: MidnightNetwork;
  matrixId: MidnightStackMatrixId | 'current';
  strategy: MidnightSubmitStrategyId;
  observedAt: string;
  innerTxHexLength?: number;
  outerTxHexLength?: number;
  serializedLength?: number;
  txId?: string | null;
  runtimeInnerCost?: string | null;
  validation: ProbeValidationResult[];
  submit: ProbeSubmitResult;
  note?: string;
}

export interface CompatibilityMatrixAttempt {
  matrixId: MidnightStackMatrixId;
  workspaceDir: string;
  packageVersions: Record<string, string>;
  compactcVersion: string;
  succeeded: boolean;
  probeIds: string[];
  note?: string;
}

export interface CompatibilitySelection {
  matrixId: MidnightStackMatrixId;
  strategy: MidnightSubmitStrategyId;
  network: MidnightNetwork;
  selectedAt: string;
  runtimeFingerprint: Pick<
    CompatibilityProfile,
    'network' | 'specVersion' | 'transactionVersion' | 'signedExtensions' | 'rawLedgerVersion'
  >;
}

export interface CompatibilityReport {
  generatedAt: string;
  profiles: CompatibilityProfile[];
  probes: ProbeResult[];
  matrices: CompatibilityMatrixAttempt[];
  selected: CompatibilitySelection | null;
}

export const DEFAULT_COMPATIBILITY_REPORT_PATH = resolve('./data/compatibility-report.json');

export function resolveCompatibilityReportPath(customPath = DEFAULT_COMPATIBILITY_REPORT_PATH): string {
  return resolve(customPath);
}

export async function readCompatibilityReport(
  reportPath = DEFAULT_COMPATIBILITY_REPORT_PATH,
): Promise<CompatibilityReport | null> {
  try {
    const raw = await readFile(reportPath, 'utf-8');
    return JSON.parse(raw) as CompatibilityReport;
  } catch {
    return null;
  }
}

export async function writeCompatibilityReport(
  report: CompatibilityReport,
  reportPath = DEFAULT_COMPATIBILITY_REPORT_PATH,
): Promise<void> {
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, stringifyJson(report), 'utf-8');
}

export async function upsertCompatibilityReport(
  update: Partial<CompatibilityReport>,
  reportPath = DEFAULT_COMPATIBILITY_REPORT_PATH,
): Promise<CompatibilityReport> {
  const existing = await readCompatibilityReport(reportPath);
  const next: CompatibilityReport = {
    generatedAt: new Date().toISOString(),
    profiles: update.profiles ?? existing?.profiles ?? [],
    probes: update.probes ?? existing?.probes ?? [],
    matrices: update.matrices ?? existing?.matrices ?? [],
    selected: update.selected ?? existing?.selected ?? null,
  };
  await writeCompatibilityReport(next, reportPath);
  return next;
}

export function withProfile(
  report: CompatibilityReport | null,
  profile: CompatibilityProfile,
): CompatibilityReport {
  const profiles = [...(report?.profiles ?? [])];
  const index = profiles.findIndex((entry) => entry.network === profile.network);
  if (index >= 0) {
    profiles[index] = profile;
  } else {
    profiles.push(profile);
  }
  return {
    generatedAt: new Date().toISOString(),
    profiles,
    probes: report?.probes ?? [],
    matrices: report?.matrices ?? [],
    selected: report?.selected ?? null,
  };
}

export function withProbe(report: CompatibilityReport | null, probe: ProbeResult): CompatibilityReport {
  const probes = [...(report?.probes ?? [])];
  const index = probes.findIndex(
    (entry) =>
      entry.probeId === probe.probeId &&
      entry.network === probe.network &&
      entry.matrixId === probe.matrixId &&
      entry.strategy === probe.strategy,
  );
  if (index >= 0) {
    probes[index] = probe;
  } else {
    probes.push(probe);
  }
  return {
    generatedAt: new Date().toISOString(),
    profiles: report?.profiles ?? [],
    probes,
    matrices: report?.matrices ?? [],
    selected: report?.selected ?? null,
  };
}

export function withMatrixAttempt(
  report: CompatibilityReport | null,
  attempt: CompatibilityMatrixAttempt,
): CompatibilityReport {
  const matrices = [...(report?.matrices ?? [])];
  const index = matrices.findIndex((entry) => entry.matrixId === attempt.matrixId);
  if (index >= 0) {
    matrices[index] = attempt;
  } else {
    matrices.push(attempt);
  }
  return {
    generatedAt: new Date().toISOString(),
    profiles: report?.profiles ?? [],
    probes: report?.probes ?? [],
    matrices,
    selected: report?.selected ?? null,
  };
}

export function runtimeFingerprintMatches(
  selection: CompatibilitySelection,
  profile: CompatibilityProfile,
): boolean {
  return (
    selection.runtimeFingerprint.network === profile.network &&
    selection.runtimeFingerprint.specVersion === profile.specVersion &&
    selection.runtimeFingerprint.transactionVersion === profile.transactionVersion &&
    selection.runtimeFingerprint.rawLedgerVersion === profile.rawLedgerVersion &&
    selection.runtimeFingerprint.signedExtensions.join(',') === profile.signedExtensions.join(',')
  );
}
