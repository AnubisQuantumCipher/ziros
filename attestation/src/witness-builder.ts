import { writeFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';

import { parseArgs, requireFlag, readJson, sha256Hex, hexToUint64Limbs } from './util.js';

interface ConformanceReportFile {
  backend?: string;
  tests_run?: number;
  tests_passed?: number;
  tests_failed?: number;
  pass_rate?: number;
  report?: {
    backend: string;
    tests_run: number;
    tests_passed: number;
    tests_failed: number;
    pass_rate: number;
  };
}

interface AuditReportFile {
  checks?: Array<{
    name?: string;
    status?: string;
  }>;
  summary?: {
    total_checks?: number;
    failed?: number;
  };
  underconstrained_analysis?: {
    unconstrained_signals?: unknown[];
    potentially_underconstrained_signals?: unknown[];
  } | null;
}

interface VerificationLedger {
  entries?: Array<{
    status?: string;
  }>;
}

function canonicalBackend(input: string): string {
  return input.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function detectBackend(file: ConformanceReportFile, pathname: string): string {
  const raw =
    file.report?.backend ??
    file.backend ??
    basename(pathname)
      .replace(/^conformance_/, '')
      .replace(/\.json$/, '');
  return canonicalBackend(raw);
}

async function buildWitness() {
  const { flags } = parseArgs(process.argv.slice(2));
  const conformancePaths = flags.get('conformance') ?? [];
  const auditPath = requireFlag(flags, 'audit');
  const ledgerPath = requireFlag(flags, 'ledger');
  const outPath = requireFlag(flags, 'out');

  if (conformancePaths.length === 0) {
    throw new Error('Provide at least one --conformance <path> input.');
  }

  const conformance: Record<
    string,
    {
      present: boolean;
      testsRun: number;
      testsPassed: number;
      testsFailed: number;
      passRate: number;
      sourcePath: string;
    }
  > = {};

  for (const inputPath of conformancePaths) {
    const absolute = resolve(inputPath);
    const payload = await readJson<ConformanceReportFile>(absolute);
    const report = payload.report ?? payload;
    const backend = detectBackend(payload, absolute);
    conformance[backend] = {
      present: true,
      testsRun: report.tests_run ?? 0,
      testsPassed: report.tests_passed ?? 0,
      testsFailed: report.tests_failed ?? 0,
      passRate: report.pass_rate ?? 0,
      sourcePath: absolute,
    };
  }

  const auditAbsolute = resolve(auditPath);
  const audit = await readJson<AuditReportFile>(auditAbsolute);
  const underconstrainedCheck = audit.checks?.find((check) => check.name === 'underconstrained_signals');
  const underconstrainedSignals =
    audit.underconstrained_analysis?.unconstrained_signals?.length ??
    audit.underconstrained_analysis?.potentially_underconstrained_signals?.length ??
    (underconstrainedCheck?.status === 'fail' ? 1 : 0);

  const ledgerAbsolute = resolve(ledgerPath);
  const ledger = await readJson<VerificationLedger>(ledgerAbsolute);
  const entries = ledger.entries ?? [];
  const mechanizedEntries = entries.filter((entry) => entry.status === 'mechanized_local').length;
  const pendingEntries = entries.filter((entry) => entry.status !== 'mechanized_local').length;

  const witness = {
    schema: 'ziros-code-attestation-witness-v1' as const,
    generatedAt: new Date().toISOString(),
    version: {
      string: '0.4.0',
      major: 0,
      minor: 4,
      patch: 0,
    },
    conformance,
    audit: {
      totalChecks: audit.summary?.total_checks ?? audit.checks?.length ?? 0,
      failedChecks: audit.summary?.failed ?? 0,
      underconstrainedSignals,
      sourcePath: auditAbsolute,
    },
    ledger: {
      totalEntries: entries.length,
      mechanizedEntries,
      pendingEntries,
      sourcePath: ledgerAbsolute,
    },
  };

  const attestationHash = sha256Hex(JSON.stringify(witness));
  const attestationRootLimbs = hexToUint64Limbs(attestationHash).map((limb) => limb.toString()) as [
    string,
    string,
    string,
    string,
  ];

  const finalPayload = {
    ...witness,
    attestationHash,
    attestationRootLimbs,
  };

  await writeFile(resolve(outPath), JSON.stringify(finalPayload, null, 2), 'utf-8');
  console.log(JSON.stringify(finalPayload, null, 2));
}

buildWitness().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
