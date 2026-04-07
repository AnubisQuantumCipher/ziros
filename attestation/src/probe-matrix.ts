import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import {
  DEFAULT_COMPATIBILITY_REPORT_PATH,
  findLatestChainControlProbe,
  probeHasValidationPanic,
  readCompatibilityReport,
  type CompatibilityMatrixAttempt,
  type MidnightStackMatrixId,
  type MidnightSubmitStrategyId,
  runtimeFingerprintMatches,
  withMatrixAttempt,
  writeCompatibilityReport,
} from './compatibility.js';
import { getRuntimeConfig } from './config.js';
import { buildCompatibilityProfile } from './runtime-probe.js';
import { optionalFlag, parseArgs, stringifyJson } from './util.js';

const execFileAsync = promisify(execFile);
const SOURCE_DIR = resolve('.');

interface MatrixDefinition {
  compactcVersion: string;
  packageVersions: Record<string, string>;
}

const MATRICES: Record<MidnightStackMatrixId, MatrixDefinition> = {
  'v4-stable': {
    compactcVersion: '0.30.0',
    packageVersions: {
      '@midnight-ntwrk/compact-js': '2.5.0',
      '@midnight-ntwrk/compact-runtime': '0.15.0',
      '@midnight-ntwrk/ledger-v8': '8.0.3',
      '@midnight-ntwrk/midnight-js-compact': '4.0.2',
      '@midnight-ntwrk/midnight-js-contracts': '4.0.2',
      '@midnight-ntwrk/midnight-js-http-client-proof-provider': '4.0.2',
      '@midnight-ntwrk/midnight-js-indexer-public-data-provider': '4.0.2',
      '@midnight-ntwrk/midnight-js-level-private-state-provider': '4.0.2',
      '@midnight-ntwrk/midnight-js-network-id': '4.0.2',
      '@midnight-ntwrk/midnight-js-node-zk-config-provider': '4.0.2',
      '@midnight-ntwrk/midnight-js-types': '4.0.2',
      '@midnight-ntwrk/midnight-js-utils': '4.0.2',
      '@midnight-ntwrk/testkit-js': '4.0.2',
    },
  },
  'v4-pre': {
    compactcVersion: '0.30.0',
    packageVersions: {
      '@midnight-ntwrk/compact-js': '2.5.0',
      '@midnight-ntwrk/compact-runtime': '0.15.0',
      '@midnight-ntwrk/ledger-v8': '8.0.3',
      '@midnight-ntwrk/midnight-js-compact': '4.0.2-0-pre.2a895cf0',
      '@midnight-ntwrk/midnight-js-contracts': '4.0.2-0-pre.2a895cf0',
      '@midnight-ntwrk/midnight-js-http-client-proof-provider': '4.0.2-0-pre.2a895cf0',
      '@midnight-ntwrk/midnight-js-indexer-public-data-provider': '4.0.2-0-pre.2a895cf0',
      '@midnight-ntwrk/midnight-js-level-private-state-provider': '4.0.2-0-pre.2a895cf0',
      '@midnight-ntwrk/midnight-js-network-id': '4.0.2-0-pre.2a895cf0',
      '@midnight-ntwrk/midnight-js-node-zk-config-provider': '4.0.2-0-pre.2a895cf0',
      '@midnight-ntwrk/midnight-js-types': '4.0.2-0-pre.2a895cf0',
      '@midnight-ntwrk/midnight-js-utils': '4.0.2-0-pre.2a895cf0',
      '@midnight-ntwrk/testkit-js': '4.0.2-0-pre.2a895cf0',
    },
  },
  'v3-compat': {
    compactcVersion: '0.28.0',
    packageVersions: {
      '@midnight-ntwrk/compact-js': '2.4.0',
      '@midnight-ntwrk/compact-runtime': '0.14.0',
      '@midnight-ntwrk/ledger-v8': 'npm:@midnight-ntwrk/ledger-v7@7.0.0',
      '@midnight-ntwrk/midnight-js-compact': '3.0.0',
      '@midnight-ntwrk/midnight-js-contracts': '3.0.0',
      '@midnight-ntwrk/midnight-js-http-client-proof-provider': '3.0.0',
      '@midnight-ntwrk/midnight-js-indexer-public-data-provider': '3.0.0',
      '@midnight-ntwrk/midnight-js-level-private-state-provider': '3.0.0',
      '@midnight-ntwrk/midnight-js-network-id': '3.0.0',
      '@midnight-ntwrk/midnight-js-node-zk-config-provider': '3.0.0',
      '@midnight-ntwrk/midnight-js-types': '3.0.0',
      '@midnight-ntwrk/midnight-js-utils': '3.0.0',
      '@midnight-ntwrk/testkit-js': '3.0.0',
    },
  },
};

function parseMatrixes(values: string[] | undefined): MidnightStackMatrixId[] {
  if (!values || values.length === 0) {
    return ['v4-stable', 'v4-pre', 'v3-compat'];
  }
  const matrixes = values.filter((value): value is MidnightStackMatrixId => value in MATRICES);
  return matrixes.length > 0 ? matrixes : ['v4-stable', 'v4-pre', 'v3-compat'];
}

function parseStrategy(value: string | undefined): MidnightSubmitStrategyId {
  if (value === 'metadata-midnight-extrinsic' || value === 'compat-node-client') {
    return value;
  }
  return 'wallet-sdk';
}

async function runCommand(
  command: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
): Promise<string> {
  const { stdout, stderr } = await execFileAsync(command, args, {
    cwd,
    env,
    maxBuffer: 20 * 1024 * 1024,
    timeout: 10 * 60_000,
  });
  return `${stdout}${stderr}`;
}

async function prepareWorkspace(matrixId: MidnightStackMatrixId): Promise<{
  workspaceDir: string;
  localReportPath: string;
}> {
  const workspaceDir = await mkdtemp(join(tmpdir(), `ziros-attestation-${matrixId}-`));
  await cp(SOURCE_DIR, workspaceDir, {
    recursive: true,
    filter(source) {
      return !source.includes('/node_modules') && !source.includes('/build');
    },
  });

  const packageJsonPath = join(workspaceDir, 'package.json');
  const packageJson = JSON.parse(await readFile(packageJsonPath, 'utf-8')) as {
    dependencies: Record<string, string>;
    devDependencies: Record<string, string>;
    scripts: Record<string, string>;
  };
  const matrix = MATRICES[matrixId];
  for (const [name, version] of Object.entries(matrix.packageVersions)) {
    if (name in packageJson.dependencies) {
      packageJson.dependencies[name] = version;
    } else {
      packageJson.devDependencies[name] = version;
    }
  }
  packageJson.scripts['fetch-compactc'] = `COMPACTC_VERSION=${matrix.compactcVersion} fetch-compactc`;

  await rm(join(workspaceDir, 'package-lock.json'), { force: true });
  await import('node:fs/promises').then(({ writeFile }) =>
    writeFile(packageJsonPath, JSON.stringify(packageJson, null, 2), 'utf-8'),
  );

  return {
    workspaceDir,
    localReportPath: join(workspaceDir, 'data', 'compatibility-report.json'),
  };
}

async function runMatrix(
  matrixId: MidnightStackMatrixId,
  strategy: MidnightSubmitStrategyId,
  liveSubmit: boolean,
  includeSedCanary: boolean,
): Promise<CompatibilityMatrixAttempt> {
  const { workspaceDir, localReportPath } = await prepareWorkspace(matrixId);
  const matrix = MATRICES[matrixId];
  const env = {
    ...process.env,
    MIDNIGHT_NETWORK: 'preprod',
  };
  const probeArgs = liveSubmit ? [] : ['--skip-submit'];
  const probeIds = includeSedCanary
    ? ['chain-control-accepted-midnight', 'attestation-backend', 'sed-contract-canary']
    : ['chain-control-accepted-midnight', 'attestation-backend'];

  try {
    await runCommand('npm', ['install', '--no-audit', '--no-fund'], workspaceDir, env);
    await runCommand('npm', ['run', 'fetch-compactc'], workspaceDir, env);
    await runCommand('npm', ['run', 'compile-contracts'], workspaceDir, env);
    await runCommand('npm', ['run', 'probe:runtime', '--', '--out', localReportPath], workspaceDir, env);
    await runCommand(
      'npm',
      ['run', 'probe:chain-control', '--', '--matrix', matrixId, '--out', localReportPath],
      workspaceDir,
      env,
    );
    await runCommand(
      'npm',
      ['run', 'probe:attestation-backend', '--', '--matrix', matrixId, '--strategy', strategy, '--out', localReportPath, ...probeArgs],
      workspaceDir,
      env,
    );
    if (includeSedCanary) {
      await runCommand(
        'npm',
        ['run', 'probe:sed-canary', '--', '--matrix', matrixId, '--strategy', strategy, '--out', localReportPath, ...probeArgs],
        workspaceDir,
        env,
      );
    }

    const report = await readCompatibilityReport(localReportPath);
    const matrixProbes = (report?.probes ?? []).filter((probe) => probe.matrixId === matrixId);
    const chainControlProbe = findLatestChainControlProbe(report, 'preprod', matrixId);
    const validatorHealthy = chainControlProbe ? !probeHasValidationPanic(chainControlProbe) : true;
    const succeeded =
      matrixProbes.length >= probeIds.length &&
      Boolean(chainControlProbe) &&
      matrixProbes
        .filter((probe) => probe.probeId !== 'chain-control-accepted-midnight')
        .every((probe) => {
          const validationOkay = validatorHealthy ? !probeHasValidationPanic(probe) : true;
          return validationOkay && (probe.submit.outcome === 'accepted' || probe.submit.outcome === 'skipped');
        });

    return {
      matrixId,
      workspaceDir,
      packageVersions: matrix.packageVersions,
      compactcVersion: matrix.compactcVersion,
      succeeded,
      probeIds,
      note: succeeded
        ? validatorHealthy
          ? 'Matrix probes completed with a healthy validator control.'
          : 'Matrix probes completed while validateTransaction remained broken on the accepted chain-control transaction.'
        : chainControlProbe == null
          ? 'Matrix probes failed before establishing a chain-control baseline.'
          : validatorHealthy
            ? 'Matrix probes still failed despite a healthy validator control.'
            : 'Matrix probes still failed after ignoring validator panics proven to occur on accepted chain traffic.',
    };
  } catch (error) {
    return {
      matrixId,
      workspaceDir,
      packageVersions: matrix.packageVersions,
      compactcVersion: matrix.compactcVersion,
      succeeded: false,
      probeIds,
      note: error instanceof Error ? error.message : String(error),
    };
  }
}

async function main() {
  const { flags } = parseArgs(process.argv.slice(2));
  const reportPath = optionalFlag(flags, 'out') ?? DEFAULT_COMPATIBILITY_REPORT_PATH;
  const matrixes = parseMatrixes(flags.get('matrix'));
  const strategy = parseStrategy(optionalFlag(flags, 'strategy'));
  const liveSubmit = flags.has('live-submit');
  const includeSedCanary = flags.has('include-sed-canary');

  let report = await readCompatibilityReport(reportPath);
  const attempts: CompatibilityMatrixAttempt[] = [];

  for (const matrixId of matrixes) {
    const attempt = await runMatrix(matrixId, strategy, liveSubmit, includeSedCanary);
    attempts.push(attempt);
    report = withMatrixAttempt(report, attempt);
  }

  const preprodProfile = await buildCompatibilityProfile('preprod', getRuntimeConfig({ network: 'preprod' }));
  const selected = attempts.find((attempt) => attempt.succeeded);
  if (selected) {
    report = {
      ...(report ?? {
        generatedAt: new Date().toISOString(),
        profiles: [],
        probes: [],
        matrices: [],
        selected: null,
      }),
      selected: {
        matrixId: selected.matrixId,
        strategy,
        network: 'preprod',
        selectedAt: new Date().toISOString(),
        runtimeFingerprint: {
          network: preprodProfile.network,
          specVersion: preprodProfile.specVersion,
          transactionVersion: preprodProfile.transactionVersion,
          signedExtensions: preprodProfile.signedExtensions,
          rawLedgerVersion: preprodProfile.rawLedgerVersion,
        },
      },
    };
  } else if (report) {
    report.selected = null;
  }

  if (report?.selected && !runtimeFingerprintMatches(report.selected, preprodProfile)) {
    report.selected = null;
  }

  if (!report) {
    throw new Error('Compatibility matrix run did not produce a report.');
  }

  await writeCompatibilityReport(report, reportPath);
  console.log(stringifyJson({ reportPath, attempts, selected: report.selected }));
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
