import {
  DEFAULT_COMPATIBILITY_REPORT_PATH,
  readCompatibilityReport,
  type MidnightStackMatrixId,
  type MidnightSubmitStrategyId,
  withProbe,
  withProfile,
  writeCompatibilityReport,
} from './compatibility.js';
import { getRuntimeConfig, type MidnightNetwork } from './config.js';
import { buildHeadlessWallet, waitForSpendableDust } from './providers.js';
import { buildCompatibilityProfile, withMidnightApi } from './runtime-probe.js';
import { createSubmitStrategy, probeSubmitStrategy } from './submit-strategy.js';
import { buildPreparedDeployTransaction } from './tx-pipeline.js';
import { optionalFlag, parseArgs, stringifyJson } from './util.js';
import { loadWitnessPayload } from './witness-data.js';

function parseStrategy(value: string | undefined): MidnightSubmitStrategyId {
  if (value === 'metadata-midnight-extrinsic' || value === 'compat-node-client') {
    return value;
  }
  return 'wallet-sdk';
}

function parseMatrix(value: string | undefined): MidnightStackMatrixId | 'current' {
  if (value === 'v4-stable' || value === 'v4-pre' || value === 'v3-compat') {
    return value;
  }
  return 'current';
}

function parseNetwork(value: string | undefined): MidnightNetwork {
  if (value === 'preview' || value === 'mainnet' || value === 'undeployed' || value === 'offline') {
    return value;
  }
  return 'preprod';
}

async function main() {
  const { flags } = parseArgs(process.argv.slice(2));
  const strategy = parseStrategy(optionalFlag(flags, 'strategy'));
  const matrixId = parseMatrix(optionalFlag(flags, 'matrix'));
  const network = parseNetwork(optionalFlag(flags, 'network'));
  const reportPath = optionalFlag(flags, 'out') ?? DEFAULT_COMPATIBILITY_REPORT_PATH;
  const witnessPath = optionalFlag(flags, 'witness') ?? './.tmp/local-attestation/witness.json';
  const skipSubmit = flags.has('skip-submit');

  const config = getRuntimeConfig({ network });
  const payload = await loadWitnessPayload(witnessPath);
  const wallet = await buildHeadlessWallet(config);

  try {
    await waitForSpendableDust(wallet);

    const prepared = await buildPreparedDeployTransaction('backend', payload, wallet, config);
    const profile = await buildCompatibilityProfile(network);

    const probe = await withMidnightApi(config, async (api) => {
      const runtimeCost = await api.call.midnightRuntimeApi.getTransactionCost(prepared.innerTxHex);
      const execution = skipSubmit
        ? await (async () => {
            const submitStrategy = createSubmitStrategy(
              strategy,
              prepared.balancedTx,
              prepared.innerTxHex,
            );
            const outerTxHex = await submitStrategy.buildOuter(prepared.innerTxHex, api);
            const validation = await submitStrategy.validate(outerTxHex, api);
            return {
              outerTxHex,
              validation,
              submit: {
                strategy,
                outcome: 'skipped' as const,
                txHash: null,
                detail: 'Submission skipped by --skip-submit.',
              },
            };
          })()
        : await probeSubmitStrategy(strategy, prepared.balancedTx, prepared.innerTxHex, {
            api,
            wallet,
          });

      return {
        probeId: 'attestation-backend',
        network,
        matrixId,
        strategy,
        observedAt: new Date().toISOString(),
        innerTxHexLength: prepared.innerTxHex.length,
        outerTxHexLength: execution.outerTxHex.length,
        serializedLength: prepared.serializedLength,
        txId: prepared.txId,
        runtimeInnerCost: runtimeCost.toString(),
        validation: execution.validation,
        submit: execution.submit,
        note: stringifyJson({
          contractKey: 'backend',
          contractAddress: prepared.contractAddress,
          localCost: prepared.cost,
        }),
      };
    });

    const existing = await readCompatibilityReport(reportPath);
    const report = withProbe(withProfile(existing, profile), probe);
    await writeCompatibilityReport(report, reportPath);
    console.log(stringifyJson({ reportPath, profile, probe }));
  } finally {
    await wallet.stop();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
