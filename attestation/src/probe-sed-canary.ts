import { Buffer } from 'node:buffer';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

import { Transaction } from '@midnight-ntwrk/ledger-v8';

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
import {
  buildHeadlessWallet,
  waitForSpendableDust,
} from './providers.js';
import { buildCompatibilityProfile, withMidnightApi } from './runtime-probe.js';
import { createSubmitStrategy, probeSubmitStrategy } from './submit-strategy.js';
import { optionalFlag, parseArgs, stringifyJson } from './util.js';

const SED_ROOT = '/Users/sicarii/Desktop/ziros-sovereign-economic-defense/dapp';
const SED_MANIFEST_PATH = `${SED_ROOT}/data/deployment-manifest.json`;
const SED_CANDIDATE_KEYS = [
  'cooperative-treasury',
  'community-land-trust',
  'anti-extraction-shield',
  'wealth-trajectory',
  'sovereignty-score',
] as const;

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

async function importModule(pathname: string): Promise<Record<string, unknown>> {
  return import(pathToFileURL(pathname).href) as Promise<Record<string, unknown>>;
}

async function readSedManifest(): Promise<{
  contracts: Array<{ name: string; address: string }>;
}> {
  const raw = await readFile(SED_MANIFEST_PATH, 'utf-8');
  return JSON.parse(raw) as { contracts: Array<{ name: string; address: string }> };
}

async function main() {
  const { flags } = parseArgs(process.argv.slice(2));
  const strategy = parseStrategy(optionalFlag(flags, 'strategy'));
  const matrixId = parseMatrix(optionalFlag(flags, 'matrix'));
  const network = parseNetwork(optionalFlag(flags, 'network'));
  const reportPath = optionalFlag(flags, 'out') ?? DEFAULT_COMPATIBILITY_REPORT_PATH;
  const skipSubmit = flags.has('skip-submit');

  const config = getRuntimeConfig({ network });
  const sedActionsModule = await importModule(`${SED_ROOT}/src/midnight/actions.ts`);
  const manifest = await readSedManifest();

  const prepareSedContractCall = sedActionsModule.prepareContractCall as (request: {
    contractKey: string;
    coinPublicKey: string;
    encryptionPublicKey: string;
    provingMode: 'local-zkf-proof-server';
    walletConfiguration?: {
      indexerUri?: string;
      indexerWsUri?: string;
      proverServerUri?: string;
      substrateNodeUri?: string;
      networkId?: string;
    } | null;
  }) => Promise<{
    preparedTxHex: string;
    contractAddress: string;
    circuitId: string;
    provingMode: string;
  }>;

  const wallet = await buildHeadlessWallet(config);
  try {
    await waitForSpendableDust(wallet);

    const originalCwd = process.cwd();
    process.chdir(SED_ROOT);
    let prepared;
    let chosenContractKey: string | null = null;
    let chosenContractAddress: string | null = null;
    const preparationErrors: Array<{ contractKey: string; error: string }> = [];
    try {
      for (const contractKey of SED_CANDIDATE_KEYS) {
        const contractEntry = manifest.contracts.find((contract) => contract.name === contractKey);
        if (!contractEntry?.address) {
          preparationErrors.push({
            contractKey,
            error: `Missing deployment manifest entry for ${contractKey}.`,
          });
          continue;
        }

        try {
          prepared = await prepareSedContractCall({
            contractKey,
            coinPublicKey: Buffer.from(wallet.getCoinPublicKey()).toString('hex'),
            encryptionPublicKey: Buffer.from(wallet.getEncryptionPublicKey()).toString('hex'),
            provingMode: 'local-zkf-proof-server',
            walletConfiguration: {
              indexerUri: config.indexerUrl,
              indexerWsUri: config.indexerWsUrl,
              proverServerUri: config.proofServerUrl,
              substrateNodeUri: config.rpcUrl,
              networkId: network === 'preview' ? 'preprod' : network,
            },
          });
          chosenContractKey = contractKey;
          chosenContractAddress = contractEntry.address;
          break;
        } catch (error) {
          preparationErrors.push({
            contractKey,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
    } finally {
      process.chdir(originalCwd);
    }
    if (!prepared || !chosenContractKey || !chosenContractAddress) {
      throw new Error(
        `No deployed SED contract could be prepared for the canary path. ${stringifyJson(preparationErrors)}`,
      );
    }
    const provenTx = Transaction.deserialize(
      'signature',
      'proof',
      'pre-binding',
      Buffer.from(prepared.preparedTxHex.replace(/^0x/, ''), 'hex'),
    );
    const balancedTx = await wallet.balanceTx(provenTx as never);

    const innerTxHex = `0x${Buffer.from(balancedTx.serialize()).toString('hex')}`;
    const txId = String(balancedTx.identifiers().at(-1) ?? '');
    const profile = await buildCompatibilityProfile(network);

    const probe = await withMidnightApi(config, async (api) => {
      const runtimeCost = await api.call.midnightRuntimeApi.getTransactionCost(innerTxHex);
      const execution = skipSubmit
        ? await (async () => {
            const submitStrategy = createSubmitStrategy(strategy, balancedTx, innerTxHex);
            const outerTxHex = await submitStrategy.buildOuter(innerTxHex, api);
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
        : await probeSubmitStrategy(strategy, balancedTx, innerTxHex, {
            api,
            wallet,
          });

      return {
        probeId: 'sed-contract-canary',
        network,
        matrixId,
        strategy,
        observedAt: new Date().toISOString(),
        innerTxHexLength: innerTxHex.length,
        outerTxHexLength: execution.outerTxHex.length,
        serializedLength: balancedTx.serialize().length,
        txId: txId || null,
        runtimeInnerCost: runtimeCost.toString(),
        validation: execution.validation,
        submit: execution.submit,
        note: stringifyJson({
          contractKey: chosenContractKey,
          contractAddress: chosenContractAddress,
          preparationErrors,
          path: 'Prepared with the SED DApp prepareContractCall entrypoint, then balanced and submitted through the attestation operator wallet.',
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
