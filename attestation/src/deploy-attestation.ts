import { loadCompiledContract } from './artifacts.js';
import { explorerLink, getRuntimeConfig, networkLabel } from './config.js';
import { CONTRACTS, type ContractKey } from './contracts.js';
import {
  readDeploymentManifest,
  upsertDeploymentManifestEntry,
} from './manifest.js';
import {
  buildHeadlessWallet,
  waitForSpendableDust,
} from './providers.js';
import { withMidnightApi } from './runtime-probe.js';
import { resolveSelectedCompatibilityStrategy } from './strategy-selection.js';
import { probeSubmitStrategy } from './submit-strategy.js';
import { buildPreparedDeployTransaction } from './tx-pipeline.js';
import { stringifyJson } from './util.js';
import { loadWitnessPayload } from './witness-data.js';
import { buildCompatibilityProfile } from './runtime-probe.js';

async function deploySingleContract(
  contractKey: ContractKey,
  payload: Awaited<ReturnType<typeof loadWitnessPayload>>,
  walletProvider: Awaited<ReturnType<typeof buildHeadlessWallet>>,
): Promise<void> {
  const config = getRuntimeConfig();
  const selection = await resolveSelectedCompatibilityStrategy(config);
  const profile = await buildCompatibilityProfile(config.network, config);
  const prepared = await buildPreparedDeployTransaction(contractKey, payload, walletProvider, config);
  const submission = await withMidnightApi(config, async (api) =>
    probeSubmitStrategy(selection.strategy, prepared.balancedTx, prepared.innerTxHex, {
      api,
      wallet: walletProvider,
    }),
  );
  if (submission.submit.outcome !== 'accepted') {
    throw new Error(
      `Deploy submit failed for ${contractKey} via ${selection.strategy}: ${submission.submit.detail}`,
    );
  }

  const txData = await prepared.providers.publicDataProvider.watchForTxData(prepared.txId as never);
  const address = String(prepared.contractAddress);
  const txHash = txData.txHash;
  const onChainState = await prepared.providers.publicDataProvider.queryContractState(address as never);
  const snapshot = onChainState ? prepared.loaded.decodeLedgerState(onChainState) : null;

  await upsertDeploymentManifestEntry(
    {
      name: contractKey,
      address,
      txHash,
      deployedAt: new Date().toISOString(),
      explorerUrl: explorerLink(config.explorerUrl, txHash, address),
      publicStateSnapshot: snapshot,
    },
    {
      network: config.network,
      networkName: networkLabel(config.network),
      selectedMatrixId: selection.matrixId === 'current' ? undefined : selection.matrixId,
      selectedSubmitStrategy: selection.strategy,
      runtimeFingerprint: {
        specVersion: profile.specVersion,
        transactionVersion: profile.transactionVersion,
        rawLedgerVersion: profile.rawLedgerVersion,
        signedExtensions: profile.signedExtensions,
      },
      manifestPath: config.manifestPath,
    },
  );
}

async function deploy() {
  const witnessPath = process.env.ATTESTATION_WITNESS_PATH ?? './data/witness.json';
  const payload = await loadWitnessPayload(witnessPath);
  const config = getRuntimeConfig();
  const walletProvider = await buildHeadlessWallet(config);

  try {
    await waitForSpendableDust(walletProvider);

    for (const contract of CONTRACTS) {
      await deploySingleContract(contract.key, payload, walletProvider);
    }
  } finally {
    await walletProvider.stop();
  }

  const manifest = await readDeploymentManifest(config.manifestPath);
  console.log(stringifyJson(manifest));
}

deploy().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
