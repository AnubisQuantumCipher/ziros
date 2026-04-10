import { pathToFileURL } from 'node:url';

import { createUnprovenCallTx } from '@midnight-ntwrk/midnight-js-contracts';

import { loadCompiledContract } from '../midnight/artifacts';
import { getRuntimeConfig, type MidnightNetwork, type MidnightProvingMode, explorerLink } from '../midnight/config';
import { appendCallReceipt, readDeploymentManifest, upsertDeploymentManifestEntry } from '../midnight/manifest';
import {
  type MidnightWalletProvider,
  buildHeadlessWallet,
  createDeployProviders,
  waitForSpendableDust,
} from '../midnight/providers';
import { callEntryById, readTradeFinanceFlowManifest, type FlowCallEntry } from '../midnight/witness-data';

export interface CallAllOptions {
  network?: string;
  provingMode?: MidnightProvingMode;
  manifestPath?: string;
  callIds?: string[];
}

function networkLabel(network: MidnightNetwork): string {
  switch (network) {
    case 'preprod': return 'Midnight Preprod';
    case 'preview': return 'Midnight Preview';
    case 'mainnet': return 'Midnight Mainnet';
    case 'undeployed': return 'Midnight Undeployed';
    case 'offline': return 'Midnight Offline';
  }
}

async function callSingleFlow(
  flow: FlowCallEntry,
  options: {
    walletProvider: MidnightWalletProvider;
    network?: string;
    provingMode?: MidnightProvingMode;
    manifestPath?: string;
  },
): Promise<void> {
  const config = getRuntimeConfig({
    network: options.network as MidnightNetwork | undefined,
    provingMode: options.provingMode,
    deploymentManifestPath: options.manifestPath,
  });
  const manifest = await readDeploymentManifest(config.deploymentManifestPath);
  const entry = manifest?.contracts.find((value) => value.name === flow.contract_id);
  if (!entry?.address) {
    throw new Error(`Contract ${flow.contract_id} is not deployed. Run "npm run deploy" first.`);
  }

  const loaded = await loadCompiledContract(flow.contract_id, { config, inputs: flow.inputs });
  const providers = createDeployProviders(
    config,
    loaded.artifactDir,
    options.walletProvider,
    flow.contract_id,
    config.provingMode,
  );
  const callTxData = await createUnprovenCallTx(providers as never, {
    compiledContract: loaded.compiledContract as never,
    contractAddress: entry.address as never,
    circuitId: flow.circuit_name as never,
    args: [],
  } as never);
  const provenTx = await (providers.proofProvider as any).proveTx(callTxData.private.unprovenTx);
  const balancedTx = await (options.walletProvider as any).balanceTx(provenTx);
  const txId = await (options.walletProvider as any).submitTx(balancedTx);
  const txData = await (providers.publicDataProvider as any).watchForTxData(txId as never);
  const onChainState = await (providers.publicDataProvider as any).queryContractState(entry.address as never);
  const snapshot = onChainState ? loaded.decodeLedgerState(onChainState) : entry.publicStateSnapshot ?? null;
  const callExplorerUrl = explorerLink(config.explorerUrl, txData.txHash, entry.address);

  await upsertDeploymentManifestEntry(
    {
      ...entry,
      publicStateSnapshot: snapshot,
      lastCallTxHash: txData.txHash,
      lastCallExplorerUrl: callExplorerUrl,
      lastCallAt: new Date().toISOString(),
    },
    {
      network: config.network,
      networkName: networkLabel(config.network),
      manifestPath: config.deploymentManifestPath,
    },
  );

  await appendCallReceipt({
    callId: flow.call_id,
    contractId: flow.contract_id,
    circuitName: flow.circuit_name,
    txHash: txData.txHash,
    contractAddress: entry.address,
    explorerUrl: callExplorerUrl,
    calledAt: new Date().toISOString(),
    inputs: flow.inputs,
  }, config.callReceiptsPath);

  console.log(`${flow.call_id}`);
  console.log(`  Contract:  ${flow.contract_id}`);
  console.log(`  Address:   ${entry.address}`);
  console.log(`  Tx Hash:   ${txData.txHash}`);
  console.log(`  Explorer:  ${callExplorerUrl}`);
  console.log('');
}

export async function callAll(options: CallAllOptions = {}): Promise<void> {
  const config = getRuntimeConfig({
    network: options.network as MidnightNetwork | undefined,
    provingMode: options.provingMode,
    deploymentManifestPath: options.manifestPath,
  });
  const flowManifest = await readTradeFinanceFlowManifest(config);
  const flows = options.callIds && options.callIds.length > 0
    ? await Promise.all(options.callIds.map((callId) => callEntryById(callId, config)))
    : flowManifest.calls;

  console.log(`
=== Private Trade Finance Settlement -- Midnight Calls ===
`);
  console.log(`Network:      ${networkLabel(config.network)}`);
  console.log(`Manifest:     ${config.deploymentManifestPath}`);
  console.log(`Call receipts:${config.callReceiptsPath}`);
  console.log('');

  const walletProvider = await buildHeadlessWallet(config);
  try {
    await waitForSpendableDust(walletProvider);
    for (const flow of flows) {
      await waitForSpendableDust(walletProvider);
      console.log(`--- Calling ${flow.call_id} ---`);
      await callSingleFlow(flow, { ...options, walletProvider, manifestPath: config.deploymentManifestPath });
    }
  } finally {
    await walletProvider.stop();
  }
}

const isDirectExecution = process.argv[1] != null && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isDirectExecution) {
  const callIds = process.env.MIDNIGHT_CALL_IDS?.split(',').map((value) => value.trim()).filter(Boolean);
  callAll({
    network: process.env.MIDNIGHT_NETWORK,
    provingMode: process.env.MIDNIGHT_PROVING_MODE === 'wallet-proving-provider' ? 'wallet-proving-provider' : 'local-zkf-proof-server',
    manifestPath: process.env.MIDNIGHT_DEPLOYMENT_MANIFEST_PATH,
    callIds,
  }).catch((error: unknown) => {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
