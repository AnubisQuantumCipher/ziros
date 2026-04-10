import { pathToFileURL } from 'node:url';

import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';

import { loadCompiledContract } from '../midnight/artifacts';
import { CONTRACTS, type ContractKey } from '../midnight/contracts';
import { explorerLink, getRuntimeConfig, type MidnightNetwork, type MidnightProvingMode } from '../midnight/config';
import { readDeploymentManifest, upsertDeploymentManifestEntry } from '../midnight/manifest';
import {
  type MidnightWalletProvider,
  buildHeadlessWallet,
  collectDustDiagnostics,
  createDeployProviders,
  formatDust,
  waitForSpendableDust,
} from '../midnight/providers';
import { callEntryById } from '../midnight/witness-data';

export interface DeployAllOptions {
  network?: string;
  provingMode?: MidnightProvingMode;
  manifestPath?: string;
  contractKeys?: ContractKey[];
  forceRedeploy?: boolean;
}

function dustSummary(diagnostics: Awaited<ReturnType<typeof collectDustDiagnostics>>): string {
  return (
    `spendable=${formatDust(diagnostics.spendableDustRaw)} DUST ` +
    `(${diagnostics.spendableDustCoins} coin(s)), ` +
    `registered NIGHT=${diagnostics.registeredNightUtxos}, ` +
    `unregistered NIGHT=${diagnostics.unregisteredNightUtxos}, ` +
    `estimated generated=${formatDust(diagnostics.estimatedGeneratedDustRaw)} DUST, ` +
    `dust sync connected=${diagnostics.dustSyncConnected}`
  );
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

async function deploySingleContract(
  contractKey: ContractKey,
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
  const flow = await callEntryById(
    CONTRACTS.find((contract) => contract.key === contractKey)?.defaultDeployCallId ?? contractKey,
    config,
  );
  const loaded = await loadCompiledContract(contractKey, { config, inputs: flow.inputs });
  const providers = createDeployProviders(
    config,
    loaded.artifactDir,
    options.walletProvider,
    contractKey,
    config.provingMode,
  );

  const deployed = await deployContract(providers, {
    compiledContract: loaded.compiledContract as never,
    args: [],
  });

  const address = String(deployed.deployTxData.public.contractAddress);
  const txHash = deployed.deployTxData.public.txHash;
  const onChainState = await providers.publicDataProvider.queryContractState(address as never);
  const snapshot = onChainState ? loaded.decodeLedgerState(onChainState) : null;
  const deepLink = explorerLink(config.explorerUrl, txHash, address);

  await upsertDeploymentManifestEntry(
    {
      name: contractKey,
      address,
      txHash,
      deployedAt: new Date().toISOString(),
      explorerUrl: deepLink,
      deploymentExplorerUrl: deepLink,
      publicStateSnapshot: snapshot,
    },
    {
      network: config.network,
      networkName: networkLabel(config.network),
      manifestPath: config.deploymentManifestPath,
    },
  );

  console.log(`${loaded.contract.displayName}`);
  console.log(`  Address:   ${address}`);
  console.log(`  Tx Hash:   ${txHash}`);
  console.log(`  Explorer:  ${deepLink}`);
  console.log('');
}

export async function deployAll(options: DeployAllOptions = {}): Promise<void> {
  const config = getRuntimeConfig({
    network: options.network as MidnightNetwork | undefined,
    provingMode: options.provingMode,
    deploymentManifestPath: options.manifestPath,
  });
  const contractKeys = options.contractKeys && options.contractKeys.length > 0
    ? options.contractKeys
    : CONTRACTS.map((contract) => contract.key);
  const forceRedeploy = options.forceRedeploy || process.env.MIDNIGHT_FORCE_REDEPLOY === '1';

  console.log(`
=== Private Trade Finance Settlement -- Midnight Deployment ===
`);
  console.log(`Network:      ${networkLabel(config.network)}`);
  console.log(`Indexer:      ${config.indexerUrl}`);
  console.log(`Proof mode:   ${config.provingMode}`);
  console.log(`Proof server: ${config.proofServerUrl}`);
  console.log(`Manifest:     ${config.deploymentManifestPath}`);
  console.log('');

  const walletProvider = await buildHeadlessWallet(config);
  try {
    const initialDust = await collectDustDiagnostics(walletProvider);
    console.log(`Wallet dust:  ${dustSummary(initialDust)}`);
    console.log('');
    await waitForSpendableDust(walletProvider);

    for (const contractKey of contractKeys) {
      const existing = await readDeploymentManifest(config.deploymentManifestPath);
      const entry = existing?.contracts.find((contract) => contract.name === contractKey);
      if (entry?.address && !forceRedeploy) {
        console.log(`--- Skipping ${contractKey}; already deployed at ${entry.address} ---`);
        continue;
      }
      await waitForSpendableDust(walletProvider);
      console.log(`--- Deploying ${contractKey} ---`);
      await deploySingleContract(contractKey, { ...options, walletProvider, manifestPath: config.deploymentManifestPath });
    }
  } finally {
    await walletProvider.stop();
  }
}

const isDirectExecution = process.argv[1] != null && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isDirectExecution) {
  deployAll({
    network: process.env.MIDNIGHT_NETWORK,
    provingMode: process.env.MIDNIGHT_PROVING_MODE === 'wallet-proving-provider' ? 'wallet-proving-provider' : 'local-zkf-proof-server',
    manifestPath: process.env.MIDNIGHT_DEPLOYMENT_MANIFEST_PATH,
  }).catch((error: unknown) => {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
