import { sampleSigningKey } from '@midnight-ntwrk/ledger-v8';
import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';

import { loadCompiledContract } from './artifacts.js';
import { explorerLink, getRuntimeConfig } from './config.js';
import { readDeploymentManifest, writeDeploymentManifest } from './manifest.js';
import { buildHeadlessWallet, collectDustDiagnostics, createDeployProviders, formatDust } from './providers.js';
import { loadWitnessPayload } from './witness-data.js';

async function deploy() {
  const witnessPath = process.env.ATTESTATION_WITNESS_PATH ?? './data/witness.json';
  const payload = await loadWitnessPayload(witnessPath);
  const config = getRuntimeConfig();
  const loaded = await loadCompiledContract(payload, config);
  const walletProvider = await buildHeadlessWallet(config);

  try {
    const dust = await collectDustDiagnostics(walletProvider);
    if (dust.spendableDustRaw <= 0n) {
      throw new Error(
        `Deployment blocked: spendable tDUST is ${formatDust(dust.spendableDustRaw)} across ${dust.spendableDustCoins} coin(s).`,
      );
    }

    const providers = createDeployProviders(
      config,
      loaded.artifactDir,
      walletProvider,
      'ziros-attestation',
      config.provingMode,
    );

    const deployed = await deployContract(providers, {
      compiledContract: loaded.compiledContract as never,
      args: [],
      signingKey: sampleSigningKey(),
    });

    const contractAddress = String(deployed.deployTxData.public.contractAddress);
    const txHash = deployed.deployTxData.public.txHash;
    const onChainState = await providers.publicDataProvider.queryContractState(contractAddress as never);
    const snapshot = onChainState ? loaded.decodeLedgerState(onChainState) : null;
    const manifest = {
      network: config.network,
      deployedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      contractAddress,
      deployTxHash: txHash,
      explorerUrl: explorerLink(config.explorerUrl, txHash, contractAddress),
      circuitTxHashes: (await readDeploymentManifest(config.manifestPath))?.circuitTxHashes ?? {},
      publicStateSnapshot: snapshot,
    };

    await writeDeploymentManifest(config.manifestPath, manifest);
    console.log(JSON.stringify(manifest, null, 2));
  } finally {
    await walletProvider.stop();
  }
}

deploy().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
