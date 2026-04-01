import { findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';

import { loadCompiledContract } from './artifacts.js';
import { getRuntimeConfig } from './config.js';
import { ATTESTATION_CONTRACT } from './contracts.js';
import { readDeploymentManifest, writeDeploymentManifest } from './manifest.js';
import { buildHeadlessWallet, collectDustDiagnostics, createDeployProviders, formatDust } from './providers.js';
import { parseArgs, requireFlag } from './util.js';
import { expectedComplianceBits, loadWitnessPayload } from './witness-data.js';

async function submitAttestation() {
  const { flags } = parseArgs(process.argv.slice(2));
  const witnessPath = requireFlag(flags, 'witness');
  const payload = await loadWitnessPayload(witnessPath);
  const config = getRuntimeConfig();
  const loaded = await loadCompiledContract(payload, config);
  const manifest = await readDeploymentManifest(config.manifestPath);
  if (!manifest?.contractAddress) {
    throw new Error(`Missing deployment manifest at ${config.manifestPath}. Run deploy-attestation first.`);
  }

  const walletProvider = await buildHeadlessWallet(config);

  try {
    const dust = await collectDustDiagnostics(walletProvider);
    if (dust.spendableDustRaw <= 0n) {
      throw new Error(
        `Submission blocked: spendable tDUST is ${formatDust(dust.spendableDustRaw)} across ${dust.spendableDustCoins} coin(s).`,
      );
    }

    const providers = createDeployProviders(
      config,
      loaded.artifactDir,
      walletProvider,
      'ziros-attestation',
      config.provingMode,
    );
    const found = await findDeployedContract(providers, {
      compiledContract: loaded.compiledContract as never,
      contractAddress: manifest.contractAddress as never,
    });

    const circuitTxHashes: Partial<Record<string, string>> = { ...manifest.circuitTxHashes };
    for (const circuitId of ATTESTATION_CONTRACT.circuitIds) {
      const invoke = found.callTx[circuitId] as () => Promise<{
        public: {
          txHash: string;
        };
      }>;
      const finalized = await invoke();
      circuitTxHashes[circuitId] = finalized.public.txHash;
    }

    const onChainState = await providers.publicDataProvider.queryContractState(
      manifest.contractAddress as never,
    );
    const snapshot = onChainState ? loaded.decodeLedgerState(onChainState) : null;
    const expectations = expectedComplianceBits(payload);
    if (Boolean(snapshot?.compliance_bit) !== expectations.overall) {
      throw new Error(
        `On-chain compliance mismatch: expected ${expectations.overall}, got ${String(snapshot?.compliance_bit)}.`,
      );
    }

    const nextManifest = {
      ...manifest,
      updatedAt: new Date().toISOString(),
      circuitTxHashes,
      publicStateSnapshot: snapshot,
    };

    await writeDeploymentManifest(config.manifestPath, nextManifest);
    console.log(JSON.stringify(nextManifest, null, 2));
  } finally {
    await walletProvider.stop();
  }
}

submitAttestation().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
