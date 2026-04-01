import { createUnprovenDeployTx } from '@midnight-ntwrk/midnight-js-contracts';
import { sampleSigningKey } from '@midnight-ntwrk/compact-runtime';

import { loadCompiledContract } from './artifacts.js';
import { getRuntimeConfig } from './config.js';
import { CONTRACTS } from './contracts.js';
import { buildHeadlessWallet, createDeployProviders, waitForSpendableDust } from './providers.js';
import { loadWitnessPayload } from './witness-data.js';

async function main() {
  const config = getRuntimeConfig();
  const payload = await loadWitnessPayload('./data/witness.json');
  const wallet = await buildHeadlessWallet(config);

  try {
    await waitForSpendableDust(wallet);

    for (const contract of CONTRACTS) {
      const loaded = await loadCompiledContract(contract.key, { payload, config });
      const providers = createDeployProviders(
        config,
        loaded.artifactDir,
        wallet,
        `debug-${contract.key}`,
        config.provingMode,
      );
      const deployTxData = await createUnprovenDeployTx(
        {
          zkConfigProvider: providers.zkConfigProvider,
          walletProvider: providers.walletProvider,
        },
        {
          compiledContract: loaded.compiledContract as never,
          args: [],
          signingKey: sampleSigningKey(),
        },
      );
      const provenTx = await providers.proofProvider.proveTx(deployTxData.private.unprovenTx);
      const balancedTx = await wallet.balanceTx(provenTx);

      console.log(
        JSON.stringify(
          {
            contract: contract.key,
            circuitId: contract.circuitId,
            serializedLength: balancedTx.serialize().length,
            contractAddress: String(deployTxData.public.contractAddress),
          },
          null,
          2,
        ),
      );
    }
  } finally {
    await wallet.stop();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
