import * as Rx from 'rxjs';

import { getRuntimeConfig } from './config.js';
import { buildHeadlessWallet, collectDustDiagnostics } from './providers.js';

async function main() {
  const config = getRuntimeConfig();
  const wallet = await buildHeadlessWallet(config);

  try {
    const state = await Rx.firstValueFrom(wallet.wallet.state());
    const unshieldedRaw = state.unshielded.availableCoins.reduce(
      (sum, coin) => sum + coin.utxo.value,
      0n,
    );
    const diagnostics = await collectDustDiagnostics(wallet);

    console.log(
      JSON.stringify(
        {
          network: config.network,
          unshieldedCoinCount: state.unshielded.availableCoins.length,
          unshieldedTotalRaw: unshieldedRaw.toString(),
          spendableDustRaw: diagnostics.spendableDustRaw.toString(),
          spendableDustCoins: diagnostics.spendableDustCoins,
          dustSyncConnected: diagnostics.dustSyncConnected,
          registeredNightUtxos: diagnostics.registeredNightUtxos,
        },
        null,
        2,
      ),
    );
  } finally {
    await wallet.stop();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
