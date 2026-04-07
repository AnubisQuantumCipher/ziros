import * as Rx from 'rxjs';

import {
  buildHeadlessWallet,
  collectDustDiagnostics,
  formatDust,
  formatWalletAddress,
  getRuntimeConfig,
} from './runtime.js';

async function main() {
  const config = getRuntimeConfig();
  const wallet = await buildHeadlessWallet(config);

  try {
    const state = await Rx.firstValueFrom(
      wallet.wallet.state().pipe(
        Rx.filter((entry) => entry.unshielded.progress.isConnected),
        Rx.timeout({ each: 60_000 }),
      ),
    );
    const diagnostics = await collectDustDiagnostics(wallet);
    const readiness =
      diagnostics.spendableDustRaw > 0n
        ? 'ready'
        : diagnostics.registeredNightUtxos === 0
          ? 'needs-dust-registration'
          : diagnostics.dustSyncConnected
            ? 'waiting-for-spendable-tdust'
            : 'dust-wallet-still-syncing';

    console.log(
      JSON.stringify(
        {
          network: config.network,
          walletFile: process.env.MIDNIGHT_OPERATOR_WALLET_FILE ?? null,
          unshieldedAddress: formatWalletAddress(state.unshielded.address, config.network),
          dustAddress: formatWalletAddress(state.dust.address, config.network),
          shieldedAddress: formatWalletAddress(state.shielded.address, config.network),
          spendableDustRaw: diagnostics.spendableDustRaw.toString(),
          spendableDust: formatDust(diagnostics.spendableDustRaw),
          spendableDustCoins: diagnostics.spendableDustCoins,
          registeredNightUtxos: diagnostics.registeredNightUtxos,
          dustSyncConnected: diagnostics.dustSyncConnected,
          unshieldedBalances: Object.fromEntries(
            Object.entries(state.unshielded.balances).map(([key, value]) => [key, value.toString()]),
          ),
          readiness,
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
