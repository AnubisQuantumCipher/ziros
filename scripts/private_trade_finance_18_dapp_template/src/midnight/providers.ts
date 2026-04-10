import { Buffer } from 'node:buffer';

import { WebSocket } from 'ws';
import { type CoinPublicKey, type DustSecretKey, type EncPublicKey, type FinalizedTransaction, LedgerParameters, type ZswapSecretKeys } from '@midnight-ntwrk/ledger-v8';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { createProofProvider, type MidnightProvider, type MidnightProviders, type PrivateStateId, type UnboundTransaction, type WalletProvider } from '@midnight-ntwrk/midnight-js-types';
import { ttlOneHour } from '@midnight-ntwrk/midnight-js-utils';
import { WalletFactory, WalletSeeds } from '@midnight-ntwrk/testkit-js';
import { type FacadeState, type WalletFacade } from '@midnight-ntwrk/wallet-sdk-facade';
import { InMemoryTransactionHistoryStorage, createKeystore } from '@midnight-ntwrk/wallet-sdk-unshielded-wallet';
import * as Rx from 'rxjs';

import { type MidnightProvingMode, type MidnightRuntimeConfig } from './config';
import { resolveOperatorWallet } from './operator-wallet';

// @ts-expect-error Midnight SDK expects a global WebSocket implementation in Node.
globalThis.WebSocket = WebSocket;

const MIDNIGHT_ADDITIONAL_FEE_OVERHEAD = 300_000_000_000_000n;
const MIDNIGHT_FEE_BLOCKS_MARGIN = 5;

export interface WalletPublicKeys {
  coinPublicKey: CoinPublicKey;
  encryptionPublicKey: EncPublicKey;
}

export interface DustDiagnostics {
  spendableDustRaw: bigint;
  spendableDustCoins: number;
  dustSyncConnected: boolean;
  dustSyncAppliedIndex: string;
  dustSyncHighestRelevantWalletIndex: string;
  registeredNightUtxos: number;
  unregisteredNightUtxos: number;
  estimatedGeneratedDustRaw: bigint;
  estimatedMaxDustRaw: bigint;
}

export interface WaitForSpendableDustOptions {
  minimumDustRaw?: bigint;
  timeoutMs?: number;
  pollMs?: number;
  onPoll?: (diagnostics: DustDiagnostics, remainingMs: number) => void;
}

function dustUtxoInput(
  coin: FacadeState['unshielded']['availableCoins'][number],
) {
  return {
    ...coin.utxo,
    ctime: coin.meta.ctime,
    registeredForDustGeneration: coin.meta.registeredForDustGeneration,
  };
}

export function formatDust(raw: bigint): string {
  const base = 10n ** 15n;
  const sign = raw < 0n ? '-' : '';
  const abs = raw < 0n ? -raw : raw;
  const whole = abs / base;
  const fractional = (abs % base).toString().padStart(15, '0').slice(0, 6);
  return `${sign}${whole}.${fractional}`;
}

export function inspectDustState(
  state: FacadeState,
  at: Date = new Date(),
): DustDiagnostics {
  const nightUtxos = state.unshielded.availableCoins.map(dustUtxoInput);
  const registeredNight = nightUtxos.filter((utxo) => utxo.registeredForDustGeneration);
  const estimated = state.dust.estimateDustGeneration(registeredNight, at);
  const estimatedGeneratedDustRaw = estimated.reduce(
    (sum, entry) => sum + entry.dust.generatedNow,
    0n,
  );
  const estimatedMaxDustRaw = estimated.reduce(
    (sum, entry) => sum + entry.dust.maxCap,
    0n,
  );

  return {
    spendableDustRaw: state.dust.balance(at),
    spendableDustCoins: state.dust.availableCoins.length,
    dustSyncConnected: state.dust.progress.isConnected,
    dustSyncAppliedIndex: String(state.dust.progress.appliedIndex),
    dustSyncHighestRelevantWalletIndex: String(state.dust.progress.highestRelevantWalletIndex),
    registeredNightUtxos: registeredNight.length,
    unregisteredNightUtxos: nightUtxos.length - registeredNight.length,
    estimatedGeneratedDustRaw,
    estimatedMaxDustRaw,
  };
}

export class BrowserPublicKeyWalletProvider implements WalletProvider {
  constructor(private readonly publicKeys: WalletPublicKeys) {}

  getCoinPublicKey(): CoinPublicKey {
    return this.publicKeys.coinPublicKey;
  }

  getEncryptionPublicKey(): EncPublicKey {
    return this.publicKeys.encryptionPublicKey;
  }

  async balanceTx(_tx: UnboundTransaction): Promise<FinalizedTransaction> {
    throw new Error('BrowserPublicKeyWalletProvider only exposes public keys for transaction preparation.');
  }
}

export class MidnightWalletProvider implements MidnightProvider, WalletProvider {
  readonly wallet: WalletFacade;

  private constructor(
    wallet: WalletFacade,
    private readonly zswapSecretKeys: ZswapSecretKeys,
    private readonly dustSecretKey: DustSecretKey,
    private readonly config: MidnightRuntimeConfig,
  ) {
    this.wallet = wallet;
  }

  getCoinPublicKey(): CoinPublicKey {
    return this.zswapSecretKeys.coinPublicKey;
  }

  getEncryptionPublicKey(): EncPublicKey {
    return this.zswapSecretKeys.encryptionPublicKey;
  }

  async balanceTx(tx: UnboundTransaction, ttl: Date = ttlOneHour()): Promise<FinalizedTransaction> {
    const recipe = await this.wallet.balanceUnboundTransaction(
      tx,
      {
        shieldedSecretKeys: this.zswapSecretKeys,
        dustSecretKey: this.dustSecretKey,
      },
      { ttl },
    );
    return this.wallet.finalizeRecipe(recipe);
  }

  async submitTx(tx: FinalizedTransaction): Promise<string> {
    return this.wallet.submitTransaction(tx);
  }

  async start(): Promise<void> {
    await this.wallet.start(this.zswapSecretKeys, this.dustSecretKey);
  }

  stop(): Promise<void> {
    return this.wallet.stop();
  }

  static async build(
    config: MidnightRuntimeConfig,
    seedOrMnemonic: { seed?: string; mnemonic?: string },
  ): Promise<MidnightWalletProvider> {
    const walletNetworkId = config.network === 'offline' ? 'preprod' : config.network;
    const seeds = seedOrMnemonic.seed
      ? WalletSeeds.fromMasterSeed(seedOrMnemonic.seed)
      : seedOrMnemonic.mnemonic
        ? WalletSeeds.fromMnemonic(seedOrMnemonic.mnemonic)
        : (() => { throw new Error('Either a Midnight operator seed or mnemonic is required.'); })();
    const walletConfig = {
      indexerClientConnection: {
        indexerHttpUrl: config.indexerUrl,
        indexerWsUrl: config.indexerWsUrl,
      },
      provingServerUrl: new URL(config.proofServerUrl),
      networkId: walletNetworkId,
      relayURL: new URL(config.rpcUrl.replace(/^http/, 'ws')),
      txHistoryStorage: new InMemoryTransactionHistoryStorage(),
      costParameters: {
        additionalFeeOverhead: MIDNIGHT_ADDITIONAL_FEE_OVERHEAD,
        feeBlocksMargin: MIDNIGHT_FEE_BLOCKS_MARGIN,
      },
    };
    const dustOptions = {
      ledgerParams: LedgerParameters.initialParameters(),
      additionalFeeOverhead: MIDNIGHT_ADDITIONAL_FEE_OVERHEAD,
      feeBlocksMargin: MIDNIGHT_FEE_BLOCKS_MARGIN,
    };
    const unshieldedKeystore = createKeystore(seeds.unshielded, walletNetworkId);
    const shieldedWallet = WalletFactory.createShieldedWallet(walletConfig as never, seeds.shielded);
    const unshieldedWallet = WalletFactory.createUnshieldedWallet(walletConfig as never, unshieldedKeystore);
    const dustWallet = WalletFactory.createDustWallet(walletConfig as never, seeds.dust, dustOptions);
    const wallet = (await WalletFactory.createWalletFacade(
      walletConfig as never,
      shieldedWallet,
      unshieldedWallet,
      dustWallet,
    )) as WalletFacade;

    return new MidnightWalletProvider(
      wallet,
      (await import('@midnight-ntwrk/ledger-v8')).ZswapSecretKeys.fromSeed(seeds.shielded) as ZswapSecretKeys,
      (await import('@midnight-ntwrk/ledger-v8')).DustSecretKey.fromSeed(seeds.dust) as DustSecretKey,
      config,
    );
  }
}

export async function waitForWalletSync(walletProvider: MidnightWalletProvider): Promise<FacadeState> {
  return Rx.firstValueFrom(
    walletProvider.wallet.state().pipe(
      Rx.filter((state) => {
        const progress = state.unshielded.progress;
        return progress.isConnected && progress.appliedId >= progress.highestTransactionId;
      }),
      Rx.timeout({ each: 600_000 }),
    ),
  );
}

export async function collectDustDiagnostics(
  walletProvider: MidnightWalletProvider,
  at: Date = new Date(),
): Promise<DustDiagnostics> {
  const state = await Rx.firstValueFrom(walletProvider.wallet.state());
  return inspectDustState(state, at);
}

export async function waitForSpendableDust(
  walletProvider: MidnightWalletProvider,
  options: WaitForSpendableDustOptions = {},
): Promise<DustDiagnostics> {
  const minimumDustRaw = options.minimumDustRaw ?? 1n;
  const timeoutMs = options.timeoutMs ?? 15 * 60_000;
  const pollMs = options.pollMs ?? 15_000;
  const deadline = Date.now() + timeoutMs;
  let latest = await collectDustDiagnostics(walletProvider);

  while (Date.now() <= deadline) {
    latest = await collectDustDiagnostics(walletProvider);
    if (latest.spendableDustRaw >= minimumDustRaw) {
      return latest;
    }
    options.onPoll?.(latest, Math.max(0, deadline - Date.now()));
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }

  const timeoutSeconds = Math.max(1, Math.round(timeoutMs / 1000));
  throw new Error(
    `Timed out waiting for spendable tDUST after ${timeoutSeconds}s. ` +
      `Spendable=${formatDust(latest.spendableDustRaw)} DUST across ${latest.spendableDustCoins} coin(s); ` +
      `registered NIGHT UTXOs=${latest.registeredNightUtxos}; ` +
      `estimated generated DUST=${formatDust(latest.estimatedGeneratedDustRaw)}.`,
  );
}

export function createPrepareProviders(
  config: MidnightRuntimeConfig,
  artifactDir: string,
  walletKeys: WalletPublicKeys,
) {
  const zkConfigProvider = new NodeZkConfigProvider<string>(artifactDir);
  return {
    publicDataProvider: indexerPublicDataProvider(config.indexerUrl, config.indexerWsUrl),
    zkConfigProvider,
    proofProvider: httpClientProofProvider(config.proofServerUrl, zkConfigProvider),
    walletProvider: new BrowserPublicKeyWalletProvider(walletKeys),
  };
}

export function createDeployProviders(
  config: MidnightRuntimeConfig,
  artifactDir: string,
  walletProvider: MidnightWalletProvider,
  storeName: string,
  provingMode: MidnightProvingMode = config.provingMode,
): MidnightProviders<string, PrivateStateId, undefined> {
  const zkConfigProvider = new NodeZkConfigProvider<string>(artifactDir);
  const accountId = Buffer.from(walletProvider.getCoinPublicKey()).toString('hex');
  const privateStatePassword =
    config.privateStatePassword ?? `ZirOS-trade-finance!2026-${accountId.slice(0, 16)}`;

  return {
    privateStateProvider: levelPrivateStateProvider<PrivateStateId, undefined>({
      privateStateStoreName: `${storeName}-private-state`,
      signingKeyStoreName: `${storeName}-signing-keys`,
      privateStoragePasswordProvider: () => privateStatePassword,
      accountId,
    }),
    publicDataProvider: indexerPublicDataProvider(config.indexerUrl, config.indexerWsUrl),
    zkConfigProvider,
    proofProvider:
      provingMode === 'wallet-proving-provider'
        ? createProofProvider(
            (walletProvider.wallet as any).provingService,
          )
        : httpClientProofProvider(config.proofServerUrl, zkConfigProvider),
    walletProvider,
    midnightProvider: walletProvider,
  };
}

export async function buildHeadlessWallet(
  config: MidnightRuntimeConfig,
): Promise<MidnightWalletProvider> {
  const resolved = await resolveOperatorWallet(config);
  if (!resolved) {
    throw new Error(
      'MIDNIGHT_WALLET_SEED, MIDNIGHT_WALLET_MNEMONIC, MIDNIGHT_WALLET_NAME, or a matching ~/.midnight active wallet for the selected network is required for CLI deployment and operator automation.',
    );
  }
  const walletProvider = await MidnightWalletProvider.build(config, {
    seed: resolved.seed,
    mnemonic: resolved.mnemonic,
  });
  await walletProvider.start();
  await waitForWalletSync(walletProvider);
  return walletProvider;
}
