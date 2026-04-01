import { Buffer } from 'node:buffer';

import { WebSocket } from 'ws';
import {
  type CoinPublicKey,
  type DustSecretKey,
  type EncPublicKey,
  LedgerParameters,
  type FinalizedTransaction,
  type ZswapSecretKeys,
} from '@midnight-ntwrk/ledger-v8';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import {
  createProofProvider,
  type MidnightProvider,
  type MidnightProviders,
  type PrivateStateId,
  type UnboundTransaction,
  type WalletProvider,
} from '@midnight-ntwrk/midnight-js-types';
import { ttlOneHour } from '@midnight-ntwrk/midnight-js-utils';
import { type EnvironmentConfiguration, FluentWalletBuilder } from '@midnight-ntwrk/testkit-js';
import { type FacadeState, type WalletFacade } from '@midnight-ntwrk/wallet-sdk-facade';
import * as Rx from 'rxjs';

import type { MidnightProvingMode, MidnightRuntimeConfig } from './config.js';

// @ts-expect-error Midnight SDK expects a global WebSocket implementation in Node.
globalThis.WebSocket = WebSocket;

export class BrowserPublicKeyWalletProvider implements WalletProvider {
  constructor(
    private readonly publicKeys: {
      coinPublicKey: CoinPublicKey;
      encryptionPublicKey: EncPublicKey;
    },
  ) {}

  getCoinPublicKey(): CoinPublicKey {
    return this.publicKeys.coinPublicKey;
  }

  getEncryptionPublicKey(): EncPublicKey {
    return this.publicKeys.encryptionPublicKey;
  }

  async balanceTx(_tx: UnboundTransaction): Promise<FinalizedTransaction> {
    throw new Error('BrowserPublicKeyWalletProvider does not support balancing.');
  }
}

export class MidnightWalletProvider implements MidnightProvider, WalletProvider {
  readonly wallet: WalletFacade;

  private constructor(
    wallet: WalletFacade,
    private readonly zswapSecretKeys: ZswapSecretKeys,
    private readonly dustSecretKey: DustSecretKey,
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

  submitTx(tx: FinalizedTransaction): Promise<string> {
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
    const env: EnvironmentConfiguration = {
      walletNetworkId: config.network === 'offline' ? 'preprod' : config.network,
      networkId: config.network === 'offline' ? 'preprod' : config.network,
      indexer: config.indexerUrl,
      indexerWS: config.indexerWsUrl,
      node: config.rpcUrl,
      nodeWS: config.rpcUrl.replace(/^http/, 'ws'),
      faucet: '',
      proofServer: config.proofServerUrl,
    };

    const dustOptions = {
      ledgerParams: LedgerParameters.initialParameters(),
      additionalFeeOverhead: 1_000n,
      feeBlocksMargin: 5,
    };

    const builder = FluentWalletBuilder.forEnvironment(env).withDustOptions(dustOptions);
    const configuredBuilder = seedOrMnemonic.seed
      ? builder.withSeed(seedOrMnemonic.seed)
      : seedOrMnemonic.mnemonic
        ? builder.withMnemonic(seedOrMnemonic.mnemonic)
        : (() => {
            throw new Error('Either MIDNIGHT_WALLET_SEED or MIDNIGHT_WALLET_MNEMONIC is required.');
          })();
    const buildResult = await configuredBuilder.buildWithoutStarting();
    const { wallet, seeds } = buildResult as {
      wallet: WalletFacade;
      seeds: {
        shielded: Uint8Array;
        dust: Uint8Array;
      };
    };

    const { DustSecretKey, ZswapSecretKeys } = await import('@midnight-ntwrk/ledger-v8');
    return new MidnightWalletProvider(
      wallet,
      ZswapSecretKeys.fromSeed(seeds.shielded) as unknown as ZswapSecretKeys,
      DustSecretKey.fromSeed(seeds.dust) as unknown as DustSecretKey,
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

export async function buildHeadlessWallet(
  config: MidnightRuntimeConfig,
): Promise<MidnightWalletProvider> {
  if (!config.operatorSeed && !config.operatorMnemonic) {
    throw new Error(
      'MIDNIGHT_WALLET_SEED or MIDNIGHT_WALLET_MNEMONIC is required for deployment and submission.',
    );
  }

  const walletProvider = await MidnightWalletProvider.build(config, {
    seed: config.operatorSeed,
    mnemonic: config.operatorMnemonic,
  });
  await walletProvider.start();
  await waitForWalletSync(walletProvider);
  return walletProvider;
}

export function createPrepareProviders(
  config: MidnightRuntimeConfig,
  artifactDir: string,
  walletKeys: {
    coinPublicKey: CoinPublicKey;
    encryptionPublicKey: EncPublicKey;
  },
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
    config.privateStatePassword ?? `ZirOS-attestation!2026-${accountId.slice(0, 16)}`;

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
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (walletProvider.wallet as any).provingService,
          )
        : httpClientProofProvider(config.proofServerUrl, zkConfigProvider),
    walletProvider,
    midnightProvider: walletProvider,
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

export async function collectDustDiagnostics(
  walletProvider: MidnightWalletProvider,
  at: Date = new Date(),
): Promise<{
  spendableDustRaw: bigint;
  spendableDustCoins: number;
  dustSyncConnected: boolean;
  registeredNightUtxos: number;
}> {
  const state = await Rx.firstValueFrom(walletProvider.wallet.state());
  const nightUtxos = state.unshielded.availableCoins.map((coin) => ({
    ...coin.utxo,
    ctime: coin.meta.ctime,
    registeredForDustGeneration: coin.meta.registeredForDustGeneration,
  }));
  const registeredNight = nightUtxos.filter((utxo) => utxo.registeredForDustGeneration);

  return {
    spendableDustRaw: state.dust.balance(at),
    spendableDustCoins: state.dust.availableCoins.length,
    dustSyncConnected: state.dust.progress.isConnected,
    registeredNightUtxos: registeredNight.length,
  };
}
