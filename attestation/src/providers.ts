import { Buffer } from 'node:buffer';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve } from 'node:path';

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
import { WalletFactory, WalletSeeds } from '@midnight-ntwrk/testkit-js';
import { type FacadeState, type WalletFacade } from '@midnight-ntwrk/wallet-sdk-facade';
import { InMemoryTransactionHistoryStorage, createKeystore } from '@midnight-ntwrk/wallet-sdk-unshielded-wallet';
import * as Rx from 'rxjs';

import type { MidnightProvingMode, MidnightRuntimeConfig } from './config.js';

// @ts-expect-error Midnight SDK expects a global WebSocket implementation in Node.
globalThis.WebSocket = WebSocket;

interface OperatorWalletProfile {
  seed?: string;
  mnemonic?: string;
}

const DEFAULT_OPERATOR_WALLET_FILES = [
  resolve(homedir(), '.midnight', 'wallets', 'ziros-lace-operator.json'),
  resolve(homedir(), '.midnight', 'wallets', 'ziros-preprod-operator.json'),
];

const MIDNIGHT_ADDITIONAL_FEE_OVERHEAD = 300_000_000_000_000n;
const MIDNIGHT_FEE_BLOCKS_MARGIN = 5;

async function readOperatorWalletProfile(pathname: string): Promise<OperatorWalletProfile | null> {
  try {
    const raw = await readFile(pathname, 'utf-8');
    const parsed = JSON.parse(raw) as OperatorWalletProfile;
    if (typeof parsed.mnemonic === 'string' && parsed.mnemonic.trim().length > 0) {
      return { mnemonic: parsed.mnemonic.trim() };
    }
    if (typeof parsed.seed === 'string' && parsed.seed.trim().length > 0) {
      return { seed: parsed.seed.trim() };
    }
    return null;
  } catch {
    return null;
  }
}

async function resolveOperatorWalletCredentials(
  config: MidnightRuntimeConfig,
): Promise<OperatorWalletProfile> {
  if (config.operatorSeed || config.operatorMnemonic) {
    return {
      seed: config.operatorSeed,
      mnemonic: config.operatorMnemonic,
    };
  }

  const candidates = [
    process.env.MIDNIGHT_OPERATOR_WALLET_FILE,
    ...DEFAULT_OPERATOR_WALLET_FILES,
  ].filter((value): value is string => typeof value === 'string' && value.length > 0);

  for (const pathname of candidates) {
    const profile = await readOperatorWalletProfile(pathname);
    if (profile?.seed || profile?.mnemonic) {
      return profile;
    }
  }

  return {};
}

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
    const walletNetworkId = config.network === 'offline' ? 'preprod' : config.network;
    const nodeWsUrl = config.rpcUrl.replace(/^http/, 'ws');
    const seeds = seedOrMnemonic.seed
      ? WalletSeeds.fromMasterSeed(seedOrMnemonic.seed)
      : seedOrMnemonic.mnemonic
        ? WalletSeeds.fromMnemonic(seedOrMnemonic.mnemonic)
        : (() => {
            throw new Error('Either MIDNIGHT_WALLET_SEED or MIDNIGHT_WALLET_MNEMONIC is required.');
          })();

    const walletConfig = {
      indexerClientConnection: {
        indexerHttpUrl: config.indexerUrl,
        indexerWsUrl: config.indexerWsUrl,
      },
      provingServerUrl: new URL(config.proofServerUrl),
      networkId: walletNetworkId,
      relayURL: new URL(nodeWsUrl),
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
  const credentials = await resolveOperatorWalletCredentials(config);
  if (!credentials.seed && !credentials.mnemonic) {
    throw new Error(
      'MIDNIGHT_WALLET_SEED or MIDNIGHT_WALLET_MNEMONIC is required for deployment and submission. ' +
        `Also checked ${DEFAULT_OPERATOR_WALLET_FILES.join(', ')}.`,
    );
  }

  const walletProvider = await MidnightWalletProvider.build(config, credentials);
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

export async function waitForSpendableDust(
  walletProvider: MidnightWalletProvider,
  options: {
    minimumDustRaw?: bigint;
    timeoutMs?: number;
    pollMs?: number;
  } = {},
): Promise<{
  spendableDustRaw: bigint;
  spendableDustCoins: number;
  dustSyncConnected: boolean;
  registeredNightUtxos: number;
}> {
  const minimumDustRaw = options.minimumDustRaw ?? 1n;
  const timeoutMs = options.timeoutMs ?? 5 * 60_000;
  const pollMs = options.pollMs ?? 5_000;
  const deadline = Date.now() + timeoutMs;
  let latest = await collectDustDiagnostics(walletProvider);

  while (Date.now() <= deadline) {
    latest = await collectDustDiagnostics(walletProvider);
    if (latest.spendableDustRaw >= minimumDustRaw) {
      return latest;
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }

  throw new Error(
    `Timed out waiting for spendable tDUST. ` +
      `Spendable=${formatDust(latest.spendableDustRaw)} across ${latest.spendableDustCoins} coin(s); ` +
      `registered NIGHT UTXOs=${latest.registeredNightUtxos}; dust sync connected=${latest.dustSyncConnected}.`,
  );
}
