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
import { setNetworkId, type NetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import {
  MidnightBech32m,
  type ShieldedAddress,
  type UnshieldedAddress,
  type DustAddress,
} from '@midnight-ntwrk/wallet-sdk-address-format';
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
import {
  InMemoryTransactionHistoryStorage,
  createKeystore,
  type UnshieldedKeystore,
} from '@midnight-ntwrk/wallet-sdk-unshielded-wallet';
import * as Rx from 'rxjs';

// @ts-expect-error Midnight SDK expects a global WebSocket implementation in Node.
globalThis.WebSocket = WebSocket;

export type MidnightNetwork = 'preprod' | 'preview';
export type MidnightProvingMode = 'local-zkf-proof-server' | 'wallet-proving-provider';

export interface MidnightRuntimeConfig {
  network: MidnightNetwork;
  provingMode: MidnightProvingMode;
  proofServerUrl: string;
  rpcUrl: string;
  indexerUrl: string;
  indexerWsUrl: string;
  compactArtifactRoot: string;
  explorerUrl: string;
  operatorSeed?: string;
  operatorMnemonic?: string;
  privateStatePassword?: string;
}

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

const NETWORK_DEFAULTS: Record<MidnightNetwork, Omit<MidnightRuntimeConfig, 'provingMode'>> = {
  preprod: {
    network: 'preprod',
    proofServerUrl: 'http://127.0.0.1:6300',
    rpcUrl: 'https://rpc.preprod.midnight.network',
    indexerUrl: 'https://indexer.preprod.midnight.network/api/v4/graphql',
    indexerWsUrl: 'wss://indexer.preprod.midnight.network/api/v4/graphql/ws',
    compactArtifactRoot: './contracts/compiled',
    explorerUrl: 'https://explorer.preprod.midnight.network',
  },
  preview: {
    network: 'preview',
    proofServerUrl: 'http://127.0.0.1:6300',
    rpcUrl: 'https://rpc.preview.midnight.network',
    indexerUrl: 'https://indexer.preview.midnight.network/api/v4/graphql',
    indexerWsUrl: 'wss://indexer.preview.midnight.network/api/v4/graphql/ws',
    compactArtifactRoot: './contracts/compiled',
    explorerUrl: 'https://explorer.preview.midnight.network',
  },
};

function normalizeProvingMode(value: string | undefined): MidnightProvingMode {
  return value === 'wallet-proving-provider' ? 'wallet-proving-provider' : 'local-zkf-proof-server';
}

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

export function getRuntimeConfig(
  overrides: Partial<MidnightRuntimeConfig> = {},
): MidnightRuntimeConfig {
  const network = overrides.network ?? ((process.env.MIDNIGHT_NETWORK as MidnightNetwork | undefined) ?? 'preprod');
  const defaults = NETWORK_DEFAULTS[network];
  const config: MidnightRuntimeConfig = {
    network,
    provingMode: overrides.provingMode ?? normalizeProvingMode(process.env.MIDNIGHT_PROVING_MODE),
    proofServerUrl: overrides.proofServerUrl ?? process.env.MIDNIGHT_PROOF_SERVER_URL ?? defaults.proofServerUrl,
    rpcUrl: overrides.rpcUrl ?? process.env.MIDNIGHT_RPC_URL ?? defaults.rpcUrl,
    indexerUrl: overrides.indexerUrl ?? process.env.MIDNIGHT_INDEXER_URL ?? defaults.indexerUrl,
    indexerWsUrl: overrides.indexerWsUrl ?? process.env.MIDNIGHT_INDEXER_WS_URL ?? defaults.indexerWsUrl,
    compactArtifactRoot:
      overrides.compactArtifactRoot ??
      process.env.MIDNIGHT_COMPACT_ARTIFACT_ROOT ??
      defaults.compactArtifactRoot,
    explorerUrl: overrides.explorerUrl ?? process.env.MIDNIGHT_EXPLORER_URL ?? defaults.explorerUrl,
    operatorSeed: overrides.operatorSeed ?? process.env.MIDNIGHT_WALLET_SEED,
    operatorMnemonic: overrides.operatorMnemonic ?? process.env.MIDNIGHT_WALLET_MNEMONIC,
    privateStatePassword:
      overrides.privateStatePassword ?? process.env.MIDNIGHT_PRIVATE_STATE_PASSWORD,
  };

  setNetworkId(config.network as NetworkId);
  return {
    ...config,
    compactArtifactRoot: resolve(config.compactArtifactRoot),
  };
}

export function explorerLink(baseUrl: string, txHash?: string, contractAddress?: string): string {
  if (txHash) {
    return `${baseUrl}/transactions/${txHash}`;
  }
  if (contractAddress) {
    return `${baseUrl}/contracts/${contractAddress}`;
  }
  return baseUrl;
}

export function formatWalletAddress(address: UnshieldedAddress, network: MidnightNetwork): string;
export function formatWalletAddress(address: ShieldedAddress, network: MidnightNetwork): string;
export function formatWalletAddress(address: DustAddress, network: MidnightNetwork): string;
export function formatWalletAddress(
  address: UnshieldedAddress | ShieldedAddress | DustAddress,
  network: MidnightNetwork,
): string {
  return MidnightBech32m.encode(network, address as UnshieldedAddress).toString();
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
    const seeds = seedOrMnemonic.seed
      ? WalletSeeds.fromMasterSeed(seedOrMnemonic.seed)
      : seedOrMnemonic.mnemonic
        ? WalletSeeds.fromMnemonic(seedOrMnemonic.mnemonic)
        : (() => {
            throw new Error('MIDNIGHT_WALLET_SEED or MIDNIGHT_WALLET_MNEMONIC is required.');
          })();

    const walletConfig = {
      indexerClientConnection: {
        indexerHttpUrl: config.indexerUrl,
        indexerWsUrl: config.indexerWsUrl,
      },
      provingServerUrl: new URL(config.proofServerUrl),
      networkId: config.network,
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
    const unshieldedKeystore = createKeystore(seeds.unshielded, config.network);
    const shieldedWallet = WalletFactory.createShieldedWallet(walletConfig as never, seeds.shielded);
    const unshieldedWallet = WalletFactory.createUnshieldedWallet(
      walletConfig as never,
      unshieldedKeystore as UnshieldedKeystore,
    );
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
    config.privateStatePassword ?? `ZirOS-mailbox!2026-${accountId.slice(0, 16)}`;

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
  const registeredNight = state.unshielded.availableCoins.filter(
    (coin) => coin.meta.registeredForDustGeneration,
  );

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
