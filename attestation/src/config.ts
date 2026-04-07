import { resolve } from 'node:path';

import { setNetworkId, type NetworkId } from '@midnight-ntwrk/midnight-js-network-id';

export type MidnightNetwork = 'preprod' | 'preview' | 'mainnet' | 'undeployed' | 'offline';
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
  manifestPath: string;
}

const NETWORK_DEFAULTS: Record<
  Exclude<MidnightNetwork, 'offline'>,
  Omit<
    MidnightRuntimeConfig,
    'provingMode' | 'operatorSeed' | 'operatorMnemonic' | 'privateStatePassword' | 'manifestPath'
  >
> = {
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
  mainnet: {
    network: 'mainnet',
    proofServerUrl: 'http://127.0.0.1:6300',
    rpcUrl: 'https://rpc.midnight.network',
    indexerUrl: 'https://indexer.midnight.network/api/v3/graphql',
    indexerWsUrl: 'wss://indexer.midnight.network/api/v3/graphql/ws',
    compactArtifactRoot: './contracts/compiled',
    explorerUrl: 'https://explorer.midnight.network',
  },
  undeployed: {
    network: 'undeployed',
    proofServerUrl: 'http://127.0.0.1:6300',
    rpcUrl: 'http://127.0.0.1:9944',
    indexerUrl: 'http://127.0.0.1:8088/api/v3/graphql',
    indexerWsUrl: 'ws://127.0.0.1:8088/api/v3/graphql/ws',
    compactArtifactRoot: './contracts/compiled',
    explorerUrl: 'http://127.0.0.1:8080',
  },
};

function normalizeNetwork(value: string | undefined): MidnightNetwork {
  if (!value) {
    return 'preprod';
  }
  if (value === 'offline') {
    return 'offline';
  }
  if (value === 'preprod' || value === 'preview' || value === 'mainnet' || value === 'undeployed') {
    return value;
  }
  return 'preprod';
}

function normalizeProvingMode(value: string | undefined): MidnightProvingMode {
  return value === 'wallet-proving-provider' ? 'wallet-proving-provider' : 'local-zkf-proof-server';
}

export function configureMidnightNetwork(network: MidnightNetwork): void {
  if (network === 'offline') {
    return;
  }
  setNetworkId(network as NetworkId);
}

export function getRuntimeConfig(
  overrides: Partial<MidnightRuntimeConfig> = {},
): MidnightRuntimeConfig {
  const network = overrides.network ?? normalizeNetwork(process.env.MIDNIGHT_NETWORK);
  const defaults = network === 'offline' ? NETWORK_DEFAULTS.preprod : NETWORK_DEFAULTS[network];
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
    manifestPath:
      overrides.manifestPath ??
      process.env.ATTESTATION_MANIFEST_PATH ??
      './data/deployment-manifest.json',
  };

  configureMidnightNetwork(config.network);
  return {
    ...config,
    compactArtifactRoot: resolve(config.compactArtifactRoot),
    manifestPath: resolve(config.manifestPath),
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

export function networkLabel(network: MidnightNetwork): string {
  switch (network) {
    case 'preprod':
      return 'Midnight Preprod';
    case 'preview':
      return 'Midnight Preview';
    case 'mainnet':
      return 'Midnight Mainnet';
    case 'undeployed':
      return 'Midnight Undeployed';
    case 'offline':
      return 'Midnight Offline';
  }
}

export function proofServerUnavailableMessage(proofServerUrl: string): string {
  return (
    `Proof server unavailable at ${proofServerUrl}. ` +
    'Start your proof server with `zkf midnight proof-server serve --port 6300 --engine umpg`.'
  );
}
