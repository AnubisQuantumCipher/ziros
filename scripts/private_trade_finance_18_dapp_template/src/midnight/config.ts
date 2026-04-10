import { resolve } from 'node:path';

import { setNetworkId, type NetworkId } from '@midnight-ntwrk/midnight-js-network-id';

export type MidnightNetwork = 'preprod' | 'preview' | 'mainnet' | 'undeployed' | 'offline';
export type MidnightProvingMode = 'local-zkf-proof-server' | 'wallet-proving-provider';

export interface MidnightRuntimeConfig {
  network: MidnightNetwork;
  provingMode: MidnightProvingMode;
  proofServerUrl: string;
  gatewayUrl: string;
  rpcUrl: string;
  indexerUrl: string;
  indexerWsUrl: string;
  compactArtifactRoot: string;
  compactSourceRoot: string;
  packageManifestPath: string;
  flowManifestPath: string;
  deploymentManifestPath: string;
  callReceiptsPath: string;
  explorerUrl: string;
  operatorSeed?: string;
  operatorMnemonic?: string;
  privateStatePassword?: string;
}

const NETWORK_DEFAULTS: Record<Exclude<MidnightNetwork, 'offline'>, Omit<MidnightRuntimeConfig, 'provingMode' | 'operatorSeed' | 'operatorMnemonic' | 'privateStatePassword'>> = {
  preprod: {
    network: 'preprod',
    proofServerUrl: 'http://127.0.0.1:6300',
    gatewayUrl: 'http://127.0.0.1:6311',
    rpcUrl: 'https://rpc.preprod.midnight.network',
    indexerUrl: 'https://indexer.preprod.midnight.network/api/v4/graphql',
    indexerWsUrl: 'wss://indexer.preprod.midnight.network/api/v4/graphql/ws',
    compactArtifactRoot: './contracts/compiled',
    compactSourceRoot: './contracts/compact',
    packageManifestPath: './contracts/package_manifest.json',
    flowManifestPath: './contracts/flow_manifest.json',
    deploymentManifestPath: './data/deployment-manifest.json',
    callReceiptsPath: './data/call-receipts.json',
    explorerUrl: 'https://explorer.preprod.midnight.network',
  },
  preview: {
    network: 'preview',
    proofServerUrl: 'http://127.0.0.1:6300',
    gatewayUrl: 'http://127.0.0.1:6311',
    rpcUrl: 'https://rpc.preview.midnight.network',
    indexerUrl: 'https://indexer.preview.midnight.network/api/v4/graphql',
    indexerWsUrl: 'wss://indexer.preview.midnight.network/api/v4/graphql/ws',
    compactArtifactRoot: './contracts/compiled',
    compactSourceRoot: './contracts/compact',
    packageManifestPath: './contracts/package_manifest.json',
    flowManifestPath: './contracts/flow_manifest.json',
    deploymentManifestPath: './data/deployment-manifest.preview.json',
    callReceiptsPath: './data/call-receipts.preview.json',
    explorerUrl: 'https://explorer.preview.midnight.network',
  },
  mainnet: {
    network: 'mainnet',
    proofServerUrl: 'http://127.0.0.1:6300',
    gatewayUrl: 'http://127.0.0.1:6311',
    rpcUrl: 'https://rpc.midnight.network',
    indexerUrl: 'https://indexer.midnight.network/api/v3/graphql',
    indexerWsUrl: 'wss://indexer.midnight.network/api/v3/graphql/ws',
    compactArtifactRoot: './contracts/compiled',
    compactSourceRoot: './contracts/compact',
    packageManifestPath: './contracts/package_manifest.json',
    flowManifestPath: './contracts/flow_manifest.json',
    deploymentManifestPath: './data/deployment-manifest.mainnet.json',
    callReceiptsPath: './data/call-receipts.mainnet.json',
    explorerUrl: 'https://explorer.midnight.network',
  },
  undeployed: {
    network: 'undeployed',
    proofServerUrl: 'http://127.0.0.1:6300',
    gatewayUrl: 'http://127.0.0.1:6311',
    rpcUrl: 'http://127.0.0.1:9944',
    indexerUrl: 'http://127.0.0.1:8088/api/v3/graphql',
    indexerWsUrl: 'ws://127.0.0.1:8088/api/v3/graphql/ws',
    compactArtifactRoot: './contracts/compiled',
    compactSourceRoot: './contracts/compact',
    packageManifestPath: './contracts/package_manifest.json',
    flowManifestPath: './contracts/flow_manifest.json',
    deploymentManifestPath: './data/deployment-manifest.undeployed.json',
    callReceiptsPath: './data/call-receipts.undeployed.json',
    explorerUrl: 'http://127.0.0.1:8080',
  },
};

function normalizeNetwork(value: string | undefined): MidnightNetwork {
  if (!value) return 'preview';
  if (value === 'offline') return 'offline';
  if (value === 'preprod' || value === 'preview' || value === 'mainnet' || value === 'undeployed') return value;
  return 'preview';
}

function normalizeProvingMode(value: string | undefined): MidnightProvingMode {
  return value === 'wallet-proving-provider' ? 'wallet-proving-provider' : 'local-zkf-proof-server';
}

export function configureMidnightNetwork(network: MidnightNetwork): void {
  if (network === 'offline') return;
  setNetworkId(network as NetworkId);
}

export function getRuntimeConfig(overrides: Partial<MidnightRuntimeConfig> = {}): MidnightRuntimeConfig {
  const network = overrides.network ?? normalizeNetwork(process.env.MIDNIGHT_NETWORK);
  const defaults = network === 'offline' ? NETWORK_DEFAULTS.preview : NETWORK_DEFAULTS[network];
  const config: MidnightRuntimeConfig = {
    network,
    provingMode: overrides.provingMode ?? normalizeProvingMode(process.env.MIDNIGHT_PROVING_MODE),
    proofServerUrl: overrides.proofServerUrl ?? process.env.MIDNIGHT_PROOF_SERVER_URL ?? defaults.proofServerUrl,
    gatewayUrl: overrides.gatewayUrl ?? process.env.MIDNIGHT_GATEWAY_URL ?? defaults.gatewayUrl,
    rpcUrl: overrides.rpcUrl ?? process.env.MIDNIGHT_RPC_URL ?? defaults.rpcUrl,
    indexerUrl: overrides.indexerUrl ?? process.env.MIDNIGHT_INDEXER_URL ?? defaults.indexerUrl,
    indexerWsUrl: overrides.indexerWsUrl ?? process.env.MIDNIGHT_INDEXER_WS_URL ?? defaults.indexerWsUrl,
    compactArtifactRoot: overrides.compactArtifactRoot ?? process.env.MIDNIGHT_COMPACT_ARTIFACT_ROOT ?? defaults.compactArtifactRoot,
    compactSourceRoot: overrides.compactSourceRoot ?? process.env.MIDNIGHT_COMPACT_SOURCE_ROOT ?? defaults.compactSourceRoot,
    packageManifestPath: overrides.packageManifestPath ?? process.env.MIDNIGHT_PACKAGE_MANIFEST_PATH ?? defaults.packageManifestPath,
    flowManifestPath: overrides.flowManifestPath ?? process.env.MIDNIGHT_FLOW_MANIFEST_PATH ?? defaults.flowManifestPath,
    deploymentManifestPath: overrides.deploymentManifestPath ?? process.env.MIDNIGHT_DEPLOYMENT_MANIFEST_PATH ?? defaults.deploymentManifestPath,
    callReceiptsPath: overrides.callReceiptsPath ?? process.env.MIDNIGHT_CALL_RECEIPTS_PATH ?? defaults.callReceiptsPath,
    explorerUrl: overrides.explorerUrl ?? process.env.MIDNIGHT_EXPLORER_URL ?? defaults.explorerUrl,
    operatorSeed: overrides.operatorSeed ?? process.env.MIDNIGHT_WALLET_SEED,
    operatorMnemonic: overrides.operatorMnemonic ?? process.env.MIDNIGHT_WALLET_MNEMONIC,
    privateStatePassword: overrides.privateStatePassword ?? process.env.MIDNIGHT_PRIVATE_STATE_PASSWORD,
  };
  configureMidnightNetwork(config.network);
  return {
    ...config,
    compactArtifactRoot: resolve(config.compactArtifactRoot),
    compactSourceRoot: resolve(config.compactSourceRoot),
    packageManifestPath: resolve(config.packageManifestPath),
    flowManifestPath: resolve(config.flowManifestPath),
    deploymentManifestPath: resolve(config.deploymentManifestPath),
    callReceiptsPath: resolve(config.callReceiptsPath),
  };
}

export function explorerLink(baseUrl: string, txHash?: string, contractAddress?: string): string {
  if (txHash) return `${baseUrl}/transactions/${txHash}`;
  if (contractAddress) return `${baseUrl}/contracts/${contractAddress}`;
  return baseUrl;
}

function proofServerPort(proofServerUrl: string): string {
  try {
    const parsed = new URL(proofServerUrl);
    return parsed.port || '6300';
  } catch {
    return '6300';
  }
}

export function proofServerStartCommand(proofServerUrl: string): string {
  return `zkf midnight proof-server serve --port ${proofServerPort(proofServerUrl)}`;
}

export function proofServerUnavailableMessage(proofServerUrl: string): string {
  return (
    `Proof server unavailable at ${proofServerUrl}. ` +
    `Start your proof server: ${proofServerStartCommand(proofServerUrl)}. ` +
    'This operator surface expects the local ZirOS proof server lane.'
  );
}
