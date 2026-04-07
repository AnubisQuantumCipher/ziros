import { setNetworkId, type NetworkId } from '@midnight-ntwrk/midnight-js-network-id';

import type { ProveRoute, WalletHelperConfig, WalletHelperNetwork } from './types.js';

const DEFAULTS: Record<WalletHelperNetwork, WalletHelperConfig> = {
  preprod: {
    network: 'preprod',
    rpcUrl: 'https://rpc.preprod.midnight.network',
    indexerUrl: 'https://indexer.preprod.midnight.network/api/v4/graphql',
    indexerWsUrl: 'wss://indexer.preprod.midnight.network/api/v4/graphql/ws',
    explorerUrl: 'https://explorer.preprod.midnight.network',
    proofServerUrl: 'http://127.0.0.1:6300',
    gatewayUrl: 'http://127.0.0.1:6311',
    proveRoutes: [
      {
        label: 'Local Midnight prover',
        kind: 'local',
        proofServerUrl: 'http://127.0.0.1:6300',
        gatewayUrl: 'http://127.0.0.1:6311',
        priority: 0,
      },
    ],
  },
  preview: {
    network: 'preview',
    rpcUrl: 'https://rpc.preview.midnight.network',
    indexerUrl: 'https://indexer.preview.midnight.network/api/v4/graphql',
    indexerWsUrl: 'wss://indexer.preview.midnight.network/api/v4/graphql/ws',
    explorerUrl: 'https://explorer.preview.midnight.network',
    proofServerUrl: 'http://127.0.0.1:6300',
    gatewayUrl: 'http://127.0.0.1:6311',
    proveRoutes: [
      {
        label: 'Local Midnight prover',
        kind: 'local',
        proofServerUrl: 'http://127.0.0.1:6300',
        gatewayUrl: 'http://127.0.0.1:6311',
        priority: 0,
      },
    ],
  },
};

export function normalizeProveRoutes(
  network: WalletHelperNetwork,
  primaryProofServerUrl: string,
  gatewayUrl: string,
  routes?: ProveRoute[],
): ProveRoute[] {
  const configured = routes && routes.length > 0 ? routes : DEFAULTS[network].proveRoutes;
  const deduped = new Map<string, ProveRoute>();

  for (const route of configured) {
    deduped.set(route.proofServerUrl, {
      ...route,
      gatewayUrl: route.gatewayUrl ?? gatewayUrl,
    });
  }

  if (!deduped.has(primaryProofServerUrl)) {
    deduped.set(primaryProofServerUrl, {
      label: primaryProofServerUrl.startsWith('http://127.0.0.1')
        ? 'Local Midnight prover'
        : 'Configured Midnight prover',
      kind: primaryProofServerUrl.startsWith('http://127.0.0.1') ? 'local' : 'custom',
      proofServerUrl: primaryProofServerUrl,
      gatewayUrl,
      priority: -1,
    });
  }

  return [...deduped.values()].sort((left, right) => {
    if (left.priority !== right.priority) {
      return left.priority - right.priority;
    }
    return left.label.localeCompare(right.label);
  });
}

export function resolveWalletHelperConfig(
  network: WalletHelperNetwork,
  overrides: Partial<WalletHelperConfig> = {},
): WalletHelperConfig {
  const base = DEFAULTS[network];
  const proofServerUrl = overrides.proofServerUrl ?? base.proofServerUrl;
  const gatewayUrl = overrides.gatewayUrl ?? base.gatewayUrl;
  const proveRoutes = normalizeProveRoutes(
    network,
    proofServerUrl,
    gatewayUrl,
    overrides.proveRoutes,
  );
  const config = {
    ...base,
    ...overrides,
    network,
    proofServerUrl: proveRoutes[0]?.proofServerUrl ?? proofServerUrl,
    gatewayUrl,
    proveRoutes,
  };
  setNetworkId(config.network as NetworkId);
  return config;
}

export function toWalletConfiguration(config: WalletHelperConfig) {
  return {
    indexerUri: config.indexerUrl,
    indexerWsUri: config.indexerWsUrl,
    proverServerUri: config.proofServerUrl,
    substrateNodeUri: config.rpcUrl,
    networkId: config.network,
    gatewayUrl: config.gatewayUrl,
    mailboxContractAddress: config.mailboxContractAddress,
    mailboxManifestPath: config.mailboxManifestPath,
    proveRoutes: config.proveRoutes,
  };
}
