/**
 * UCCR Showcase — Network Configuration
 *
 * Targets the Midnight Preview network by default.
 * Override via environment variables for local devnet or testnet.
 */

export interface NetworkConfig {
  name: string;
  networkId: string;
  node: string;
  indexer: string;
  indexerWS: string;
  proofServer: string;
}

const PREVIEW: NetworkConfig = {
  name: "preview",
  networkId: "preview",
  node: "https://rpc.preview.midnight.network",
  indexer: "https://indexer.preview.midnight.network/api/v3/graphql",
  indexerWS: "wss://indexer.preview.midnight.network/api/v3/graphql",
  proofServer: process.env.PROOF_SERVER_URL ?? "http://localhost:6300",
};

const DEVNET: NetworkConfig = {
  name: "devnet",
  networkId: "devnet",
  node: process.env.DEVNET_NODE_URL ?? "http://localhost:9944",
  indexer: process.env.DEVNET_INDEXER_URL ?? "http://localhost:8088/api/v3/graphql",
  indexerWS: process.env.DEVNET_INDEXER_WS ?? "ws://localhost:8088/api/v3/graphql",
  proofServer: process.env.PROOF_SERVER_URL ?? "http://localhost:6300",
};

export function loadConfig(): NetworkConfig {
  const network = (process.env.MIDNIGHT_NETWORK ?? "preview").toLowerCase();
  switch (network) {
    case "preview":
      return PREVIEW;
    case "devnet":
    case "undeployed":
      return DEVNET;
    default:
      throw new Error(
        `Unknown MIDNIGHT_NETWORK="${network}". Valid values: preview, devnet`
      );
  }
}
