/**
 * UCCR Showcase — Wallet & Provider Setup
 *
 * Builds a Midnight wallet from a 64-hex-char seed and constructs
 * the full MidnightProviders bundle required by submitDeployTx / submitCallTx.
 */

import { WalletBuilder } from "@midnight-ntwrk/wallet";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { levelPrivateStateProvider } from "@midnight-ntwrk/midnight-js-level-private-state-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import * as Rx from "rxjs";
import { nativeToken } from "@midnight-ntwrk/ledger";
import type { NetworkConfig } from "./config.js";

export interface UCCRProviders {
  wallet: any;
  walletProvider: any;
  midnightProvider: any;
  publicDataProvider: any;
  privateStateProvider: any;
  proofProvider: any;
  zkConfigProvider: any;
}

/**
 * Wait until the wallet has synced and holds a positive NIGHT balance.
 */
export async function waitForFunds(wallet: any): Promise<bigint> {
  return Rx.firstValueFrom(
    wallet.state().pipe(
      Rx.filter((s: any) => s.syncProgress?.synced === true),
      Rx.map((s: any) => s.balances[nativeToken()] ?? 0n),
      Rx.filter((balance: bigint) => balance > 0n)
    )
  );
}

/**
 * Build the full providers bundle from a wallet seed.
 *
 * @param seed        64-character hex wallet seed
 * @param cfg         Network configuration
 * @param dbName      LevelDB database name for private state
 */
export async function buildProviders(
  seed: string,
  cfg: NetworkConfig,
  dbName = "uccr-showcase-db"
): Promise<UCCRProviders> {
  setNetworkId(cfg.networkId as any);

  const wallet = await WalletBuilder.buildFromSeed(
    cfg.indexer,
    cfg.indexerWS,
    cfg.proofServer,
    cfg.node,
    seed,
    cfg.networkId as any,
    "info"
  );

  const walletProvider = await wallet.walletProvider();
  const midnightProvider = await wallet.midnightProvider();

  const publicDataProvider = indexerPublicDataProvider(
    cfg.indexer,
    cfg.indexerWS
  );

  const privateStateProv = levelPrivateStateProvider({
    midnightDbName: dbName,
    privateStateStoreName: "private-states",
    signingKeyStoreName: "signing-keys",
    walletProvider,
  });

  const proofProv = httpClientProofProvider(cfg.proofServer);

  const zkConfigProv = new NodeZkConfigProvider(cfg.proofServer);

  return {
    wallet,
    walletProvider,
    midnightProvider,
    publicDataProvider,
    privateStateProvider: privateStateProv,
    proofProvider: proofProv,
    zkConfigProvider: zkConfigProv,
  };
}
