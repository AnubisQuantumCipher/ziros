/**
 * UCCR Showcase — Wallet Setup
 *
 * Generates a fresh 64-hex wallet seed and writes it to .wallet-seed.
 * Prints the wallet's shielded address for funding via the Preview faucet.
 *
 * Usage:
 *   MIDNIGHT_NETWORK=preview npm run wallet:setup
 */

import { WalletBuilder } from "@midnight-ntwrk/wallet";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as Rx from "rxjs";
import { loadConfig } from "./config.js";

async function main() {
  const cfg = loadConfig();
  const seedFile = path.join(process.cwd(), ".wallet-seed");

  if (fs.existsSync(seedFile)) {
    console.log(`Wallet seed already exists at ${seedFile}.`);
    console.log("Delete it first if you want to generate a new wallet.");
    process.exit(0);
  }

  const seed = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(seedFile, seed + "\n", { mode: 0o600 });
  console.log(`New wallet seed written to ${seedFile} (chmod 600).`);
  console.log("IMPORTANT: Back this file up securely. It cannot be recovered.\n");

  setNetworkId(cfg.networkId as any);

  console.log("Building wallet...");
  const wallet = await WalletBuilder.buildFromSeed(
    cfg.indexer,
    cfg.indexerWS,
    cfg.proofServer,
    cfg.node,
    seed,
    cfg.networkId as any,
    "info"
  );

  // Wait for initial sync
  const state = await Rx.firstValueFrom(
    wallet.state().pipe(
      Rx.filter((s: any) => s.syncProgress?.synced === true || s.addresses?.shielded)
    )
  );

  const shieldedAddress = state.addresses?.shielded ?? "(syncing — run again after sync)";
  const unshieldedAddress = state.addresses?.unshielded ?? "(syncing)";
  const dustAddress = state.addresses?.dust ?? "(syncing)";

  console.log("\n=== Wallet Ready ===");
  console.log(`Network:            ${cfg.name}`);
  console.log(`Shielded address:   ${shieldedAddress}`);
  console.log(`Unshielded address: ${unshieldedAddress}`);
  console.log(`DUST address:       ${dustAddress}`);
  console.log(`\nFund this wallet at: https://faucet.preview.midnight.network`);
  console.log("Use the shielded address for NIGHT tokens.");
  console.log("\nAfter funding, delegate DUST production via the Midnight Lace Preview wallet.");
  console.log("Then run: npm run deploy:all");

  wallet.close();
  process.exit(0);
}

main().catch((err) => {
  console.error("Wallet setup failed:", err);
  process.exit(1);
});
