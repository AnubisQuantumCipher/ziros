/**
 * UCCR Showcase — Deploy All Three Compliance Contracts
 *
 * Deploys the finance solvency, clinical trial eligibility, and
 * engineering safety contracts to the Midnight Network in sequence.
 *
 * Usage:
 *   MIDNIGHT_NETWORK=preview WALLET_SEED=<64hex> npm run deploy:all
 *
 * Or with a seed file:
 *   MIDNIGHT_NETWORK=preview WALLET_SEED_FILE=.wallet-seed npm run deploy:all
 */

import { submitDeployTx } from "@midnight-ntwrk/midnight-js-contracts";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { loadConfig } from "./config.js";
import { buildProviders, waitForFunds } from "./wallet.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONTRACTS_DIR = path.resolve(__dirname, "../contracts");

interface DeploymentRecord {
  contractName: string;
  contractAddress: string;
  txId: string;
  deployedAt: string;
  network: string;
}

function readSeed(): string {
  const envSeed = process.env.WALLET_SEED;
  if (envSeed) {
    if (!/^[0-9a-fA-F]{64}$/.test(envSeed.trim())) {
      throw new Error("WALLET_SEED must be exactly 64 hex characters.");
    }
    return envSeed.trim();
  }
  const seedFile = process.env.WALLET_SEED_FILE ?? path.join(process.cwd(), ".wallet-seed");
  if (!fs.existsSync(seedFile)) {
    throw new Error(
      `No wallet seed found. Set WALLET_SEED env var or create ${seedFile}.`
    );
  }
  const seed = fs.readFileSync(seedFile, "utf8").trim();
  if (!/^[0-9a-fA-F]{64}$/.test(seed)) {
    throw new Error(`Invalid seed in ${seedFile}. Must be 64 hex characters.`);
  }
  return seed;
}

async function deployContract(
  providers: any,
  contractName: string,
  contractFile: string,
  cfg: ReturnType<typeof loadConfig>
): Promise<DeploymentRecord> {
  console.log(`\n[${contractName}] Loading compiled contract...`);
  const contractPath = path.join(CONTRACTS_DIR, contractFile);
  if (!fs.existsSync(contractPath)) {
    throw new Error(
      `Contract artifact not found at ${contractPath}. ` +
      `Run: cd .. && ./target-local/release/zkf-cli compile --spec uccr-showcase/circuits/${contractName.replace(/_/g, "_")}.zirapp.json --backend midnight-compact --out uccr-showcase/contracts/${contractFile}`
    );
  }

  const contractArtifact = JSON.parse(fs.readFileSync(contractPath, "utf8"));
  const compactSource: string = contractArtifact.metadata?.compact_source;
  if (!compactSource) {
    throw new Error(`No compact_source in ${contractFile}. Recompile with zkf-cli.`);
  }

  console.log(`[${contractName}] Deploying to ${cfg.name}...`);

  // The compiled compact source is embedded in the ZirOS artifact.
  // We pass it directly to the Midnight JS SDK as a pre-compiled contract.
  const deployResult = await submitDeployTx(
    {
      walletProvider: providers.walletProvider,
      midnightProvider: providers.midnightProvider,
      publicDataProvider: providers.publicDataProvider,
      privateStateProvider: providers.privateStateProvider,
      proofProvider: providers.proofProvider,
      zkConfigProvider: providers.zkConfigProvider,
    },
    {
      // The contract object wraps the ZirOS-generated Compact source.
      // In a full Compact toolchain flow, this would be the compiled .js module.
      // Here we use the compact_source directly as the contract definition.
      contract: {
        name: contractArtifact.program?.name ?? contractName,
        compactSource,
        initialState: {},
      },
    }
  );

  const record: DeploymentRecord = {
    contractName,
    contractAddress: deployResult.deployedContractAddress,
    txId: deployResult.txId,
    deployedAt: new Date().toISOString(),
    network: cfg.name,
  };

  console.log(`[${contractName}] ✓ Deployed!`);
  console.log(`  Contract address: ${record.contractAddress}`);
  console.log(`  Transaction ID:   ${record.txId}`);

  return record;
}

async function main() {
  console.log("=== UCCR Showcase — Deploy All Contracts ===\n");

  const cfg = loadConfig();
  console.log(`Network: ${cfg.name} (${cfg.node})`);
  console.log(`Proof Server: ${cfg.proofServer}\n`);

  const seed = readSeed();
  console.log("Building wallet and providers...");
  const providers = await buildProviders(seed, cfg, "uccr-deploy-db");

  console.log("Waiting for wallet sync and NIGHT balance...");
  const balance = await waitForFunds(providers.wallet);
  console.log(`Wallet funded: ${balance} NIGHT\n`);

  const deployments: DeploymentRecord[] = [];

  // Deploy Finance Solvency
  deployments.push(await deployContract(
    providers,
    "uccr_finance_solvency",
    "finance_solvency_generated.compact",
    cfg
  ));

  // Deploy Clinical Trial Eligibility
  deployments.push(await deployContract(
    providers,
    "uccr_clinical_trial_eligibility",
    "clinical_trial_eligibility_generated.compact",
    cfg
  ));

  // Deploy Engineering Safety
  deployments.push(await deployContract(
    providers,
    "uccr_engineering_safety",
    "engineering_safety_generated.compact",
    cfg
  ));

  // Write deployment manifest
  const manifestPath = path.join(process.cwd(), "uccr-deployment.json");
  fs.writeFileSync(manifestPath, JSON.stringify(deployments, null, 2));
  console.log(`\n=== All contracts deployed ===`);
  console.log(`Deployment manifest written to: ${manifestPath}`);
  console.log("\nDeployment summary:");
  for (const d of deployments) {
    console.log(`  ${d.contractName}: ${d.contractAddress}`);
  }

  providers.wallet.close();
  process.exit(0);
}

main().catch((err) => {
  console.error("Deployment failed:", err);
  process.exit(1);
});
