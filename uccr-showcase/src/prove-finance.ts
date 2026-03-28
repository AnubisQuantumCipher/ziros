/**
 * UCCR Showcase — Finance Solvency: End-to-End Proof Demo
 *
 * This script demonstrates the full ZirOS → Midnight proof pipeline:
 *
 *   1. Load the finance_solvency zirapp.json circuit definition
 *   2. Use ZirOS CLI to generate a witness from private inputs
 *   3. Use ZirOS CLI to generate a ZK proof via the midnight-compact backend
 *   4. Verify the proof locally
 *   5. Submit the public commitment to the deployed Midnight contract
 *
 * The prover never reveals total_assets or total_liabilities.
 * The verifier only sees the SHA-256 commitment and the proof.
 *
 * Usage:
 *   MIDNIGHT_NETWORK=preview \
 *   WALLET_SEED=<64hex> \
 *   CONTRACT_ADDRESS=<address> \
 *   TOTAL_ASSETS=125000000 \
 *   TOTAL_LIABILITIES=100000000 \
 *   BLINDING=<random_u32> \
 *   npm run prove:finance
 */

import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";
import { submitCallTx } from "@midnight-ntwrk/midnight-js-contracts";
import { loadConfig } from "./config.js";
import { buildProviders, waitForFunds } from "./wallet.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ZIROS_CLI = path.resolve(__dirname, "../../target-local/release/zkf-cli");
const CIRCUITS_DIR = path.resolve(__dirname, "../circuits");
const CONTRACTS_DIR = path.resolve(__dirname, "../contracts");

interface FinanceSolvencyInputs {
  total_assets_scaled: string;
  total_liabilities_scaled: string;
  blinding: string;
}

interface ProofResult {
  commitment_hi: string;
  commitment_lo: string;
  proofPath: string;
  proofSizeBytes: number;
  proveTimeMs: number;
}

function readSeed(): string {
  const envSeed = process.env.WALLET_SEED;
  if (envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed.trim())) return envSeed.trim();
  const seedFile = process.env.WALLET_SEED_FILE ?? path.join(process.cwd(), ".wallet-seed");
  if (!fs.existsSync(seedFile)) throw new Error(`No wallet seed. Set WALLET_SEED or create ${seedFile}.`);
  return fs.readFileSync(seedFile, "utf8").trim();
}

function generateBlinding(): string {
  // Generate a random 32-bit blinding factor
  return String(Math.floor(Math.random() * 0xFFFFFFFF));
}

async function generateProof(inputs: FinanceSolvencyInputs): Promise<ProofResult> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "uccr-finance-"));
  const inputsPath = path.join(tmpDir, "inputs.json");
  const proofPath = path.join(tmpDir, "proof.json");
  const specPath = path.join(CIRCUITS_DIR, "finance_solvency.zirapp.json");

  // Write inputs file
  fs.writeFileSync(inputsPath, JSON.stringify(inputs, null, 2));

  console.log("\n[ZirOS] Generating witness and proof...");
  console.log(`  Spec:    ${specPath}`);
  console.log(`  Backend: midnight-compact (Halo2 delegate, pasta-fp field)`);
  console.log(`  Inputs:  total_assets=${inputs.total_assets_scaled}, liabilities=${inputs.total_liabilities_scaled}`);
  console.log(`  Blinding: ${inputs.blinding} (never revealed)`);

  const t0 = Date.now();

  // Use ZirOS CLI to prove: compile + witness + prove in one step
  const proveOutput = execFileSync(
    ZIROS_CLI,
    [
      "prove",
      "--spec", specPath,
      "--backend", "midnight-compact",
      "--inputs", inputsPath,
      "--out", proofPath,
      "--allow-compat",
    ],
    { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }
  );

  const proveTimeMs = Date.now() - t0;
  console.log(`[ZirOS] Proof generated in ${proveTimeMs}ms`);

  // Parse the proof artifact to extract public outputs
  const proofArtifact = JSON.parse(fs.readFileSync(proofPath, "utf8"));
  const publicOutputs = proofArtifact.public_outputs ?? {};

  const commitment_hi = publicOutputs.commitment_hi ?? publicOutputs["commitment_hi"];
  const commitment_lo = publicOutputs.commitment_lo ?? publicOutputs["commitment_lo"];

  if (!commitment_hi || !commitment_lo) {
    throw new Error(
      `Proof artifact missing public outputs. Got: ${JSON.stringify(publicOutputs)}`
    );
  }

  const proofSizeBytes = fs.statSync(proofPath).size;
  console.log(`[ZirOS] Proof size: ${proofSizeBytes} bytes`);
  console.log(`[ZirOS] Public commitment_hi: ${commitment_hi}`);
  console.log(`[ZirOS] Public commitment_lo: ${commitment_lo}`);

  // Verify locally before submitting on-chain
  console.log("\n[ZirOS] Verifying proof locally...");
  execFileSync(
    ZIROS_CLI,
    ["verify", "--proof", proofPath, "--spec", specPath, "--backend", "midnight-compact", "--allow-compat"],
    { encoding: "utf8" }
  );
  console.log("[ZirOS] ✓ Local verification passed");

  return { commitment_hi, commitment_lo, proofPath, proofSizeBytes, proveTimeMs };
}

async function submitToMidnight(
  result: ProofResult,
  contractAddress: string,
  providers: any
): Promise<string> {
  console.log("\n[Midnight] Submitting commitment to on-chain registry...");
  console.log(`  Contract: ${contractAddress}`);

  const callResult = await submitCallTx(
    {
      walletProvider: providers.walletProvider,
      midnightProvider: providers.midnightProvider,
      publicDataProvider: providers.publicDataProvider,
      privateStateProvider: providers.privateStateProvider,
      proofProvider: providers.proofProvider,
      zkConfigProvider: providers.zkConfigProvider,
    },
    {
      contractAddress,
      circuit: "register_compliance",
      args: [result.commitment_hi, result.commitment_lo],
    }
  );

  console.log(`[Midnight] ✓ Commitment registered on-chain`);
  console.log(`  Transaction ID: ${callResult.txId}`);
  return callResult.txId;
}

async function main() {
  console.log("=== UCCR Showcase — Finance Solvency Proof Demo ===\n");
  console.log("This demonstrates a financial institution proving Basel III capital");
  console.log("adequacy WITHOUT revealing its actual asset or liability figures.\n");

  const inputs: FinanceSolvencyInputs = {
    total_assets_scaled:      process.env.TOTAL_ASSETS      ?? "125000000",
    total_liabilities_scaled: process.env.TOTAL_LIABILITIES ?? "100000000",
    blinding:                 process.env.BLINDING           ?? generateBlinding(),
  };

  // Step 1: Generate proof locally using ZirOS
  const proofResult = await generateProof(inputs);

  // Step 2: Optionally submit to Midnight Network
  const contractAddress = process.env.CONTRACT_ADDRESS;
  if (contractAddress) {
    const cfg = loadConfig();
    const seed = readSeed();
    console.log("\nBuilding wallet for on-chain submission...");
    const providers = await buildProviders(seed, cfg, "uccr-prove-db");
    await waitForFunds(providers.wallet);

    const txId = await submitToMidnight(proofResult, contractAddress, providers);

    console.log("\n=== PROOF COMPLETE ===");
    console.log(`Network:          ${cfg.name}`);
    console.log(`Contract:         ${contractAddress}`);
    console.log(`Transaction:      ${txId}`);
    console.log(`Proof size:       ${proofResult.proofSizeBytes} bytes`);
    console.log(`Prove time:       ${proofResult.proveTimeMs}ms`);
    console.log(`commitment_hi:    ${proofResult.commitment_hi}`);
    console.log(`commitment_lo:    ${proofResult.commitment_lo}`);
    console.log("\nThe institution has proven solvency. No financial data was revealed.");

    providers.wallet.close();
  } else {
    console.log("\n=== LOCAL PROOF COMPLETE (no CONTRACT_ADDRESS set — skipping on-chain) ===");
    console.log(`Proof size:    ${proofResult.proofSizeBytes} bytes`);
    console.log(`Prove time:    ${proofResult.proveTimeMs}ms`);
    console.log(`commitment_hi: ${proofResult.commitment_hi}`);
    console.log(`commitment_lo: ${proofResult.commitment_lo}`);
    console.log("\nTo submit on-chain, set CONTRACT_ADDRESS=<address> and re-run.");
  }

  process.exit(0);
}

main().catch((err) => {
  console.error("Proof demo failed:", err);
  process.exit(1);
});
