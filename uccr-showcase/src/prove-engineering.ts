/**
 * UCCR Showcase — Engineering Safety: End-to-End Proof Demo
 *
 * Demonstrates an aerospace or civil engineering firm proving their design
 * meets required safety factors WITHOUT revealing proprietary load capacities,
 * material specifications, or exact design margins.
 *
 * Usage:
 *   MIDNIGHT_NETWORK=preview \
 *   WALLET_SEED=<64hex> \
 *   CONTRACT_ADDRESS=<address> \
 *   DESIGN_LOAD_CAPACITY=15000 \
 *   APPLIED_LOAD=10000 \
 *   YIELD_STRESS=25000 \
 *   APPLIED_STRESS=16000 \
 *   DESIGN_ID=<u32_design_identifier> \
 *   BLINDING=<random_u32> \
 *   npm run prove:engineering
 */

import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as crypto from "crypto";
import { fileURLToPath } from "url";
import { submitCallTx } from "@midnight-ntwrk/midnight-js-contracts";
import { loadConfig } from "./config.js";
import { buildProviders, waitForFunds } from "./wallet.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ZIROS_CLI = path.resolve(__dirname, "../../target-local/release/zkf-cli");
const CIRCUITS_DIR = path.resolve(__dirname, "../circuits");

interface EngineeringInputs {
  design_load_capacity_scaled: string;
  applied_load_scaled: string;
  material_yield_stress_scaled: string;
  applied_stress_scaled: string;
  design_id_hash: string;
  blinding: string;
}

function hashDesignId(designId: string): string {
  const hash = crypto.createHash("sha256").update(designId).digest();
  return String(hash.readUInt32BE(0));
}

function readSeed(): string {
  const envSeed = process.env.WALLET_SEED;
  if (envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed.trim())) return envSeed.trim();
  const seedFile = process.env.WALLET_SEED_FILE ?? path.join(process.cwd(), ".wallet-seed");
  if (!fs.existsSync(seedFile)) throw new Error(`No wallet seed. Set WALLET_SEED or create ${seedFile}.`);
  return fs.readFileSync(seedFile, "utf8").trim();
}

async function generateProof(inputs: EngineeringInputs) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "uccr-eng-"));
  const inputsPath = path.join(tmpDir, "inputs.json");
  const proofPath = path.join(tmpDir, "proof.json");
  const specPath = path.join(CIRCUITS_DIR, "engineering_safety.zirapp.json");

  fs.writeFileSync(inputsPath, JSON.stringify(inputs, null, 2));

  console.log("\n[ZirOS] Generating safety certification proof...");
  console.log(`  Load capacity:   [PRIVATE — proprietary design parameter]`);
  console.log(`  Applied load:    [PRIVATE — proprietary design parameter]`);
  console.log(`  Yield stress:    [PRIVATE — proprietary material spec]`);
  console.log(`  Applied stress:  [PRIVATE — proprietary design parameter]`);
  console.log(`  Proving: load_capacity > applied_load AND yield_stress > applied_stress`);
  console.log(`  Standard: DO-178C / AS9100 / ASME BPVC / ISO 2394`);

  const t0 = Date.now();
  execFileSync(
    ZIROS_CLI,
    [
      "prove",
      "--spec", specPath,
      "--backend", "midnight-compact",
      "--inputs", inputsPath,
      "--out", proofPath,
      "--allow-compat",
    ],
    { encoding: "utf8" }
  );
  const proveTimeMs = Date.now() - t0;

  const proofArtifact = JSON.parse(fs.readFileSync(proofPath, "utf8"));
  const pub = proofArtifact.public_outputs ?? {};

  console.log(`[ZirOS] ✓ Proof generated in ${proveTimeMs}ms`);
  console.log(`[ZirOS] safety_commitment_hi: ${pub.safety_commitment_hi}`);
  console.log(`[ZirOS] safety_commitment_lo: ${pub.safety_commitment_lo}`);

  execFileSync(
    ZIROS_CLI,
    ["verify", "--proof", proofPath, "--spec", specPath, "--backend", "midnight-compact", "--allow-compat"],
    { encoding: "utf8" }
  );
  console.log("[ZirOS] ✓ Local verification passed");

  return {
    safety_commitment_hi: pub.safety_commitment_hi,
    safety_commitment_lo: pub.safety_commitment_lo,
    proofPath,
    proofSizeBytes: fs.statSync(proofPath).size,
    proveTimeMs,
  };
}

async function main() {
  console.log("=== UCCR Showcase — Engineering Safety Certification Proof Demo ===\n");
  console.log("An engineering firm proves their design meets safety factor requirements");
  console.log("without revealing proprietary load capacities or material specifications.\n");

  const designIdRaw = process.env.DESIGN_ID_RAW ?? "DESIGN-DEMO-WING-SPAR-001";
  const inputs: EngineeringInputs = {
    design_load_capacity_scaled:  process.env.DESIGN_LOAD_CAPACITY ?? "15000",
    applied_load_scaled:          process.env.APPLIED_LOAD          ?? "10000",
    material_yield_stress_scaled: process.env.YIELD_STRESS          ?? "25000",
    applied_stress_scaled:        process.env.APPLIED_STRESS        ?? "16000",
    design_id_hash:               process.env.DESIGN_ID             ?? hashDesignId(designIdRaw),
    blinding:                     process.env.BLINDING              ?? String(Math.floor(Math.random() * 0xFFFFFFFF)),
  };

  const result = await generateProof(inputs);

  const contractAddress = process.env.CONTRACT_ADDRESS;
  if (contractAddress) {
    const cfg = loadConfig();
    const seed = readSeed();
    const providers = await buildProviders(seed, cfg, "uccr-eng-db");
    await waitForFunds(providers.wallet);

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
        circuit: "register_safety_cert",
        args: [result.safety_commitment_hi, result.safety_commitment_lo],
      }
    );

    console.log(`\n[Midnight] ✓ Safety certification registered on-chain`);
    console.log(`  Transaction ID: ${callResult.txId}`);
    console.log("\nThe design is certified safe. No proprietary data was revealed.");
    providers.wallet.close();
  } else {
    console.log("\n=== LOCAL PROOF COMPLETE (set CONTRACT_ADDRESS to submit on-chain) ===");
    console.log(`Proof size:            ${result.proofSizeBytes} bytes`);
    console.log(`Prove time:            ${result.proveTimeMs}ms`);
    console.log(`safety_commitment_hi:  ${result.safety_commitment_hi}`);
    console.log(`safety_commitment_lo:  ${result.safety_commitment_lo}`);
  }

  process.exit(0);
}

main().catch((err) => {
  console.error("Engineering proof demo failed:", err);
  process.exit(1);
});
