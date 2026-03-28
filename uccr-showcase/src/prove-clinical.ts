/**
 * UCCR Showcase — Clinical Trial Eligibility: End-to-End Proof Demo
 *
 * Demonstrates a patient proving they meet clinical trial enrollment
 * criteria (age 18–75, biomarker 100–5000 scaled) WITHOUT revealing
 * their identity, exact age, or biomarker value.
 *
 * Usage:
 *   MIDNIGHT_NETWORK=preview \
 *   WALLET_SEED=<64hex> \
 *   CONTRACT_ADDRESS=<address> \
 *   PATIENT_AGE=45 \
 *   BIOMARKER=2500 \
 *   PATIENT_ID_HASH=<u32_hash_of_patient_id> \
 *   BLINDING=<random_u32> \
 *   npm run prove:clinical
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

interface ClinicalInputs {
  patient_age: string;
  biomarker_level_scaled: string;
  patient_id_hash: string;
  blinding: string;
}

function hashPatientId(patientId: string): string {
  // One-way hash of patient ID to a 32-bit integer (for circuit compatibility)
  const hash = crypto.createHash("sha256").update(patientId).digest();
  const u32 = hash.readUInt32BE(0);
  return String(u32);
}

function readSeed(): string {
  const envSeed = process.env.WALLET_SEED;
  if (envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed.trim())) return envSeed.trim();
  const seedFile = process.env.WALLET_SEED_FILE ?? path.join(process.cwd(), ".wallet-seed");
  if (!fs.existsSync(seedFile)) throw new Error(`No wallet seed. Set WALLET_SEED or create ${seedFile}.`);
  return fs.readFileSync(seedFile, "utf8").trim();
}

async function generateProof(inputs: ClinicalInputs) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "uccr-clinical-"));
  const inputsPath = path.join(tmpDir, "inputs.json");
  const proofPath = path.join(tmpDir, "proof.json");
  const specPath = path.join(CIRCUITS_DIR, "clinical_trial_eligibility.zirapp.json");

  fs.writeFileSync(inputsPath, JSON.stringify(inputs, null, 2));

  console.log("\n[ZirOS] Generating eligibility proof...");
  console.log(`  Patient age:     [PRIVATE — not revealed]`);
  console.log(`  Biomarker level: [PRIVATE — not revealed]`);
  console.log(`  Patient ID:      [PRIVATE — only hash used]`);
  console.log(`  Proving: age ∈ [18, 75] AND biomarker ∈ [100, 5000]`);

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
  console.log(`[ZirOS] eligibility_commitment_hi: ${pub.eligibility_commitment_hi}`);
  console.log(`[ZirOS] eligibility_commitment_lo: ${pub.eligibility_commitment_lo}`);

  // Local verification
  execFileSync(
    ZIROS_CLI,
    ["verify", "--proof", proofPath, "--spec", specPath, "--backend", "midnight-compact", "--allow-compat"],
    { encoding: "utf8" }
  );
  console.log("[ZirOS] ✓ Local verification passed");

  return {
    eligibility_commitment_hi: pub.eligibility_commitment_hi,
    eligibility_commitment_lo: pub.eligibility_commitment_lo,
    proofPath,
    proofSizeBytes: fs.statSync(proofPath).size,
    proveTimeMs,
  };
}

async function main() {
  console.log("=== UCCR Showcase — Clinical Trial Eligibility Proof Demo ===\n");
  console.log("A patient proves they meet trial criteria without revealing their");
  console.log("identity, exact age, or biomarker value. HIPAA/GDPR compliant.\n");

  const patientIdRaw = process.env.PATIENT_ID ?? "PATIENT-DEMO-001";
  const inputs: ClinicalInputs = {
    patient_age:            process.env.PATIENT_AGE  ?? "45",
    biomarker_level_scaled: process.env.BIOMARKER     ?? "2500",
    patient_id_hash:        process.env.PATIENT_ID_HASH ?? hashPatientId(patientIdRaw),
    blinding:               process.env.BLINDING      ?? String(Math.floor(Math.random() * 0xFFFFFFFF)),
  };

  const result = await generateProof(inputs);

  const contractAddress = process.env.CONTRACT_ADDRESS;
  if (contractAddress) {
    const cfg = loadConfig();
    const seed = readSeed();
    const providers = await buildProviders(seed, cfg, "uccr-clinical-db");
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
        circuit: "register_eligibility",
        args: [result.eligibility_commitment_hi, result.eligibility_commitment_lo],
      }
    );

    console.log(`\n[Midnight] ✓ Eligibility registered on-chain`);
    console.log(`  Transaction ID: ${callResult.txId}`);
    console.log("\nThe patient is eligible. No health data was revealed.");
    providers.wallet.close();
  } else {
    console.log("\n=== LOCAL PROOF COMPLETE (set CONTRACT_ADDRESS to submit on-chain) ===");
    console.log(`Proof size:                  ${result.proofSizeBytes} bytes`);
    console.log(`Prove time:                  ${result.proveTimeMs}ms`);
    console.log(`eligibility_commitment_hi:   ${result.eligibility_commitment_hi}`);
    console.log(`eligibility_commitment_lo:   ${result.eligibility_commitment_lo}`);
  }

  process.exit(0);
}

main().catch((err) => {
  console.error("Clinical proof demo failed:", err);
  process.exit(1);
});
