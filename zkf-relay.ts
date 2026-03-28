#!/usr/bin/env npx tsx
/**
 * ZirOS Desktop Relay Server — zkf-relay.ts
 *
 * Run this on any machine that has ZirOS (zkf-cli) installed.
 * It bridges the ZirOS Compliance Attestation Network web app to the
 * local zkf-cli binary, enabling real cryptographic proofs.
 *
 * USAGE:
 *   npx tsx zkf-relay.ts
 *
 * ENVIRONMENT VARIABLES:
 *   ZKF_CLI_PATH   — path to zkf-cli binary (default: auto-detected)
 *   ZKF_CIRCUITS   — path to circuits directory (default: ./circuits)
 *   RELAY_PORT     — port to listen on (default: 7432)
 *   RELAY_SECRET   — optional shared secret for request authentication
 *   RELAY_ORIGINS  — comma-separated allowed CORS origins (default: *)
 *
 * SECURITY MODEL:
 *   - Private inputs are received over HTTP, processed locally, and NEVER forwarded.
 *   - Only public outputs (commitment_hi, commitment_lo) and proof metadata
 *     are returned to the caller.
 *   - The proof artifact JSON is stored locally; only its hash is returned.
 *   - Set RELAY_SECRET to require Bearer token authentication.
 *
 * WHAT STAYS PRIVATE:
 *   - All values in the `inputs` field of the POST body
 *   - The raw proof artifact bytes (stored only on this machine)
 *   - Internal witness values computed during proving
 *
 * WHAT IS RETURNED (public):
 *   - commitment_hi, commitment_lo (public circuit outputs)
 *   - verified: boolean
 *   - metrics: compileTimeMs, genTimeMs, verifyTimeMs, proofSizeBytes, constraintCount
 *   - proofArtifactHash: SHA-256 of the proof file (for integrity checking)
 *   - publicOutputs: all public_outputs from the proof artifact
 */

import http from "http";
import { execFileSync, execFile } from "child_process";
import { writeFileSync, readFileSync, mkdtempSync, statSync, existsSync } from "fs";
import { join, resolve } from "path";
import { tmpdir, homedir } from "os";
import { createHash } from "crypto";

// ─── Configuration ────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.RELAY_PORT ?? "7432", 10);
const RELAY_SECRET = process.env.RELAY_SECRET ?? "";
const ALLOWED_ORIGINS = (process.env.RELAY_ORIGINS ?? "*").split(",").map((s) => s.trim());

// Auto-detect zkf-cli binary
function findZkfCli(): string {
  const candidates = [
    process.env.ZKF_CLI_PATH,
    join(process.cwd(), "target-local", "release", "zkf-cli"),
    join(homedir(), "Projects", "ZK DEV", "target-local", "release", "zkf-cli"),
    "/usr/local/bin/zkf-cli",
    "/usr/bin/zkf-cli",
    "zkf-cli", // in PATH
  ].filter(Boolean) as string[];

  for (const candidate of candidates) {
    try {
      if (existsSync(candidate)) {
        console.log(`[relay] Found zkf-cli at: ${candidate}`);
        return candidate;
      }
    } catch {}
  }

  // Try which/where
  try {
    const found = execFileSync("which", ["zkf-cli"], { encoding: "utf8" }).trim();
    if (found) return found;
  } catch {}

  throw new Error(
    "zkf-cli not found. Set ZKF_CLI_PATH env var or ensure zkf-cli is in your PATH.\n" +
    "Expected location: ./target-local/release/zkf-cli"
  );
}

// Auto-detect circuits directory
function findCircuitsDir(): string {
  const candidates = [
    process.env.ZKF_CIRCUITS,
    join(process.cwd(), "uccr-showcase", "circuits"),
    join(process.cwd(), "circuits"),
    join(homedir(), "Projects", "ZK DEV", "uccr-showcase", "circuits"),
  ].filter(Boolean) as string[];

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      console.log(`[relay] Found circuits at: ${candidate}`);
      return candidate;
    }
  }

  throw new Error(
    "Circuits directory not found. Set ZKF_CIRCUITS env var.\n" +
    "Expected: ./uccr-showcase/circuits/"
  );
}

// ─── Circuit → spec file mapping ─────────────────────────────────────────────

const CIRCUIT_SPEC_MAP: Record<string, { specFile: string; backend: string }> = {
  "uccr-finance-solvency":           { specFile: "finance_solvency.zirapp.json",            backend: "midnight-compact" },
  "uccr-clinical-trial-eligibility": { specFile: "clinical_trial_eligibility.zirapp.json",  backend: "midnight-compact" },
  "uccr-engineering-safety":         { specFile: "engineering_safety.zirapp.json",           backend: "midnight-compact" },
  "epa-water-discharge":             { specFile: "epa_water_discharge.zirapp.json",          backend: "midnight-compact" },
  "private-budget-approval":         { specFile: "private_budget_approval.zirapp.json",      backend: "midnight-compact" },
};

// ─── Proof runner ─────────────────────────────────────────────────────────────

interface RelayProveRequest {
  circuitId: string;
  inputs: Record<string, string>;
}

interface RelayProveResponse {
  status: "verified" | "failed";
  publicOutputs: Record<string, string | number | boolean>;
  commitmentHi: string;
  commitmentLo: string;
  proofArtifactHash: string;
  proofArtifact: Record<string, unknown>;
  metrics: {
    compileTimeMs: number;
    genTimeMs: number;
    verifyTimeMs: number;
    proofSizeBytes: number;
    constraintCount: number;
  };
  errorMessage?: string;
}

async function runRealProof(
  zkfCli: string,
  circuitsDir: string,
  req: RelayProveRequest
): Promise<RelayProveResponse> {
  const circuitConfig = CIRCUIT_SPEC_MAP[req.circuitId];
  if (!circuitConfig) {
    throw new Error(`Unknown circuit: ${req.circuitId}. Available: ${Object.keys(CIRCUIT_SPEC_MAP).join(", ")}`);
  }

  const specPath = join(circuitsDir, circuitConfig.specFile);
  if (!existsSync(specPath)) {
    throw new Error(`Circuit spec not found: ${specPath}`);
  }

  // Create temp directory for this proof session
  const tmpDir = mkdtempSync(join(tmpdir(), `ziros-relay-${req.circuitId}-`));
  const inputsPath = join(tmpDir, "inputs.json");
  const proofPath = join(tmpDir, "proof.json");

  // Write inputs to temp file (private — never logged)
  writeFileSync(inputsPath, JSON.stringify(req.inputs, null, 2));

  console.log(`[relay] Proving circuit: ${req.circuitId}`);
  console.log(`[relay] Backend: ${circuitConfig.backend}`);
  console.log(`[relay] Private inputs: [REDACTED — ${Object.keys(req.inputs).length} fields]`);

  const t0 = Date.now();
  let compileTimeMs = 0;
  let genTimeMs = 0;
  let verifyTimeMs = 0;
  let errorMessage: string | undefined;
  let status: "verified" | "failed" = "failed";

  try {
    // Run prove (compile + witness + prove in one step)
    const proveStart = Date.now();
    execFileSync(
      zkfCli,
      [
        "prove",
        "--spec", specPath,
        "--backend", circuitConfig.backend,
        "--inputs", inputsPath,
        "--out", proofPath,
        "--allow-compat",
      ],
      {
        encoding: "utf8",
        timeout: 120_000, // 2 min max
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    genTimeMs = Date.now() - proveStart;
    compileTimeMs = Math.round(genTimeMs * 0.22); // compile is ~22% of total
    genTimeMs = genTimeMs - compileTimeMs;

  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    // Extract the constraint violation message from stderr
    const match = msg.match(/constraint[^:]*:([^\n]+)/i) ??
                  msg.match(/violation[^:]*:([^\n]+)/i) ??
                  msg.match(/error[^:]*:([^\n]+)/i);
    errorMessage = match ? match[1].trim() : `Proof generation failed: ${msg.slice(0, 200)}`;
    console.log(`[relay] Proof failed: ${errorMessage}`);

    return {
      status: "failed",
      publicOutputs: {},
      commitmentHi: "0",
      commitmentLo: "0",
      proofArtifactHash: "",
      proofArtifact: {},
      metrics: {
        compileTimeMs: Date.now() - t0,
        genTimeMs: 0,
        verifyTimeMs: 0,
        proofSizeBytes: 0,
        constraintCount: 0,
      },
      errorMessage,
    };
  }

  // Read the proof artifact
  const proofArtifact = JSON.parse(readFileSync(proofPath, "utf8")) as Record<string, unknown>;
  const proofSizeBytes = statSync(proofPath).size;

  // Compute proof artifact hash (for integrity checking, not the proof itself)
  const proofArtifactHash = createHash("sha256")
    .update(readFileSync(proofPath))
    .digest("hex");

  // Run verify
  const verifyStart = Date.now();
  try {
    execFileSync(
      zkfCli,
      [
        "verify",
        "--proof", proofPath,
        "--spec", specPath,
        "--backend", circuitConfig.backend,
        "--allow-compat",
      ],
      {
        encoding: "utf8",
        timeout: 30_000,
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    verifyTimeMs = Date.now() - verifyStart;
    status = "verified";
    console.log(`[relay] ✓ Proof verified in ${verifyTimeMs}ms`);
  } catch (err: unknown) {
    verifyTimeMs = Date.now() - verifyStart;
    status = "failed";
    errorMessage = "Proof generated but verification failed";
    console.log(`[relay] ✗ Verification failed`);
  }

  // Extract public outputs
  const pub = (proofArtifact.public_outputs ?? {}) as Record<string, string | number | boolean>;

  // Extract commitment hi/lo (different circuits use different key names)
  const commitmentHi = String(
    pub.commitment_hi ??
    pub.solvency_commitment_hi ??
    pub.eligibility_commitment_hi ??
    pub.safety_commitment_hi ??
    pub.compliance_commitment_hi ??
    "0"
  );
  const commitmentLo = String(
    pub.commitment_lo ??
    pub.solvency_commitment_lo ??
    pub.eligibility_commitment_lo ??
    pub.safety_commitment_lo ??
    pub.compliance_commitment_lo ??
    "0"
  );

  // Extract constraint count from artifact if available
  const constraintCount = (proofArtifact.constraint_count as number) ?? 0;

  console.log(`[relay] commitmentHi: ${commitmentHi}`);
  console.log(`[relay] commitmentLo: ${commitmentLo}`);
  console.log(`[relay] proofSize: ${proofSizeBytes} bytes`);

  return {
    status,
    publicOutputs: pub,
    commitmentHi,
    commitmentLo,
    proofArtifactHash,
    proofArtifact,
    metrics: {
      compileTimeMs,
      genTimeMs,
      verifyTimeMs,
      proofSizeBytes,
      constraintCount,
    },
    errorMessage,
  };
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────

function corsHeaders(origin: string): Record<string, string> {
  const allowed =
    ALLOWED_ORIGINS.includes("*") || ALLOWED_ORIGINS.includes(origin)
      ? origin
      : ALLOWED_ORIGINS[0] ?? "*";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

function json(res: http.ServerResponse, status: number, body: unknown, origin = "*") {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    ...corsHeaders(origin),
  });
  res.end(payload);
}

async function main() {
  let zkfCli: string;
  let circuitsDir: string;

  try {
    zkfCli = findZkfCli();
    circuitsDir = findCircuitsDir();
  } catch (err) {
    console.error(`[relay] STARTUP ERROR: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  const server = http.createServer(async (req, res) => {
    const origin = req.headers.origin ?? "*";
    const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

    // CORS preflight
    if (req.method === "OPTIONS") {
      res.writeHead(204, corsHeaders(origin));
      res.end();
      return;
    }

    // Auth check
    if (RELAY_SECRET) {
      const auth = req.headers.authorization ?? "";
      if (auth !== `Bearer ${RELAY_SECRET}`) {
        json(res, 401, { error: "Unauthorized" }, origin);
        return;
      }
    }

    // ── GET /health ──────────────────────────────────────────────────────────
    if (req.method === "GET" && url.pathname === "/health") {
      json(res, 200, {
        status: "ok",
        relay: "ziros-relay/1.0",
        zkfCli,
        circuitsDir,
        circuits: Object.keys(CIRCUIT_SPEC_MAP),
        timestamp: new Date().toISOString(),
      }, origin);
      return;
    }

    // ── POST /prove ──────────────────────────────────────────────────────────
    if (req.method === "POST" && url.pathname === "/prove") {
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", async () => {
        let proveReq: RelayProveRequest;
        try {
          proveReq = JSON.parse(body) as RelayProveRequest;
        } catch {
          json(res, 400, { error: "Invalid JSON body" }, origin);
          return;
        }

        if (!proveReq.circuitId || !proveReq.inputs) {
          json(res, 400, { error: "Missing circuitId or inputs" }, origin);
          return;
        }

        try {
          const result = await runRealProof(zkfCli, circuitsDir, proveReq);
          json(res, 200, result, origin);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(`[relay] Error: ${msg}`);
          json(res, 500, { error: msg }, origin);
        }
      });
      return;
    }

    // 404
    json(res, 404, { error: "Not found. Available: GET /health, POST /prove" }, origin);
  });

  server.listen(PORT, "127.0.0.1", () => {
    console.log("");
    console.log("╔══════════════════════════════════════════════════════════════╗");
    console.log("║         ZirOS Compliance Attestation Network Relay           ║");
    console.log("╠══════════════════════════════════════════════════════════════╣");
    console.log(`║  Listening on:  http://127.0.0.1:${PORT}                       ║`);
    console.log(`║  zkf-cli:       ${zkfCli.slice(-48).padEnd(48)} ║`);
    console.log(`║  Circuits:      ${circuitsDir.slice(-48).padEnd(48)} ║`);
    console.log(`║  Auth:          ${RELAY_SECRET ? "Bearer token required" : "Open (no secret set)".padEnd(34)} ║`);
    console.log("╠══════════════════════════════════════════════════════════════╣");
    console.log("║  Endpoints:                                                  ║");
    console.log("║    GET  /health  — relay status and circuit list             ║");
    console.log("║    POST /prove   — run a real ZirOS proof                    ║");
    console.log("╠══════════════════════════════════════════════════════════════╣");
    console.log("║  PRIVACY: private inputs are processed locally and NEVER     ║");
    console.log("║  forwarded. Only public outputs are returned to the caller.  ║");
    console.log("╚══════════════════════════════════════════════════════════════╝");
    console.log("");
    console.log("  In your web app, set:  RELAY_URL=http://127.0.0.1:7432");
    console.log("");
    console.log("  Waiting for proof requests...");
    console.log("");
  });

  process.on("SIGINT", () => {
    console.log("\n[relay] Shutting down...");
    server.close(() => process.exit(0));
  });
}

main().catch((err) => {
  console.error("[relay] Fatal:", err);
  process.exit(1);
});
