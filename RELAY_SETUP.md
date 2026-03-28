# ZirOS Relay Setup — Real Cryptographic Proofs

This document explains how to connect the ZirOS Compliance Attestation Network
to a real `zkf-cli` installation so that every proof is cryptographically
generated rather than simulated.

---

## Architecture

```
Browser / Agent
      │
      │  HTTPS
      ▼
ZirOS CAN Web App (cloud)
      │
      │  HTTP  (localhost only — private inputs never leave your machine)
      ▼
zkf-relay.ts  ◄──── runs on YOUR machine
      │
      │  subprocess
      ▼
zkf-cli prove / verify  ◄──── ZirOS binary on YOUR machine
      │
      ▼
Proof artifact (stored locally)
      │
      │  public outputs only (commitment_hi, commitment_lo)
      ▼
ZirOS CAN Web App  ◄──── only public data returned
```

**Privacy guarantee:** Private inputs (patient age, asset values, sensor readings)
are sent from the browser to the web app server, then forwarded to the relay
over localhost. They are processed by `zkf-cli` on your machine and are **never
stored in the cloud database**. Only the public commitment values are returned.

---

## Prerequisites

- ZirOS (`zkf-cli`) installed and compiled at `./target-local/release/zkf-cli`
- Node.js 18+ or Bun installed
- `npx tsx` available (`npm install -g tsx` if not)

---

## Step 1 — Start the relay

From your ZK DEV directory:

```bash
cd "/Users/sicarii/Projects/ZK DEV"
npx tsx ziros-showcase/zkf-relay.ts
```

You should see:

```
╔══════════════════════════════════════════════════════════════╗
║         ZirOS Compliance Attestation Network Relay           ║
╠══════════════════════════════════════════════════════════════╣
║  Listening on:  http://127.0.0.1:7432                        ║
║  zkf-cli:       .../target-local/release/zkf-cli             ║
║  Circuits:      .../uccr-showcase/circuits                   ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Step 2 — Set RELAY_URL in the web app

In the Manus project settings (Secrets panel), add:

```
RELAY_URL = http://127.0.0.1:7432
```

Or for a remote relay (e.g. your organization's proving server):

```
RELAY_URL = https://prover.yourorg.com:7432
```

---

## Step 3 — Verify the connection

Navigate to **Submit Proof** in the web app. The header badge will show:

- 🟢 **ZirOS Relay Connected — Real Proofs** — relay is reachable, all proofs are real
- 🟡 **Relay Unreachable — Simulation Mode** — RELAY_URL is set but relay is not running
- ⚪ **Simulation Mode** — RELAY_URL is not set, using faithful simulation

---

## Environment variables for the relay

| Variable | Default | Description |
|---|---|---|
| `ZKF_CLI_PATH` | auto-detected | Path to `zkf-cli` binary |
| `ZKF_CIRCUITS` | auto-detected | Path to `uccr-showcase/circuits/` |
| `RELAY_PORT` | `7432` | Port to listen on |
| `RELAY_SECRET` | (none) | Optional Bearer token for auth |
| `RELAY_ORIGINS` | `*` | Comma-separated allowed CORS origins |

---

## Circuit → spec file mapping

| Circuit ID | Spec file | Backend |
|---|---|---|
| `uccr-finance-solvency` | `finance_solvency.zirapp.json` | `midnight-compact` |
| `uccr-clinical-trial-eligibility` | `clinical_trial_eligibility.zirapp.json` | `midnight-compact` |
| `uccr-engineering-safety` | `engineering_safety.zirapp.json` | `midnight-compact` |
| `epa-water-discharge` | `epa_water_discharge.zirapp.json` | `midnight-compact` |
| `private-budget-approval` | `private_budget_approval.zirapp.json` | `midnight-compact` |

---

## Adding new circuits

1. Add the `zirapp.json` file to `uccr-showcase/circuits/`
2. Add an entry to `CIRCUIT_SPEC_MAP` in `zkf-relay.ts`
3. Add the circuit spec to `server/circuits.ts`
4. Add the input form to `client/src/pages/Submit.tsx`

---

## Security considerations

- Run the relay on `127.0.0.1` (localhost only) unless you have a dedicated
  proving server with TLS and authentication.
- Set `RELAY_SECRET` to require Bearer token authentication if exposing over
  a network.
- The relay never logs private input values — only the circuit ID and field
  count are logged.
- Proof artifacts are written to a temp directory and are not persisted by
  the relay. Store them yourself if you need them for audit purposes.
