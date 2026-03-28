# M4 Max Operator Handoff

This document is the release handoff for the certified `apple-silicon-m4-max-48gb` lane on this machine.

## Signed-Off State

- Release binary:
  - `/Users/sicarii/Projects/ZK DEV/target/release/zkf-cli`
- Strict production health:
  - `metal-doctor --strict --json` returns `production_ready=true`
- Gate status:
  - passed
- Soak status:
  - passed
- Certified mode:
  - strict cryptographic
- Certified lane:
  - `wrapped-v2`
  - `direct-fri-v2`
  - BN254 strict auto-route enabled

## Certification Artifacts

- Soak output report:
  - `/tmp/zkf-production-soak-current/strict-certification.json`
- Soak progress:
  - `/tmp/zkf-production-soak-current/soak-progress.json`
- Installed matching strict certification report:
  - `/var/folders/bg/pt9l6y1j47q642kp3z5blrmh0000gn/T/zkf-stark-to-groth16/certification/strict-m4-max.json`
- Assistant bundle:
  - `/Users/sicarii/Library/Application Support/ZFK/assistant/knowledge_bundle.json`
- Finalized release bundle outputs:
  - `<bundle>/assistant/knowledge_bundle.json`
  - `<bundle>/assistant/system_context.md`
  - `<bundle>/assistant/competitive_harness.json`
  - `<bundle>/assistant/competition_gate.json`
  - `<bundle>/assistant/toolchain_manifest.json`

## Final Certification Result

- `final_pass=true`
- `gate_passed=true`
- `soak_passed=true`
- `parallel_jobs=1`
- `strict_gpu_busy_ratio_peak=0.25`
- `doctor_flips=0`
- `degraded_runs=0`
- `fault_injection_failed_closed=true`

## One-Command Health Checks

Run from `/Users/sicarii/Projects/ZK DEV`.

```bash
target/release/zkf-cli metal-doctor --strict --json
```

```bash
python3 - <<'PY'
import json
with open('/tmp/zkf-production-soak-current/strict-certification.json') as f:
    data = json.load(f)
print(json.dumps(data['summary'], indent=2))
PY
```

## Safe Operator Checks

Low-impact checks that do not start a heavy proving workload:

```bash
target/release/zkf-cli metal-doctor --json
```

```bash
target/release/zkf-cli runtime policy --trace /tmp/zkf-production-soak-current/warm-cycle-119/warm-cycle-119.runtime-trace.json --json
```

```bash
python3 scripts/build_zfk_assistant_bundle.py
```

```bash
python3 scripts/competition_bootstrap.py --out /tmp/zkf-toolchain-manifest.json
python3 scripts/competitive_harness.py --out /tmp/zkf-competitive-harness.json --gate-out /tmp/zkf-competition-gate.json --toolchain-manifest /tmp/zkf-toolchain-manifest.json --iterations 1 --skip-zkf-wrap
```

## Dashboard

- Dashboard URL:
  - `http://127.0.0.1:8777`
- Dashboard script:
  - `/Users/sicarii/Projects/ZK DEV/scripts/system_dashboard.py`
- Dashboard agent:
  - `/Users/sicarii/Projects/ZK DEV/scripts/system_dashboard_agent.py`
- Assistant bundle builder:
  - `/Users/sicarii/Projects/ZK DEV/scripts/build_zfk_assistant_bundle.py`
- Competitive harness:
  - `/Users/sicarii/Projects/ZK DEV/scripts/competitive_harness.py`
- Competition bootstrap:
  - `/Users/sicarii/Projects/ZK DEV/scripts/competition_bootstrap.py`
- Competitive harness config template:
  - `/Users/sicarii/Projects/ZK DEV/scripts/competitive_harness.example.json`

## If You Need To Re-Run Certification

Gate:

```bash
bash /Users/sicarii/Projects/ZK\ DEV/scripts/production_gate.sh \
  --proof /Users/sicarii/Projects/ZK\ DEV/proof-plonky3.json \
  --compiled /Users/sicarii/Projects/ZK\ DEV/compiled-plonky3.json \
  --bin /Users/sicarii/Projects/ZK\ DEV/target/release/zkf-cli \
  --out-dir /tmp/zkf-production-gate-current
```

Soak under launchd:

```bash
python3 /Users/sicarii/Projects/ZK\ DEV/scripts/production_soak_agent.py start \
  --proof /Users/sicarii/Projects/ZK\ DEV/proof-plonky3.json \
  --compiled /Users/sicarii/Projects/ZK\ DEV/compiled-plonky3.json \
  --out-dir /tmp/zkf-production-soak-current \
  --json-out /tmp/zkf-production-soak-current/strict-certification.json \
  --bin /Users/sicarii/Projects/ZK\ DEV/target/release/zkf-cli \
  --parallel-jobs 1 \
  --hours 12 \
  --cycles 20
```

Status:

```bash
python3 /Users/sicarii/Projects/ZK\ DEV/scripts/production_soak_agent.py status
```

Stop:

```bash
python3 /Users/sicarii/Projects/ZK\ DEV/scripts/production_soak_agent.py stop
```

## Current Honest Boundaries

- This certification is for the certified M4 Max lane on this host profile, not every machine.
- The public proving surface is routed through UMPG, but not every backend is decomposed into a fully parallel runtime-native arithmetic graph.
- The strict lane is certified in desktop-safe soak mode with `parallel_jobs=1`.
- The Neural Engine lane is control-plane only; model failures fall back to heuristics and do not weaken proof soundness.

## Neural Engine Operations

- Train/install/rollback runbook:
  - `/Users/sicarii/Projects/ZK DEV/docs/NEURAL_ENGINE_OPERATIONS.md`
- Runtime model directory:
  - `~/.zkf/models/`
- Primary validation command:
  - `target/release/zkf-cli runtime policy --trace /tmp/zkf-production-soak-current/warm-cycle-119/warm-cycle-119.runtime-trace.json --json`

## Release Checklist

- `target/release/zkf-cli` exists and is the intended binary
- `metal-doctor --strict --json` returns `production_ready=true`
- `/tmp/zkf-production-soak-current/strict-certification.json` has `final_pass=true`
- Assistant bundle refreshed at least once after final certification
- Finalized bundle contains bundle-local assistant and competitive reports for the shipped binary
- Dashboard reachable on `127.0.0.1:8777`
- Competitive harness run at least once with the current binary or intentionally skipped with a written reason
