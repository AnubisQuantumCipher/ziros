#!/usr/bin/env python3
"""Permanent ZKF system dashboard.

Runs a lightweight local web server with a birds-eye view of:
- runtime / Metal health
- current proving activity
- UMPG routing and execution surface
- certification and soak state
- Neural Engine / Core ML control-plane policy
- machine metrics and workspace state
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from build_zfk_assistant_bundle import (  # type: ignore
    DEFAULT_GATE_REPORT,
    DEFAULT_SOAK_PROGRESS,
    DEFAULT_SOAK_REPORT,
    DEFAULT_ZFK_HOME,
)
from soak_monitor import (  # type: ignore
    collect_process_memory,
    collect_soak_data,
    collect_thermal,
    read_json,
)


DEFAULT_PORT = 8777
DEFAULT_SOAK_DIR = Path("/tmp/zkf-production-soak-current")
ROOT = SCRIPT_DIR.parent


def assistant_home() -> Path:
    if (ROOT / "bin" / "zkf-cli").exists():
        return ROOT
    return DEFAULT_ZFK_HOME


def default_bundle_path() -> Path:
    return assistant_home() / "assistant" / "knowledge_bundle.json"


def default_context_path() -> Path:
    return assistant_home() / "assistant" / "system_context.md"


def bundled_certification_paths() -> tuple[Path, Path, Path] | None:
    gate_report = ROOT / "certification" / "strict-gate.json"
    soak_progress = ROOT / "certification" / "soak-progress.json"
    soak_report = ROOT / "certification" / "strict-certification.json"
    if gate_report.exists() or soak_progress.exists() or soak_report.exists():
        return gate_report, soak_progress, soak_report
    return None

_CACHE: dict[str, dict] = {}


def cached(key: str, ttl: float, fn):
    now = time.time()
    entry = _CACHE.get(key)
    if entry and (now - entry["ts"]) < ttl:
        return entry["value"]
    value = fn()
    _CACHE[key] = {"ts": now, "value": value}
    return value


def run(argv: list[str], *, cwd: Path | None = None, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def build_binary() -> Path | None:
    for path in (
        ROOT / "bin" / "zkf-cli",
        ROOT / "target" / "release" / "zkf-cli",
        ROOT / "target" / "debug" / "zkf-cli",
    ):
        if path.exists():
            return path
    return None


def refresh_assistant_bundle() -> dict:
    script = ROOT / "scripts" / "build_zfk_assistant_bundle.py"
    command = [
        sys.executable,
        str(script),
        "--zfk-home",
        str(assistant_home()),
    ]
    certification_paths = bundled_certification_paths()
    if certification_paths is not None:
        gate_report, soak_progress, soak_report = certification_paths
        command.extend(
            [
                "--gate-report",
                str(gate_report),
                "--soak-progress",
                str(soak_progress),
                "--soak-report",
                str(soak_report),
            ]
        )
    else:
        command.extend(
            [
                "--gate-report",
                str(DEFAULT_GATE_REPORT),
                "--soak-progress",
                str(DEFAULT_SOAK_PROGRESS),
                "--soak-report",
                str(DEFAULT_SOAK_REPORT),
            ]
        )
    proc = run(command, cwd=ROOT, timeout=30)
    return {
        "ok": proc.returncode == 0,
        "command": command,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "exit_code": proc.returncode,
    }


def collect_metal_doctor() -> dict:
    binary = build_binary()
    if not binary:
        return {"error": "zkf-cli binary not found"}
    proc = run([str(binary), "metal-doctor", "--json"], cwd=ROOT, timeout=15)
    if proc.returncode != 0:
        return {"error": proc.stderr.strip() or "metal-doctor failed", "exit_code": proc.returncode}
    try:
        return json.loads(proc.stdout)
    except Exception as exc:
        return {"error": f"invalid metal-doctor JSON: {exc}", "stdout": proc.stdout}


def collect_active_jobs() -> dict:
    proc = run(
        [
            "zsh",
            "-lc",
            "ps -axo pid=,ppid=,etime=,rss=,state=,command= | rg 'zkf-cli (prove|wrap|benchmark|runtime execute|runtime certify|package prove|package prove-all|deploy|verify|explore)|production_soak|caffeinate' || true",
        ],
        timeout=5,
    )
    jobs = []
    for line in proc.stdout.splitlines():
        raw = line.strip()
        if not raw:
            continue
        parts = raw.split(None, 5)
        if len(parts) < 6:
            continue
        pid, ppid, etime, rss, state, command = parts
        if "rg " in command or "system_dashboard.py" in command:
            continue
        jobs.append(
            {
                "pid": int(pid),
                "ppid": int(ppid),
                "elapsed": etime,
                "rss_kb": int(rss),
                "state": state,
                "command": command,
            }
        )
    return {"jobs": jobs, "count": len(jobs)}


def collect_bundle_state(auto_refresh: bool) -> dict:
    refresh_result = None
    bundle_path = default_bundle_path()
    if auto_refresh:
        refresh_result = cached("bundle_refresh", 60.0, refresh_assistant_bundle)
    bundle = read_json(bundle_path) or {}
    context_path = default_context_path()
    context_preview = None
    if context_path.exists():
        try:
            context_preview = context_path.read_text()[:4000]
        except Exception:
            context_preview = None
    return {
        "path": str(bundle_path),
        "context_path": str(context_path),
        "bundle": bundle,
        "context_preview": context_preview,
        "refresh": refresh_result,
    }


def collect_system_payload(soak_dir: Path, auto_refresh_bundle: bool) -> dict:
    bundle_state = collect_bundle_state(auto_refresh_bundle)
    bundle = bundle_state.get("bundle") or {}
    soak = collect_soak_data(soak_dir) if soak_dir.is_dir() else None
    certification = (bundle.get("certification") or {}) if isinstance(bundle, dict) else {}
    return {
        "schema": "zkf-system-dashboard-v1",
        "collected_at": time.time(),
        "root": str(ROOT),
        "soak_dir": str(soak_dir),
        "metal_doctor": cached("metal_doctor", 15.0, collect_metal_doctor),
        "activity": collect_active_jobs(),
        "machine": {
            "thermal": collect_thermal(),
            "memory": collect_process_memory(),
        },
        "assistant": bundle_state,
        "certification": certification,
        "umpg": bundle.get("umpg") or {},
        "workspace": bundle.get("workspace") or {},
        "host": bundle.get("host") or {},
        "backend_matrix": bundle.get("backend_matrix") or {},
        "neural_engine": bundle.get("neural_engine") or {},
        "assistant_rules": bundle.get("assistant_rules") or [],
        "official_sources": bundle.get("official_sources") or [],
        "recommended_next_actions": bundle.get("recommended_next_actions") or [],
        "soak": soak,
    }


HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZirOS System Dashboard</title>
<style>
:root{
  --bg:#0b1220; --panel:#121a2a; --panel2:#182235; --border:#243247;
  --text:#e8eef8; --dim:#9ca9be; --blue:#64b5ff; --green:#48d597; --yellow:#f2c14e;
  --red:#ff6b6b; --purple:#b48cff; --cyan:#42d6d6; --orange:#f59e0b;
}
*{box-sizing:border-box} body{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--bg);color:var(--text);padding:16px}
h1{margin:0;font-size:20px;color:var(--blue)} h2{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin:0 0 8px}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;margin-bottom:14px}
.sub{color:var(--dim);font-size:11px}
.grid{display:grid;gap:10px}.g4{grid-template-columns:repeat(4,minmax(0,1fr))}.g3{grid-template-columns:repeat(3,minmax(0,1fr))}.g2{grid-template-columns:repeat(2,minmax(0,1fr))}
@media (max-width:1100px){.g4,.g3,.g2{grid-template-columns:1fr 1fr}} @media (max-width:700px){.g4,.g3,.g2{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px;overflow:hidden}
.stat{padding:10px;text-align:center}.value{font-size:24px;font-weight:700}.label{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em}.small{font-size:10px;color:var(--dim);margin-top:3px}
.green{color:var(--green)} .yellow{color:var(--yellow)} .red{color:var(--red)} .blue{color:var(--blue)} .purple{color:var(--purple)} .cyan{color:var(--cyan)} .orange{color:var(--orange)}
.badge{display:inline-block;padding:2px 7px;border-radius:999px;font-size:10px;font-weight:700;text-transform:uppercase}
.b-green{background:#103326;color:var(--green)} .b-yellow{background:#3a2e11;color:var(--yellow)} .b-red{background:#3a1616;color:var(--red)} .b-blue{background:#10263d;color:var(--blue)}
.list{display:flex;flex-direction:column;gap:6px}.row{display:flex;gap:8px;justify-content:space-between;align-items:flex-start;font-size:11px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04)} .row:last-child{border-bottom:none}
.k{color:var(--dim);min-width:120px}.v{flex:1;text-align:right;word-break:break-word}
pre{margin:0;white-space:pre-wrap;word-break:break-word;background:var(--panel2);border-radius:8px;padding:10px;font-size:10px;color:var(--text)}
table{width:100%;border-collapse:collapse;font-size:11px} th,td{padding:6px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left;vertical-align:top} th{color:var(--dim);font-weight:600}
.spark{display:flex;align-items:flex-end;gap:2px;height:54px;margin-top:6px}.bar{flex:1;min-width:5px;border-radius:3px 3px 0 0}
.pwrap{height:18px;background:var(--panel2);border-radius:999px;overflow:hidden;border:1px solid var(--border)} .pfill{height:100%;background:linear-gradient(90deg,var(--blue),var(--purple))}
a{color:var(--blue)}
</style>
</head>
<body>
<div class="top">
  <div>
    <h1>ZirOS System Dashboard</h1>
    <div class="sub" id="sub"></div>
  </div>
  <div class="sub" id="ts"></div>
</div>

<div class="grid g4" id="top"></div>
<div class="grid g2" style="margin-top:10px">
  <div class="card" id="runtime"></div>
  <div class="card" id="activity"></div>
</div>
<div class="grid g2" style="margin-top:10px">
  <div class="card" id="cert"></div>
  <div class="card" id="ane"></div>
</div>
<div class="grid g2" style="margin-top:10px">
  <div class="card" id="umpg"></div>
  <div class="card" id="machine"></div>
</div>
<div class="grid g2" style="margin-top:10px">
  <div class="card" id="workspace"></div>
  <div class="card" id="sources"></div>
</div>
<div class="card" style="margin-top:10px" id="soak"></div>

<script>
let DATA=null;
function fmtBytes(b){ if(b===null||b===undefined) return '-'; if(b<1024)return b+' B'; if(b<1048576)return (b/1024).toFixed(1)+' KB'; if(b<1073741824)return (b/1048576).toFixed(1)+' MB'; return (b/1073741824).toFixed(2)+' GB'; }
function cls(ok,mid=false){ return ok ? 'green' : (mid ? 'yellow' : 'red'); }
function badge(text,c){ return `<span class="badge ${c}">${text}</span>`; }
function esc(s){ return String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }
function spark(vals,color){ if(!vals||!vals.length) return '<div class="small">no data</div>'; const mx=Math.max(...vals,0.001); return `<div class="spark">`+vals.map(v=>`<div class="bar" style="height:${Math.max(2,(v/mx)*100)}%;background:${color}"></div>`).join('')+`</div>`; }
function row(k,v){ return `<div class="row"><div class="k">${k}</div><div class="v">${v ?? '-'}</div></div>`; }

function render(d){
  DATA=d;
  const host=d.host||{}, md=(d.metal_doctor||{}).runtime||{}, act=d.activity||{}, cert=d.certification||{}, ane=d.neural_engine||{}, umpg=d.umpg||{}, ws=d.workspace||{}, soak=d.soak||{}, prog=soak.progress||{}, therm=(d.machine||{}).thermal||{}, mem=(d.machine||{}).memory||{};
  document.getElementById('sub').textContent = `${host.cpu_brand||'Unknown host'} • ${host.certified_profile||'uncertified'} • ${d.root}`;
  document.getElementById('ts').textContent = `Updated ${new Date((d.collected_at||0)*1000).toLocaleTimeString()}`;

  const top = [
    {v: md.metal_available ? 'YES' : 'NO', l:'Metal Available', c: cls(md.metal_available)},
    {v: md.metal_dispatch_circuit_open ? 'OPEN' : 'CLOSED', l:'Dispatch Circuit', c: cls(!md.metal_dispatch_circuit_open)},
    {v: cert.gate_report?.final_pass ? 'PASS' : 'PENDING', l:'Gate', c: cls(!!cert.gate_report?.final_pass, !cert.gate_report?.present)},
    {v: cert.soak_report?.final_pass ? 'PASS' : (cert.soak_running ? 'RUNNING' : 'PENDING'), l:'Soak', c: cert.soak_report?.final_pass ? 'green' : cert.soak_running ? 'yellow' : 'red'},
  ];
  document.getElementById('top').innerHTML = top.map(s=>`<div class="card stat"><div class="value ${s.c}">${s.v}</div><div class="label">${s.l}</div></div>`).join('');

  document.getElementById('runtime').innerHTML = `<h2>Runtime Health</h2>`+
    row('Metal device', md.metal_device)+
    row('Mode', md.metallib_mode)+
    row('Threshold profile', md.threshold_summary)+
    row('Working-set budget', fmtBytes(md.recommended_working_set_size_bytes))+
    row('Current allocated', fmtBytes(md.current_allocated_size_bytes))+
    row('Headroom', fmtBytes(md.working_set_headroom_bytes))+
    row('Working-set utilization', md.working_set_utilization_pct!==undefined ? (md.working_set_utilization_pct*100).toFixed(3)+'%' : '-')+
    row('Prewarmed pipelines', md.prewarmed_pipelines)+
    row('Primary/secondary queue depth', `${md.metal_primary_queue_depth ?? '-'} / ${md.metal_secondary_queue_depth ?? '-'}`)+
    row('Scheduler max jobs', md.metal_scheduler_max_jobs)+
    row('Active accelerators', Object.entries(md.active_accelerators||{}).map(([k,v])=>`${k}:${v}`).join(', '));

  const jobs = act.jobs || [];
  document.getElementById('activity').innerHTML = `<h2>Proving Activity</h2>`+
    row('Active jobs', jobs.length)+
    (jobs.length ? `<table><thead><tr><th>PID</th><th>Elapsed</th><th>RSS</th><th>State</th><th>Command</th></tr></thead><tbody>${
      jobs.map(j=>`<tr><td>${j.pid}</td><td>${j.elapsed}</td><td>${fmtBytes((j.rss_kb||0)*1024)}</td><td>${j.state}</td><td>${esc(j.command)}</td></tr>`).join('')
    }</tbody></table>` : `<div class="small">No active proving jobs.</div>`);

  const gatePass = cert.gate_report?.final_pass;
  const soakPass = cert.soak_report?.final_pass;
  const soakData = cert.soak_progress?.data || {};
  const elapsed = soakData.elapsed_ms || 0, minDur = soakData.min_duration_ms || 1;
  const pct = Math.min(100, (elapsed/minDur)*100);
  document.getElementById('cert').innerHTML = `<h2>Certification</h2>`+
    row('Gate report', cert.gate_report?.present ? badge(gatePass ? 'pass' : 'present', gatePass ? 'b-green' : 'b-yellow') : badge('missing','b-red'))+
    row('Soak report', cert.soak_report?.present ? badge(soakPass ? 'pass' : 'present', soakPass ? 'b-green' : 'b-yellow') : badge(cert.soak_running ? 'running' : 'missing', cert.soak_running ? 'b-yellow' : 'b-red'))+
    row('Soak phase', `${soakData.phase || '-'} ${soakData.subphase ? '• '+soakData.subphase : ''}`)+
    row('Cycle', `${soakData.current_cycle || 0}/${soakData.required_cycles || 0}`)+
    row('Degraded runs', soakData.degraded_runs ?? '-')+
    row('Doctor flips', soakData.doctor_flips ?? '-')+
    `<div class="small" style="margin:8px 0 4px">Soak time floor</div><div class="pwrap"><div class="pfill" style="width:${pct}%"></div></div><div class="small">${pct.toFixed(1)}% of minimum duration</div>`;

  const policy = ane.runtime_policy_snapshot || {};
  const feats = policy.features || {};
  document.getElementById('ane').innerHTML = `<h2>Neural Engine / Core ML</h2>`+
    row('Model present', ane.available ? 'yes' : 'no')+
    row('Compute units', policy.model?.compute_units || ane.compute_units_default)+
    row('Final GPU lane score', policy.final_gpu_lane_score!==undefined ? (policy.final_gpu_lane_score*100).toFixed(1)+'%' : '-')+
    row('Heuristic score', policy.heuristic_gpu_lane_score!==undefined ? (policy.heuristic_gpu_lane_score*100).toFixed(1)+'%' : '-')+
    row('Model score', policy.model_gpu_lane_score!==undefined && policy.model_gpu_lane_score!==null ? (policy.model_gpu_lane_score*100).toFixed(1)+'%' : '-')+
    row('Recommended jobs', policy.recommended_parallel_jobs)+
    row('Recommend metal-first', policy.recommend_metal_first ? badge('yes','b-green') : badge('no','b-yellow'))+
    row('Policy trace', ane.latest_trace_path || policy.trace_path)+
    (policy.notes ? `<div class="small" style="margin-top:8px">${policy.notes.join(' ')}</div>` : '');

  document.getElementById('umpg').innerHTML = `<h2>UMPG State</h2>`+
    row('Generic proving surface', umpg.generic_proving_surface)+
    row('Wrapper surface', umpg.wrapper_surface)+
    row('Backend prove under UMPG', umpg.backend_prove_under_umpg ? badge('yes','b-green') : badge('no','b-red'))+
    row('Wrapper runtime-native', umpg.wrapper_outer_prove_native_under_runtime ? badge('yes','b-green') : badge('no','b-red'))+
    row('Public proving routes', Object.entries(umpg.public_proving_routes||{}).map(([k,v])=>`${k}:${v.via_umpg_backend_prove?'umpg':'direct'}`).join(', '))+
    row('Public wrap routes', Object.entries(umpg.public_wrap_routes||{}).map(([k,v])=>`${k}:${v.via_runtime_wrap?'runtime':'direct'}`).join(', '))+
    (umpg.notes ? `<div class="small" style="margin-top:8px">${umpg.notes.join(' ')}</div>` : '');

  const memVals = [];
  if (soak.warm_cycles) for (const c of soak.warm_cycles.slice(-24)) memVals.push((c.runtime_trace?.gpu_stage_busy_ratio||0)*100);
  document.getElementById('machine').innerHTML = `<h2>Machine Metrics</h2>`+
    row('CPU speed limit', `${therm.cpu_speed_limit ?? 100}%`)+
    row('Thermal pressure', therm.thermal_pressure || '-')+
    row('Power source', therm.power_source || '-')+
    row('Battery', therm.battery_state!==undefined && therm.battery_state!==null ? therm.battery_state+'%' : '-')+
    row('RAM utilization', mem.utilization_pct!==undefined ? mem.utilization_pct.toFixed(1)+'%' : '-')+
    row('Memory pressure', mem.pressure_level || '-')+
    row('Total RAM', fmtBytes(mem.ram_total_bytes))+
    row('RAM used', fmtBytes(mem.ram_used_bytes))+
    row('Swap used', fmtBytes(mem.swap_used_bytes))+
    `<div class="small" style="margin-top:8px">Recent GPU busy trend</div>` + spark(memVals, 'var(--green)');

  const nativeBackends = (d.backend_matrix?.native_backends || []).join(', ');
  const delegatedBackends = (d.backend_matrix?.delegated_backends || []).join(', ');
  const readyRealBackends = (d.backend_matrix?.ready_real_backends || []).join(', ');
  const compatAliases = Object.entries(d.backend_matrix?.compat_aliases || {}).map(([k,v])=>`${k}:${v}`).join(', ');
  const blockedNative = d.backend_matrix?.blocked_native_backends || [];
  document.getElementById('workspace').innerHTML = `<h2>Workspace / Capabilities</h2>`+
    row('Projects', ws.project_count)+
    row('Session note', ws.session_note)+
    row('Proof files', (ws.proof_files||[]).join(', '))+
    row('Export files', (ws.export_files||[]).join(', '))+
    row('Capability source', d.backend_matrix?.source || '-')+
    row('Ready real backends', readyRealBackends || '-')+
    row('Native backends', nativeBackends)+
    row('Delegated backends', delegatedBackends)+
    row('Compat aliases', compatAliases || '-')+
    row('Fastest native', d.backend_matrix?.fastest_native ? `${d.backend_matrix.fastest_native.name} (${d.backend_matrix.fastest_native.prove_time_ms} ms)` : '-')+
    (blockedNative.length ? `<div class="small" style="margin:8px 0 4px">Blocked native backends</div><table><thead><tr><th>Name</th><th>Reason</th><th>Action</th></tr></thead><tbody>${
      blockedNative.map(b=>`<tr><td>${esc(b.name || '-')}</td><td>${esc(b.readiness_reason || b.readiness || '-')}</td><td>${esc(b.operator_action || '-')}</td></tr>`).join('')
    }</tbody></table>` : `<div class="small" style="margin-top:8px">No blocked native backends.</div>`);

  document.getElementById('sources').innerHTML = `<h2>Assistant / Sources</h2>`+
    row('Assistant bundle', d.assistant.path)+
    row('Context file', d.assistant.context_path)+
    row('Bundle refresh', d.assistant.refresh ? (d.assistant.refresh.ok ? badge('ok','b-green') : badge('failed','b-red')) : badge('manual','b-blue'))+
    row('Rules', (d.assistant_rules||[]).length)+
    row('Next actions', (d.recommended_next_actions||[]).length)+
    `<div class="list" style="margin-top:8px">`+
    (d.recommended_next_actions||[]).slice(0,6).map(x=>`<div class="small">• ${esc(x)}</div>`).join('')+
    `</div>`+
    `<div class="list" style="margin-top:8px">`+
    (d.official_sources||[]).slice(0,4).map(s=>`<div class="small"><a href="${s.url}" target="_blank">${esc(s.label)}</a></div>`).join('')+
    `</div>`;

  let soakHtml = `<h2>Soak / Runtime Detail</h2>`;
  if(!soak || !soak.progress){ soakHtml += `<div class="small">No soak directory data available.</div>`; }
  else {
    const active = soak.active_logs || {};
    soakHtml += row('Active label', prog.active_label || '-')+
      row('Updated', prog.updated_at_unix_ms ? new Date(prog.updated_at_unix_ms).toLocaleString() : '-')+
      row('Strict GPU peak', prog.strict_gpu_busy_ratio_peak!==undefined ? (prog.strict_gpu_busy_ratio_peak*100).toFixed(1)+'%' : '-')+
      row('Warm GPU', prog.warm_gpu_stage_busy_ratio!==undefined ? (prog.warm_gpu_stage_busy_ratio*100).toFixed(1)+'%' : '-')+
      row('Parallel GPU peak', prog.parallel_gpu_stage_busy_ratio_peak!==undefined ? (prog.parallel_gpu_stage_busy_ratio_peak*100).toFixed(1)+'%' : '-');
    if (active.stderr_tail || active.stdout_tail) {
      soakHtml += `<div class="grid g2" style="margin-top:10px">`;
      soakHtml += `<div><div class="small">stderr tail ${active.stderr_path ? '('+esc(active.stderr_path)+')' : ''}</div><pre>${esc(active.stderr_tail || '')}</pre></div>`;
      soakHtml += `<div><div class="small">stdout tail ${active.stdout_path ? '('+esc(active.stdout_path)+')' : ''}</div><pre>${esc(active.stdout_tail || '')}</pre></div>`;
      soakHtml += `</div>`;
    }
  }
  document.getElementById('soak').innerHTML = soakHtml;
}

async function poll(){
  try{ const res = await fetch('/api/data'); render(await res.json()); }
  catch(err){ console.error(err); }
}
poll(); setInterval(poll, 5000);
</script>
</body></html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    soak_dir: Path = DEFAULT_SOAK_DIR
    auto_refresh_bundle: bool = False

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/api/data":
            payload = collect_system_payload(self.soak_dir, self.auto_refresh_bundle)
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="Permanent ZKF system dashboard")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--dir", type=str, default=str(DEFAULT_SOAK_DIR), help="Optional soak directory to include")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--auto-refresh-bundle", action="store_true", help="Regenerate the assistant bundle at most once per minute")
    args = parser.parse_args()

    DashboardHandler.soak_dir = Path(args.dir)
    DashboardHandler.auto_refresh_bundle = args.auto_refresh_bundle
    server = HTTPServer(("127.0.0.1", args.port), DashboardHandler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"ZKF system dashboard running at {url}")
    print(f"Soak source: {DashboardHandler.soak_dir}")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
