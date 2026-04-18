# ZirOS Agent Quickstart

This is the shortest supported path from checkout to first autonomous prompt on
an Apple Silicon Mac.

## 1. Install Or Build The Public Command Alias

Public install:

```bash
npm install -g @ziros/agent
ziros setup
```

From the repo root, if you are working from source:

```bash
mkdir -p "$HOME/.ziros"
cp examples/agent/ziros-agent.env.example "$HOME/.ziros/agent.env"
$EDITOR "$HOME/.ziros/agent.env"
source "$HOME/.ziros/agent.env"
bash setup/agent/bootstrap.sh
ziros setup --non-interactive
```

What the bootstrap does:

- verifies macOS on Apple Silicon
- builds `zkf` and `ziros-agentd` in release mode
- installs managed binaries into `~/.ziros/bin/`
- installs `ziros` and `zkf` compatibility symlinks into `~/.local/bin`
- runs the doctor chain for the agent, Metal, Midnight, and EVM lanes

If you only want validation:

```bash
bash setup/agent/bootstrap.sh --check-only
```

## 2. Confirm The Runtime

Run the canonical checks:

```bash
ziros doctor --json
ziros metal-doctor --json
ziros agent --json doctor
ziros agent --json provider status
ziros agent --json bridge status
ziros agent --json browser status
ziros agent --json web fetch --url https://platform.openai.com/docs/guides/tools-shell
ziros midnight doctor --json --network preprod
ziros evm diagnose --json
```

Interpretation:

- `ziros doctor` checks the CLI/runtime surface
- `ziros metal-doctor` checks the Apple Silicon proof lane
- `ziros agent doctor` checks the agent trust gate and workgraph posture
- `ziros agent provider status` shows direct local/provider routing
- `ziros agent bridge status` shows whether the ChatGPT Pro bridge is the primary reasoning lane
- `ziros agent browser status` shows whether Safari or Chrome are available for GUI automation
- `ziros agent web fetch` resolves official docs and redirects without relying on a GUI browser
- `ziros midnight doctor` checks contract tooling and network readiness
- `ziros evm diagnose` checks Foundry/Anvil-style secondary-lane readiness

## 3. Start The Daemon

Use the installed daemon:

```bash
ziros-agentd
```

The default socket is:

```text
~/.ziros/agent/ziros-agentd.sock
```

If you want the optional macOS shell, build it separately after the daemon is
running:

```bash
swift build --package-path ZirOSAgentHost
swift run --package-path ZirOSAgentHost
```

## 4. Give The Agent A First Prompt

Repo analysis:

```bash
ziros agent --json run \
  --events-jsonl /tmp/ziros-agent.events.jsonl \
  --goal "Inspect this ZirOS checkout, summarize the current operator state, and tell me what you can do next."
```

If you want a specific OpenAI model instead of the env default:

```bash
ziros agent --json run \
  --provider openai-api \
  --model gpt-5.2-codex \
  --goal "Inspect this ZirOS checkout and summarize the current operator state."
```

On OpenAI-compatible assistant routes, the selected model is used during
goal-intent compilation. If that call fails, ZirOS falls back to the embedded
planner.

If you use the ChatGPT Pro bridge, the bridge-side `GPT-5.4 Thinking` label is
tracked separately from direct provider model ids. Use `ziros agent --json
bridge status` to confirm the bridge-first lane and fail-closed posture before
running critical implementation, audit, proof, or release tasks.

If you need to repair or verify an official doc URL and the browser path is not
available, use `ziros agent --json web fetch --url ...` first. It follows
redirects and returns the final URL, canonical URL, title, and same-host links
from allowlisted official hosts.

If the page is genuinely interactive, escalate to:

```bash
ziros agent --json browser open --url https://platform.openai.com/docs/guides/tools-shell --browser chrome
ziros agent --json browser eval --browser chrome --script 'return { title: document.title, href: location.href }'
```

Subsystem creation:

```bash
ziros agent --json run \
  --goal "Create a new subsystem named mission-policy-ledger with a Midnight-first contract surface and a public evidence bundle."
```

Midnight-first contract work:

```bash
ziros agent --json run \
  --goal "Scaffold a private-voting subsystem, prove it, and prepare the Midnight deployment artifacts."
```

## 5. Inspect What The Agent Learned

After the first run:

```bash
ziros agent status --limit 10
ziros agent memory sessions --limit 10
ziros agent memory procedures
ziros agent memory incidents
ziros agent memory artifacts
ziros agent memory environments
```

The agent does not become more capable by vague self-modification. It improves
through persisted local memory:

- procedures from successful runs
- incidents from failed runs
- project registration
- worktrees and checkpoints
- provider-route history
- artifact and deployment lineage

## 6. Next Docs

- [Apple Silicon Setup](SETUP_APPLE_SILICON.md)
- [Memory And Learning](MEMORY_AND_LEARNING.md)
- [First Prompts](FIRST_PROMPTS.md)
- [Troubleshooting](TROUBLESHOOTING.md)
