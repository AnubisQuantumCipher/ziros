# ChatGPT Bridge

ZirOS now exposes its existing MCP tool surface over HTTP so ChatGPT-facing
clients can plan remotely without bypassing the local ZirOS execution boundary.

## Architecture

- `ziros agent mcp serve` remains the canonical local stdio MCP surface.
- `ziros gateway serve` now also exposes that same MCP surface at `/mcp`.
- Remote MCP defaults to `remote-bridge-read-only`.
- Mutating work is handed off locally through `ziros agent bridge accept`.
- `ziros-agentd` remains the single execution authority and Brain owner.

This is not a second control plane. It is the same MCP semantics with a remote
transport wrapper.

## Hermes-Style Bridge Flow

```bash
ziros gateway setup
ziros gateway status --json
```

That installs and starts the local gateway plus the public tunnel, copies the
public MCP URL to your clipboard, and opens ChatGPT by default.

If you want foreground mode instead of the managed service:

```bash
ziros gateway serve --bind 127.0.0.1:8788
```

Managed lifecycle commands:

```bash
ziros gateway install
ziros gateway start
ziros gateway stop
ziros gateway restart
ziros gateway status --json
```

Key endpoints:

- `GET /mcp/health`
- `GET /mcp/manifest.json`
- `POST /mcp`

## Remote Planning Flow

List the exposed remote tools:

```bash
curl -sf -X POST http://127.0.0.1:8788/mcp \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Prepare a local handoff from a remote client:

```bash
curl -sf -X POST http://127.0.0.1:8788/mcp \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"agent_bridge_prepare","arguments":{"goal":"Prepare a Midnight-first subsystem plan for remote review."}}}'
```

Then accept it locally:

```bash
ziros agent --json bridge list
ziros agent --json bridge accept --handoff-id <handoff-id>
```

## Exposure Rules

Read-only remote MCP exposes planning, inspection, receipts, artifacts,
procedures, provider routing, and bridge preparation/listing.

It does not expose direct mutating tools like `agent_run`:

```bash
curl -sf -X POST http://127.0.0.1:8788/mcp \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"agent_run","arguments":{"goal":"This should not run remotely."}}}'
```

Expected result:

```json
{"jsonrpc":"2.0","id":3,"result":{"content":[{"text":"tool 'agent_run' is not exposed for remote-bridge-read-only","type":"text"}],"isError":true}}
```

## Optional Remote Writes

If you intentionally want the gateway to expose the mutating MCP toolset, start
it with:

```bash
ziros gateway serve --bind 127.0.0.1:8788 --allow-remote-writes
```

Do that only behind your own network and policy boundary. The default mode is
the safe one.
