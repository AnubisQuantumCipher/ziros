---
name: ziros-command-routing
description: Route ZirOS operator work through the structured command surface before falling back to raw shell execution.
---

# ZirOS Command Routing

Use this order:

1. `ziros` or `zkf` CLI
2. `zkf-command-surface`
3. `zkf-agent` typed APIs or MCP tools
4. raw shell only when the structured surface does not exist

When a structured surface exists, use it.
