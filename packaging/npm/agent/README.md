# `@ziros/agent`

Thin npm installer for the ZirOS Apple-Silicon agent runtime.

This package does not ship ZirOS core source. It downloads a pinned ZirOS
binary bundle, verifies the bundle SHA-256 against the installer manifest, and
installs the managed binaries under `~/.ziros/bin/`.

Install:

```bash
npm install -g @ziros/agent
ziros setup
ziros
```

Local development:

```bash
npx @ziros/agent setup
```
