# ZirOSAgentHost

Thin macOS supervisory host for `ziros-agentd`.

## What it does

- connects directly to the local ZirOS agent Unix socket
- shows daemon health, recent sessions, registered projects, and append-only receipts
- lets an operator approve or reject wallet pending requests through the daemon-backed agent flow

## Build

```bash
swift build --package-path /Users/sicarii/Desktop/ZirOS/ZirOSAgentHost
```

## Xcode App Target

An XcodeGen specification is included so the host can be built as a real macOS
app bundle without changing the daemon-first architecture.

```bash
xcodegen generate --spec /Users/sicarii/Desktop/ZirOS/ZirOSAgentHost/project.yml
xcodebuild \
  -project /Users/sicarii/Desktop/ZirOS/ZirOSAgentHost/ZirOSAgentHost.xcodeproj \
  -scheme ZirOSAgentHost \
  -configuration Debug \
  -destination 'platform=macOS' \
  build
```

## Run

Start the daemon first:

```bash
cargo run -p zkf-agent --bin ziros-agentd
```

Then launch the host:

```bash
swift run --package-path /Users/sicarii/Desktop/ZirOS/ZirOSAgentHost
```

The default socket path is:

```text
~/.zkf/cache/agent/ziros-agentd.sock
```

## launchd

A development launchd wrapper is provided under:

```text
/Users/sicarii/Desktop/ZirOS/setup/launchd/com.ziros.agentd.plist
```

Load it with:

```bash
chmod +x /Users/sicarii/Desktop/ZirOS/setup/launchd/ziros-agentd-launch.sh
launchctl unload ~/Library/LaunchAgents/com.ziros.agentd.plist 2>/dev/null || true
cp /Users/sicarii/Desktop/ZirOS/setup/launchd/com.ziros.agentd.plist ~/Library/LaunchAgents/com.ziros.agentd.plist
launchctl load ~/Library/LaunchAgents/com.ziros.agentd.plist
```

The host continues to talk only to the daemon socket. It does not bypass the
agent runtime or call wallet or proof code directly.
