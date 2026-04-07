# ZirOS Twitter/X MCP

Private operator-only MCP server for `@jacobiproves`.

This project is intentionally local:

- Reads OAuth credentials from macOS Keychain.
- Runs as a local stdio MCP server.
- Fails closed on blocked writes instead of falling back to browser automation.
- Logs engagement activity to `~/.jacobian/workspace/engagement-log.jsonl`.
- Is not part of `zkf`, `zkf-sdk`, `zkf.h`, or the public attestation repo.

## Build

```bash
cd /Users/sicarii/Desktop/ZirOS/ziros-twitter-mcp
npm install
npm run build
```

## Local MCP registration

Register the built server in `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "ziros-twitter": {
      "command": "node",
      "args": ["/Users/sicarii/Desktop/ZirOS/ziros-twitter-mcp/build/src/index.js"],
      "env": {
        "TWITTER_USER_ID": "2027436400422096900",
        "TWITTER_USERNAME": "jacobiproves",
        "ENGAGEMENT_LOG_PATH": "/Users/sicarii/.jacobian/workspace/engagement-log.jsonl",
        "JACOBIAN_SCRIPTS": "/Users/sicarii/.jacobian/scripts"
      }
    }
  }
}
```

## Codex automation integration

This server is passive. It does not schedule work.

Codex automations are the only orchestrator:

- Weekly attestation automation calls `tweet_attestation`.
- Conformance automations call `tweet_conformance`.
- Proof/release automations call `tweet_proof_result` or `post_thread`.
- Engagement automations call `search_tweets`, `like_tweet`, `quote_tweet`, `retweet`, and `get_engagement_log`.
- If the MCP mount is unavailable inside a Codex automation session, the automation should fall back to local Jacobian scripts rather than browser automation.
