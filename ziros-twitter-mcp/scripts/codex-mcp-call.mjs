#!/usr/bin/env node

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

function usage() {
  console.error("Usage: node scripts/codex-mcp-call.mjs <tool_name> [json_args]");
  process.exit(2);
}

const toolName = process.argv[2];
if (!toolName) {
  usage();
}

let args = {};
if (process.argv[3]) {
  try {
    args = JSON.parse(process.argv[3]);
  } catch (error) {
    console.error(`Invalid JSON args: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(2);
  }
}

const transport = new StdioClientTransport({
  command: "node",
  args: [new URL("../build/src/index.js", import.meta.url).pathname],
  env: {
    ...process.env,
    TWITTER_USER_ID: process.env.TWITTER_USER_ID ?? "2027436400422096900",
    TWITTER_USERNAME: process.env.TWITTER_USERNAME ?? "jacobiproves",
    ENGAGEMENT_LOG_PATH: process.env.ENGAGEMENT_LOG_PATH ?? `${process.env.HOME}/.jacobian/workspace/engagement-log.jsonl`,
    JACOBIAN_SCRIPTS:
      process.env.JACOBIAN_SCRIPTS ?? process.env.OPENCLAW_SCRIPTS ?? `${process.env.HOME}/.jacobian/scripts`,
  },
});

const client = new Client({ name: "codex-cli", version: "1.0.0" }, { capabilities: {} });

try {
  await client.connect(transport);
  if (toolName === "__list_tools__") {
    const tools = await client.listTools();
    process.stdout.write(JSON.stringify(tools, null, 2));
  } else {
    const response = await client.callTool({ name: toolName, arguments: args });
    const text = response.content
      ?.filter((item) => item.type === "text")
      .map((item) => item.text ?? "")
      .join("\n");
    process.stdout.write(text && text.length > 0 ? text : JSON.stringify(response, null, 2));
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
} finally {
  await client.close().catch(() => {});
}
