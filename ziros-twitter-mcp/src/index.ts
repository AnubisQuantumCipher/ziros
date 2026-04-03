import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { PROMPTS } from "./prompts/index.js";
import { RESOURCES } from "./resources/index.js";
import { ZirosTwitterMcp } from "./server.js";
import { TOOL_DEFINITIONS } from "./tools/definitions.js";

const app = new ZirosTwitterMcp();
const server = new Server(
  { name: "ziros-twitter", version: "1.0.0" },
  { capabilities: { tools: {}, resources: {}, prompts: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOL_DEFINITIONS.map((tool) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const args = (request.params.arguments ?? {}) as Record<string, unknown>;
  return app.callTool(request.params.name, args);
});

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: RESOURCES.map((resource) => ({
    uri: resource.uri,
    name: resource.name,
    description: resource.description,
    mimeType: "application/json",
  })),
}));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => ({
  contents: [
    {
      uri: request.params.uri,
      mimeType: "application/json",
      text: await app.readResource(request.params.uri),
    },
  ],
}));

server.setRequestHandler(ListPromptsRequestSchema, async () => ({
  prompts: PROMPTS.map((prompt) => ({
    name: prompt.name,
    description: prompt.description,
    arguments: prompt.arguments,
  })),
}));

server.setRequestHandler(GetPromptRequestSchema, async (request) =>
  app.getPrompt(
    request.params.name,
    ((request.params.arguments ?? {}) as Record<string, string | undefined>),
  ),
);

const transport = new StdioServerTransport();
await server.connect(transport);
