import { createInterface } from 'node:readline';

import { HelperRpcServer } from './rpc.js';

const server = new HelperRpcServer();

function writeResponse(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

async function main(): Promise<void> {
  const rl = createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  rl.on('line', async (line) => {
    if (!line.trim()) {
      return;
    }
    let request: unknown;
    try {
      request = JSON.parse(line);
    } catch (error) {
      writeResponse({
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32700,
          message: error instanceof Error ? error.message : String(error),
        },
      });
      return;
    }

    const response = await server.handleRequest(
      request as Parameters<HelperRpcServer['handleRequest']>[0],
    );
    writeResponse(response);
  });

  rl.on('close', async () => {
    await server.closeAll();
  });
}

main().catch(async (error: unknown) => {
  writeResponse({
    jsonrpc: '2.0',
    id: null,
    error: {
      code: -32001,
      message: error instanceof Error ? error.stack ?? error.message : String(error),
    },
  });
  await server.closeAll();
  process.exitCode = 1;
});
