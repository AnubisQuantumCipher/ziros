interface HelperRpcServerLike {
  handleRequest(request: unknown): Promise<unknown>;
  closeAll(): Promise<void>;
}

interface HostCompatibilityReport {
  mode: string;
  bridgeLoaded: boolean;
  helperRootConfigured: boolean;
  hasWebCrypto: boolean;
  hasRandomUUID: boolean;
  hasWebSocket: boolean;
  runtimeAvailable: boolean;
  reason: string | null;
}

type JsonRpcEnvelope = {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
  };
};

let helperRootHref = '';
let serverPromise: Promise<HelperRpcServerLike> | null = null;

function normalizeRootHref(candidate: string): string {
  return candidate.endsWith('/') ? candidate : `${candidate}/`;
}

function compatibilityReport(reason?: string): HostCompatibilityReport {
  return {
    mode: 'webkit-bridge',
    bridgeLoaded: true,
    helperRootConfigured: helperRootHref.length > 0,
    hasWebCrypto: typeof globalThis.crypto?.subtle !== 'undefined',
    hasRandomUUID: typeof globalThis.crypto?.randomUUID === 'function',
    hasWebSocket: typeof (globalThis as { WebSocket?: unknown }).WebSocket !== 'undefined',
    runtimeAvailable: false,
    reason:
      reason ??
      'WebKit bridge is live, but the current Midnight wallet/testkit dependency graph is not yet browser-safe end to end.',
  };
}

function moduleURL(relativePath: string): string {
  return new URL(relativePath, helperRootHref).href;
}

async function probeModuleLoad(relativePath: string): Promise<{ ok: boolean; message?: string }> {
  try {
    await import(moduleURL(relativePath));
    return { ok: true };
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

async function buildCompatibilityReport(): Promise<HostCompatibilityReport> {
  if (!helperRootHref) {
    return compatibilityReport(
      'WebKit bridge loaded, but the helper root URL has not been configured by the native host yet.',
    );
  }

  const rpcProbe = await probeModuleLoad('./dist/src/rpc.js');
  if (!rpcProbe.ok) {
    return compatibilityReport(`WebKit helper RPC module failed to load: ${rpcProbe.message}`);
  }

  const providersProbe = await probeModuleLoad('./dist/src/providers.js');
  if (!providersProbe.ok) {
    return compatibilityReport(
      `Midnight provider graph is not yet browser-safe in WebKit: ${providersProbe.message}`,
    );
  }

  return {
    ...compatibilityReport(),
    runtimeAvailable: false,
    reason:
      'Core helper modules load in WebKit, but iPhone execution remains fail-closed until the Midnight session/prover/private-state lane is audited end to end.',
  };
}

function jsonRpcFailure(request: unknown, message: string): JsonRpcEnvelope {
  const requestId =
    request && typeof request === 'object' && 'id' in request ? (request as { id?: JsonRpcEnvelope['id'] }).id ?? null : null;
  return {
    jsonrpc: '2.0',
    id: requestId,
    error: {
      code: -32001,
      message,
    },
  };
}

async function ensureServer(): Promise<HelperRpcServerLike> {
  if (!helperRootHref) {
    throw new Error('webkit_runtime_unavailable: helper root URL is not configured');
  }
  if (!serverPromise) {
    serverPromise = import(moduleURL('./dist/src/rpc.js')).then(
      (module) => new module.HelperRpcServer() as HelperRpcServerLike,
    );
  }
  return serverPromise;
}

async function handleRequestInternal(request: unknown): Promise<unknown> {
  const server = await ensureServer();
  return server.handleRequest(request);
}

(globalThis as Record<string, unknown>).__zirosWalletHelper = {
  async bootstrap(helperRootURL: string): Promise<HostCompatibilityReport> {
    helperRootHref = normalizeRootHref(helperRootURL);
    return buildCompatibilityReport();
  },
  async probeHostCompatibility(): Promise<HostCompatibilityReport> {
    return buildCompatibilityReport();
  },
  async handleRequest(request: unknown): Promise<unknown> {
    try {
      return await handleRequestInternal(request);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return jsonRpcFailure(request, message);
    }
  },
  async handleRequestJSON(requestJSON: string): Promise<string> {
    let parsedRequest: unknown = null;
    try {
      parsedRequest = JSON.parse(requestJSON);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return JSON.stringify(jsonRpcFailure(null, `invalid_request: ${message}`));
    }

    const helperBridge = (globalThis as unknown as Record<
      string,
      { handleRequest: (request: unknown) => Promise<unknown> }
    >).__zirosWalletHelper;
    const response = await helperBridge.handleRequest(parsedRequest);
    return JSON.stringify(response);
  },
  async close(): Promise<void> {
    if (!serverPromise) {
      return;
    }
    const server = await serverPromise;
    await server.closeAll();
    serverPromise = null;
  },
};
