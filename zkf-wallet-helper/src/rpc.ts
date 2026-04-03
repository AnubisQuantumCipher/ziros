import type { MidnightHelperSession } from './providers.js';
import type {
  BuildIntentRequest,
  BuildSelfTransferRequest,
  BuildTransferRequest,
  DustOperationRequest,
  FinalizeAndSubmitRequest,
  MailboxPollRequest,
  MailboxPostRequest,
  MailboxTransportProbeRequest,
  OpenWalletSessionRequest,
  SyncRequest,
} from './types.js';

type JsonRpcId = string | number | null;

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: JsonRpcId;
  method: string;
  params?: unknown;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: JsonRpcId;
  result?: unknown;
  error?: {
    code: number;
    message: string;
  };
}

export class HelperRpcServer {
  private readonly sessions = new Map<string, MidnightHelperSession>();

  async closeAll(): Promise<void> {
    for (const session of this.sessions.values()) {
      await session.stop();
    }
    this.sessions.clear();
  }

  async handleRequest(request: JsonRpcRequest): Promise<JsonRpcResponse> {
    try {
      if (request.jsonrpc !== '2.0') {
        throw new Error('Only JSON-RPC 2.0 requests are supported');
      }
      const result = await this.dispatch(request.method, request.params);
      return {
        jsonrpc: '2.0',
        id: request.id,
        result,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        jsonrpc: '2.0',
        id: request.id,
        error: {
          code: -32000,
          message,
        },
      };
    }
  }

  private async dispatch(method: string, params: unknown): Promise<unknown> {
    switch (method) {
      case 'openWalletSession': {
        const { MidnightHelperSession } = await import('./providers.js');
        const { session, response } = await MidnightHelperSession.open(
          params as OpenWalletSessionRequest,
        );
        this.sessions.set(session.sessionId, session);
        return response;
      }
      case 'closeWalletSession': {
        const session = this.requireSession((params as { sessionId: string }).sessionId);
        await session.stop();
        this.sessions.delete(session.sessionId);
        return { closed: true };
      }
      case 'sync':
        return this.requireSession((params as SyncRequest).sessionId).sync(params as SyncRequest);
      case 'getOverview':
        return this.requireSession((params as { sessionId: string }).sessionId).getOverview();
      case 'getBalances':
        return this.requireSession((params as { sessionId: string }).sessionId).getBalances();
      case 'getAddresses':
        return this.requireSession((params as { sessionId: string }).sessionId).getAddresses();
      case 'listDustCandidates':
        return this.requireSession((params as { sessionId: string }).sessionId).listDustCandidates();
      case 'getActivity':
        return this.requireSession((params as { sessionId: string }).sessionId).getActivity();
      case 'getConfiguration':
        return this.requireSession((params as { sessionId: string }).sessionId).getConfiguration();
      case 'getConnectionStatus':
        return this.requireSession((params as { sessionId: string }).sessionId).getConnectionStatus();
      case 'buildTransfer':
        return this.requireSession((params as BuildTransferRequest).sessionId).buildTransfer(
          params as BuildTransferRequest,
        );
      case 'buildIntent':
        return this.requireSession((params as BuildIntentRequest).sessionId).buildIntent(
          params as BuildIntentRequest,
        );
      case 'buildShield':
        return this.requireSession((params as BuildSelfTransferRequest).sessionId).buildShield(
          params as BuildSelfTransferRequest,
        );
      case 'buildUnshield':
        return this.requireSession((params as BuildSelfTransferRequest).sessionId).buildUnshield(
          params as BuildSelfTransferRequest,
        );
      case 'registerDust':
        return this.requireSession((params as DustOperationRequest).sessionId).registerDust(
          params as DustOperationRequest,
        );
      case 'deregisterDust':
        return this.requireSession((params as DustOperationRequest).sessionId).deregisterDust(
          params as DustOperationRequest,
        );
      case 'redesignateDust':
        return this.requireSession((params as DustOperationRequest).sessionId).redesignateDust(
          params as DustOperationRequest,
        );
      case 'finalizeAndSubmit':
        return this.requireSession((params as FinalizeAndSubmitRequest).sessionId).finalizeAndSubmit(
          params as FinalizeAndSubmitRequest,
        );
      case 'probeMailboxTransport':
        return this.requireSession((params as MailboxTransportProbeRequest).sessionId).probeMailboxTransport(
          params as MailboxTransportProbeRequest,
        );
      case 'postMailboxEnvelope':
        return this.requireSession((params as MailboxPostRequest).sessionId).postMailboxEnvelope(
          params as MailboxPostRequest,
        );
      case 'pollMailboxEnvelopes':
        return this.requireSession((params as MailboxPollRequest).sessionId).pollMailboxEnvelopes(
          params as MailboxPollRequest,
        );
      default:
        throw new Error(`Unsupported helper method '${method}'`);
    }
  }

  private requireSession(sessionId: string): MidnightHelperSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Unknown helper session '${sessionId}'`);
    }
    return session;
  }
}

export type { JsonRpcRequest, JsonRpcResponse };
