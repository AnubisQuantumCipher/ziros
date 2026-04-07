import { Buffer } from 'node:buffer';

import { ApiPromise, WsProvider } from '@polkadot/api';
import type { ApiOptions } from '@polkadot/api/types';
import { type FinalizedTransaction } from '@midnight-ntwrk/ledger-v8';
import { findUnknownExtensions } from '@polkadot/types/extrinsic/signedExtensions';
import type { ExtDef } from '@polkadot/types/extrinsic/signedExtensions/types';

import type {
  ProbeOutcome,
  ProbeValidationResult,
} from './compatibility.js';
import type { MidnightRuntimeConfig } from './config.js';

export interface MidnightSignedExtensionStatus {
  runtimeSignedExtensions: string[];
  injectedSignedExtensions: string[];
  unknownSignedExtensions: string[];
}

export const MIDNIGHT_ZERO_LENGTH_SIGNED_EXTENSIONS = {
  CheckCallFilter: { extrinsic: {}, payload: {} },
  CheckThrottle: { extrinsic: {}, payload: {} },
} satisfies ExtDef;

const INJECTED_SIGNED_EXTENSION_NAMES = Object.keys(
  MIDNIGHT_ZERO_LENGTH_SIGNED_EXTENSIONS,
);

function errorRecord(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack ?? null,
      code:
        'code' in error && typeof error.code === 'number'
          ? error.code
          : 'code' in error && typeof error.code === 'string'
            ? error.code
            : null,
      data: 'data' in error ? error.data ?? null : null,
    };
  }
  return { message: String(error) };
}

function classifyOutcome(error: unknown): ProbeOutcome {
  const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  if (/panic/i.test(message) || /wasm trap/i.test(message)) {
    return 'panic';
  }
  return 'error';
}

function wsUrl(rpcUrl: string): string {
  return rpcUrl.replace(/^http/, 'ws');
}

export function finalizedTransactionToInnerTxHex(tx: FinalizedTransaction): string {
  return `0x${Buffer.from(tx.serialize()).toString('hex')}`;
}

export function finalizedTransactionId(tx: FinalizedTransaction): string {
  const txId = tx.identifiers().at(-1);
  if (!txId) {
    throw new Error('Finalized Midnight transaction did not expose an identifier.');
  }
  return String(txId);
}

export async function createMidnightApi(
  config: MidnightRuntimeConfig,
): Promise<ApiPromise> {
  const options: ApiOptions = {
    provider: new WsProvider(wsUrl(config.rpcUrl)),
    signedExtensions: MIDNIGHT_ZERO_LENGTH_SIGNED_EXTENSIONS,
  };
  return ApiPromise.create(options);
}

export async function withMidnightApi<T>(
  config: MidnightRuntimeConfig,
  task: (api: ApiPromise) => Promise<T>,
): Promise<T> {
  const api = await createMidnightApi(config);
  try {
    return await task(api);
  } finally {
    await api.disconnect();
  }
}

export function describeMidnightSignedExtensions(
  api: ApiPromise,
): MidnightSignedExtensionStatus {
  const runtimeSignedExtensions = [...api.registry.signedExtensions];
  return {
    runtimeSignedExtensions,
    injectedSignedExtensions: [...INJECTED_SIGNED_EXTENSION_NAMES],
    unknownSignedExtensions: findUnknownExtensions(
      runtimeSignedExtensions,
      MIDNIGHT_ZERO_LENGTH_SIGNED_EXTENSIONS,
    ),
  };
}

export function assertSupportedMidnightSignedExtensions(
  api: ApiPromise,
): MidnightSignedExtensionStatus {
  const status = describeMidnightSignedExtensions(api);
  if (status.unknownSignedExtensions.length > 0) {
    throw new Error(
      `Midnight runtime advertised unsupported signed extensions: ${status.unknownSignedExtensions.join(', ')}.`,
    );
  }
  return status;
}

export function buildMidnightOuterTx(
  innerTxHex: string,
  api: ApiPromise,
): string {
  assertSupportedMidnightSignedExtensions(api);
  return api.tx.midnight.sendMnTransaction(innerTxHex).toHex();
}

export async function validateMidnightOuterTx(
  outerTxHex: string,
  api: ApiPromise,
): Promise<ProbeValidationResult[]> {
  assertSupportedMidnightSignedExtensions(api);
  const bestHash = await api.rpc.chain.getBlockHash();
  const results: ProbeValidationResult[] = [];

  for (const source of ['External', 'Local', 'InBlock'] as const) {
    try {
      const validity = await api.call.taggedTransactionQueue.validateTransaction(
        source,
        outerTxHex,
        bestHash,
      );
      results.push({
        source,
        outcome: 'accepted',
        detail: validity.toString(),
        raw: {
          human: validity.toHuman?.() ?? null,
          json: validity.toJSON?.() ?? null,
          text: validity.toString(),
        },
      });
    } catch (error) {
      results.push({
        source,
        outcome: classifyOutcome(error),
        detail: error instanceof Error ? error.message : String(error),
        raw: errorRecord(error),
      });
    }
  }

  return results;
}

export async function submitMidnightOuterTx(
  outerTxHex: string,
  api: ApiPromise,
): Promise<string> {
  assertSupportedMidnightSignedExtensions(api);
  const txHash = await api.rpc.author.submitExtrinsic(outerTxHex);
  return txHash.toString();
}

export async function submitFinalizedMidnightTx(
  tx: FinalizedTransaction,
  config: MidnightRuntimeConfig,
): Promise<{
  txId: string;
  outerTxHex: string;
  outerTxHash: string;
  signedExtensions: MidnightSignedExtensionStatus;
}> {
  const innerTxHex = finalizedTransactionToInnerTxHex(tx);
  const txId = finalizedTransactionId(tx);
  return withMidnightApi(config, async (api) => {
    const signedExtensions = assertSupportedMidnightSignedExtensions(api);
    const outerTxHex = buildMidnightOuterTx(innerTxHex, api);
    const outerTxHash = await submitMidnightOuterTx(outerTxHex, api);
    return {
      txId,
      outerTxHex,
      outerTxHash,
      signedExtensions,
    };
  });
}
