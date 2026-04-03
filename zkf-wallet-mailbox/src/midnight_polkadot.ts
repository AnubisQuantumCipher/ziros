import { Buffer } from 'node:buffer';

import { ApiPromise, WsProvider } from '@polkadot/api';
import type { ApiOptions } from '@polkadot/api/types';
import type { FinalizedTransaction } from '@midnight-ntwrk/ledger-v8';
import { findUnknownExtensions } from '@polkadot/types/extrinsic/signedExtensions';
import type { ExtDef } from '@polkadot/types/extrinsic/signedExtensions/types';

import type { MidnightRuntimeConfig } from './runtime.js';

export const MIDNIGHT_ZERO_LENGTH_SIGNED_EXTENSIONS = {
  CheckCallFilter: { extrinsic: {}, payload: {} },
  CheckThrottle: { extrinsic: {}, payload: {} },
} satisfies ExtDef;

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

export async function createMidnightApi(config: MidnightRuntimeConfig): Promise<ApiPromise> {
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

export function assertSupportedMidnightSignedExtensions(api: ApiPromise): void {
  const unknownSignedExtensions = findUnknownExtensions(
    [...api.registry.signedExtensions],
    MIDNIGHT_ZERO_LENGTH_SIGNED_EXTENSIONS,
  );
  if (unknownSignedExtensions.length > 0) {
    throw new Error(
      `Midnight runtime advertised unsupported signed extensions: ${unknownSignedExtensions.join(', ')}.`,
    );
  }
}

export function buildMidnightOuterTx(innerTxHex: string, api: ApiPromise): string {
  assertSupportedMidnightSignedExtensions(api);
  return api.tx.midnight.sendMnTransaction(innerTxHex).toHex();
}

export async function validateMidnightOuterTx(
  outerTxHex: string,
  api: ApiPromise,
): Promise<Array<{ source: string; outcome: string; detail: string }>> {
  assertSupportedMidnightSignedExtensions(api);
  const bestHash = await api.rpc.chain.getBlockHash();
  const results: Array<{ source: string; outcome: string; detail: string }> = [];

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
      });
    } catch (error) {
      results.push({
        source,
        outcome: 'error',
        detail: error instanceof Error ? error.message : String(error),
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
