import type { ApiPromise } from '@polkadot/api';

import type { CompatibilityProfile, RuntimeWeightValue } from './compatibility.js';
import { getRuntimeConfig, type MidnightNetwork, type MidnightRuntimeConfig } from './config.js';
import {
  describeMidnightSignedExtensions,
  withMidnightApi as withConfiguredMidnightApi,
} from './midnight-polkadot.js';

function unknownToString(value: unknown): string {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (value == null) {
    return '';
  }
  return String(value);
}

function normalizeWeight(value: unknown): RuntimeWeightValue | null {
  if (!value || typeof value !== 'object') {
    return null;
  }
  const record = value as Record<string, unknown>;
  return {
    refTime: unknownToString(record.refTime ?? 0),
    proofSize: unknownToString(record.proofSize ?? 0),
  };
}

function normalizeCodec(value: unknown): unknown {
  if (value == null) {
    return null;
  }
  if (typeof value === 'bigint' || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeCodec(entry));
  }
  if (typeof value === 'object') {
    const maybeCodec = value as {
      toHuman?: () => unknown;
      toJSON?: () => unknown;
      toHex?: () => string;
      toString?: () => string;
    };
    if (typeof maybeCodec.toJSON === 'function') {
      return maybeCodec.toJSON();
    }
    if (typeof maybeCodec.toHuman === 'function') {
      return maybeCodec.toHuman();
    }
    if (typeof maybeCodec.toHex === 'function') {
      return maybeCodec.toHex();
    }
    if (typeof maybeCodec.toString === 'function') {
      return maybeCodec.toString();
    }
  }
  return String(value);
}

export async function withMidnightApi<T>(
  config: MidnightRuntimeConfig,
  task: (api: ApiPromise) => Promise<T>,
): Promise<T> {
  return withConfiguredMidnightApi(config, task);
}

export async function buildCompatibilityProfile(
  network: MidnightNetwork,
  overrides: Partial<MidnightRuntimeConfig> = {},
): Promise<CompatibilityProfile> {
  const config = getRuntimeConfig({ ...overrides, network });
  return withMidnightApi(config, async (api) => {
    const ledgerVersionCodec = await api.call.midnightRuntimeApi.getLedgerVersion();
    const midnightQueries = api.query.midnight as Record<string, (() => Promise<unknown>) | undefined>;
    const sizeWeightCodec = midnightQueries.configurableTransactionSizeWeight
      ? await midnightQueries.configurableTransactionSizeWeight()
      : null;
    const pausedCallsCodec = await api.query.txPause.pausedCalls.entries();
    const throttleKeys = Object.keys(api.query.throttle ?? {});

    let accountUsage: string | null = null;
    const operatorAccount = overrides.operatorSeed ?? overrides.operatorMnemonic ? undefined : undefined;
    void operatorAccount;
    try {
      const usageCodec = await api.query.throttle.accountUsage.entries();
      accountUsage = JSON.stringify(normalizeCodec(usageCodec), null, 2);
    } catch {
      accountUsage = null;
    }

    const signedExtensionStatus = describeMidnightSignedExtensions(api);

    return {
      observedAt: new Date().toISOString(),
      network,
      rpcUrl: config.rpcUrl,
      indexerUrl: config.indexerUrl,
      specVersion: api.runtimeVersion.specVersion.toString(),
      transactionVersion: api.runtimeVersion.transactionVersion.toString(),
      signedExtensions: signedExtensionStatus.runtimeSignedExtensions,
      injectedSignedExtensions: signedExtensionStatus.injectedSignedExtensions,
      unknownSignedExtensions: signedExtensionStatus.unknownSignedExtensions,
      rawLedgerVersion:
        typeof ledgerVersionCodec.toHex === 'function'
          ? ledgerVersionCodec.toHex()
          : unknownToString(normalizeCodec(ledgerVersionCodec)),
      configurableTransactionSizeWeight: normalizeWeight(normalizeCodec(sizeWeightCodec)),
      txPause: {
        pausedCalls: Array.isArray(pausedCallsCodec) ? pausedCallsCodec.length : 0,
      },
      throttle: {
        palletKeys: throttleKeys,
        accountUsage,
      },
    };
  });
}
