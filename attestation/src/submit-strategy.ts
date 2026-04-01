import type { ApiPromise } from '@polkadot/api';
import type { FinalizedTransaction } from '@midnight-ntwrk/ledger-v8';

import type {
  MidnightSubmitStrategyId,
  ProbeOutcome,
  ProbeSubmitResult,
  ProbeValidationResult,
} from './compatibility.js';
import {
  buildMidnightOuterTx,
  submitMidnightOuterTx,
  validateMidnightOuterTx,
} from './midnight-polkadot.js';
import type { MidnightWalletProvider } from './providers.js';

interface SubmitStrategyContext {
  api: ApiPromise;
  wallet?: MidnightWalletProvider;
}

export interface MidnightSubmitStrategy {
  id: MidnightSubmitStrategyId;
  buildOuter(innerTxHex: string, api: ApiPromise): Promise<string>;
  validate(outerTxHex: string, api: ApiPromise): Promise<ProbeValidationResult[]>;
  submit(outerTxHex: string, api: ApiPromise, wallet?: MidnightWalletProvider): Promise<ProbeSubmitResult>;
}

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

function makeWalletSdkStrategy(finalizedTx: FinalizedTransaction): MidnightSubmitStrategy {
  return {
    id: 'wallet-sdk',
    async buildOuter(innerTxHex: string, api: ApiPromise): Promise<string> {
      return buildMidnightOuterTx(innerTxHex, api);
    },
    validate(outerTxHex: string, api: ApiPromise) {
      return validateMidnightOuterTx(outerTxHex, api);
    },
    async submit(_outerTxHex: string, _api: ApiPromise, wallet?: MidnightWalletProvider): Promise<ProbeSubmitResult> {
      if (!wallet) {
        return {
          strategy: 'wallet-sdk',
          outcome: 'error',
          txHash: null,
          detail: 'Wallet submit strategy requires a started Midnight wallet provider.',
        };
      }
      try {
        const txHash = await wallet.submitTx(finalizedTx);
        return {
          strategy: 'wallet-sdk',
          outcome: 'accepted',
          txHash,
          detail: `Wallet-backed submitter accepted Midnight transaction ${txHash}.`,
        };
      } catch (error) {
        return {
          strategy: 'wallet-sdk',
          outcome: classifyOutcome(error),
          txHash: null,
          detail: error instanceof Error ? error.message : String(error),
          raw: errorRecord(error),
        };
      }
    },
  };
}

function makeMetadataStrategy(innerTxHex: string): MidnightSubmitStrategy {
  return {
    id: 'metadata-midnight-extrinsic',
    async buildOuter(_innerTxHex: string, api: ApiPromise): Promise<string> {
      return buildMidnightOuterTx(innerTxHex, api);
    },
    validate(outerTxHex: string, api: ApiPromise) {
      return validateMidnightOuterTx(outerTxHex, api);
    },
    async submit(_outerTxHex: string, api: ApiPromise): Promise<ProbeSubmitResult> {
      try {
        const txHash = await new Promise<string>((resolve, reject) => {
          let unsubscribe: (() => void) | undefined;
          api.tx.midnight
            .sendMnTransaction(innerTxHex)
            .send((result) => {
              if (result.status.isInvalid) {
                unsubscribe?.();
                reject(new Error(`Transaction became invalid: ${result.status.toString()}`));
                return;
              }
              if (result.status.isInBlock || result.status.isFinalized) {
                unsubscribe?.();
                resolve(result.txHash.toString());
              }
            })
            .then((handle) => {
              unsubscribe = handle;
            })
            .catch(reject);
        });
        return {
          strategy: 'metadata-midnight-extrinsic',
          outcome: 'accepted',
          txHash,
          detail: `Metadata submit accepted transaction ${txHash}.`,
        };
      } catch (error) {
        return {
          strategy: 'metadata-midnight-extrinsic',
          outcome: classifyOutcome(error),
          txHash: null,
          detail: error instanceof Error ? error.message : String(error),
          raw: errorRecord(error),
        };
      }
    },
  };
}

function makeCompatNodeClientStrategy(innerTxHex: string): MidnightSubmitStrategy {
  return {
    id: 'compat-node-client',
    async buildOuter(_innerTxHex: string, api: ApiPromise): Promise<string> {
      return buildMidnightOuterTx(innerTxHex, api);
    },
    validate(outerTxHex: string, api: ApiPromise) {
      return validateMidnightOuterTx(outerTxHex, api);
    },
    async submit(outerTxHex: string, api: ApiPromise): Promise<ProbeSubmitResult> {
      try {
        const txHash = await submitMidnightOuterTx(outerTxHex, api);
        return {
          strategy: 'compat-node-client',
          outcome: 'accepted',
          txHash,
          detail: `Raw author_submitExtrinsic accepted transaction ${txHash}.`,
          raw: { innerTxHexLength: innerTxHex.length, outerTxHexLength: outerTxHex.length },
        };
      } catch (error) {
        return {
          strategy: 'compat-node-client',
          outcome: classifyOutcome(error),
          txHash: null,
          detail: error instanceof Error ? error.message : String(error),
          raw: errorRecord(error),
        };
      }
    },
  };
}

export function createSubmitStrategy(
  strategyId: MidnightSubmitStrategyId,
  finalizedTx: FinalizedTransaction,
  innerTxHex: string,
): MidnightSubmitStrategy {
  switch (strategyId) {
    case 'wallet-sdk':
      return makeWalletSdkStrategy(finalizedTx);
    case 'metadata-midnight-extrinsic':
      return makeMetadataStrategy(innerTxHex);
    case 'compat-node-client':
      return makeCompatNodeClientStrategy(innerTxHex);
  }
}

export async function probeSubmitStrategy(
  strategyId: MidnightSubmitStrategyId,
  finalizedTx: FinalizedTransaction,
  innerTxHex: string,
  context: SubmitStrategyContext,
): Promise<{
  outerTxHex: string;
  validation: ProbeValidationResult[];
  submit: ProbeSubmitResult;
}> {
  const strategy = createSubmitStrategy(strategyId, finalizedTx, innerTxHex);
  const outerTxHex = await strategy.buildOuter(innerTxHex, context.api);
  const validation = await strategy.validate(outerTxHex, context.api);
  const submit = await strategy.submit(outerTxHex, context.api, context.wallet);
  return {
    outerTxHex,
    validation,
    submit,
  };
}
