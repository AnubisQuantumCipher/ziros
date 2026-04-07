import { Buffer } from 'node:buffer';

import { LedgerParameters, type FinalizedTransaction } from '@midnight-ntwrk/ledger-v8';
import {
  createUnprovenCallTx,
  createUnprovenDeployTx,
} from '@midnight-ntwrk/midnight-js-contracts';
import { sampleSigningKey } from '@midnight-ntwrk/compact-runtime';

import { loadCompiledContract, type LoadedContractArtifacts } from './artifacts.js';
import { type MidnightRuntimeConfig } from './config.js';
import { type ContractKey } from './contracts.js';
import {
  type MidnightWalletProvider,
  createDeployProviders,
} from './providers.js';
import { type AttestationWitnessPayload } from './witness-data.js';

export interface PreparedMidnightTransaction {
  contractKey: ContractKey;
  loaded: LoadedContractArtifacts;
  providers: ReturnType<typeof createDeployProviders>;
  balancedTx: FinalizedTransaction;
  innerTxHex: string;
  txId: string;
  serializedLength: number;
  cost: {
    readTime: string;
    computeTime: string;
    blockUsage: string;
    bytesWritten: string;
    bytesChurned: string;
  };
  contractAddress?: string;
  nextContractState?: unknown;
}

function txInspection(tx: FinalizedTransaction) {
  const params = LedgerParameters.initialParameters();
  const cost = tx.cost(params);
  return {
    serializedLength: tx.serialize().length,
    cost: {
      readTime: cost.readTime.toString(),
      computeTime: cost.computeTime.toString(),
      blockUsage: cost.blockUsage.toString(),
      bytesWritten: cost.bytesWritten.toString(),
      bytesChurned: cost.bytesChurned.toString(),
    },
  };
}

function requireTxId(tx: FinalizedTransaction): string {
  const txId = tx.identifiers().at(-1);
  if (!txId) {
    throw new Error('Balanced Midnight transaction did not expose a transaction identifier.');
  }
  return String(txId);
}

function serializeInnerTx(tx: FinalizedTransaction): string {
  return `0x${Buffer.from(tx.serialize()).toString('hex')}`;
}

export async function buildPreparedDeployTransaction(
  contractKey: ContractKey,
  payload: AttestationWitnessPayload,
  walletProvider: MidnightWalletProvider,
  config: MidnightRuntimeConfig,
): Promise<PreparedMidnightTransaction> {
  const loaded = await loadCompiledContract(contractKey, { payload, config });
  const providers = createDeployProviders(
    config,
    loaded.artifactDir,
    walletProvider,
    `ziros-attestation-${contractKey}`,
    config.provingMode,
  );
  const deployTxData = await createUnprovenDeployTx(
    {
      zkConfigProvider: providers.zkConfigProvider,
      walletProvider: providers.walletProvider,
    },
    {
      compiledContract: loaded.compiledContract as never,
      args: [],
      signingKey: sampleSigningKey(),
    },
  );
  const provenTx = await providers.proofProvider.proveTx(deployTxData.private.unprovenTx);
  const balancedTx = await walletProvider.balanceTx(provenTx);
  const inspection = txInspection(balancedTx);

  return {
    contractKey,
    loaded,
    providers,
    balancedTx,
    innerTxHex: serializeInnerTx(balancedTx),
    txId: requireTxId(balancedTx),
    serializedLength: inspection.serializedLength,
    cost: inspection.cost,
    contractAddress: String(deployTxData.public.contractAddress),
  };
}

export async function buildPreparedCallTransaction(
  contractKey: ContractKey,
  payload: AttestationWitnessPayload,
  walletProvider: MidnightWalletProvider,
  config: MidnightRuntimeConfig,
  contractAddress: string,
  contractSnapshots?: Partial<Record<ContractKey, Record<string, unknown>>>,
): Promise<PreparedMidnightTransaction> {
  const loaded = await loadCompiledContract(contractKey, {
    payload,
    config,
    contractSnapshots,
  });
  const providers = createDeployProviders(
    config,
    loaded.artifactDir,
    walletProvider,
    `ziros-attestation-${contractKey}`,
    config.provingMode,
  );
  const callTxData = await createUnprovenCallTx(providers as never, {
    compiledContract: loaded.compiledContract as never,
    contractAddress: contractAddress as never,
    circuitId: loaded.contract.circuitId as never,
    args: [],
  } as never);
  const provenTx = await providers.proofProvider.proveTx(callTxData.private.unprovenTx);
  const balancedTx = await walletProvider.balanceTx(provenTx);
  const inspection = txInspection(balancedTx);

  return {
    contractKey,
    loaded,
    providers,
    balancedTx,
    innerTxHex: serializeInnerTx(balancedTx),
    txId: requireTxId(balancedTx),
    serializedLength: inspection.serializedLength,
    cost: inspection.cost,
    contractAddress,
    nextContractState: callTxData.public.nextContractState,
  };
}
