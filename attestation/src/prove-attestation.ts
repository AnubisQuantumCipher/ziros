import { writeFile } from 'node:fs/promises';
import { Buffer } from 'node:buffer';
import { resolve } from 'node:path';

import {
  LedgerParameters,
  LedgerState,
  TransactionContext,
  WellFormedStrictness,
  ZswapChainState,
  sampleCoinPublicKey,
  sampleEncryptionPublicKey,
} from '@midnight-ntwrk/ledger-v8';
import {
  createUnprovenCallTxFromInitialStates,
  createUnprovenDeployTx,
} from '@midnight-ntwrk/midnight-js-contracts';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { sampleSigningKey } from '@midnight-ntwrk/compact-runtime';

import { loadCompiledContract } from './artifacts.js';
import { getRuntimeConfig } from './config.js';
import { type ContractKey } from './contracts.js';
import { asBigInt, parseArgs, requireFlag } from './util.js';
import {
  expectedComplianceBits,
  loadWitnessPayload,
  theoremCount,
  totalPassedCount,
} from './witness-data.js';

function strictness(): WellFormedStrictness {
  const value = new WellFormedStrictness();
  value.verifyContractProofs = true;
  value.verifyNativeProofs = false;
  value.verifySignatures = false;
  value.enforceBalancing = false;
  value.enforceLimits = false;
  return value;
}

function blockContext(now: Date) {
  const secondsSinceEpoch = BigInt(Math.floor(now.getTime() / 1000));
  return {
    secondsSinceEpoch,
    secondsSinceEpochErr: 0,
    parentBlockHash: '00'.repeat(32),
    lastBlockTime: secondsSinceEpoch > 0n ? secondsSinceEpoch - 1n : 0n,
  };
}

function jsonReplacer(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value;
}

function normalizedCommitment(snapshot: Record<string, unknown> | null | undefined): string {
  const value = snapshot?.attestation_commitment;
  return typeof value === 'string' ? value.toLowerCase() : '';
}

async function proveSingleContract(
  contractKey: ContractKey,
  payload: Awaited<ReturnType<typeof loadWitnessPayload>>,
  ledger: LedgerState,
  options: {
    contractSnapshots?: Partial<Record<ContractKey, Record<string, unknown>>>;
  } = {},
): Promise<{
  nextLedger: LedgerState;
  contractKey: ContractKey;
  contractAddress: string;
  circuitId: string;
  deployTxHash: string;
  callTxHash: string;
  finalState: Record<string, unknown>;
}> {
  const config = getRuntimeConfig({ network: 'preprod' });
  const loaded = await loadCompiledContract(contractKey, {
    payload,
    config,
    contractSnapshots: options.contractSnapshots,
  });
  const zkConfigProvider = new NodeZkConfigProvider<string>(loaded.artifactDir);
  const proofProvider = httpClientProofProvider(config.proofServerUrl, zkConfigProvider);
  const walletProvider = {
    getCoinPublicKey: () => sampleCoinPublicKey(),
    getEncryptionPublicKey: () => sampleEncryptionPublicKey(),
    async balanceTx(): Promise<never> {
      throw new Error('Local proof flow does not balance transactions.');
    },
  };

  const deployTxData = await createUnprovenDeployTx(
    {
      zkConfigProvider,
      walletProvider,
    },
    {
      compiledContract: loaded.compiledContract as never,
      args: [],
      signingKey: sampleSigningKey(),
    },
  );

  const provenDeployTx = await proofProvider.proveTx(deployTxData.private.unprovenTx);
  const deployTime = new Date();
  const verifiedDeployTx = provenDeployTx.wellFormed(ledger, strictness(), deployTime);
  const deployContext = new TransactionContext(
    ledger,
    blockContext(deployTime),
    new Set([deployTxData.public.contractAddress]),
  );
  const [ledgerAfterDeploy, deployResult] = ledger.apply(verifiedDeployTx, deployContext);
  if (deployResult.type !== 'success') {
    throw new Error(
      `Local deploy verification failed for ${contractKey}: ${deployResult.error ?? deployResult.type}`,
    );
  }

  const callTxData = await createUnprovenCallTxFromInitialStates(
    zkConfigProvider,
    {
      compiledContract: loaded.compiledContract as never,
      circuitId: loaded.contract.circuitId,
      contractAddress: deployTxData.public.contractAddress,
      args: [],
      coinPublicKey: walletProvider.getCoinPublicKey(),
      initialContractState: deployTxData.public.initialContractState,
      initialZswapChainState: ZswapChainState.deserializeFromLedgerState(ledgerAfterDeploy.serialize()),
      ledgerParameters: LedgerParameters.initialParameters(),
    },
    walletProvider.getEncryptionPublicKey(),
  );

  const provenCallTx = await proofProvider.proveTx(callTxData.private.unprovenTx);
  const callTime = new Date();
  const verifiedCallTx = provenCallTx.wellFormed(ledgerAfterDeploy, strictness(), callTime);
  const callContext = new TransactionContext(
    ledgerAfterDeploy,
    blockContext(callTime),
    new Set([deployTxData.public.contractAddress]),
  );
  const [nextLedger, txResult] = ledgerAfterDeploy.apply(verifiedCallTx, callContext);
  if (txResult.type !== 'success') {
    throw new Error(
      `Local verification failed for ${contractKey}: ${txResult.error ?? txResult.type}`,
    );
  }

  return {
    nextLedger,
    contractKey,
    contractAddress: String(deployTxData.public.contractAddress),
    circuitId: loaded.contract.circuitId,
    deployTxHash: Buffer.from(provenDeployTx.serialize()).toString('hex').slice(0, 32),
    callTxHash: Buffer.from(provenCallTx.serialize()).toString('hex').slice(0, 32),
    finalState: loaded.decodeLedgerState(callTxData.public.nextContractState),
  };
}

async function proveAttestation() {
  const { flags } = parseArgs(process.argv.slice(2));
  const witnessPath = requireFlag(flags, 'witness');
  const outPath = flags.get('out')?.[0] ?? './data/local-proof-report.json';

  const payload = await loadWitnessPayload(resolve(witnessPath));
  let ledger = LedgerState.blank('preprod');
  const expectations = expectedComplianceBits(payload);
  const contractResults: Array<{
    contractKey: ContractKey;
    contractAddress: string;
    circuitId: string;
    deployTxHash: string;
    callTxHash: string;
    publicState: Record<string, unknown>;
  }> = [];

  const backendResult = await proveSingleContract('backend', payload, ledger);
  ledger = backendResult.nextLedger;
  contractResults.push({
    contractKey: backendResult.contractKey,
    contractAddress: backendResult.contractAddress,
    circuitId: backendResult.circuitId,
    deployTxHash: backendResult.deployTxHash,
    callTxHash: backendResult.callTxHash,
    publicState: backendResult.finalState,
  });
  if (Boolean(backendResult.finalState.compliance_bit) !== expectations.backend) {
    throw new Error(
      `Backend compliance mismatch: expected ${expectations.backend}, got ${String(backendResult.finalState.compliance_bit)}.`,
    );
  }

  const formalResult = await proveSingleContract('formal', payload, ledger);
  ledger = formalResult.nextLedger;
  contractResults.push({
    contractKey: formalResult.contractKey,
    contractAddress: formalResult.contractAddress,
    circuitId: formalResult.circuitId,
    deployTxHash: formalResult.deployTxHash,
    callTxHash: formalResult.callTxHash,
    publicState: formalResult.finalState,
  });
  if (Boolean(formalResult.finalState.compliance_bit) !== expectations.formal) {
    throw new Error(
      `Formal compliance mismatch: expected ${expectations.formal}, got ${String(formalResult.finalState.compliance_bit)}.`,
    );
  }

  const auditResult = await proveSingleContract('audit', payload, ledger, {
    contractSnapshots: {
      backend: backendResult.finalState,
      formal: formalResult.finalState,
    },
  });
  contractResults.push({
    contractKey: auditResult.contractKey,
    contractAddress: auditResult.contractAddress,
    circuitId: auditResult.circuitId,
    deployTxHash: auditResult.deployTxHash,
    callTxHash: auditResult.callTxHash,
    publicState: auditResult.finalState,
  });

  const finalState = auditResult.finalState;

  const report = {
    provedAt: new Date().toISOString(),
    witnessPath: resolve(witnessPath),
    contractResults,
    expectedCompliance: expectations,
    finalState,
  };

  if (Boolean(finalState.compliance_bit) !== expectations.overall) {
    throw new Error(
      `Final compliance bit mismatch: expected ${expectations.overall}, got ${String(finalState.compliance_bit)}.`,
    );
  }
  if (asBigInt(finalState.verification_count ?? 0) !== totalPassedCount(payload)) {
    throw new Error('Final verification_count does not match the witness payload.');
  }
  if (asBigInt(finalState.theorem_count ?? 0) !== theoremCount(payload)) {
    throw new Error('Final theorem_count does not match the witness payload.');
  }
  const backendCommitment = normalizedCommitment(backendResult.finalState);
  const formalCommitment = normalizedCommitment(formalResult.finalState);
  const auditCommitment = normalizedCommitment(finalState);
  if (!backendCommitment || backendCommitment !== formalCommitment || backendCommitment !== auditCommitment) {
    throw new Error('Local attestation commitments diverged across backend, formal, and audit contracts.');
  }

  const serializedReport = JSON.stringify(report, jsonReplacer, 2);
  await writeFile(resolve(outPath), serializedReport, 'utf-8');
  console.log(serializedReport);
}

proveAttestation().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
