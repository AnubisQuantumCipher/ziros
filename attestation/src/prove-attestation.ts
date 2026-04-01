import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import {
  LedgerParameters,
  LedgerState,
  TransactionContext,
  WellFormedStrictness,
  ZswapChainState,
  sampleCoinPublicKey,
  sampleEncryptionPublicKey,
  sampleSigningKey,
} from '@midnight-ntwrk/ledger-v8';
import {
  createUnprovenCallTxFromInitialStates,
  createUnprovenDeployTx,
} from '@midnight-ntwrk/midnight-js-contracts';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import {
  ChargedState,
  ContractState,
  type StateValue,
} from '@midnight-ntwrk/onchain-runtime-v3';

import { loadCompiledContract } from './artifacts.js';
import { getRuntimeConfig } from './config.js';
import { ATTESTATION_CONTRACT, type AttestationCircuitId } from './contracts.js';
import { requireFlag, parseArgs } from './util.js';
import { expectedComplianceBits, loadWitnessPayload } from './witness-data.js';

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

function nextPublicContractState(
  contractState: ContractState,
  nextStateValue: StateValue,
): ContractState {
  const cloned = ContractState.deserialize(contractState.serialize());
  cloned.data = new ChargedState(nextStateValue);
  return cloned;
}

function jsonReplacer(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value;
}

async function proveAttestation() {
  const { flags } = parseArgs(process.argv.slice(2));
  const witnessPath = requireFlag(flags, 'witness');
  const outPath = flags.get('out')?.[0] ?? './data/local-proof-report.json';

  const payload = await loadWitnessPayload(resolve(witnessPath));
  const config = getRuntimeConfig({ network: 'preprod' });
  const loaded = await loadCompiledContract(payload, config);
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
  let ledger = LedgerState.blank('preprod');
  let currentContractState = deployTxData.public.initialContractState;
  const now = new Date();
  const verifiedDeployTx = provenDeployTx.wellFormed(ledger, strictness(), now);
  const deployContext = new TransactionContext(
    ledger,
    blockContext(now),
    new Set([deployTxData.public.contractAddress]),
  );
  const [ledgerAfterDeploy, deployResult] = ledger.apply(verifiedDeployTx, deployContext);
  if (deployResult.type !== 'success') {
    throw new Error(`Local deploy verification failed: ${deployResult.error ?? deployResult.type}`);
  }
  ledger = ledgerAfterDeploy;

  const circuitResults: Array<{
    circuitId: AttestationCircuitId;
    txHash: string;
    resultType: string;
    publicState: Record<string, unknown>;
  }> = [];

  for (const circuitId of ATTESTATION_CONTRACT.circuitIds) {
    const callTxData = await createUnprovenCallTxFromInitialStates(
      zkConfigProvider,
      {
        compiledContract: loaded.compiledContract as never,
        circuitId,
        contractAddress: deployTxData.public.contractAddress,
        args: [],
        coinPublicKey: walletProvider.getCoinPublicKey(),
        initialContractState: currentContractState,
        initialZswapChainState: ZswapChainState.deserializeFromLedgerState(ledger.serialize()),
        ledgerParameters: LedgerParameters.initialParameters(),
      },
      walletProvider.getEncryptionPublicKey(),
    );

    const provenCallTx = await proofProvider.proveTx(callTxData.private.unprovenTx);
    const callTime = new Date();
    const verifiedCallTx = provenCallTx.wellFormed(ledger, strictness(), callTime);
    const callContext = new TransactionContext(
      ledger,
      blockContext(callTime),
      new Set([deployTxData.public.contractAddress]),
    );
    const [nextLedger, txResult] = ledger.apply(verifiedCallTx, callContext);
    if (txResult.type !== 'success') {
      throw new Error(`Local verification failed for ${circuitId}: ${txResult.error ?? txResult.type}`);
    }
    ledger = nextLedger;
    currentContractState = nextPublicContractState(
      currentContractState,
      callTxData.public.nextContractState,
    );

    const decodedState = loaded.decodeLedgerState(currentContractState);
    circuitResults.push({
      circuitId,
      txHash: Buffer.from(provenCallTx.serialize()).toString('hex').slice(0, 32),
      resultType: txResult.type,
      publicState: decodedState,
    });
  }

  const finalState = loaded.decodeLedgerState(currentContractState);
  const expectations = expectedComplianceBits(payload);

  const report = {
    provedAt: new Date().toISOString(),
    witnessPath: resolve(witnessPath),
    contractAddress: String(deployTxData.public.contractAddress),
    deployTxHash: Buffer.from(provenDeployTx.serialize()).toString('hex').slice(0, 32),
    circuitResults,
    expectedCompliance: expectations,
    finalState,
  };

  if (Boolean(finalState.compliance_bit) !== expectations.overall) {
    throw new Error(
      `Final compliance bit mismatch: expected ${expectations.overall}, got ${String(finalState.compliance_bit)}.`,
    );
  }

  const serializedReport = JSON.stringify(report, jsonReplacer, 2);
  await writeFile(resolve(outPath), serializedReport, 'utf-8');
  console.log(serializedReport);
}

proveAttestation().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
