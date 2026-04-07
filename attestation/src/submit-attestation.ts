import { findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';

import { explorerLink, getRuntimeConfig, networkLabel } from './config.js';
import { type ContractKey } from './contracts.js';
import {
  findDeploymentManifestEntry,
  readDeploymentManifest,
  upsertDeploymentManifestEntry,
} from './manifest.js';
import {
  buildHeadlessWallet,
  waitForSpendableDust,
} from './providers.js';
import { buildCompatibilityProfile, withMidnightApi } from './runtime-probe.js';
import { resolveSelectedCompatibilityStrategy } from './strategy-selection.js';
import { probeSubmitStrategy } from './submit-strategy.js';
import { buildPreparedCallTransaction } from './tx-pipeline.js';
import { asBigInt, parseArgs, requireFlag, stringifyJson } from './util.js';
import {
  expectedComplianceBits,
  loadWitnessPayload,
  theoremCount,
  totalPassedCount,
} from './witness-data.js';

function normalizedCommitment(snapshot: Record<string, unknown> | null | undefined): string {
  const value = snapshot?.attestation_commitment;
  return typeof value === 'string' ? value.toLowerCase() : '';
}

async function submitSingleContract(
  contractKey: ContractKey,
  payload: Awaited<ReturnType<typeof loadWitnessPayload>>,
  walletProvider: Awaited<ReturnType<typeof buildHeadlessWallet>>,
  contractSnapshots: Partial<Record<ContractKey, Record<string, unknown>>> = {},
): Promise<Record<string, unknown> | null> {
  const config = getRuntimeConfig();
  const selection = await resolveSelectedCompatibilityStrategy(config);
  const profile = await buildCompatibilityProfile(config.network, config);
  const manifest = await readDeploymentManifest(config.manifestPath);
  const entry = findDeploymentManifestEntry(manifest, contractKey);
  if (!entry?.address) {
    throw new Error(`Contract ${contractKey} is not deployed. Run deploy-attestation first.`);
  }

  const prepared = await buildPreparedCallTransaction(
    contractKey,
    payload,
    walletProvider,
    config,
    entry.address,
    contractSnapshots,
  );
  const submission = await withMidnightApi(config, async (api) =>
    probeSubmitStrategy(selection.strategy, prepared.balancedTx, prepared.innerTxHex, {
      api,
      wallet: walletProvider,
    }),
  );
  if (submission.submit.outcome !== 'accepted') {
    throw new Error(
      `Submit failed for ${contractKey} via ${selection.strategy}: ${submission.submit.detail}`,
    );
  }

  const txData = await prepared.providers.publicDataProvider.watchForTxData(prepared.txId as never);
  const onChainState = await prepared.providers.publicDataProvider.queryContractState(entry.address as never);
  const snapshot = onChainState ? prepared.loaded.decodeLedgerState(onChainState) : null;

  await upsertDeploymentManifestEntry(
    {
      ...entry,
      explorerUrl: explorerLink(config.explorerUrl, txData.txHash, entry.address),
      publicStateSnapshot: snapshot,
      lastCallTxHash: txData.txHash,
      lastCallAt: new Date().toISOString(),
    },
    {
      network: config.network,
      networkName: networkLabel(config.network),
      selectedMatrixId: selection.matrixId === 'current' ? undefined : selection.matrixId,
      selectedSubmitStrategy: selection.strategy,
      runtimeFingerprint: {
        specVersion: profile.specVersion,
        transactionVersion: profile.transactionVersion,
        rawLedgerVersion: profile.rawLedgerVersion,
        signedExtensions: profile.signedExtensions,
      },
      manifestPath: config.manifestPath,
    },
  );

  return snapshot;
}

async function submitAttestation() {
  const { flags } = parseArgs(process.argv.slice(2));
  const witnessPath = requireFlag(flags, 'witness');
  const payload = await loadWitnessPayload(witnessPath);
  const config = getRuntimeConfig();
  const manifest = await readDeploymentManifest(config.manifestPath);
  if (!manifest?.contracts?.length) {
    throw new Error(`Missing deployment manifest at ${config.manifestPath}. Run deploy-attestation first.`);
  }

  const walletProvider = await buildHeadlessWallet(config);

  try {
    await waitForSpendableDust(walletProvider);

    const expectations = expectedComplianceBits(payload);
    const backendSnapshot = await submitSingleContract('backend', payload, walletProvider);
    if (Boolean(backendSnapshot?.compliance_bit) !== expectations.backend) {
      throw new Error(
        `Backend compliance mismatch: expected ${expectations.backend}, got ${String(backendSnapshot?.compliance_bit)}.`,
      );
    }

    const formalSnapshot = await submitSingleContract('formal', payload, walletProvider);
    if (Boolean(formalSnapshot?.compliance_bit) !== expectations.formal) {
      throw new Error(
        `Formal compliance mismatch: expected ${expectations.formal}, got ${String(formalSnapshot?.compliance_bit)}.`,
      );
    }

    const auditSnapshot = await submitSingleContract('audit', payload, walletProvider, {
      backend: backendSnapshot ?? undefined,
      formal: formalSnapshot ?? undefined,
    });
    if (Boolean(auditSnapshot?.compliance_bit) !== expectations.overall) {
      throw new Error(
        `On-chain compliance mismatch: expected ${expectations.overall}, got ${String(auditSnapshot?.compliance_bit)}.`,
      );
    }
    if (asBigInt(auditSnapshot?.verification_count ?? 0) !== totalPassedCount(payload)) {
      throw new Error('On-chain verification_count does not match the attestation witness.');
    }
    if (asBigInt(auditSnapshot?.theorem_count ?? 0) !== theoremCount(payload)) {
      throw new Error('On-chain theorem_count does not match the attestation witness.');
    }
    const backendCommitment = normalizedCommitment(backendSnapshot);
    const formalCommitment = normalizedCommitment(formalSnapshot);
    const auditCommitment = normalizedCommitment(auditSnapshot);
    if (!backendCommitment || backendCommitment !== formalCommitment || backendCommitment !== auditCommitment) {
      throw new Error('Attestation commitments diverged across backend, formal, and audit contracts.');
    }
  } finally {
    await walletProvider.stop();
  }

  const nextManifest = await readDeploymentManifest(config.manifestPath);
  console.log(stringifyJson(nextManifest));
}

submitAttestation().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
