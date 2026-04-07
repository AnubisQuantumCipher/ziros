import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

import type { MidnightStackMatrixId, MidnightSubmitStrategyId } from './compatibility.js';
import type { ContractKey } from './contracts.js';
import { stringifyJson } from './util.js';

export interface DeploymentManifestEntry {
  name: ContractKey;
  address: string;
  txHash: string;
  deployedAt: string;
  explorerUrl: string;
  publicStateSnapshot: Record<string, unknown> | null;
  lastCallTxHash?: string;
  lastCallAt?: string;
}

export interface DeploymentManifest {
  network: string;
  networkName: string;
  deployedAt: string;
  updatedAt: string;
  selectedMatrixId?: MidnightStackMatrixId;
  selectedSubmitStrategy?: MidnightSubmitStrategyId;
  runtimeFingerprint?: {
    specVersion: string;
    transactionVersion: string;
    rawLedgerVersion: string;
    signedExtensions: string[];
  };
  contracts: DeploymentManifestEntry[];
}

export function resolveManifestPath(customPath = './data/deployment-manifest.json'): string {
  return resolve(customPath);
}

export async function readDeploymentManifest(
  manifestPath = resolveManifestPath(),
): Promise<DeploymentManifest | null> {
  try {
    const raw = await readFile(manifestPath, 'utf-8');
    return JSON.parse(raw) as DeploymentManifest;
  } catch {
    return null;
  }
}

export async function writeDeploymentManifest(
  manifest: DeploymentManifest,
  manifestPath = resolveManifestPath(),
): Promise<void> {
  await mkdir(dirname(manifestPath), { recursive: true });
  await writeFile(manifestPath, stringifyJson(manifest), 'utf-8');
}

export async function upsertDeploymentManifestEntry(
  entry: DeploymentManifestEntry,
  options: {
    network: string;
    networkName: string;
    selectedMatrixId?: MidnightStackMatrixId;
    selectedSubmitStrategy?: MidnightSubmitStrategyId;
    runtimeFingerprint?: DeploymentManifest['runtimeFingerprint'];
    manifestPath?: string;
  },
): Promise<DeploymentManifest> {
  const manifestPath = options.manifestPath ?? resolveManifestPath();
  const existing = await readDeploymentManifest(manifestPath);
  const deployedAt = existing?.deployedAt ?? entry.deployedAt;
  const contracts = [...(existing?.contracts ?? [])];
  const idx = contracts.findIndex((contract) => contract.name === entry.name);

  if (idx >= 0) {
    contracts[idx] = { ...contracts[idx], ...entry };
  } else {
    contracts.push(entry);
  }

  const manifest: DeploymentManifest = {
    network: options.network,
    networkName: options.networkName,
    deployedAt,
    updatedAt: new Date().toISOString(),
    selectedMatrixId: options.selectedMatrixId ?? existing?.selectedMatrixId,
    selectedSubmitStrategy: options.selectedSubmitStrategy ?? existing?.selectedSubmitStrategy,
    runtimeFingerprint: options.runtimeFingerprint ?? existing?.runtimeFingerprint,
    contracts,
  };

  await writeDeploymentManifest(manifest, manifestPath);
  return manifest;
}

export function findDeploymentManifestEntry(
  manifest: DeploymentManifest | null,
  contractKey: ContractKey,
): DeploymentManifestEntry | null {
  return manifest?.contracts.find((contract) => contract.name === contractKey) ?? null;
}
