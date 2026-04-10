import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

import type { ContractKey } from './contracts';

export interface DeploymentManifestEntry {
  name: ContractKey;
  address: string;
  txHash: string;
  deployedAt: string;
  explorerUrl: string;
  deploymentExplorerUrl?: string;
  publicStateSnapshot: Record<string, unknown> | null;
  lastCallTxHash?: string;
  lastCallExplorerUrl?: string;
  lastCallAt?: string;
}

export interface DeploymentManifest {
  network: string;
  networkName: string;
  deployedAt: string;
  updatedAt: string;
  contracts: DeploymentManifestEntry[];
}

export interface CallReceiptEntry {
  callId: string;
  contractId: ContractKey;
  circuitName: string;
  txHash: string;
  contractAddress: string;
  explorerUrl: string;
  calledAt: string;
  inputs: Record<string, unknown>;
}

export interface CallReceipts {
  network: string;
  receipts: CallReceiptEntry[];
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
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf-8');
}

export async function upsertDeploymentManifestEntry(
  entry: DeploymentManifestEntry,
  options: {
    network: string;
    networkName: string;
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
    contracts,
  };
  await writeDeploymentManifest(manifest, manifestPath);
  return manifest;
}

export async function readCallReceipts(receiptsPath = resolve('./data/call-receipts.json')): Promise<CallReceipts | null> {
  try {
    const raw = await readFile(receiptsPath, 'utf-8');
    return JSON.parse(raw) as CallReceipts;
  } catch {
    return null;
  }
}

export async function appendCallReceipt(
  entry: CallReceiptEntry,
  receiptsPath = resolve('./data/call-receipts.json'),
): Promise<CallReceipts> {
  const current = await readCallReceipts(receiptsPath);
  const receipts: CallReceipts = {
    network: current?.network ?? 'unknown',
    receipts: [...(current?.receipts ?? []), entry],
  };
  await mkdir(dirname(receiptsPath), { recursive: true });
  await writeFile(receiptsPath, `${JSON.stringify(receipts, null, 2)}\n`, 'utf-8');
  return receipts;
}
