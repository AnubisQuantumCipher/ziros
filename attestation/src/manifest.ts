import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

export interface DeploymentManifest {
  network: string;
  deployedAt: string;
  updatedAt: string;
  contractAddress: string;
  deployTxHash: string;
  explorerUrl: string;
  circuitTxHashes: Partial<Record<string, string>>;
  publicStateSnapshot: Record<string, unknown> | null;
}

export async function readDeploymentManifest(
  manifestPath: string,
): Promise<DeploymentManifest | null> {
  try {
    const raw = await readFile(manifestPath, 'utf-8');
    return JSON.parse(raw) as DeploymentManifest;
  } catch {
    return null;
  }
}

export async function writeDeploymentManifest(
  manifestPath: string,
  manifest: DeploymentManifest,
): Promise<void> {
  await mkdir(dirname(manifestPath), { recursive: true });
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');
}
