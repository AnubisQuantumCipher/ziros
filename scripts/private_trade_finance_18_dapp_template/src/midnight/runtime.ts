import { getRuntimeConfig } from './config';
import { CONTRACTS } from './contracts';
import { getArtifactStatus } from './artifacts';
import { readDeploymentManifest } from './manifest';

async function probeProofServer(url: string): Promise<{ healthy: boolean; statusCode?: number; error?: string }> {
  try {
    const response = await fetch(new URL('/health', url));
    return { healthy: response.ok, statusCode: response.status, error: response.ok ? undefined : `HTTP ${response.status}` };
  } catch (error) {
    return { healthy: false, error: error instanceof Error ? error.message : String(error) };
  }
}

export async function buildRuntimeSnapshot() {
  const config = getRuntimeConfig();
  const manifest = await readDeploymentManifest(config.deploymentManifestPath);
  const proofServer = await probeProofServer(config.proofServerUrl);
  const contracts = await Promise.all(
    CONTRACTS.map(async (contract) => {
      const artifactStatus = await getArtifactStatus(contract.key, config);
      const deployed = manifest?.contracts.find((entry) => entry.name === contract.key) ?? null;
      return {
        key: contract.key,
        artifactReady: artifactStatus.ready,
        deployed: Boolean(deployed?.address),
        address: deployed?.address ?? null,
      };
    }),
  );
  return { config, manifest, proofServer, contracts };
}
