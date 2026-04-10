import { buildRuntimeSnapshot } from '../midnight/runtime';

async function main() {
  const runtime = await buildRuntimeSnapshot();
  const missingArtifacts = runtime.contracts.filter((entry) => !entry.artifactReady).map((entry) => entry.key);
  const requireDeployed = process.env.MIDNIGHT_REQUIRE_DEPLOYED_CONTRACTS === '1';
  const missingDeployments = requireDeployed
    ? runtime.contracts.filter((entry) => !entry.deployed).map((entry) => entry.key)
    : [];

  if (!runtime.proofServer.healthy) {
    throw new Error(runtime.proofServer.error ?? 'Proof server is unhealthy.');
  }
  if (missingArtifacts.length > 0) {
    throw new Error(`Missing compiled artifacts for: ${missingArtifacts.join(', ')}`);
  }
  if (missingDeployments.length > 0) {
    throw new Error(`Missing deployed contracts for: ${missingDeployments.join(', ')}`);
  }

  console.log(JSON.stringify({
    network: runtime.config.network,
    proofServerHealthy: runtime.proofServer.healthy,
    artifactReadyContracts: runtime.contracts.filter((entry) => entry.artifactReady).length,
    deployedContracts: runtime.contracts.filter((entry) => entry.deployed).length,
    requireDeployed,
  }, null, 2));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
