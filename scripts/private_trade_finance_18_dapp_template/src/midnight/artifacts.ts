import { access } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { CompiledContract } from '@midnight-ntwrk/compact-js';

import { CONTRACTS, type ContractDefinition, type ContractKey, getContractDefinition } from './contracts';
import { getRuntimeConfig, type MidnightRuntimeConfig } from './config';
import { buildCompactWitnesses } from './witness-data';

export interface ArtifactStatus {
  contract: ContractDefinition;
  artifactDir: string;
  contractModulePath: string;
  ready: boolean;
}

export interface LoadedContractArtifacts {
  contract: ContractDefinition;
  artifactDir: string;
  contractModule: Record<string, unknown>;
  compiledContract: unknown;
  decodeLedgerState: (contractState: unknown) => Record<string, unknown>;
}

async function isReadable(pathname: string): Promise<boolean> {
  try {
    await access(pathname);
    return true;
  } catch {
    return false;
  }
}

export function resolveArtifactDirectory(
  contractKey: ContractKey,
  config: MidnightRuntimeConfig = getRuntimeConfig(),
): string {
  return resolve(config.compactArtifactRoot, getContractDefinition(contractKey).artifactDirectory);
}

export async function getArtifactStatus(
  contractKey: ContractKey,
  config: MidnightRuntimeConfig = getRuntimeConfig(),
): Promise<ArtifactStatus> {
  const contract = getContractDefinition(contractKey);
  const artifactDir = resolveArtifactDirectory(contractKey, config);
  const contractModulePath = join(artifactDir, 'contract', 'index.js');
  const keysDir = join(artifactDir, 'keys');
  const zkirDir = join(artifactDir, 'zkir');
  const ready =
    (await isReadable(contractModulePath)) &&
    (await isReadable(keysDir)) &&
    (await isReadable(zkirDir));
  return { contract, artifactDir, contractModulePath, ready };
}

export async function listArtifactStatuses(
  config: MidnightRuntimeConfig = getRuntimeConfig(),
): Promise<ArtifactStatus[]> {
  return Promise.all(CONTRACTS.map((contract) => getArtifactStatus(contract.key, config)));
}

export async function loadCompiledContract(
  contractKey: ContractKey,
  options: { config?: MidnightRuntimeConfig; inputs?: Record<string, unknown> } = {},
): Promise<LoadedContractArtifacts> {
  const config = options.config ?? getRuntimeConfig();
  const status = await getArtifactStatus(contractKey, config);
  if (!status.ready) {
    throw new Error(`Compiled Midnight artifacts are missing for ${contractKey}.`);
  }
  const moduleUrl = pathToFileURL(status.contractModulePath).href;
  const contractModule = (await import(moduleUrl)) as Record<string, unknown>;
  const contractCtor = contractModule.Contract as never;
  const witnesses = await buildCompactWitnesses(status.artifactDir, options.inputs ?? {});
  const compiledContract = CompiledContract.make(status.contract.artifactDirectory, contractCtor).pipe(
    CompiledContract.withWitnesses(witnesses as never),
    CompiledContract.withCompiledFileAssets(status.artifactDir),
  );
  return {
    contract: status.contract,
    artifactDir: status.artifactDir,
    contractModule,
    compiledContract,
    decodeLedgerState(contractState: unknown) {
      const ledgerDecoder = contractModule.ledger as ((value: unknown) => Record<string, unknown>) | undefined;
      if (!ledgerDecoder) return {};
      const maybeData = contractState && typeof contractState === 'object' && 'data' in (contractState as Record<string, unknown>)
        ? (contractState as Record<string, unknown>).data
        : contractState;
      return ledgerDecoder(maybeData);
    },
  };
}
