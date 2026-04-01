import { access } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { CompiledContract } from '@midnight-ntwrk/compact-js';

import { getRuntimeConfig, type MidnightRuntimeConfig } from './config.js';
import { ATTESTATION_CONTRACT } from './contracts.js';
import { buildCompactWitnesses, type AttestationWitnessPayload } from './witness-data.js';

async function isReadable(pathname: string): Promise<boolean> {
  try {
    await access(pathname);
    return true;
  } catch {
    return false;
  }
}

export function resolveArtifactDirectory(
  config: MidnightRuntimeConfig = getRuntimeConfig(),
): string {
  return resolve(config.compactArtifactRoot, ATTESTATION_CONTRACT.artifactDirectory);
}

export async function loadCompiledContract(
  payload: AttestationWitnessPayload,
  config: MidnightRuntimeConfig = getRuntimeConfig(),
): Promise<{
  artifactDir: string;
  contractModule: Record<string, unknown>;
  compiledContract: unknown;
  decodeLedgerState: (contractState: unknown) => Record<string, unknown>;
}> {
  const artifactDir = resolveArtifactDirectory(config);
  const contractModulePath = join(artifactDir, 'contract', 'index.js');
  const keysDir = join(artifactDir, 'keys');
  const zkirDir = join(artifactDir, 'zkir');

  const ready =
    (await isReadable(contractModulePath)) &&
    (await isReadable(keysDir)) &&
    (await isReadable(zkirDir));

  if (!ready) {
    throw new Error('Compiled Midnight artifacts are missing. Run `npm run compile-contracts` first.');
  }

  const moduleUrl = pathToFileURL(contractModulePath).href;
  const contractModule = (await import(moduleUrl)) as Record<string, unknown>;
  const contractCtor = contractModule.Contract as never;
  const witnesses = buildCompactWitnesses(payload);
  const compiledContract = CompiledContract.make(
    ATTESTATION_CONTRACT.artifactDirectory,
    contractCtor,
  ).pipe(
    CompiledContract.withWitnesses(witnesses as never),
    CompiledContract.withCompiledFileAssets(artifactDir),
  );

  return {
    artifactDir,
    contractModule,
    compiledContract,
    decodeLedgerState(contractState: unknown) {
      const ledgerDecoder = contractModule.ledger as ((value: unknown) => Record<string, unknown>) | undefined;
      if (!ledgerDecoder) {
        return {};
      }
      const maybeData =
        contractState &&
        typeof contractState === 'object' &&
        'data' in (contractState as Record<string, unknown>)
          ? (contractState as Record<string, unknown>).data
          : contractState;
      return ledgerDecoder(maybeData);
    },
  };
}
