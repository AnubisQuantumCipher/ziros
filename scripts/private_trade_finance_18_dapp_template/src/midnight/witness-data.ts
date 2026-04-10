import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { getRuntimeConfig, type MidnightRuntimeConfig } from './config';
import { type ContractKey, isContractKey } from './contracts';

export interface FlowCallEntry {
  call_id: string;
  contract_id: ContractKey;
  compact_source: string;
  circuit_name: string;
  inputs: Record<string, unknown>;
}

export interface FlowManifest {
  schema: string;
  package_id: string;
  calls: FlowCallEntry[];
}

interface ContractInfoWitnessEntry {
  name: string;
  ['result type']?: {
    ['type-name']?: string;
  };
}

interface ContractInfo {
  witnesses?: ContractInfoWitnessEntry[];
}

function coerceWitnessValue(value: unknown, typeName?: string): unknown {
  if (typeName === 'Boolean') {
    return Boolean(value);
  }
  if (typeof value === 'bigint' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return BigInt(value);
  }
  if (typeof value === 'string') {
    if (/^-?\d+$/.test(value)) {
      return BigInt(value);
    }
    return value;
  }
  if (value == null) {
    return typeName === 'Boolean' ? false : 0n;
  }
  return value;
}

export async function readTradeFinanceFlowManifest(
  config: MidnightRuntimeConfig = getRuntimeConfig(),
): Promise<FlowManifest> {
  const raw = await readFile(config.flowManifestPath, 'utf-8');
  const parsed = JSON.parse(raw) as { schema: string; package_id: string; calls: Array<Record<string, unknown>> };
  const calls = parsed.calls.map((entry) => {
    const contractId = String(entry.contract_id);
    if (!isContractKey(contractId)) {
      throw new Error(`Unknown trade-finance contract id in flow manifest: ${contractId}`);
    }
    return {
      call_id: String(entry.call_id),
      contract_id: contractId,
      compact_source: String(entry.compact_source),
      circuit_name: String(entry.circuit_name),
      inputs: (entry.inputs ?? {}) as Record<string, unknown>,
    } satisfies FlowCallEntry;
  });
  return {
    schema: parsed.schema,
    package_id: parsed.package_id,
    calls,
  };
}

export async function callEntryById(
  callId: string,
  config: MidnightRuntimeConfig = getRuntimeConfig(),
): Promise<FlowCallEntry> {
  const manifest = await readTradeFinanceFlowManifest(config);
  const entry = manifest.calls.find((candidate) => candidate.call_id === callId);
  if (!entry) {
    throw new Error(`Unknown trade-finance flow call id: ${callId}`);
  }
  return entry;
}

export async function buildCompactWitnesses(
  artifactDir: string,
  inputs: Record<string, unknown> = {},
): Promise<Record<string, (context: { privateState: unknown }) => [unknown, unknown]>> {
  const contractInfoPath = join(artifactDir, 'compiler', 'contract-info.json');
  const raw = await readFile(contractInfoPath, 'utf-8');
  const contractInfo = JSON.parse(raw) as ContractInfo;
  const witnesses: Record<string, (context: { privateState: unknown }) => [unknown, unknown]> = {};
  for (const witness of contractInfo.witnesses ?? []) {
    const name = witness.name;
    if (!(name in inputs)) {
      throw new Error(`Missing witness input ${name} for artifact ${artifactDir}`);
    }
    const typeName = witness['result type']?.['type-name'];
    witnesses[name] = ({ privateState }) => [privateState, coerceWitnessValue(inputs[name], typeName)];
  }
  return witnesses;
}
