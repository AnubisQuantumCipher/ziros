import { Buffer } from 'node:buffer';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

import { createUnprovenDeployTx } from '@midnight-ntwrk/midnight-js-contracts';
import { sampleSigningKey } from '@midnight-ntwrk/compact-runtime';

import { loadCompiledContract } from '../midnight/artifacts';
import { getRuntimeConfig, type MidnightNetwork } from '../midnight/config';
import { buildHeadlessWallet, createDeployProviders, waitForSpendableDust } from '../midnight/providers';
import { callEntryById } from '../midnight/witness-data';

function toHex(bytes: Uint8Array): string {
  return `0x${Buffer.from(bytes).toString('hex')}`;
}

async function exportVariant(
  network: MidnightNetwork,
  variant: 'without-private-state' | 'with-empty-private-state',
): Promise<{ hexPath?: string; error?: string }> {
  const config = getRuntimeConfig({ network });
  const wallet = await buildHeadlessWallet(config);
  try {
    await waitForSpendableDust(wallet, { timeoutMs: 180000, pollMs: 15000 });
    const flow = await callEntryById('register_financing_request', config);
    const loaded = await loadCompiledContract('financing_request_registration', { config, inputs: flow.inputs });
    const providers = createDeployProviders(
      config,
      loaded.artifactDir,
      wallet,
      `probe-${network}-${variant}`,
      config.provingMode,
    );
    const baseOptions: Record<string, unknown> = {
      compiledContract: loaded.compiledContract as never,
      args: [],
      signingKey: sampleSigningKey(),
    };
    if (variant === 'with-empty-private-state') {
      baseOptions.privateStateId = `${network}-probe-private-state`;
      baseOptions.initialPrivateState = {};
    }
    const unproven = await createUnprovenDeployTx(
      {
        zkConfigProvider: providers.zkConfigProvider,
        walletProvider: providers.walletProvider,
      },
      baseOptions as never,
    );
    const provenTx = await (providers.proofProvider as any).proveTx(unproven.private.unprovenTx);
    const balancedTx = await wallet.balanceTx(provenTx);
    const hex = toHex(balancedTx.serialize());
    const outPath = resolve(`./data/probes/${network}.${variant}.tx.hex`);
    await mkdir(dirname(outPath), { recursive: true });
    await writeFile(outPath, hex + '\n', 'utf-8');
    const metaPath = resolve(`./data/probes/${network}.${variant}.json`);
    await writeFile(metaPath, JSON.stringify({
      network,
      variant,
      contractId: 'financing_request_registration',
      circuitId: flow.circuit_name,
      txFile: outPath,
      serializedBytes: balancedTx.serialize().length,
      contractAddress: String(unproven.public.contractAddress),
    }, null, 2) + '\n', 'utf-8');
    return { hexPath: outPath };
  } catch (error) {
    return { error: error instanceof Error ? error.stack ?? error.message : String(error) };
  } finally {
    await wallet.stop();
  }
}

async function main() {
  const requested = process.env.MIDNIGHT_NETWORK as MidnightNetwork | undefined;
  const networks: MidnightNetwork[] = requested ? [requested] : ['preview', 'preprod'];
  const results: Record<string, unknown> = {};
  for (const network of networks) {
    results[network] = {
      withoutPrivateState: await exportVariant(network, 'without-private-state'),
      withEmptyPrivateState: await exportVariant(network, 'with-empty-private-state'),
    };
  }
  console.log(JSON.stringify(results, null, 2));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
