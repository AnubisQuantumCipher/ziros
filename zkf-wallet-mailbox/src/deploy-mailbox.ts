// @ts-nocheck
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { CompiledContract } from '@midnight-ntwrk/compact-js';
import { sampleSigningKey } from '@midnight-ntwrk/compact-runtime';
import { createUnprovenDeployTx } from '@midnight-ntwrk/midnight-js-contracts';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import type { FinalizedTransaction } from '@midnight-ntwrk/ledger-v8';

import {
  buildMidnightOuterTx,
  finalizedTransactionId,
  finalizedTransactionToInnerTxHex,
  submitMidnightOuterTx,
  validateMidnightOuterTx,
  withMidnightApi,
} from './midnight_polkadot.js';
import {
  buildHeadlessWallet,
  createDeployProviders,
  explorerLink,
  getRuntimeConfig,
  type MidnightNetwork,
  waitForSpendableDust,
} from './runtime.js';
import type { MailboxDeploymentManifest } from './types.js';

interface CliFlags {
  network?: MidnightNetwork;
  out?: string;
  manifest?: string;
}

function envNumber(name: string): number | undefined {
  const value = process.env[name];
  if (!value) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function dummyMailboxWitnesses() {
  return {
    senderFingerprint: () => new Uint8Array(32),
    receiverFingerprint: () => new Uint8Array(32),
    channelFingerprint: () => new Uint8Array(32),
    messageKind: () => 0n,
    sequence: () => 0n,
    epochId: () => 0n,
    postedAt: () => 0n,
    envelopeHash: () => new Uint8Array(32),
    nonce: () => new Uint8Array(12),
    ciphertextLength: () => 0n,
    ciphertext: () => new Uint8Array(1024),
    mlKemCiphertextLength: () => 0n,
    mlKemCiphertext: () => new Uint8Array(1568),
    senderX25519PublicKeyLength: () => 0n,
    senderX25519PublicKey: () => new Uint8Array(32),
    senderIdentityPublicKeyLength: () => 0n,
    senderIdentityPublicKey: () => new Uint8Array(2592),
    senderSignatureLength: () => 0n,
    senderSignature: () => new Uint8Array(4627),
    nextMessageCount: () => 0n,
  };
}

function parseFlags(argv: string[]): CliFlags {
  const flags: CliFlags = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    const value = argv[index + 1];
    if (token === '--network' && value) {
      flags.network = value as MidnightNetwork;
      index += 1;
    } else if (token === '--out' && value) {
      flags.out = value;
      index += 1;
    } else if (token === '--manifest' && value) {
      flags.manifest = value;
      index += 1;
    }
  }
  return flags;
}

async function readManifest(pathname: string): Promise<MailboxDeploymentManifest> {
  const raw = await readFile(pathname, 'utf8');
  return JSON.parse(raw) as MailboxDeploymentManifest;
}

async function loadCompiledMailboxContract(artifactDir: string) {
  const contractModulePath = resolve(artifactDir, 'contract', 'index.js');
  const contractModule = (await import(pathToFileURL(contractModulePath).href)) as Record<
    string,
    unknown
  >;
  const contractCtor = contractModule.Contract as never;
  return CompiledContract.make('ziros_wallet_mailbox', contractCtor).pipe(
    CompiledContract.withWitnesses(dummyMailboxWitnesses() as never),
    CompiledContract.withCompiledFileAssets(artifactDir),
  );
}

async function writeManifest(pathname: string, manifest: MailboxDeploymentManifest): Promise<void> {
  await mkdir(dirname(pathname), { recursive: true });
  await writeFile(pathname, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}

async function submitDeploymentTransaction(
  tx: FinalizedTransaction,
  wallet: Awaited<ReturnType<typeof buildHeadlessWallet>>,
  config: ReturnType<typeof getRuntimeConfig>,
): Promise<string> {
  try {
    return await wallet.submitTx(tx);
  } catch (walletError) {
    const innerTxId = finalizedTransactionId(tx);
    const innerTxHex = finalizedTransactionToInnerTxHex(tx);
    await withMidnightApi(config, async (api) => {
      const outerTxHex = buildMidnightOuterTx(innerTxHex, api);
      const validation = await validateMidnightOuterTx(outerTxHex, api);
      if (!validation.some((entry) => entry.outcome === 'accepted')) {
        throw new Error(
          `Wallet submit failed (${walletError instanceof Error ? walletError.message : String(walletError)}); ` +
            `outer Midnight extrinsic validation also failed: ${JSON.stringify(validation)}`,
        );
      }
      await submitMidnightOuterTx(outerTxHex, api);
    });
    return innerTxId;
  }
}

async function main() {
  const root = resolve(import.meta.dirname, '..');
  const flags = parseFlags(process.argv.slice(2));
  const manifestTemplatePath = resolve(
    root,
    flags.manifest ?? 'deployment/mailbox.deployment.template.json',
  );
  const outPath = resolve(root, flags.out ?? 'deployment/mailbox.deployment.json');
  const manifest = await readManifest(manifestTemplatePath);
  const network = flags.network ?? (process.env.MIDNIGHT_NETWORK as MidnightNetwork | undefined) ?? 'preprod';
  const deployment = manifest.networks[network];
  if (!deployment) {
    throw new Error(`Mailbox manifest does not define network '${network}'`);
  }
  setNetworkId(network);

  const artifactDir = resolve(dirname(manifestTemplatePath), deployment.compiledArtifactDir);
  const compiledContract = await loadCompiledMailboxContract(artifactDir);
  const runtimeConfig = getRuntimeConfig({
    network,
    compactArtifactRoot: resolve(root, 'contracts/compiled'),
  });
  const wallet = await buildHeadlessWallet(runtimeConfig);

  try {
    await waitForSpendableDust(wallet, {
      timeoutMs: envNumber('MIDNIGHT_DUST_WAIT_TIMEOUT_MS'),
      pollMs: envNumber('MIDNIGHT_DUST_WAIT_POLL_MS'),
    });
    const providers = createDeployProviders(
      runtimeConfig,
      artifactDir,
      wallet,
      `ziros-wallet-mailbox-${network}`,
      runtimeConfig.provingMode,
    );
    const deployTxData = await createUnprovenDeployTx(
      {
        zkConfigProvider: providers.zkConfigProvider,
        walletProvider: providers.walletProvider,
      },
      {
        compiledContract: compiledContract as never,
        args: [],
        signingKey: sampleSigningKey(),
      },
    );
    const provenTx = await providers.proofProvider.proveTx(deployTxData.private.unprovenTx);
    const balancedTx = await wallet.balanceTx(provenTx);
    const txId = await submitDeploymentTransaction(balancedTx, wallet, runtimeConfig);
    const txData = await providers.publicDataProvider.watchForTxData(txId as never);
    const contractAddress = String(deployTxData.public.contractAddress);
    const deployedAt = new Date().toISOString();

    const nextManifest: MailboxDeploymentManifest = {
      ...manifest,
      description:
        'Shared ZirOS Midnight wallet mailbox deployment manifest for macOS helper-backed messaging.',
      networks: {
        ...manifest.networks,
        [network]: {
          ...deployment,
          contractAddress,
          status: 'deployed',
          txHash: String(txData.txHash),
          deployedAt,
          explorerUrl: explorerLink(runtimeConfig.explorerUrl, String(txData.txHash), contractAddress),
        },
      },
      notes: [
        `Mailbox deployed for ${network} at ${deployedAt}.`,
        'This manifest is consumed by the ZirOS wallet helper as an explicit_tcb_adapter transport config.',
      ],
    };

    await writeManifest(outPath, nextManifest);
    console.log(JSON.stringify(nextManifest, null, 2));
  } finally {
    await wallet.stop();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
