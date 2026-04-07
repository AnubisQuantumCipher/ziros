import { Buffer } from 'buffer';
import { CompiledContract } from '@midnight-ntwrk/compact-js';

import type {
  MailboxEnvelope,
  MessagingTransportMode,
  MessagingTransportUpdate,
  WalletHelperNetwork,
} from './types.js';
import {
  bytesHex,
  hexToBytes,
  sha256Bytes,
  sha256Hex,
  utf8Bytes,
} from './portable_crypto.js';

interface MailboxNetworkDeployment {
  contractAddress: string | null;
  compiledArtifactDir: string;
  status: 'pending-deployment' | 'deployed' | 'retired';
}

interface MailboxDeploymentManifest {
  schema: 'ziros-wallet-mailbox-deployment-v1';
  contractName: 'ziros_wallet_mailbox';
  description: string;
  networks: Record<WalletHelperNetwork, MailboxNetworkDeployment>;
  notes: string[];
}

interface LoadedMailboxContract {
  contractAddress: string;
  artifactDir: string;
  buildCompiledContract(witnesses: Record<string, unknown>): unknown;
  decodeLedgerState(contractState: unknown): Record<string, unknown>;
}

function trimBytes(value: unknown, expectedLength: unknown): Uint8Array {
  const bytes = value instanceof Uint8Array ? value : Uint8Array.from(value as Iterable<number>);
  const length = typeof expectedLength === 'bigint'
    ? Number(expectedLength)
    : typeof expectedLength === 'number'
      ? expectedLength
      : bytes.length;
  return bytes.slice(0, length);
}

function valueAsString(value: unknown): string {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  return String(value);
}

function peerFingerprint(peerId: string): Uint8Array {
  return sha256Bytes(peerId);
}

function peerIdFromIdentityPublicKey(identityPublicKeyHex: string): string {
  const digest = sha256Hex(hexToBytes(identityPublicKeyHex));
  return `midpeer-${digest}`;
}

async function readTextFileNode(path: string): Promise<string> {
  const { readFile } = await import('node:fs/promises');
  return readFile(path, 'utf8');
}

async function ensureAccessibleNode(path: string): Promise<void> {
  const { access } = await import('node:fs/promises');
  await access(path);
}

async function resolveNodePath(path: string, relative: string): Promise<string> {
  const { dirname, resolve } = await import('node:path');
  return resolve(dirname(path), relative);
}

async function importNodeModule(path: string): Promise<Record<string, unknown>> {
  const { pathToFileURL } = await import('node:url');
  return import(pathToFileURL(path).href) as Promise<Record<string, unknown>>;
}

function kindToNumber(kind: MailboxEnvelope['messageKind']): bigint {
  switch (kind) {
    case 'text':
      return 0n;
    case 'transfer-receipt':
      return 1n;
    case 'credential-request':
      return 2n;
    case 'credential-response':
      return 3n;
  }
}

function kindFromNumber(value: unknown): MailboxEnvelope['messageKind'] {
  switch (Number(valueAsString(value))) {
    case 0:
      return 'text';
    case 1:
      return 'transfer-receipt';
    case 2:
      return 'credential-request';
    case 3:
      return 'credential-response';
    default:
      throw new Error(`Unsupported mailbox message kind '${valueAsString(value)}'`);
  }
}

function requiredField<T>(record: Record<string, unknown>, key: string): T {
  if (!(key in record)) {
    throw new Error(`Mailbox ledger state is missing required field '${key}'`);
  }
  return record[key] as T;
}

function buildTransportUpdate(params: {
  mode: MessagingTransportMode;
  available: boolean;
  contractAddress: string;
  reason?: string;
  cursor?: string;
  includeHealthyProbe?: boolean;
  includePoll?: boolean;
}): MessagingTransportUpdate {
  const now = new Date().toISOString();
  return {
    mode: params.mode,
    available: params.available,
    mailboxContractAddress: params.contractAddress,
    lastHealthyProbeAt: params.includeHealthyProbe === false ? undefined : now,
    lastPollAt: params.includePoll ? now : undefined,
    lastObservedCursor: params.cursor,
    reason: params.reason,
  };
}

export async function resolveMailboxDeployment(
  network: WalletHelperNetwork,
  manifestPath: string,
  contractAddressOverride?: string,
): Promise<{ manifest: MailboxDeploymentManifest; contractAddress: string; artifactDir: string }> {
  const manifestRaw = await readTextFileNode(manifestPath);
  const manifest = JSON.parse(manifestRaw) as MailboxDeploymentManifest;
  if (manifest.schema !== 'ziros-wallet-mailbox-deployment-v1') {
    throw new Error(`Unsupported mailbox deployment manifest schema at ${manifestPath}`);
  }
  const deployment = manifest.networks[network];
  if (!deployment) {
    throw new Error(`Mailbox manifest ${manifestPath} does not define ${network}`);
  }
  const contractAddress = contractAddressOverride ?? deployment.contractAddress ?? undefined;
  if (!contractAddress) {
    throw new Error(`Mailbox manifest ${manifestPath} has no deployed ${network} contract address`);
  }
  const artifactDir = await resolveNodePath(manifestPath, deployment.compiledArtifactDir);
  await ensureAccessibleNode(artifactDir);
  return { manifest, contractAddress, artifactDir };
}

export async function loadMailboxCompiledContract(
  network: WalletHelperNetwork,
  manifestPath: string,
  contractAddressOverride?: string,
): Promise<LoadedMailboxContract> {
  const resolved = await resolveMailboxDeployment(network, manifestPath, contractAddressOverride);
  const contractModulePath = `${resolved.artifactDir}/contract/index.js`;
  const contractModule = await importNodeModule(contractModulePath);
  const contractCtor = contractModule.Contract as never;
  return {
    contractAddress: resolved.contractAddress,
    artifactDir: resolved.artifactDir,
    buildCompiledContract(witnesses: Record<string, unknown>) {
      return CompiledContract.make(
        resolved.manifest.contractName,
        contractCtor,
      ).pipe(
        CompiledContract.withWitnesses(witnesses as never),
        CompiledContract.withCompiledFileAssets(resolved.artifactDir),
      );
    },
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

export function mailboxCursor(decodedState: Record<string, unknown> | null): string | undefined {
  if (!decodedState) {
    return undefined;
  }
  const count = valueAsString(decodedState.mailbox_message_count);
  const envelopeHash = bytesHex(trimBytes(decodedState.latest_envelope_hash, 32));
  if (!count || !envelopeHash) {
    return undefined;
  }
  return `${count}:${envelopeHash}`;
}

export function buildMailboxWitnesses(
  envelope: MailboxEnvelope,
  nextMessageCount: bigint,
) {
  return {
    senderFingerprint: () => peerFingerprint(envelope.senderPeerId),
    receiverFingerprint: () => peerFingerprint(envelope.receiverPeerId),
    channelFingerprint: () => sha256Bytes(envelope.channelId),
    messageKind: () => kindToNumber(envelope.messageKind),
    sequence: () => BigInt(envelope.sequence),
    epochId: () => BigInt(envelope.epochId),
    postedAt: () => BigInt(Math.floor(Date.parse(envelope.postedAt) / 1000)),
    envelopeHash: () => hexToBytes(envelope.envelopeHash),
    nonce: () => hexToBytes(envelope.nonceHex),
    ciphertextLength: () => BigInt(Buffer.from(envelope.ciphertextHex, 'hex').length),
    ciphertext: () => hexToBytes(envelope.ciphertextHex),
    mlKemCiphertextLength: () => BigInt(Buffer.from(envelope.mlKemCiphertextHex, 'hex').length),
    mlKemCiphertext: () => hexToBytes(envelope.mlKemCiphertextHex),
    senderX25519PublicKeyLength: () =>
      BigInt(Buffer.from(envelope.senderAdvertisement.x25519PublicKeyHex, 'hex').length),
    senderX25519PublicKey: () => hexToBytes(envelope.senderAdvertisement.x25519PublicKeyHex),
    senderIdentityPublicKeyLength: () =>
      BigInt(Buffer.from(envelope.senderAdvertisement.identityPublicKeyHex, 'hex').length),
    senderIdentityPublicKey: () => hexToBytes(envelope.senderAdvertisement.identityPublicKeyHex),
    senderSignatureLength: () => BigInt(Buffer.from(envelope.senderSignatureHex, 'hex').length),
    senderSignature: () => hexToBytes(envelope.senderSignatureHex),
    nextMessageCount: () => nextMessageCount,
  };
}

export function decodeLatestEnvelopeFromLedger(
  decodedState: Record<string, unknown>,
  receiverPeerId: string,
): MailboxEnvelope | null {
  const storedReceiverFingerprint = Buffer.from(
    trimBytes(requiredField(decodedState, 'latest_receiver_fingerprint'), 32),
  ).toString('hex');
  const expectedReceiverFingerprint = bytesHex(peerFingerprint(receiverPeerId));
  if (storedReceiverFingerprint !== expectedReceiverFingerprint) {
    return null;
  }

  const senderIdentityPublicKeyHex = Buffer.from(
    trimBytes(
      requiredField(decodedState, 'latest_sender_identity_public_key'),
      requiredField(decodedState, 'latest_sender_identity_public_key_length'),
    ),
  ).toString('hex');

  return {
    channelId: '',
    senderPeerId: peerIdFromIdentityPublicKey(senderIdentityPublicKeyHex),
    receiverPeerId,
    messageKind: kindFromNumber(requiredField(decodedState, 'latest_message_kind')),
    sequence: Number(valueAsString(requiredField(decodedState, 'latest_sequence'))),
    epochId: Number(valueAsString(requiredField(decodedState, 'latest_epoch_id'))),
    senderAdvertisement: {
      epochId: Number(valueAsString(requiredField(decodedState, 'latest_epoch_id'))),
      x25519PublicKeyHex: Buffer.from(
        trimBytes(
          requiredField(decodedState, 'latest_sender_x25519_public_key'),
          requiredField(decodedState, 'latest_sender_x25519_public_key_length'),
        ),
      ).toString('hex'),
      mlKemPublicKeyHex: '',
      identityPublicKeyHex: senderIdentityPublicKeyHex,
    },
    nonceHex: Buffer.from(
      trimBytes(requiredField(decodedState, 'latest_nonce'), 12),
    ).toString('hex'),
    ciphertextHex: Buffer.from(
      trimBytes(
        requiredField(decodedState, 'latest_ciphertext'),
        requiredField(decodedState, 'latest_ciphertext_length'),
      ),
    ).toString('hex'),
    mlKemCiphertextHex: Buffer.from(
      trimBytes(
        requiredField(decodedState, 'latest_ml_kem_ciphertext'),
        requiredField(decodedState, 'latest_ml_kem_ciphertext_length'),
      ),
    ).toString('hex'),
    payloadVersion: 1,
    senderSignatureHex: Buffer.from(
      trimBytes(
        requiredField(decodedState, 'latest_sender_signature'),
        requiredField(decodedState, 'latest_sender_signature_length'),
      ),
    ).toString('hex'),
    envelopeHash: Buffer.from(
      trimBytes(requiredField(decodedState, 'latest_envelope_hash'), 32),
    ).toString('hex'),
    postedAt: new Date(
      Number(valueAsString(requiredField(decodedState, 'latest_posted_at'))) * 1000,
    ).toISOString(),
  };
}

export function healthyTransportUpdate(
  contractAddress: string,
  cursor?: string,
  includePoll = false,
): MessagingTransportUpdate {
  return buildTransportUpdate({
    mode: 'helper-adapter',
    available: true,
    contractAddress,
    cursor,
    includePoll,
  });
}

export function failedTransportUpdate(
  contractAddress: string,
  reason: string,
  mode: MessagingTransportMode = 'helper-adapter',
  includePoll = false,
): MessagingTransportUpdate {
  return buildTransportUpdate({
    mode,
    available: false,
    contractAddress,
    reason,
    includePoll,
  });
}
