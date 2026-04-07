export type WalletHelperNetwork = 'preprod' | 'preview';

export interface ProveRoute {
  label: string;
  kind: 'local' | 'upstream' | 'custom';
  proofServerUrl: string;
  gatewayUrl?: string;
  priority: number;
}

export interface WalletSeedMaterial {
  kind: 'master-seed' | 'mnemonic';
  value: string;
}

export interface WalletHelperConfig {
  network: WalletHelperNetwork;
  rpcUrl: string;
  indexerUrl: string;
  indexerWsUrl: string;
  explorerUrl: string;
  proofServerUrl: string;
  gatewayUrl: string;
  mailboxContractAddress?: string;
  mailboxManifestPath?: string;
  proveRoutes: ProveRoute[];
}

export interface OpenWalletSessionRequest {
  network: WalletHelperNetwork;
  seed: WalletSeedMaterial;
  services?: Partial<WalletHelperConfig>;
}

export interface DesiredOutput {
  mode: 'shielded' | 'unshielded';
  receiverAddress: string;
  tokenType: string;
  amountRaw: string;
}

export interface DesiredInput {
  mode: 'shielded' | 'unshielded';
  tokenType: string;
  amountRaw: string;
}

export interface ReviewOutput {
  recipient: string;
  token_kind: string;
  amount_raw: string;
}

export interface TxReviewPayload {
  origin: string;
  network: WalletHelperNetwork;
  method:
    | 'transfer'
    | 'intent'
    | 'shield'
    | 'unshield'
    | 'dust-register'
    | 'dust-deregister'
    | 'dust-redesignate';
  tx_digest: string;
  outputs: ReviewOutput[];
  night_total_raw: string;
  dust_total_raw: string;
  fee_raw: string;
  dust_impact?: string;
  shielded: boolean;
  prover_route?: string;
  warnings: string[];
  human_summary: string;
}

export interface SubmissionGrant {
  grant_id: string;
  token_id: string;
  origin: string;
  network: WalletHelperNetwork;
  method: string;
  tx_digest: string;
  issued_at: string;
  expires_at: string;
}

export interface PreparedTransactionHandle {
  sessionId: string;
  txDigest: string;
  review: TxReviewPayload;
  method: TxReviewPayload['method'];
}

export interface OpenWalletSessionResponse {
  sessionId: string;
  configuration: {
    indexerUri: string;
    indexerWsUri: string;
    proverServerUri: string;
    substrateNodeUri: string;
    networkId: WalletHelperNetwork;
    mailboxContractAddress?: string;
    mailboxManifestPath?: string;
  };
  addresses: {
    shieldedAddress: string;
    shieldedCoinPublicKey: string;
    shieldedEncryptionPublicKey: string;
    unshieldedAddress: string;
    dustAddress: string;
  };
}

export interface WalletOverview {
  network: WalletHelperNetwork;
  sync: {
    shieldedConnected: boolean;
    unshieldedConnected: boolean;
    dustConnected: boolean;
    synced: boolean;
  };
  balances: {
    shielded: Record<string, string>;
    unshielded: Record<string, string>;
    dust: {
      spendableRaw: string;
      coinCount: number;
      registeredNightUtxos: number;
    };
  };
  addresses: OpenWalletSessionResponse['addresses'];
}

export interface DustUtxoCandidate {
  index: number;
  valueRaw: string;
  tokenType: string;
  owner: string;
  intentHash: string;
  outputNo: number;
  ctime: string;
  registeredForDustGeneration: boolean;
}

export interface WalletActivityEntry {
  id: number;
  hash: string;
  protocolVersion: number;
  identifiers: string[];
  timestamp: string;
  feesRaw?: string;
  status: string;
  createdUtxos: Array<Record<string, unknown>>;
  spentUtxos: Array<Record<string, unknown>>;
}

export interface BuildTransferRequest {
  sessionId: string;
  origin: string;
  desiredOutputs: DesiredOutput[];
  payFees?: boolean;
}

export interface BuildIntentRequest {
  sessionId: string;
  origin: string;
  desiredInputs: DesiredInput[];
  desiredOutputs: DesiredOutput[];
  payFees?: boolean;
}

export interface BuildSelfTransferRequest {
  sessionId: string;
  origin: string;
  tokenType: string;
  amountRaw: string;
  payFees?: boolean;
}

export interface DustOperationRequest {
  sessionId: string;
  origin: string;
  utxoIndexes?: number[];
  dustReceiverAddress?: string;
}

export interface FinalizeAndSubmitRequest {
  sessionId: string;
  txDigest: string;
  submissionGrant: SubmissionGrant;
}

export interface SyncRequest {
  sessionId: string;
}

export type WalletMessageKind =
  | 'text'
  | 'transfer-receipt'
  | 'credential-request'
  | 'credential-response';

export interface WalletPeerAdvertisement {
  epochId: number;
  x25519PublicKeyHex: string;
  mlKemPublicKeyHex: string;
  identityPublicKeyHex: string;
}

export interface MailboxEnvelope {
  channelId: string;
  senderPeerId: string;
  receiverPeerId: string;
  messageKind: WalletMessageKind;
  sequence: number;
  epochId: number;
  senderAdvertisement: WalletPeerAdvertisement;
  nonceHex: string;
  ciphertextHex: string;
  mlKemCiphertextHex: string;
  payloadVersion: number;
  senderSignatureHex: string;
  envelopeHash: string;
  postedAt: string;
}

export interface PreparedMessage {
  message: {
    envelopeHash: string;
  };
  envelope: MailboxEnvelope;
  submissionGrant?: SubmissionGrant;
}

export type MessagingTransportMode =
  | 'unavailable'
  | 'helper-adapter'
  | 'disabled-on-ios';

export interface MessagingTransportUpdate {
  mode: MessagingTransportMode;
  available: boolean;
  mailboxContractAddress?: string;
  lastHealthyProbeAt?: string;
  lastPollAt?: string;
  lastObservedCursor?: string;
  reason?: string;
}

export interface MailboxTransportProbeRequest {
  sessionId: string;
  contractAddress: string;
  manifestPath: string;
}

export interface MailboxPostRequest extends MailboxTransportProbeRequest {
  preparedMessage: PreparedMessage;
}

export interface MailboxPostResponse {
  txHash: string;
  blockHeight?: number;
  postedAt: string;
  cursor?: string;
}

export interface MailboxPollRequest extends MailboxTransportProbeRequest {
  receiverPeerId: string;
  lastObservedCursor?: string;
}

export interface MailboxPollResponse {
  envelopes: MailboxEnvelope[];
  transport: MessagingTransportUpdate;
}
