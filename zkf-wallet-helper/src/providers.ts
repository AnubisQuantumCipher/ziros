import {
  type CombinedSwapInputs,
  type CombinedTokenTransfer,
  type FacadeState,
  type UtxoWithMeta,
  type WalletFacade,
} from '@midnight-ntwrk/wallet-sdk-facade';
import type { DustSecretKey, ZswapSecretKeys } from '@midnight-ntwrk/ledger-v8';
import type { UnshieldedKeystore } from '@midnight-ntwrk/wallet-sdk-unshielded-wallet';
import * as Rx from 'rxjs';

import { resolveWalletHelperConfig, toWalletConfiguration } from './config.js';
import {
  buildMailboxWitnesses,
  decodeLatestEnvelopeFromLedger,
  failedTransportUpdate,
  healthyTransportUpdate,
  loadMailboxCompiledContract,
  mailboxCursor,
} from './mailbox.js';
import { randomUUIDPortable, sha256Hex } from './portable_crypto.js';
import type {
  BuildIntentRequest,
  MailboxPollRequest,
  MailboxPollResponse,
  MailboxPostRequest,
  MailboxPostResponse,
  MailboxTransportProbeRequest,
  MessagingTransportUpdate,
  BuildSelfTransferRequest,
  BuildTransferRequest,
  DustUtxoCandidate,
  DesiredInput,
  DesiredOutput,
  DustOperationRequest,
  FinalizeAndSubmitRequest,
  OpenWalletSessionRequest,
  OpenWalletSessionResponse,
  PreparedTransactionHandle,
  PreparedMessage,
  ProveRoute,
  SubmissionGrant,
  SyncRequest,
  TxReviewPayload,
  WalletActivityEntry,
  WalletHelperConfig,
  WalletOverview,
  WalletSeedMaterial,
} from './types.js';

const MIDNIGHT_ADDITIONAL_FEE_OVERHEAD = 300_000_000_000_000n;
const MIDNIGHT_FEE_BLOCKS_MARGIN = 5;
const PROBE_TIMEOUT_MS = 4_000;

interface PreparedTransactionState {
  method: PreparedTransactionHandle['method'];
  review: TxReviewPayload;
  recipe: unknown;
}

interface MailboxDustDiagnostics {
  spendableDustRaw: bigint;
  spendableDustCoins: number;
  registeredNightUtxos: number;
  dustSyncConnected: boolean;
}

async function ensureWebSocketImplementation(): Promise<void> {
  if (typeof (globalThis as { WebSocket?: unknown }).WebSocket !== 'undefined') {
    return;
  }
  const ws = await import('ws');
  // @ts-expect-error Midnight SDK expects a global WebSocket implementation in Node.
  globalThis.WebSocket = ws.WebSocket;
}

async function loadAddressFormat() {
  return import('@midnight-ntwrk/wallet-sdk-address-format');
}

async function loadIndexerPublicDataProvider() {
  await ensureWebSocketImplementation();
  return (await import('@midnight-ntwrk/midnight-js-indexer-public-data-provider'))
    .indexerPublicDataProvider;
}

async function loadMailboxPostingModules() {
  const [
    { createUnprovenCallTx },
    { httpClientProofProvider },
    { NodeZkConfigProvider },
  ] = await Promise.all([
    import('@midnight-ntwrk/midnight-js-contracts'),
    import('@midnight-ntwrk/midnight-js-http-client-proof-provider'),
    import('@midnight-ntwrk/midnight-js-node-zk-config-provider'),
  ]);

  return {
    createUnprovenCallTx,
    httpClientProofProvider,
    NodeZkConfigProvider,
  };
}

function parseRawAmount(raw: string): bigint {
  return BigInt(raw);
}

function stringifyValue(value: unknown): string {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (typeof value === 'string') {
    return value;
  }
  if (value && typeof value === 'object' && 'toString' in value) {
    return value.toString();
  }
  return String(value);
}

function normalizeBigintRecord(record: Record<string, bigint>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(record).map(([key, value]) => [key, value.toString()]),
  );
}

async function groupOutputs(
  network: WalletHelperConfig['network'],
  desiredOutputs: DesiredOutput[],
): Promise<CombinedTokenTransfer[]> {
  const {
    MidnightBech32m,
    ShieldedAddress,
    UnshieldedAddress,
  } = await loadAddressFormat();
  const shielded = desiredOutputs.filter((output) => output.mode === 'shielded');
  const unshielded = desiredOutputs.filter((output) => output.mode === 'unshielded');
  const groups: CombinedTokenTransfer[] = [];

  if (shielded.length > 0) {
    groups.push({
      type: 'shielded',
      outputs: shielded.map((output) => ({
        type: output.tokenType as never,
        receiverAddress: MidnightBech32m.parse(output.receiverAddress).decode(
          ShieldedAddress,
          network,
        ),
        amount: parseRawAmount(output.amountRaw),
      })),
    });
  }

  if (unshielded.length > 0) {
    groups.push({
      type: 'unshielded',
      outputs: unshielded.map((output) => ({
        type: output.tokenType as never,
        receiverAddress: MidnightBech32m.parse(output.receiverAddress).decode(
          UnshieldedAddress,
          network,
        ),
        amount: parseRawAmount(output.amountRaw),
      })),
    });
  }

  return groups;
}

function groupInputs(desiredInputs: DesiredInput[]): CombinedSwapInputs {
  const shielded: Record<string, bigint> = {};
  const unshielded: Record<string, bigint> = {};

  for (const input of desiredInputs) {
    const amount = parseRawAmount(input.amountRaw);
    if (input.mode === 'shielded') {
      shielded[input.tokenType] = amount;
    } else {
      unshielded[input.tokenType] = amount;
    }
  }

  return {
    shielded: Object.keys(shielded).length > 0 ? shielded : undefined,
    unshielded: Object.keys(unshielded).length > 0 ? unshielded : undefined,
  };
}

function digestForPreparedRecipe(method: string, review: TxReviewPayload, recipe: unknown): string {
  return sha256Hex(
    method,
    JSON.stringify(review),
    JSON.stringify(renderRecipeForDigest(recipe)),
  );
}

function renderRecipeForDigest(recipe: unknown): unknown {
  if (!recipe || typeof recipe !== 'object') {
    return recipe;
  }
  const value = recipe as Record<string, unknown>;
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => {
      if (entry && typeof entry === 'object' && 'toString' in entry) {
        return [key, entry.toString()];
      }
      return [key, entry];
    }),
  );
}

async function probeProofServer(url: string): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
    });
    void response;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`proof_server_unavailable: ${url} is unreachable (${message})`);
  } finally {
    clearTimeout(timer);
  }
}

export async function selectHealthyProveRoute(
  routes: readonly ProveRoute[],
  probe: (url: string) => Promise<void> = probeProofServer,
): Promise<ProveRoute> {
  let lastError: unknown;
  for (const route of routes) {
    try {
      await probe(route.proofServerUrl);
      return route;
    } catch (error) {
      lastError = error;
    }
  }
  if (lastError instanceof Error) {
    throw lastError;
  }
  throw new Error('proof_server_unavailable: no configured prover route is reachable');
}

export function normalizeDustCandidates(coins: readonly UtxoWithMeta[]): DustUtxoCandidate[] {
  return coins
    .filter((coin) => stringifyValue(coin.utxo.type).toUpperCase() === 'NIGHT')
    .map((coin, index) => ({
      index,
      valueRaw: stringifyValue(coin.utxo.value),
      tokenType: stringifyValue(coin.utxo.type),
      owner: stringifyValue(coin.utxo.owner),
      intentHash: stringifyValue(coin.utxo.intentHash),
      outputNo: coin.utxo.outputNo,
      ctime: coin.meta.ctime.toISOString(),
      registeredForDustGeneration: coin.meta.registeredForDustGeneration,
    }));
}

export function mailboxTransportBlockReason(
  diagnostics: MailboxDustDiagnostics,
): string | undefined {
  if (!diagnostics.dustSyncConnected) {
    return 'Mailbox transport is configured, but the DUST wallet is still syncing.';
  }
  if (diagnostics.spendableDustRaw > 0n) {
    return undefined;
  }
  if (diagnostics.registeredNightUtxos === 0) {
    return 'Mailbox transport is configured, but this wallet has no NIGHT UTXOs registered for DUST generation yet.';
  }
  return (
    'Mailbox transport is configured, but the wallet still has no spendable tDUST. ' +
    `Registered NIGHT UTXOs: ${diagnostics.registeredNightUtxos}. Wait for tDUST to materialize before sending messages.`
  );
}

async function waitForWalletSync(wallet: WalletFacade): Promise<FacadeState> {
  return Rx.firstValueFrom(
    wallet.state().pipe(
      Rx.filter((state) => state.isSynced),
      Rx.timeout({ each: 600_000 }),
    ),
  );
}

export class MidnightHelperSession {
  readonly sessionId: string;
  readonly config: WalletHelperConfig;
  readonly seed: WalletSeedMaterial;

  private wallet: WalletFacade;
  private zswapSecretKeys: ZswapSecretKeys;
  private dustSecretKey: DustSecretKey;
  private unshieldedKeystore: UnshieldedKeystore;
  private activeProveRoute: ProveRoute;
  private readonly prepared = new Map<string, PreparedTransactionState>();
  private readonly consumedSubmissionGrants = new Set<string>();

  private constructor(params: {
    sessionId: string;
    config: WalletHelperConfig;
    seed: WalletSeedMaterial;
    wallet: WalletFacade;
    zswapSecretKeys: ZswapSecretKeys;
    dustSecretKey: DustSecretKey;
    unshieldedKeystore: UnshieldedKeystore;
    activeProveRoute: ProveRoute;
  }) {
    this.sessionId = params.sessionId;
    this.config = params.config;
    this.seed = params.seed;
    this.wallet = params.wallet;
    this.zswapSecretKeys = params.zswapSecretKeys;
    this.dustSecretKey = params.dustSecretKey;
    this.unshieldedKeystore = params.unshieldedKeystore;
    this.activeProveRoute = params.activeProveRoute;
  }

  static async open(request: OpenWalletSessionRequest): Promise<{
    session: MidnightHelperSession;
    response: OpenWalletSessionResponse;
  }> {
    const config = resolveWalletHelperConfig(request.network, request.services);
    const activeProveRoute = await selectHealthyProveRoute(config.proveRoutes);
    const runtime = await createWalletRuntime(config, request.seed, activeProveRoute);

    const session = new MidnightHelperSession({
      sessionId: randomUUIDPortable(),
      config,
      seed: request.seed,
      wallet: runtime.wallet,
      zswapSecretKeys: runtime.zswapSecretKeys,
      dustSecretKey: runtime.dustSecretKey,
      unshieldedKeystore: runtime.unshieldedKeystore,
      activeProveRoute,
    });
    const addresses = await session.getAddresses();
    return {
      session,
      response: {
        sessionId: session.sessionId,
        configuration: toWalletConfiguration(session.currentConfig()),
        addresses,
      },
    };
  }

  async stop(): Promise<void> {
    await this.wallet.stop();
    this.prepared.clear();
    this.consumedSubmissionGrants.clear();
  }

  async sync(_request: SyncRequest): Promise<WalletOverview> {
    await this.ensureHealthyProveRoute();
    await waitForWalletSync(this.wallet);
    return this.getOverview();
  }

  async getOverview(): Promise<WalletOverview> {
    const state = await Rx.firstValueFrom(this.wallet.state());
    const addresses = await this.getAddresses();
    const registeredNightUtxos = state.unshielded.availableCoins.filter(
      (coin) => coin.meta.registeredForDustGeneration,
    ).length;

    return {
      network: this.config.network,
      sync: {
        shieldedConnected: state.shielded.progress.isConnected,
        unshieldedConnected: state.unshielded.progress.isConnected,
        dustConnected: state.dust.progress.isConnected,
        synced: state.isSynced,
      },
      balances: {
        shielded: normalizeBigintRecord(state.shielded.balances),
        unshielded: normalizeBigintRecord(state.unshielded.balances),
        dust: {
          spendableRaw: state.dust.balance(new Date()).toString(),
          coinCount: state.dust.availableCoins.length,
          registeredNightUtxos,
        },
      },
      addresses,
    };
  }

  async getBalances() {
    return (await this.getOverview()).balances;
  }

  async listDustCandidates(): Promise<DustUtxoCandidate[]> {
    const state = await Rx.firstValueFrom(this.wallet.state());
    return normalizeDustCandidates(state.unshielded.availableCoins);
  }

  async getAddresses(): Promise<OpenWalletSessionResponse['addresses']> {
    const state = await Rx.firstValueFrom(this.wallet.state());
    return {
      shieldedAddress: stringifyValue(state.shielded.address),
      shieldedCoinPublicKey: stringifyValue(state.shielded.coinPublicKey),
      shieldedEncryptionPublicKey: stringifyValue(state.shielded.encryptionPublicKey),
      unshieldedAddress: stringifyValue(state.unshielded.address),
      dustAddress: stringifyValue(state.dust.address),
    };
  }

  async getActivity(): Promise<WalletActivityEntry[]> {
    const state = await Rx.firstValueFrom(this.wallet.state());
    const entries: WalletActivityEntry[] = [];
    for await (const entry of state.unshielded.transactionHistory.getAll()) {
      entries.push({
        id: entry.id,
        hash: entry.hash,
        protocolVersion: entry.protocolVersion,
        identifiers: [...entry.identifiers],
        timestamp: entry.timestamp.toISOString(),
        feesRaw: entry.fees?.toString(),
        status: entry.status,
        createdUtxos: entry.createdUtxos.map((utxo) => ({
          ...utxo,
          value: utxo.value.toString(),
        })),
        spentUtxos: entry.spentUtxos.map((utxo) => ({
          ...utxo,
          value: utxo.value.toString(),
        })),
      });
    }
    entries.sort((left, right) => right.id - left.id);
    return entries;
  }

  async buildTransfer(request: BuildTransferRequest): Promise<PreparedTransactionHandle> {
    const activeProveRoute = await this.ensureHealthyProveRoute();
    const groupedOutputs = await groupOutputs(this.config.network, request.desiredOutputs);
    const recipe = await this.wallet.transferTransaction(
      groupedOutputs,
      {
        shieldedSecretKeys: this.zswapSecretKeys,
        dustSecretKey: this.dustSecretKey,
      },
      {
        ttl: ttlOneHour(),
        payFees: request.payFees ?? true,
      },
    );
    const review = buildReviewPayload({
      origin: request.origin,
      network: this.config.network,
      method: 'transfer',
      outputs: request.desiredOutputs,
      proveRoute: activeProveRoute,
      warnings: [],
      humanSummary: `Transfer ${request.desiredOutputs.map((output) => `${output.amountRaw} ${output.tokenType}`).join(', ')}`,
    });
    return this.storePrepared('transfer', review, recipe);
  }

  async buildIntent(request: BuildIntentRequest): Promise<PreparedTransactionHandle> {
    const activeProveRoute = await this.ensureHealthyProveRoute();
    const recipe = await this.wallet.initSwap(
      groupInputs(request.desiredInputs),
      await groupOutputs(this.config.network, request.desiredOutputs),
      {
        shieldedSecretKeys: this.zswapSecretKeys,
        dustSecretKey: this.dustSecretKey,
      },
      {
        ttl: ttlOneHour(),
        payFees: request.payFees ?? true,
      },
    );
    const review = buildReviewPayload({
      origin: request.origin,
      network: this.config.network,
      method: 'intent',
      outputs: request.desiredOutputs,
      proveRoute: activeProveRoute,
      warnings: request.desiredInputs.map(
        (input) => `Intent consumes ${input.amountRaw} ${input.tokenType} from ${input.mode}`,
      ),
      humanSummary: `Intent ${request.desiredOutputs.map((output) => `${output.amountRaw} ${output.tokenType}`).join(', ')}`,
    });
    return this.storePrepared('intent', review, recipe);
  }

  async buildShield(request: BuildSelfTransferRequest): Promise<PreparedTransactionHandle> {
    const activeProveRoute = await this.ensureHealthyProveRoute();
    const addresses = await this.getAddresses();
    const recipe = await this.wallet.transferTransaction(
      await groupOutputs(this.config.network, [
        {
          mode: 'shielded',
          receiverAddress: addresses.shieldedAddress,
          tokenType: request.tokenType,
          amountRaw: request.amountRaw,
        },
      ]),
      {
        shieldedSecretKeys: this.zswapSecretKeys,
        dustSecretKey: this.dustSecretKey,
      },
      {
        ttl: ttlOneHour(),
        payFees: request.payFees ?? true,
      },
    );
    const review = buildReviewPayload({
      origin: request.origin,
      network: this.config.network,
      method: 'shield',
      outputs: [
        {
          mode: 'shielded',
          receiverAddress: addresses.shieldedAddress,
          tokenType: request.tokenType,
          amountRaw: request.amountRaw,
        },
      ],
      proveRoute: activeProveRoute,
      warnings: [],
      humanSummary: `Shield ${request.amountRaw} ${request.tokenType}`,
    });
    return this.storePrepared('shield', review, recipe);
  }

  async buildUnshield(request: BuildSelfTransferRequest): Promise<PreparedTransactionHandle> {
    const activeProveRoute = await this.ensureHealthyProveRoute();
    const addresses = await this.getAddresses();
    const recipe = await this.wallet.transferTransaction(
      await groupOutputs(this.config.network, [
        {
          mode: 'unshielded',
          receiverAddress: addresses.unshieldedAddress,
          tokenType: request.tokenType,
          amountRaw: request.amountRaw,
        },
      ]),
      {
        shieldedSecretKeys: this.zswapSecretKeys,
        dustSecretKey: this.dustSecretKey,
      },
      {
        ttl: ttlOneHour(),
        payFees: request.payFees ?? true,
      },
    );
    const review = buildReviewPayload({
      origin: request.origin,
      network: this.config.network,
      method: 'unshield',
      outputs: [
        {
          mode: 'unshielded',
          receiverAddress: addresses.unshieldedAddress,
          tokenType: request.tokenType,
          amountRaw: request.amountRaw,
        },
      ],
      proveRoute: activeProveRoute,
      warnings: [],
      humanSummary: `Unshield ${request.amountRaw} ${request.tokenType}`,
    });
    return this.storePrepared('unshield', review, recipe);
  }

  async registerDust(request: DustOperationRequest): Promise<PreparedTransactionHandle> {
    const activeProveRoute = await this.ensureHealthyProveRoute();
    const selected = await this.selectNightUtxos(request.utxoIndexes, false);
    const { DustAddress, MidnightBech32m } = await loadAddressFormat();
    const dustReceiverAddress = request.dustReceiverAddress
      ? MidnightBech32m.parse(request.dustReceiverAddress).decode(DustAddress, this.config.network)
      : undefined;
    const recipe = await this.wallet.registerNightUtxosForDustGeneration(
      selected,
      this.unshieldedKeystore.getPublicKey(),
      (payload) => this.unshieldedKeystore.signData(payload),
      dustReceiverAddress,
    );
    const review = buildReviewPayload({
      origin: request.origin,
      network: this.config.network,
      method: 'dust-register',
      outputs: [],
      proveRoute: activeProveRoute,
      warnings: [`Registers ${selected.length} NIGHT UTXO(s) for DUST generation.`],
      humanSummary: 'Register NIGHT UTXOs for DUST generation',
      dustImpact: 'Register selected NIGHT UTXOs for DUST generation.',
    });
    return this.storePrepared('dust-register', review, recipe);
  }

  async deregisterDust(request: DustOperationRequest): Promise<PreparedTransactionHandle> {
    const activeProveRoute = await this.ensureHealthyProveRoute();
    const selected = await this.selectNightUtxos(request.utxoIndexes, true);
    const recipe = await this.wallet.deregisterFromDustGeneration(
      selected,
      this.unshieldedKeystore.getPublicKey(),
      (payload) => this.unshieldedKeystore.signData(payload),
    );
    const review = buildReviewPayload({
      origin: request.origin,
      network: this.config.network,
      method: 'dust-deregister',
      outputs: [],
      proveRoute: activeProveRoute,
      warnings: [`Deregisters ${selected.length} NIGHT UTXO(s) from DUST generation.`],
      humanSummary: 'Deregister NIGHT UTXOs from DUST generation',
      dustImpact: 'Stop DUST generation on the selected NIGHT UTXOs.',
    });
    return this.storePrepared('dust-deregister', review, recipe);
  }

  async redesignateDust(request: DustOperationRequest): Promise<PreparedTransactionHandle> {
    const handle = await this.registerDust(request);
    return {
      ...handle,
      review: {
        ...handle.review,
        method: 'dust-redesignate',
        warnings: [
          ...handle.review.warnings,
          'Redesignate uses a fresh DUST registration flow with the requested receiver address.',
        ],
        human_summary: 'Redesignate DUST receiver for selected NIGHT UTXOs',
      },
      method: 'dust-redesignate',
    };
  }

  async finalizeAndSubmit(request: FinalizeAndSubmitRequest): Promise<{ txId: string }> {
    const prepared = this.prepared.get(request.txDigest);
    if (!prepared) {
      throw new Error(`Unknown prepared transaction ${request.txDigest}`);
    }
    validateSubmissionGrant(request.submissionGrant, request.txDigest, this.config.network, prepared.method);
    if (this.consumedSubmissionGrants.has(request.submissionGrant.grant_id)) {
      throw new Error(`Submission grant ${request.submissionGrant.grant_id} has already been used`);
    }
    const finalized = await this.wallet.finalizeRecipe(prepared.recipe as never);
    const txId = await this.wallet.submitTransaction(finalized);
    this.consumedSubmissionGrants.add(request.submissionGrant.grant_id);
    this.prepared.delete(request.txDigest);
    return { txId };
  }

  getConfiguration() {
    return toWalletConfiguration(this.currentConfig());
  }

  getConnectionStatus() {
    return { connected: true, networkId: this.config.network };
  }

  async probeMailboxTransport(
    request: MailboxTransportProbeRequest,
  ): Promise<MessagingTransportUpdate> {
    try {
      const indexerPublicDataProvider = await loadIndexerPublicDataProvider();
      const loaded = await loadMailboxCompiledContract(
        this.config.network,
        request.manifestPath,
        request.contractAddress,
      );
      const publicDataProvider = indexerPublicDataProvider(
        this.config.indexerUrl,
        this.config.indexerWsUrl,
      );
      const contractState = await publicDataProvider.queryContractState(loaded.contractAddress as never);
      if (!contractState) {
        return failedTransportUpdate(
          loaded.contractAddress,
          `Mailbox probe failed: contract ${loaded.contractAddress} is not deployed or not yet indexed.`,
        );
      }
      const diagnostics = await this.collectMailboxDustDiagnostics();
      const blockReason = mailboxTransportBlockReason(diagnostics);
      if (blockReason) {
        return failedTransportUpdate(loaded.contractAddress, blockReason);
      }
      return healthyTransportUpdate(loaded.contractAddress);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return failedTransportUpdate(
        request.contractAddress,
        `Mailbox probe failed: ${message}`,
      );
    }
  }

  async postMailboxEnvelope(request: MailboxPostRequest): Promise<MailboxPostResponse> {
    const grant = request.preparedMessage.submissionGrant;
    if (!grant) {
      throw new Error('Prepared mailbox post is missing a Rust-issued submission grant');
    }
    validateSubmissionGrant(
      grant,
      request.preparedMessage.message.envelopeHash,
      this.config.network,
      'send-message',
    );
    if (this.consumedSubmissionGrants.has(grant.grant_id)) {
      throw new Error(`Submission grant ${grant.grant_id} has already been used`);
    }

    const indexerPublicDataProvider = await loadIndexerPublicDataProvider();
    const {
      createUnprovenCallTx,
      httpClientProofProvider,
      NodeZkConfigProvider,
    } = await loadMailboxPostingModules();
    const loaded = await loadMailboxCompiledContract(
      this.config.network,
      request.manifestPath,
      request.contractAddress,
    );
    const publicDataProvider = indexerPublicDataProvider(
      this.config.indexerUrl,
      this.config.indexerWsUrl,
    );
    const diagnostics = await this.collectMailboxDustDiagnostics();
    const blockReason = mailboxTransportBlockReason(diagnostics);
    if (blockReason) {
      throw new Error(blockReason);
    }
    const currentState = await publicDataProvider.queryContractState(loaded.contractAddress as never);
    if (!currentState) {
      throw new Error(
        `Mailbox contract ${loaded.contractAddress} is not deployed or not yet indexed.`,
      );
    }
    const decodedState = currentState ? loaded.decodeLedgerState(currentState) : null;
    const currentCount = decodedState?.mailbox_message_count
      ? BigInt(stringifyValue(decodedState.mailbox_message_count))
      : 0n;
    const compiledContract = loaded.buildCompiledContract(
      buildMailboxWitnesses(request.preparedMessage.envelope, currentCount + 1n),
    );
    const zkConfigProvider = new NodeZkConfigProvider<string>(loaded.artifactDir);
    const callTxData = await createUnprovenCallTx(
      {
        zkConfigProvider,
        publicDataProvider,
        walletProvider: {
          getCoinPublicKey: () => this.zswapSecretKeys.coinPublicKey,
          getEncryptionPublicKey: () => this.zswapSecretKeys.encryptionPublicKey,
        },
      } as never,
      {
        compiledContract: compiledContract as never,
        contractAddress: loaded.contractAddress as never,
        circuitId: 'post_mailbox_envelope' as never,
        args: [],
      } as never,
    );
    const proofProvider = httpClientProofProvider(
      this.activeProveRoute.proofServerUrl,
      zkConfigProvider,
    );
    const provenTx = await proofProvider.proveTx(callTxData.private.unprovenTx);
    const recipe = await this.wallet.balanceUnboundTransaction(
      provenTx,
      {
        shieldedSecretKeys: this.zswapSecretKeys,
        dustSecretKey: this.dustSecretKey,
      },
      { ttl: ttlOneHour() },
    );
    const finalized = await this.wallet.finalizeRecipe(recipe);
    const txId = await this.wallet.submitTransaction(finalized);
    const txData = await publicDataProvider.watchForTxData(txId as never);
    this.consumedSubmissionGrants.add(grant.grant_id);
    const nextState = await publicDataProvider.queryContractState(loaded.contractAddress as never);
    const nextDecoded = nextState ? loaded.decodeLedgerState(nextState) : null;
    return {
      txHash: String(txData.txHash),
      blockHeight: txData.blockHeight,
      postedAt: new Date(txData.blockTimestamp).toISOString(),
      cursor: mailboxCursor(nextDecoded),
    };
  }

  async pollMailboxEnvelopes(request: MailboxPollRequest): Promise<MailboxPollResponse> {
    const indexerPublicDataProvider = await loadIndexerPublicDataProvider();
    const loaded = await loadMailboxCompiledContract(
      this.config.network,
      request.manifestPath,
      request.contractAddress,
    );
    const publicDataProvider = indexerPublicDataProvider(
      this.config.indexerUrl,
      this.config.indexerWsUrl,
    );
    const diagnostics = await this.collectMailboxDustDiagnostics();
    const state = await publicDataProvider.queryContractState(loaded.contractAddress as never);
    if (!state) {
      return {
        envelopes: [],
        transport: failedTransportUpdate(
          loaded.contractAddress,
          `Mailbox contract ${loaded.contractAddress} is not deployed or not yet indexed.`,
          'helper-adapter',
          true,
        ),
      };
    }
    const decodedState = state ? loaded.decodeLedgerState(state) : null;
    const cursor = mailboxCursor(decodedState);
    const blockReason = mailboxTransportBlockReason(diagnostics);
    const transport = blockReason
      ? failedTransportUpdate(loaded.contractAddress, blockReason, 'helper-adapter', true)
      : healthyTransportUpdate(
          loaded.contractAddress,
          cursor,
          true,
        );
    if (!decodedState || !cursor || cursor === request.lastObservedCursor) {
      return {
        envelopes: [],
        transport,
      };
    }
    const envelope = decodeLatestEnvelopeFromLedger(decodedState, request.receiverPeerId);
    return {
      envelopes: envelope ? [envelope] : [],
      transport,
    };
  }

  private async selectNightUtxos(
    indexes: number[] | undefined,
    requireRegistered: boolean,
  ): Promise<UtxoWithMeta[]> {
    const state = await Rx.firstValueFrom(this.wallet.state());
    const candidates = state.unshielded.availableCoins.filter(
      (coin) => stringifyValue(coin.utxo.type).toUpperCase() === 'NIGHT',
    );
    const selected = indexes?.length
      ? indexes.map((index) => candidates[index]).filter((coin): coin is UtxoWithMeta => Boolean(coin))
      : candidates.filter((coin) => coin.meta.registeredForDustGeneration === requireRegistered).slice(0, 1);
    if (selected.length === 0) {
      throw new Error(
        requireRegistered
          ? 'No registered NIGHT UTXOs are available for DUST deregistration.'
          : 'No NIGHT UTXOs are available for DUST registration.',
      );
    }
    if (selected.some((coin) => coin.meta.registeredForDustGeneration !== requireRegistered)) {
      throw new Error(
        requireRegistered
          ? 'Selected UTXO set includes NIGHT outputs that are not registered for DUST generation.'
          : 'Selected UTXO set includes NIGHT outputs that are already registered for DUST generation.',
      );
    }
    return selected;
  }

  private currentConfig(): WalletHelperConfig {
    return {
      ...this.config,
      proofServerUrl: this.activeProveRoute.proofServerUrl,
      gatewayUrl: this.activeProveRoute.gatewayUrl ?? this.config.gatewayUrl,
    };
  }

  private async ensureHealthyProveRoute(): Promise<ProveRoute> {
    try {
      await probeProofServer(this.activeProveRoute.proofServerUrl);
      return this.activeProveRoute;
    } catch {
      const route = await selectHealthyProveRoute(this.config.proveRoutes);
      if (route.proofServerUrl === this.activeProveRoute.proofServerUrl) {
        throw new Error(`proof_server_unavailable: ${route.proofServerUrl} is unreachable`);
      }
      await this.reopenForProveRoute(route);
      return route;
    }
  }

  private async reopenForProveRoute(route: ProveRoute): Promise<void> {
    await this.wallet.stop();
    const runtime = await createWalletRuntime(this.config, this.seed, route);
    this.wallet = runtime.wallet;
    this.zswapSecretKeys = runtime.zswapSecretKeys;
    this.dustSecretKey = runtime.dustSecretKey;
    this.unshieldedKeystore = runtime.unshieldedKeystore;
    this.activeProveRoute = route;
  }

  private storePrepared(
    method: PreparedTransactionHandle['method'],
    review: TxReviewPayload,
    recipe: unknown,
  ): PreparedTransactionHandle {
    const txDigest = digestForPreparedRecipe(method, review, recipe);
    const preparedReview = { ...review, tx_digest: txDigest, method };
    this.prepared.set(txDigest, { method, review: preparedReview, recipe });
    return {
      sessionId: this.sessionId,
      txDigest,
      review: preparedReview,
      method,
    };
  }

  private async collectMailboxDustDiagnostics(): Promise<MailboxDustDiagnostics> {
    const state = await Rx.firstValueFrom(this.wallet.state());
    return {
      spendableDustRaw: state.dust.balance(new Date()),
      spendableDustCoins: state.dust.availableCoins.length,
      registeredNightUtxos: state.unshielded.availableCoins.filter(
        (coin) => coin.meta.registeredForDustGeneration,
      ).length,
      dustSyncConnected: state.dust.progress.isConnected,
    };
  }
}

function ttlOneHour(): Date {
  return new Date(Date.now() + 60 * 60 * 1000);
}

function buildReviewPayload(params: {
  origin: string;
  network: WalletHelperConfig['network'];
  method: TxReviewPayload['method'];
  outputs: DesiredOutput[];
  proveRoute?: ProveRoute;
  warnings: string[];
  humanSummary: string;
  dustImpact?: string;
}): TxReviewPayload {
  const nightTotal = params.outputs
    .filter((output) => output.tokenType.toUpperCase() === 'NIGHT')
    .reduce((sum, output) => sum + parseRawAmount(output.amountRaw), 0n);
  const dustTotal = params.outputs
    .filter((output) => output.tokenType.toUpperCase() === 'DUST')
    .reduce((sum, output) => sum + parseRawAmount(output.amountRaw), 0n);

  return {
    origin: params.origin,
    network: params.network,
    method: params.method,
    tx_digest: '',
    outputs: params.outputs.map((output) => ({
      recipient: output.receiverAddress,
      token_kind: output.tokenType,
      amount_raw: output.amountRaw,
    })),
    night_total_raw: nightTotal.toString(),
    dust_total_raw: dustTotal.toString(),
    fee_raw: '0',
    dust_impact: params.dustImpact,
    shielded: params.outputs.some((output) => output.mode === 'shielded'),
    prover_route: params.proveRoute?.label ?? 'proof-server',
    warnings: params.warnings,
    human_summary: params.humanSummary,
  };
}

async function createWalletRuntime(
  config: WalletHelperConfig,
  seed: WalletSeedMaterial,
  proveRoute: ProveRoute,
): Promise<{
  wallet: WalletFacade;
  zswapSecretKeys: ZswapSecretKeys;
  dustSecretKey: DustSecretKey;
  unshieldedKeystore: UnshieldedKeystore;
}> {
  await ensureWebSocketImplementation();
  let WalletFactory: Awaited<typeof import('@midnight-ntwrk/testkit-js')>['WalletFactory'];
  let WalletSeeds: Awaited<typeof import('@midnight-ntwrk/testkit-js')>['WalletSeeds'];
  let createKeystore: Awaited<
    typeof import('@midnight-ntwrk/wallet-sdk-unshielded-wallet')
  >['createKeystore'];
  let InMemoryTransactionHistoryStorage: Awaited<
    typeof import('@midnight-ntwrk/wallet-sdk-unshielded-wallet')
  >['InMemoryTransactionHistoryStorage'];
  let LedgerParameters: Awaited<typeof import('@midnight-ntwrk/ledger-v8')>['LedgerParameters'];
  let ZswapSecretKeys: Awaited<typeof import('@midnight-ntwrk/ledger-v8')>['ZswapSecretKeys'];
  let DustSecretKey: Awaited<typeof import('@midnight-ntwrk/ledger-v8')>['DustSecretKey'];

  try {
    ({
      WalletFactory,
      WalletSeeds,
    } = await import('@midnight-ntwrk/testkit-js'));
    ({
      createKeystore,
      InMemoryTransactionHistoryStorage,
    } = await import('@midnight-ntwrk/wallet-sdk-unshielded-wallet'));
    ({
      LedgerParameters,
      ZswapSecretKeys,
      DustSecretKey,
    } = await import('@midnight-ntwrk/ledger-v8'));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `execution_unavailable: Midnight wallet runtime could not initialize in this host (${message})`,
    );
  }

  const walletNetworkId = config.network;
  const seeds =
    seed.kind === 'master-seed'
      ? WalletSeeds.fromMasterSeed(seed.value)
      : WalletSeeds.fromMnemonic(seed.value);
  const walletConfig = {
    indexerClientConnection: {
      indexerHttpUrl: config.indexerUrl,
      indexerWsUrl: config.indexerWsUrl,
    },
    provingServerUrl: new URL(proveRoute.proofServerUrl),
    networkId: walletNetworkId,
    relayURL: new URL(config.rpcUrl.replace(/^http/, 'ws')),
    txHistoryStorage: new InMemoryTransactionHistoryStorage(),
    costParameters: {
      additionalFeeOverhead: MIDNIGHT_ADDITIONAL_FEE_OVERHEAD,
      feeBlocksMargin: MIDNIGHT_FEE_BLOCKS_MARGIN,
    },
  };
  const dustOptions = {
    ledgerParams: LedgerParameters.initialParameters(),
    additionalFeeOverhead: MIDNIGHT_ADDITIONAL_FEE_OVERHEAD,
    feeBlocksMargin: MIDNIGHT_FEE_BLOCKS_MARGIN,
  };
  const unshieldedKeystore = createKeystore(seeds.unshielded, walletNetworkId);
  const shieldedWallet = WalletFactory.createShieldedWallet(walletConfig as never, seeds.shielded);
  const unshieldedWallet = WalletFactory.createUnshieldedWallet(
    walletConfig as never,
    unshieldedKeystore,
  );
  const dustWallet = WalletFactory.createDustWallet(walletConfig as never, seeds.dust, dustOptions);
  const wallet = (await WalletFactory.createWalletFacade(
    walletConfig as never,
    shieldedWallet,
    unshieldedWallet,
    dustWallet,
  )) as WalletFacade;
  const zswapSecretKeys = ZswapSecretKeys.fromSeed(seeds.shielded) as unknown as ZswapSecretKeys;
  const dustSecretKey = DustSecretKey.fromSeed(seeds.dust) as unknown as DustSecretKey;

  await wallet.start(zswapSecretKeys, dustSecretKey);
  await waitForWalletSync(wallet);

  return {
    wallet,
    zswapSecretKeys,
    dustSecretKey,
    unshieldedKeystore,
  };
}

export function validateSubmissionGrant(
  grant: SubmissionGrant,
  txDigest: string,
  network: WalletHelperConfig['network'],
  method: PreparedTransactionHandle['method'] | 'send-message',
): void {
  if (grant.tx_digest !== txDigest) {
    throw new Error(
      `Submission grant digest mismatch: expected ${txDigest}, got ${grant.tx_digest}`,
    );
  }
  if (grant.network !== network) {
    throw new Error(`Submission grant network mismatch: expected ${network}, got ${grant.network}`);
  }
  if (grant.method !== method && !(grant.method === 'transfer' && (method === 'shield' || method === 'unshield'))) {
    throw new Error(`Submission grant method mismatch: expected ${method}, got ${grant.method}`);
  }
  if (Date.parse(grant.expires_at) <= Date.now()) {
    throw new Error(`Submission grant ${grant.grant_id} has expired`);
  }
}
