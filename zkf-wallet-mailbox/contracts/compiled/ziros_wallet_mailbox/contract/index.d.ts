import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type Witnesses<PS> = {
  senderFingerprint(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
  receiverFingerprint(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
  channelFingerprint(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
  messageKind(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, bigint];
  sequence(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, bigint];
  epochId(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, bigint];
  postedAt(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, bigint];
  envelopeHash(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
  nonce(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
  ciphertextLength(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, bigint];
  ciphertext(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
  mlKemCiphertextLength(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, bigint];
  mlKemCiphertext(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
  senderX25519PublicKeyLength(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, bigint];
  senderX25519PublicKey(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
  senderIdentityPublicKeyLength(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, bigint];
  senderIdentityPublicKey(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
  senderSignatureLength(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, bigint];
  senderSignature(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
  nextMessageCount(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, bigint];
}

export type ImpureCircuits<PS> = {
  post_mailbox_envelope(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, []>;
}

export type ProvableCircuits<PS> = {
  post_mailbox_envelope(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, []>;
}

export type PureCircuits = {
}

export type Circuits<PS> = {
  post_mailbox_envelope(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, []>;
}

export type Ledger = {
  readonly latest_sender_fingerprint: Uint8Array;
  readonly latest_receiver_fingerprint: Uint8Array;
  readonly latest_channel_fingerprint: Uint8Array;
  readonly latest_message_kind: bigint;
  readonly latest_sequence: bigint;
  readonly latest_epoch_id: bigint;
  readonly latest_posted_at: bigint;
  readonly latest_envelope_hash: Uint8Array;
  readonly latest_nonce: Uint8Array;
  readonly latest_ciphertext_length: bigint;
  readonly latest_ciphertext: Uint8Array;
  readonly latest_ml_kem_ciphertext_length: bigint;
  readonly latest_ml_kem_ciphertext: Uint8Array;
  readonly latest_sender_x25519_public_key_length: bigint;
  readonly latest_sender_x25519_public_key: Uint8Array;
  readonly latest_sender_identity_public_key_length: bigint;
  readonly latest_sender_identity_public_key: Uint8Array;
  readonly latest_sender_signature_length: bigint;
  readonly latest_sender_signature: Uint8Array;
  readonly mailbox_message_count: bigint;
}

export type ContractReferenceLocations = any;

export declare const contractReferenceLocations : ContractReferenceLocations;

export declare class Contract<PS = any, W extends Witnesses<PS> = Witnesses<PS>> {
  witnesses: W;
  circuits: Circuits<PS>;
  impureCircuits: ImpureCircuits<PS>;
  provableCircuits: ProvableCircuits<PS>;
  constructor(witnesses: W);
  initialState(context: __compactRuntime.ConstructorContext<PS>): __compactRuntime.ConstructorResult<PS>;
}

export declare function ledger(state: __compactRuntime.StateValue | __compactRuntime.ChargedState): Ledger;
export declare const pureCircuits: PureCircuits;
