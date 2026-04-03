import { sha256 } from '@noble/hashes/sha256';
import {
  bytesToHex,
  hexToBytes as nobleHexToBytes,
  utf8ToBytes,
} from '@noble/hashes/utils';

type PortableBytes = string | Uint8Array;

function toBytes(value: PortableBytes): Uint8Array {
  return typeof value === 'string' ? utf8ToBytes(value) : value;
}

export function sha256Hex(...parts: PortableBytes[]): string {
  const state = sha256.create();
  for (const part of parts) {
    state.update(toBytes(part));
  }
  return bytesToHex(state.digest());
}

export function sha256Bytes(value: PortableBytes): Uint8Array {
  return sha256(toBytes(value));
}

export function hexToBytes(value: string): Uint8Array {
  return nobleHexToBytes(value);
}

export function utf8Bytes(value: string): Uint8Array {
  return utf8ToBytes(value);
}

export function bytesHex(value: Uint8Array): string {
  return bytesToHex(value);
}

export function randomUUIDPortable(): string {
  const cryptoObject = (globalThis as { crypto?: {
    randomUUID?: () => string;
    getRandomValues?: (values: Uint8Array) => Uint8Array;
  } }).crypto;

  if (typeof cryptoObject?.randomUUID === 'function') {
    return cryptoObject.randomUUID();
  }

  const bytes = new Uint8Array(16);
  if (typeof cryptoObject?.getRandomValues === 'function') {
    cryptoObject.getRandomValues(bytes);
  } else {
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Math.floor(Math.random() * 256);
    }
  }

  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = bytesHex(bytes);
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join('-');
}
