import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve } from 'node:path';

import type { MidnightRuntimeConfig } from './config';

interface MidnightHomeConfig {
  network?: string;
  wallet?: string;
}

interface MidnightStoredWallet {
  seed?: string;
  mnemonic?: string;
  addresses?: Record<string, unknown>;
  createdAt?: string;
}

export interface ResolvedOperatorWallet {
  source: 'env-mnemonic' | 'env-seed' | 'midnight-wallet-file';
  walletName?: string;
  path?: string;
  mnemonic?: string;
  seed?: string;
}

function midnightHomePath(): string {
  return resolve(homedir(), '.midnight');
}

async function readJsonIfPresent<T>(pathname: string): Promise<T | null> {
  try {
    const raw = await readFile(pathname, 'utf-8');
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export async function resolveActiveMidnightWalletName(
  runtimeConfig?: MidnightRuntimeConfig,
): Promise<string | null> {
  const explicitWalletName = process.env.MIDNIGHT_WALLET_NAME?.trim();
  if (explicitWalletName) return explicitWalletName;

  const configPath = resolve(midnightHomePath(), 'config.json');
  const config = await readJsonIfPresent<MidnightHomeConfig>(configPath);
  const walletName = String(config?.wallet ?? '').trim();
  if (!walletName) return null;

  const activeNetwork = String(config?.network ?? '').trim();
  const requestedNetwork = runtimeConfig?.network && runtimeConfig.network !== 'offline'
    ? runtimeConfig.network
    : activeNetwork;
  if (requestedNetwork && activeNetwork && requestedNetwork !== activeNetwork) {
    return null;
  }

  return walletName;
}

export async function readStoredMidnightWallet(
  walletName: string,
): Promise<{ path: string; wallet: MidnightStoredWallet } | null> {
  const walletPath = resolve(midnightHomePath(), 'wallets', `${walletName}.json`);
  const wallet = await readJsonIfPresent<MidnightStoredWallet>(walletPath);
  if (!wallet) return null;
  return { path: walletPath, wallet };
}

export async function resolveNamedMidnightWallet(
  walletName: string,
): Promise<ResolvedOperatorWallet | null> {
  const stored = await readStoredMidnightWallet(walletName);
  if (!stored) return null;
  const mnemonic = typeof stored.wallet.mnemonic === 'string' && stored.wallet.mnemonic.trim()
    ? stored.wallet.mnemonic.trim()
    : undefined;
  const seed = typeof stored.wallet.seed === 'string' && stored.wallet.seed.trim()
    ? stored.wallet.seed.trim()
    : undefined;
  if (!mnemonic && !seed) return null;
  return { source: 'midnight-wallet-file', walletName, path: stored.path, mnemonic, seed };
}

export async function resolveOperatorWallet(
  config: MidnightRuntimeConfig,
): Promise<ResolvedOperatorWallet | null> {
  if (config.operatorMnemonic?.trim()) {
    return { source: 'env-mnemonic', mnemonic: config.operatorMnemonic.trim() };
  }
  if (config.operatorSeed?.trim()) {
    return { source: 'env-seed', seed: config.operatorSeed.trim() };
  }
  const walletName = await resolveActiveMidnightWalletName(config);
  if (!walletName) return null;
  return resolveNamedMidnightWallet(walletName);
}
