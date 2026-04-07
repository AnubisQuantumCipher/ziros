import assert from 'node:assert/strict';
import test from 'node:test';

import { normalizeProveRoutes } from '../src/config.js';
import {
  mailboxTransportBlockReason,
  normalizeDustCandidates,
  selectHealthyProveRoute,
  validateSubmissionGrant,
} from '../src/providers.js';
import { HelperRpcServer } from '../src/rpc.js';

test('validateSubmissionGrant rejects digest mutation', () => {
  assert.throws(
    () =>
      validateSubmissionGrant(
        {
          grant_id: 'grant-1',
          token_id: 'token-1',
          origin: 'https://dapp.example',
          network: 'preprod',
          method: 'transfer',
          tx_digest: 'tx-expected',
          issued_at: '2026-04-03T00:00:00Z',
          expires_at: '2099-04-03T00:00:00Z',
        },
        'tx-mutated',
        'preprod',
        'transfer',
      ),
    /digest mismatch/i,
  );
});

test('rpc server rejects unknown methods', async () => {
  const server = new HelperRpcServer();
  const response = await server.handleRequest({
    jsonrpc: '2.0',
    id: 7,
    method: 'nope',
  });
  assert.deepEqual(response, {
    jsonrpc: '2.0',
    id: 7,
    error: {
      code: -32000,
      message: "Unsupported helper method 'nope'",
    },
  });
});

test('normalizeProveRoutes prepends configured primary route and keeps ordering stable', () => {
  const routes = normalizeProveRoutes('preprod', 'https://prover.example', 'https://gateway.example', [
    {
      label: 'Upstream fallback',
      kind: 'upstream',
      proofServerUrl: 'https://fallback.example',
      gatewayUrl: 'https://gateway-fallback.example',
      priority: 5,
    },
  ]);

  assert.deepEqual(
    routes.map((route) => route.proofServerUrl),
    ['https://prover.example', 'https://fallback.example'],
  );
  assert.equal(routes[0]?.priority, -1);
});

test('selectHealthyProveRoute falls back to the first reachable route', async () => {
  const route = await selectHealthyProveRoute(
    [
      {
        label: 'Local',
        kind: 'local',
        proofServerUrl: 'http://127.0.0.1:6300',
        priority: 0,
      },
      {
        label: 'Fallback',
        kind: 'upstream',
        proofServerUrl: 'https://fallback.example',
        priority: 1,
      },
    ],
    async (url) => {
      if (url.includes('127.0.0.1')) {
        throw new Error('down');
      }
    },
  );

  assert.equal(route.proofServerUrl, 'https://fallback.example');
});

test('normalizeDustCandidates exposes stable selectable NIGHT utxos', () => {
  const candidates = normalizeDustCandidates([
    {
      utxo: {
        value: 42n,
        owner: 'midnight1owner',
        type: 'NIGHT',
        intentHash: '0xabc',
        outputNo: 3,
      },
      meta: {
        ctime: new Date('2026-04-03T00:00:00Z'),
        registeredForDustGeneration: true,
      },
    },
    {
      utxo: {
        value: 7n,
        owner: 'midnight1dust',
        type: 'DUST',
        intentHash: '0xdef',
        outputNo: 1,
      },
      meta: {
        ctime: new Date('2026-04-03T01:00:00Z'),
        registeredForDustGeneration: false,
      },
    },
  ] as never);

  assert.deepEqual(candidates, [
    {
      index: 0,
      valueRaw: '42',
      tokenType: 'NIGHT',
      owner: 'midnight1owner',
      intentHash: '0xabc',
      outputNo: 3,
      ctime: '2026-04-03T00:00:00.000Z',
      registeredForDustGeneration: true,
    },
  ]);
});

test('mailboxTransportBlockReason reports missing spendable tDUST after registration', () => {
  assert.match(
    mailboxTransportBlockReason({
      spendableDustRaw: 0n,
      spendableDustCoins: 0,
      registeredNightUtxos: 2,
      dustSyncConnected: true,
    }) ?? '',
    /no spendable tDUST/i,
  );
});

test('mailboxTransportBlockReason clears once spendable tDUST exists', () => {
  assert.equal(
    mailboxTransportBlockReason({
      spendableDustRaw: 1n,
      spendableDustCoins: 1,
      registeredNightUtxos: 2,
      dustSyncConnected: true,
    }),
    undefined,
  );
});
