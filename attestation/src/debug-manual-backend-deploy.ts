import { Buffer } from 'node:buffer';

import { ApiPromise, WsProvider } from '@polkadot/api';
import { createUnprovenDeployTx } from '@midnight-ntwrk/midnight-js-contracts';
import { sampleSigningKey } from '@midnight-ntwrk/compact-runtime';
import { LedgerParameters } from '@midnight-ntwrk/ledger-v8';

import { loadCompiledContract } from './artifacts.js';
import { getRuntimeConfig } from './config.js';
import {
  buildHeadlessWallet,
  createDeployProviders,
  waitForSpendableDust,
} from './providers.js';
import { loadWitnessPayload } from './witness-data.js';

async function main() {
  const config = getRuntimeConfig({
    privateStatePassword: process.env.MIDNIGHT_PRIVATE_STATE_PASSWORD ?? 'Strong-Password!2026',
  });
  const payload = await loadWitnessPayload('./data/witness.json');
  const wallet = await buildHeadlessWallet(config);

  try {
    await waitForSpendableDust(wallet);

    const loaded = await loadCompiledContract('backend', { payload, config });
    const providers = createDeployProviders(
      config,
      loaded.artifactDir,
      wallet,
      'manual-backend',
      config.provingMode,
    );
    const deployTxData = await createUnprovenDeployTx(
      {
        zkConfigProvider: providers.zkConfigProvider,
        walletProvider: providers.walletProvider,
      },
      {
        compiledContract: loaded.compiledContract as never,
        args: [],
        signingKey: sampleSigningKey(),
      },
    );
    const provenTx = await providers.proofProvider.proveTx(deployTxData.private.unprovenTx);
    const balancedTx = await wallet.balanceTx(provenTx);
    const balancedTxBytes = balancedTx.serialize();
    const innerTxHex = `0x${Buffer.from(balancedTxBytes).toString('hex')}`;
    const params = LedgerParameters.initialParameters();
    const cost = balancedTx.cost(params);

    console.log(
      JSON.stringify(
        {
          contractAddress: String(deployTxData.public.contractAddress),
          serializedLength: balancedTx.serialize().length,
          fees: balancedTx.fees(params).toString(),
          identifiers: balancedTx.identifiers().map(String),
          cost: {
            readTime: cost.readTime.toString(),
            computeTime: cost.computeTime.toString(),
            blockUsage: cost.blockUsage.toString(),
            bytesWritten: cost.bytesWritten.toString(),
            bytesChurned: cost.bytesChurned.toString(),
          },
        },
        null,
        2,
      ),
    );

    const api = await ApiPromise.create({ provider: new WsProvider('wss://rpc.preprod.midnight.network') });
    try {
      const runtimeCost = await api.call.midnightRuntimeApi.getTransactionCost(innerTxHex);
      const decodedTx = await api.call.midnightRuntimeApi.getDecodedTransaction(innerTxHex);
      const outerTx = api.tx.midnight.sendMnTransaction(innerTxHex);
      const outerTxHex = outerTx.toHex();
      const bestHash = await api.rpc.chain.getBlockHash();

      console.log(
        JSON.stringify(
          {
            runtimeInspection: {
              innerTxHexLength: innerTxHex.length,
              outerTxHexLength: outerTxHex.length,
              runtimeInnerCost: runtimeCost.toString(),
              decodedTransaction: decodedTx.toHuman?.() ?? decodedTx.toJSON?.() ?? decodedTx.toString(),
            },
          },
          null,
          2,
        ),
      );

      for (const source of ['External', 'Local', 'InBlock'] as const) {
        try {
          const validity = await api.call.taggedTransactionQueue.validateTransaction(
            source,
            outerTxHex,
            bestHash,
          );
          console.log(
            JSON.stringify(
              {
                validateTransaction: {
                  source,
                  human: validity.toHuman?.() ?? null,
                  json: validity.toJSON?.() ?? null,
                  text: validity.toString(),
                },
              },
              null,
              2,
            ),
          );
        } catch (error) {
          console.log(
            JSON.stringify(
              {
                validateTransactionError:
                  error instanceof Error
                    ? {
                        source,
                        name: error.name,
                        message: error.message,
                        stack: error.stack ?? null,
                        code:
                          'code' in error && typeof error.code === 'number' ? error.code : null,
                        data: 'data' in error ? error.data ?? null : null,
                      }
                    : { source, message: String(error) },
              },
              null,
              2,
            ),
          );
        }
      }

      try {
        const dryRunResult = await api.rpc.system.dryRun(outerTxHex);
        console.log(
          JSON.stringify(
            {
              dryRun: {
                toString: dryRunResult.toString(),
                human: dryRunResult.toHuman?.() ?? null,
                json: dryRunResult.toJSON?.() ?? null,
              },
            },
            null,
            2,
          ),
        );
      } catch (error) {
        console.log(
          JSON.stringify(
            {
              dryRunError:
                error instanceof Error
                  ? {
                      name: error.name,
                      message: error.message,
                      stack: error.stack ?? null,
                      code:
                        'code' in error && typeof error.code === 'number' ? error.code : null,
                      data: 'data' in error ? error.data ?? null : null,
                    }
                  : { message: String(error) },
            },
            null,
            2,
          ),
        );
      }

      try {
        const unsubscribe = await api.tx.midnight
          .sendMnTransaction(innerTxHex)
          .send((result) => {
            console.log(
              JSON.stringify(
                {
                  rawSubmitStatus: result.status.toString(),
                  txHash: result.txHash.toString(),
                },
                null,
                2,
              ),
            );
          });
        unsubscribe();
      } catch (error) {
        console.log(
          JSON.stringify(
            {
              rawSubmitError:
                error instanceof Error
                  ? {
                      name: error.name,
                      message: error.message,
                      stack: error.stack ?? null,
                      code:
                        'code' in error && typeof error.code === 'number' ? error.code : null,
                      data: 'data' in error ? error.data ?? null : null,
                      ownKeys:
                        typeof error === 'object' && error != null
                          ? Object.getOwnPropertyNames(error)
                          : [],
                    }
                  : { message: String(error) },
            },
            null,
            2,
          ),
        );
      }
    } finally {
      await api.disconnect();
    }

    try {
      const txHash = await wallet.submitTx(balancedTx);
      console.log(JSON.stringify({ submitted: true, txHash }, null, 2));
    } catch (error) {
      const details =
        error instanceof Error
          ? {
              name: error.name,
              message: error.message,
              stack: error.stack ?? null,
              cause:
                error.cause instanceof Error
                  ? {
                      name: error.cause.name,
                      message: error.cause.message,
                      stack: error.cause.stack ?? null,
                    }
                  : error.cause ?? null,
            }
          : { message: String(error) };
      console.error(JSON.stringify({ submitError: details }, null, 2));
      throw error;
    }
  } finally {
    await wallet.stop();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
