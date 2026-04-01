import {
  DEFAULT_COMPATIBILITY_REPORT_PATH,
  readCompatibilityReport,
  type MidnightStackMatrixId,
  withProbe,
  withProfile,
  writeCompatibilityReport,
} from './compatibility.js';
import { getRuntimeConfig, type MidnightNetwork } from './config.js';
import {
  buildMidnightOuterTx,
  submitMidnightOuterTx,
  validateMidnightOuterTx,
} from './midnight-polkadot.js';
import { buildCompatibilityProfile, withMidnightApi } from './runtime-probe.js';
import { optionalFlag, parseArgs, stringifyJson } from './util.js';

function parseMatrix(value: string | undefined): MidnightStackMatrixId | 'current' {
  if (value === 'v4-stable' || value === 'v4-pre' || value === 'v3-compat') {
    return value;
  }
  return 'current';
}

function parseNetwork(value: string | undefined): MidnightNetwork {
  if (value === 'preview' || value === 'mainnet' || value === 'undeployed' || value === 'offline') {
    return value;
  }
  return 'preprod';
}

async function findAcceptedMidnightTransaction(
  network: MidnightNetwork,
  searchDepth: number,
): Promise<{
  blockNumber: number;
  blockHash: string;
  index: number;
  outerTxHex: string;
  innerTxHex: string;
  encodedLength: number;
}> {
  const config = getRuntimeConfig({ network });
  return withMidnightApi(config, async (api) => {
    const head = await api.rpc.chain.getHeader();
    const latest = head.number.toNumber();

    for (let number = latest; number >= Math.max(0, latest - searchDepth); number--) {
      const blockHash = await api.rpc.chain.getBlockHash(number);
      const signedBlock = await api.rpc.chain.getBlock(blockHash);

      for (const [index, extrinsic] of signedBlock.block.extrinsics.entries()) {
        if (
          extrinsic.method.section === 'midnight' &&
          extrinsic.method.method === 'sendMnTransaction'
        ) {
          const innerTxHex = extrinsic.method.args[0].toHex();
          const rebuiltOuterTxHex = buildMidnightOuterTx(innerTxHex, api);

          return {
            blockNumber: number,
            blockHash: blockHash.toString(),
            index,
            outerTxHex: rebuiltOuterTxHex,
            innerTxHex,
            encodedLength: extrinsic.encodedLength,
          };
        }
      }
    }

    throw new Error(
      `Unable to find an accepted midnight.sendMnTransaction extrinsic within the last ${searchDepth} blocks on ${network}.`,
    );
  });
}

async function main() {
  const { flags } = parseArgs(process.argv.slice(2));
  const matrixId = parseMatrix(optionalFlag(flags, 'matrix'));
  const network = parseNetwork(optionalFlag(flags, 'network'));
  const reportPath = optionalFlag(flags, 'out') ?? DEFAULT_COMPATIBILITY_REPORT_PATH;
  const searchDepth = Number.parseInt(optionalFlag(flags, 'search-depth') ?? '120', 10);

  const profile = await buildCompatibilityProfile(network);
  const accepted = await findAcceptedMidnightTransaction(network, searchDepth);
  const config = getRuntimeConfig({ network });

  const probe = await withMidnightApi(config, async (api) => {
    const runtimeCost = await api.call.midnightRuntimeApi.getTransactionCost(accepted.innerTxHex);
    const validation = await validateMidnightOuterTx(accepted.outerTxHex, api);

    let submit;
    try {
      const txHash = await submitMidnightOuterTx(accepted.outerTxHex, api);
      submit = {
        strategy: 'compat-node-client' as const,
        outcome: 'accepted' as const,
        txHash,
        detail: 'Duplicate chain-control submit was unexpectedly accepted.',
      };
    } catch (error) {
      submit = {
        strategy: 'compat-node-client' as const,
        outcome: 'error' as const,
        txHash: null,
        detail: error instanceof Error ? error.message : String(error),
        raw:
          error instanceof Error
            ? {
                name: error.name,
                message: error.message,
                stack: error.stack ?? null,
                code:
                  'code' in error && typeof error.code === 'number'
                    ? error.code
                    : 'code' in error && typeof error.code === 'string'
                      ? error.code
                      : null,
                data: 'data' in error ? error.data ?? null : null,
              }
            : { message: String(error) },
      };
    }

    return {
      probeId: 'chain-control-accepted-midnight',
      network,
      matrixId,
      strategy: 'compat-node-client' as const,
      observedAt: new Date().toISOString(),
      innerTxHexLength: accepted.innerTxHex.length,
      outerTxHexLength: accepted.outerTxHex.length,
      serializedLength: accepted.encodedLength,
      txId: null,
      runtimeInnerCost: runtimeCost.toString(),
      validation,
      submit,
      note: stringifyJson({
        blockNumber: accepted.blockNumber,
        blockHash: accepted.blockHash,
        extrinsicIndex: accepted.index,
      }),
    };
  });

  const existing = await readCompatibilityReport(reportPath);
  const report = withProbe(withProfile(existing, profile), probe);
  await writeCompatibilityReport(report, reportPath);
  console.log(
    stringifyJson({
      reportPath,
      profile,
      probe,
    }),
  );
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
