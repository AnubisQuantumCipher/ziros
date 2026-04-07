import {
  DEFAULT_COMPATIBILITY_REPORT_PATH,
  readCompatibilityReport,
  withProfile,
  writeCompatibilityReport,
} from './compatibility.js';
import { type MidnightNetwork } from './config.js';
import { buildCompatibilityProfile } from './runtime-probe.js';
import { parseArgs, stringifyJson } from './util.js';

function parseNetworks(values: string[] | undefined): MidnightNetwork[] {
  if (!values || values.length === 0) {
    return ['preprod', 'preview'];
  }

  const accepted = new Set<MidnightNetwork>(['preprod', 'preview', 'mainnet', 'undeployed', 'offline']);
  const networks = values.filter((value): value is MidnightNetwork => accepted.has(value as MidnightNetwork));
  return networks.length > 0 ? networks : ['preprod', 'preview'];
}

async function main() {
  const { flags } = parseArgs(process.argv.slice(2));
  const reportPath = flags.get('out')?.[0] ?? DEFAULT_COMPATIBILITY_REPORT_PATH;
  const networks = parseNetworks(flags.get('network'));

  let report = await readCompatibilityReport(reportPath);
  const profiles = [];

  for (const network of networks) {
    const profile = await buildCompatibilityProfile(network);
    profiles.push(profile);
    report = withProfile(report, profile);
  }

  if (!report) {
    throw new Error('Failed to build compatibility report.');
  }

  await writeCompatibilityReport(report, reportPath);
  console.log(stringifyJson({ reportPath, profiles }));
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
