import {
  readCompatibilityReport,
  type MidnightStackMatrixId,
  type MidnightSubmitStrategyId,
  runtimeFingerprintMatches,
} from './compatibility.js';
import { type MidnightRuntimeConfig } from './config.js';
import { buildCompatibilityProfile } from './runtime-probe.js';

export interface SelectedCompatibilityStrategy {
  matrixId: MidnightStackMatrixId | 'current';
  strategy: MidnightSubmitStrategyId;
}

export async function resolveSelectedCompatibilityStrategy(
  config: MidnightRuntimeConfig,
): Promise<SelectedCompatibilityStrategy> {
  const report = await readCompatibilityReport();
  if (!report?.selected) {
    return {
      matrixId: 'current',
      strategy: 'wallet-sdk',
    };
  }

  const liveProfile = await buildCompatibilityProfile(config.network, config);
  if (!runtimeFingerprintMatches(report.selected, liveProfile)) {
    throw new Error(
      `Live Midnight runtime fingerprint drifted from the selected compatibility report for ${config.network}. ` +
        'Run the compatibility probes again before deploying or submitting.',
    );
  }

  return {
    matrixId: report.selected.matrixId,
    strategy: report.selected.strategy,
  };
}
