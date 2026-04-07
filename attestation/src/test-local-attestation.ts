import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

async function runCommand(command: string, args: string[], cwd: string): Promise<void> {
  const { stdout, stderr } = await execFileAsync(command, args, {
    cwd,
    env: process.env,
    maxBuffer: 20 * 1024 * 1024,
  });
  if (stdout.trim()) {
    process.stdout.write(stdout);
  }
  if (stderr.trim()) {
    process.stderr.write(stderr);
  }
}

async function captureStdout(command: string, args: string[], cwd: string, outPath: string): Promise<void> {
  const { stdout, stderr } = await execFileAsync(command, args, {
    cwd,
    env: process.env,
    maxBuffer: 20 * 1024 * 1024,
  });
  await writeFile(outPath, stdout, 'utf-8');
  if (stderr.trim()) {
    process.stderr.write(stderr);
  }
}

async function main() {
  const attestationRoot = resolve('.');
  const zirosRoot = resolve(attestationRoot, '..');
  const zkfBinary =
    process.env.ZKF_BINARY ?? resolve(zirosRoot, 'dist', 'aarch64-apple-darwin', 'zkf');
  const tempDir = resolve(attestationRoot, '.tmp', 'local-attestation');
  await mkdir(tempDir, { recursive: true });

  const conformancePath = join(tempDir, 'conformance_plonky3.json');
  const programPath = resolve(zirosRoot, 'zkf-examples', 'circuits', 'multiply.json');
  const auditPath = join(tempDir, 'audit.json');
  const witnessPath = join(tempDir, 'witness.json');
  const reportPath = join(tempDir, 'local-proof-report.json');

  await mkdir(resolve(zirosRoot, 'zkf-examples', 'circuits'), { recursive: true });
  await runCommand(zkfBinary, ['emit-example', '--out', programPath], zirosRoot);
  await captureStdout(zkfBinary, ['conformance', '--backend', 'plonky3', '--json'], zirosRoot, conformancePath);
  await captureStdout(
    zkfBinary,
    ['audit', '--program', programPath, '--backend', 'plonky3', '--json'],
    zirosRoot,
    auditPath,
  );

  await runCommand(
    'npm',
    [
      'run',
      'witness-builder',
      '--',
      '--conformance',
      conformancePath,
      '--audit',
      auditPath,
      '--ledger',
      resolve(zirosRoot, 'zkf-ir-spec', 'verification-ledger.json'),
      '--out',
      witnessPath,
    ],
    attestationRoot,
  );

  await runCommand(
    'npm',
    ['run', 'prove-attestation', '--', '--witness', witnessPath, '--out', reportPath],
    attestationRoot,
  );
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
