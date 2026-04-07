"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const http = require("node:http");
const https = require("node:https");

const PACKAGE_VERSION = require("../package.json").version;
const DEFAULT_MANIFEST_URL =
  process.env.ZIROS_INSTALLER_MANIFEST_URL ||
  "https://github.com/AnubisQuantumCipher/ziros-attestation/releases/latest/download/installer-manifest.json";

function zirosHome() {
  return process.env.ZIROS_HOME || path.join(os.homedir(), ".ziros");
}

function managedBinRoot() {
  return path.join(zirosHome(), "bin");
}

function installRoot() {
  return path.join(zirosHome(), "install");
}

function currentPlatformId() {
  return `${process.platform}-${process.arch}`;
}

function fail(message) {
  console.error(`@ziros/agent: ${message}`);
  process.exit(1);
}

function ensureSupportedPlatform() {
  if (process.platform !== "darwin" || process.arch !== "arm64") {
    fail("Apple Silicon macOS is the only supported install target.");
  }
}

function resolveManifestUrl() {
  return DEFAULT_MANIFEST_URL;
}

function fetchBytes(url, redirectBudget = 5) {
  if (url.startsWith("file://")) {
    return Promise.resolve(fs.readFileSync(url.slice("file://".length)));
  }
  const client = url.startsWith("https://") ? https : http;
  return new Promise((resolve, reject) => {
    client
      .get(url, (response) => {
        if (
          response.statusCode &&
          [301, 302, 303, 307, 308].includes(response.statusCode) &&
          response.headers.location
        ) {
          if (redirectBudget <= 0) {
            reject(new Error(`redirect limit exceeded for ${url}`));
            return;
          }
          const redirectedUrl = new URL(response.headers.location, url).toString();
          response.resume();
          fetchBytes(redirectedUrl, redirectBudget - 1).then(resolve, reject);
          return;
        }
        if (response.statusCode && response.statusCode >= 400) {
          reject(new Error(`HTTP ${response.statusCode} for ${url}`));
          return;
        }
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolve(Buffer.concat(chunks)));
      })
      .on("error", reject);
  });
}

async function fetchManifest() {
  const bytes = await fetchBytes(resolveManifestUrl());
  return JSON.parse(bytes.toString("utf8"));
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function ensureDirs() {
  fs.mkdirSync(managedBinRoot(), { recursive: true });
  fs.mkdirSync(installRoot(), { recursive: true });
}

function metadataPath() {
  return path.join(installRoot(), "installed.json");
}

function readInstalledMetadata() {
  try {
    return JSON.parse(fs.readFileSync(metadataPath(), "utf8"));
  } catch (_) {
    return null;
  }
}

function writeInstalledMetadata(payload) {
  fs.writeFileSync(metadataPath(), JSON.stringify(payload, null, 2));
}

function findBinary(root, name) {
  const entries = fs.readdirSync(root, { withFileTypes: true });
  for (const entry of entries) {
    const target = path.join(root, entry.name);
    if (entry.isDirectory()) {
      const nested = findBinary(target, name);
      if (nested) {
        return nested;
      }
      continue;
    }
    if (entry.isFile() && entry.name === name) {
      return target;
    }
  }
  return null;
}

async function installManagedBundle() {
  ensureSupportedPlatform();
  ensureDirs();

  const installed = readInstalledMetadata();
  if (installed && installed.version === PACKAGE_VERSION) {
    return installed;
  }

  const manifest = await fetchManifest();
  const channel = (manifest.platforms || []).find(
    (candidate) => candidate.platform === currentPlatformId(),
  );
  if (!channel) {
    throw new Error(`no installer channel for ${currentPlatformId()}`);
  }

  const archiveBytes = await fetchBytes(channel.archive_url);
  if (!channel.sha256 || channel.sha256 === "PENDING") {
    throw new Error("installer manifest sha256 is not release-ready");
  }
  const digest = sha256Hex(archiveBytes);
  if (digest !== channel.sha256) {
    throw new Error(`archive checksum mismatch: expected ${channel.sha256}, got ${digest}`);
  }

  const archivePath = path.join(installRoot(), "ziros-agent.tar.gz");
  const unpackRoot = path.join(installRoot(), "unpack");
  fs.rmSync(unpackRoot, { recursive: true, force: true });
  fs.mkdirSync(unpackRoot, { recursive: true });
  fs.writeFileSync(archivePath, archiveBytes);

  const tarResult = spawnSync("tar", ["-xzf", archivePath, "-C", unpackRoot], {
    stdio: "inherit",
  });
  if (tarResult.status !== 0) {
    throw new Error("failed to unpack ZirOS binary bundle");
  }

  for (const binary of channel.binaries || []) {
    const source = findBinary(unpackRoot, binary);
    if (!source) {
      throw new Error(`bundle is missing '${binary}'`);
    }
    const destination = path.join(managedBinRoot(), binary);
    fs.copyFileSync(source, destination);
    fs.chmodSync(destination, 0o755);
  }

  const metadata = {
    version: manifest.version,
    release_tag: manifest.release_tag,
    installed_at: new Date().toISOString(),
    manifest_url: resolveManifestUrl(),
  };
  writeInstalledMetadata(metadata);
  return metadata;
}

async function runBinary(name, args) {
  try {
    await installManagedBundle();
  } catch (error) {
    fail(error.message || String(error));
  }
  const binaryPath = path.join(managedBinRoot(), name);
  const result = spawnSync(binaryPath, args, { stdio: "inherit" });
  process.exit(result.status == null ? 1 : result.status);
}

if (require.main === module) {
  installManagedBundle().catch((error) => fail(error.message || String(error)));
}

module.exports = {
  installManagedBundle,
  runBinary,
};
