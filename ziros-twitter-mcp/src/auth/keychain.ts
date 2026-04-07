import { execFileSync } from "node:child_process";
import type { OAuthCredentials } from "../twitter/types.js";

const KEYCHAIN_ACCOUNT = "jacobi";

function getKeychainSecret(service: string): string {
  return execFileSync("security", ["find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", service, "-w"], {
    encoding: "utf8",
  }).trim();
}

export class KeychainAuth {
  getCredentials(): OAuthCredentials {
    return {
      consumerKey: getKeychainSecret("twitter-oauth-consumer-key"),
      consumerSecret: getKeychainSecret("twitter-oauth-consumer-secret"),
      accessToken: getKeychainSecret("twitter-oauth-access-token"),
      accessSecret: getKeychainSecret("twitter-oauth-access-secret"),
    };
  }
}
