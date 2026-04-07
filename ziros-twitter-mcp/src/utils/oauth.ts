import crypto from "node:crypto";
import { URL } from "node:url";
import type { OAuthCredentials } from "../twitter/types.js";

function percentEncode(value: string): string {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

function generateNonce(): string {
  return crypto.randomBytes(24).toString("base64url");
}

function collectQueryParams(url: URL): Array<[string, string]> {
  return Array.from(url.searchParams.entries()).map(([key, value]) => [key, value]);
}

export function buildOAuthHeader(
  method: string,
  rawUrl: string,
  credentials: OAuthCredentials,
  extraParams: Array<[string, string]> = [],
): string {
  const url = new URL(rawUrl);
  const oauthParams: Array<[string, string]> = [
    ["oauth_consumer_key", credentials.consumerKey],
    ["oauth_nonce", generateNonce()],
    ["oauth_signature_method", "HMAC-SHA1"],
    ["oauth_timestamp", Math.floor(Date.now() / 1000).toString()],
    ["oauth_token", credentials.accessToken],
    ["oauth_version", "1.0"],
  ];

  const signatureParams = [...oauthParams, ...collectQueryParams(url), ...extraParams]
    .sort(([leftKey, leftValue], [rightKey, rightValue]) => {
      const left = `${leftKey}=${leftValue}`;
      const right = `${rightKey}=${rightValue}`;
      return left.localeCompare(right);
    });

  const normalizedUrl = `${url.protocol}//${url.host}${url.pathname}`;
  const parameterString = signatureParams
    .map(([key, value]) => `${percentEncode(key)}=${percentEncode(value)}`)
    .join("&");
  const signatureBase = [
    method.toUpperCase(),
    percentEncode(normalizedUrl),
    percentEncode(parameterString),
  ].join("&");
  const signingKey = `${percentEncode(credentials.consumerSecret)}&${percentEncode(
    credentials.accessSecret,
  )}`;
  const signature = crypto
    .createHmac("sha1", signingKey)
    .update(signatureBase)
    .digest("base64");

  const headerParams = [...oauthParams, ["oauth_signature", signature]]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${percentEncode(key)}="${percentEncode(value)}"`)
    .join(", ");

  return `OAuth ${headerParams}`;
}
