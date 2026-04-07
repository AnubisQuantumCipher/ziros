import test from "node:test";
import assert from "node:assert/strict";
import { buildOAuthHeader } from "../src/utils/oauth.js";
import { PoliticalFilter } from "../src/infra/political-filter.js";
import { splitThreadTexts } from "../src/utils/text.js";

test("political filter blocks known political terms", () => {
  const filter = new PoliticalFilter();
  assert.equal(filter.isPolitical("This post is about Trump", "@zkresearch"), true);
  assert.equal(filter.isPolitical("This post is about recursion", "@zkresearch"), false);
});

test("thread splitting keeps items below tweet length", () => {
  const chunks = splitThreadTexts(["a ".repeat(200)]);
  assert.ok(chunks.length > 1);
  assert.ok(chunks.every((chunk) => chunk.length <= 280));
});

test("oauth header includes signature and token metadata", () => {
  const header = buildOAuthHeader("GET", "https://api.twitter.com/2/tweets", {
    consumerKey: "ck",
    consumerSecret: "cs",
    accessToken: "at",
    accessSecret: "as",
  });
  assert.match(header, /^OAuth /);
  assert.match(header, /oauth_signature=/);
  assert.match(header, /oauth_token=/);
});
