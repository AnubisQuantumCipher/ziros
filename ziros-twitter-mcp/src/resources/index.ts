import type { ZirosTwitterMcp } from "../server.js";

export const RESOURCES = [
  {
    uri: "twitter://rate-limits",
    name: "Rate limits",
    description: "Current rate limit buckets tracked by the MCP server.",
  },
  {
    uri: "twitter://engagement-log",
    name: "Engagement log",
    description: "Recent operator actions written to the engagement log.",
  },
  {
    uri: "twitter://profile",
    name: "Profile",
    description: "Authenticated account profile for @jacobiproves.",
  },
  {
    uri: "twitter://blocked-keywords",
    name: "Blocked keywords",
    description: "Political filter keyword and author blocks.",
  },
] as const;

export async function readResource(app: ZirosTwitterMcp, uri: string): Promise<string> {
  switch (uri) {
    case "twitter://rate-limits":
      return JSON.stringify(app.rateLimiter.snapshot(), null, 2);
    case "twitter://engagement-log":
      return JSON.stringify(app.engagementLog.read(50), null, 2);
    case "twitter://profile":
      return JSON.stringify(await app.getProfileSummary(), null, 2);
    case "twitter://blocked-keywords":
      return JSON.stringify(
        {
          blocked_keywords: app.politicalFilter.blockedKeywords,
          blocked_authors: app.politicalFilter.blockedAuthors,
        },
        null,
        2,
      );
    default:
      throw new Error(`Unknown resource: ${uri}`);
  }
}
