export type JsonObject = Record<string, unknown>;

export interface OAuthCredentials {
  consumerKey: string;
  consumerSecret: string;
  accessToken: string;
  accessSecret: string;
}

export interface RateLimitBucket {
  remaining: number;
  limit: number;
  reset: number;
}

export interface TwitterRequestOptions {
  endpointKey: string;
  query?: Record<string, string | number | boolean | undefined>;
  jsonBody?: unknown;
  formBody?: URLSearchParams;
  headers?: Record<string, string>;
}

export interface TwitterResponse<T = JsonObject> {
  data: T;
  headers: Headers;
  status: number;
}

export interface TweetSummary {
  id: string;
  text: string;
  author?: string;
  author_name?: string;
  author_followers?: number;
  likes?: number;
  retweets?: number;
  replies?: number;
  quotes?: number;
  created_at?: string;
  url?: string;
}

export interface EngagementLogEntry {
  ts: string;
  action: string;
  tweet_id?: string;
  author?: string;
  topic?: string;
  result: "ok" | "fallback" | "failed";
  extra?: Record<string, unknown>;
}
