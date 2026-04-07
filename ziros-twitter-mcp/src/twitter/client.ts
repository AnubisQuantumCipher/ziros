import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { buildOAuthHeader } from "../utils/oauth.js";
import { MEDIA_UPLOAD_URL, TWEET_URL, USERS_URL } from "./endpoints.js";
import type { OAuthCredentials, TwitterRequestOptions, TwitterResponse } from "./types.js";
import { RateLimiter } from "../infra/rate-limiter.js";

function buildQuery(query: Record<string, string | number | boolean | undefined> | undefined): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined) continue;
    params.set(key, String(value));
  }
  return params;
}

export class TwitterApiError extends Error {
  constructor(message: string, readonly status: number, readonly body: string) {
    super(message);
  }
}

export class TwitterClient {
  constructor(
    private readonly credentials: OAuthCredentials,
    private readonly rateLimiter: RateLimiter,
  ) {}

  async request<T = Record<string, unknown>>(
    method: string,
    url: string,
    options: TwitterRequestOptions,
  ): Promise<TwitterResponse<T>> {
    const limitCheck = this.rateLimiter.canProceed(options.endpointKey);
    if (!limitCheck.allowed) {
      throw new Error(`Rate limit blocked for ${options.endpointKey}; retry after ${limitCheck.retryAfterMs}ms`);
    }

    const query = buildQuery(options.query);
    const finalUrl = query.size > 0 ? `${url}?${query.toString()}` : url;
    const extraParams: Array<[string, string]> = [];
    if (options.formBody) {
      for (const [key, value] of options.formBody.entries()) {
        extraParams.push([key, value]);
      }
    }

    const headers = new Headers(options.headers);
    headers.set("Authorization", buildOAuthHeader(method, finalUrl, this.credentials, extraParams));

    let body: BodyInit | undefined;
    if (options.jsonBody !== undefined) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(options.jsonBody);
    } else if (options.formBody) {
      headers.set("Content-Type", "application/x-www-form-urlencoded");
      body = options.formBody.toString();
    }

    const response = await fetch(finalUrl, { method, headers, body });
    this.rateLimiter.updateFromHeaders(options.endpointKey, response.headers);
    const text = await response.text();
    if (!response.ok) {
      throw new TwitterApiError(`Twitter API ${method} ${url} failed with ${response.status}`, response.status, text);
    }
    const data = text.trim() ? (JSON.parse(text) as T) : ({} as T);
    return { data, headers: response.headers, status: response.status };
  }

  getProfile(userId: string): Promise<TwitterResponse> {
    return this.request("GET", `${USERS_URL}/${userId}`, {
      endpointKey: "profile",
      query: { "user.fields": "public_metrics,description,created_at,verified,profile_image_url" },
    });
  }

  lookupUser(username: string): Promise<TwitterResponse> {
    return this.request("GET", `${USERS_URL}/by/username/${username}`, {
      endpointKey: "lookup_user",
      query: { "user.fields": "public_metrics,description,created_at,verified,profile_image_url" },
    });
  }

  postTweet(body: Record<string, unknown>): Promise<TwitterResponse> {
    return this.request("POST", TWEET_URL, {
      endpointKey: "post_tweet",
      jsonBody: body,
    });
  }

  deleteTweet(tweetId: string): Promise<TwitterResponse> {
    return this.request("DELETE", `${TWEET_URL}/${tweetId}`, {
      endpointKey: "delete_tweet",
    });
  }

  async simpleMediaUpload(filePath: string, mediaCategory = "tweet_image"): Promise<TwitterResponse> {
    const mediaData = readFileSync(filePath).toString("base64");
    const form = new URLSearchParams({
      media_data: mediaData,
      media_category: mediaCategory,
    });
    return this.request("POST", MEDIA_UPLOAD_URL, {
      endpointKey: "upload_media",
      formBody: form,
    });
  }

  async chunkedVideoUpload(filePath: string): Promise<string> {
    const data = readFileSync(filePath);
    const initForm = new URLSearchParams({
      command: "INIT",
      total_bytes: String(data.byteLength),
      media_type: "video/mp4",
      media_category: "tweet_video",
    });
    const initResponse = await this.request<{ media_id_string: string }>("POST", MEDIA_UPLOAD_URL, {
      endpointKey: "upload_video_init",
      formBody: initForm,
    });
    const mediaId = initResponse.data.media_id_string;

    const chunkSize = 1024 * 1024;
    for (let offset = 0, segmentIndex = 0; offset < data.byteLength; offset += chunkSize, segmentIndex += 1) {
      const slice = data.subarray(offset, Math.min(offset + chunkSize, data.byteLength));
      const appendForm = new URLSearchParams({
        command: "APPEND",
        media_id: mediaId,
        segment_index: String(segmentIndex),
        media_data: slice.toString("base64"),
      });
      await this.request("POST", MEDIA_UPLOAD_URL, {
        endpointKey: "upload_video_append",
        formBody: appendForm,
      });
    }

    const finalizeForm = new URLSearchParams({
      command: "FINALIZE",
      media_id: mediaId,
    });
    await this.request("POST", MEDIA_UPLOAD_URL, {
      endpointKey: "upload_video_finalize",
      formBody: finalizeForm,
    });
    return mediaId;
  }

  mediaAltText(mediaId: string, altText: string): Promise<TwitterResponse> {
    return this.request("POST", "https://upload.twitter.com/1.1/media/metadata/create.json", {
      endpointKey: "media_alt_text",
      jsonBody: {
        media_id: mediaId,
        alt_text: { text: altText },
      },
    });
  }

  static tweetUrl(tweetId: string): string {
    return `https://x.com/i/status/${tweetId}`;
  }

  static inferMediaType(filePath: string): string {
    const name = basename(filePath).toLowerCase();
    if (name.endsWith(".png")) return "image/png";
    if (name.endsWith(".jpg") || name.endsWith(".jpeg")) return "image/jpeg";
    if (name.endsWith(".gif")) return "image/gif";
    if (name.endsWith(".webp")) return "image/webp";
    if (name.endsWith(".mp4") || name.endsWith(".mov")) return "video/mp4";
    return "application/octet-stream";
  }
}
