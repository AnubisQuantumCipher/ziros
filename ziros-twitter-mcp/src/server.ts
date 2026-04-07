import { KeychainAuth } from "./auth/keychain.js";
import { EngagementLog } from "./infra/engagement-log.js";
import { PoliticalFilter } from "./infra/political-filter.js";
import { RateLimiter } from "./infra/rate-limiter.js";
import { renderPrompt } from "./prompts/index.js";
import { readResource } from "./resources/index.js";
import { TwitterClient } from "./twitter/client.js";
import { normalizeHashtag, splitThreadTexts } from "./utils/text.js";

type Json = Record<string, unknown>;

export class ZirosTwitterMcp {
  readonly rateLimiter = new RateLimiter();
  readonly politicalFilter = new PoliticalFilter();
  readonly engagementLog = new EngagementLog(
    process.env.ENGAGEMENT_LOG_PATH ?? `${process.env.HOME}/.jacobian/workspace/engagement-log.jsonl`,
  );
  readonly userId = process.env.TWITTER_USER_ID ?? "2027436400422096900";
  readonly username = process.env.TWITTER_USERNAME ?? "jacobiproves";

  private readonly client = new TwitterClient(new KeychainAuth().getCredentials(), this.rateLimiter);

  async getProfileSummary(): Promise<Json> {
    return (await this.client.getProfile(this.userId)).data as Json;
  }

  async readResource(uri: string): Promise<string> {
    return readResource(this, uri);
  }

  getPrompt(name: string, args: Record<string, string | undefined>) {
    return renderPrompt(name, args);
  }

  private toolOk(payload: unknown) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(payload, null, 2),
        },
      ],
    };
  }

  private log(action: string, result: "ok" | "fallback" | "failed", extra: Record<string, unknown> = {}) {
    this.engagementLog.log({ action, result, extra });
  }

  private async postTweet(text: string, extras: Json = {}) {
    this.politicalFilter.assertAllowed(text);
    const data = await this.client.postTweet({ text, ...extras });
    this.engagementLog.log({ action: "post_tweet", result: "ok", extra: data.data as Json });
    return this.toolOk(data.data);
  }

  private async resolveUserId(username: string): Promise<string> {
    const data = await this.client.lookupUser(username.replace(/^@/, ""));
    const user = (data.data as Json).data as Json;
    return String(user.id);
  }

  async callTool(name: string, args: Record<string, unknown> = {}) {
    switch (name) {
      case "post_tweet":
        return this.postTweet(String(args.text), this.buildPollExtras(args));
      case "reply_to_tweet":
        return this.replyToTweet(String(args.tweet_id), String(args.text));
      case "quote_tweet":
        return this.quoteTweet(String(args.tweet_id), String(args.text));
      case "delete_tweet":
        return this.toolOk((await this.client.deleteTweet(String(args.tweet_id))).data);
      case "post_thread":
        return this.postThread(args.tweets as string[]);
      case "like_tweet":
        return this.userMutation("POST", `/likes`, { tweet_id: String(args.tweet_id) }, "like_tweet");
      case "unlike_tweet":
        return this.userMutation("DELETE", `/likes/${args.tweet_id}`, undefined, "unlike_tweet");
      case "retweet":
        return this.userMutation("POST", `/retweets`, { tweet_id: String(args.tweet_id) }, "retweet");
      case "unretweet":
        return this.userMutation("DELETE", `/retweets/${args.tweet_id}`, undefined, "unretweet");
      case "bookmark_tweet":
        return this.userMutation("POST", `/bookmarks`, { tweet_id: String(args.tweet_id) }, "bookmark_tweet");
      case "search_tweets":
        return this.searchTweets(String(args.query), Number(args.max_results ?? 10), String(args.sort_order ?? "recency"));
      case "get_mentions":
        return this.searchTweets(`@${this.username} -from:${this.username}`, Number(args.max_results ?? 10), "recency");
      case "search_hashtag":
        return this.searchTweets(normalizeHashtag(String(args.hashtag)), Number(args.max_results ?? 10), "recency");
      case "get_home_timeline":
        return this.toolOk((await this.client.request("GET", `https://api.twitter.com/2/users/${this.userId}/timelines/reverse_chronological`, { endpointKey: "home_timeline", query: { max_results: Number(args.max_results ?? 10), "tweet.fields": "public_metrics,created_at,author_id" } })).data);
      case "lookup_user":
        return this.toolOk((await this.client.lookupUser(String(args.username).replace(/^@/, ""))).data);
      case "lookup_user_by_id":
        return this.toolOk((await this.client.request("GET", `https://api.twitter.com/2/users/${args.user_id}`, { endpointKey: "lookup_user_by_id", query: { "user.fields": "public_metrics,description,created_at,verified,profile_image_url" } })).data);
      case "get_followers":
        return this.toolOk(await this.followGraph("followers", String(args.username), Number(args.max_results ?? 20)));
      case "get_following":
        return this.toolOk(await this.followGraph("following", String(args.username), Number(args.max_results ?? 20)));
      case "follow_user":
        return this.relationshipMutation("following", String(args.username), "follow_user");
      case "unfollow_user":
        return this.relationshipDelete("following", String(args.username), "unfollow_user");
      case "block_user":
        return this.relationshipMutation("blocking", String(args.username), "block_user");
      case "mute_user":
        return this.relationshipMutation("muting", String(args.username), "mute_user");
      case "upload_image":
        return this.uploadImage(String(args.file_path), args.alt_text ? String(args.alt_text) : undefined);
      case "upload_video":
        return this.toolOk({ media_id: await this.client.chunkedVideoUpload(String(args.file_path)) });
      case "tweet_with_media":
        return this.postTweet(String(args.text), { media: { media_ids: args.media_ids } });
      case "create_list":
        return this.toolOk((await this.client.request("POST", "https://api.twitter.com/2/lists", { endpointKey: "create_list", jsonBody: { name: String(args.name), description: args.description, private: Boolean(args.private) } })).data);
      case "add_to_list":
        return this.listMutation("POST", String(args.list_id), String(args.username));
      case "remove_from_list":
        return this.listMutation("DELETE", String(args.list_id), String(args.username));
      case "get_list_tweets":
        return this.toolOk((await this.client.request("GET", `https://api.twitter.com/2/lists/${args.list_id}/tweets`, { endpointKey: "get_list_tweets", query: { max_results: Number(args.max_results ?? 20), "tweet.fields": "public_metrics,created_at,author_id" } })).data);
      case "get_tweet_metrics":
        return this.toolOk((await this.client.request("GET", `https://api.twitter.com/2/tweets/${args.tweet_id}`, { endpointKey: "get_tweet_metrics", query: { "tweet.fields": "public_metrics,non_public_metrics,organic_metrics,created_at,author_id" } })).data);
      case "get_engagement_log":
        return this.toolOk(this.engagementLog.read(Number(args.limit ?? 50), args.action_filter ? String(args.action_filter) : undefined));
      case "get_rate_limits":
        return this.toolOk(this.rateLimiter.snapshot());
      case "get_profile":
        return this.toolOk(await this.getProfileSummary());
      case "tweet_proof_result":
        return this.postTweet(
          `ZirOS proof result: ${args.circuit_name} on ${args.backend}. Verified=${args.verified}. Constraints=${args.constraints}. Proof=${args.proof_size}. Time=${args.proving_time_ms}ms. The math is the authority.`,
        );
      case "tweet_attestation":
        return this.postTweet(
          `ZirOS attestation complete: ${args.theorem_count} theorems, ${args.conformance_count} conformance checks, reference ${args.tx_hash}. ${args.explorer_url}`,
        );
      case "tweet_conformance":
        return this.postTweet(
          `ZirOS conformance: ${args.backend} passed ${args.tests_passed}/${args.tests_total} (${args.pass_rate}). Proof system status: green.`,
        );
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  private buildPollExtras(args: Record<string, unknown>): Json {
    if (!Array.isArray(args.poll_options)) {
      return {};
    }
    return {
      poll: {
        options: args.poll_options,
        duration_minutes: Number(args.poll_duration ?? 1440),
      },
    };
  }

  private async replyToTweet(tweetId: string, text: string) {
    this.politicalFilter.assertAllowed(text);
    const data = await this.client.postTweet({ text, reply: { in_reply_to_tweet_id: tweetId } });
    this.engagementLog.log({ action: "reply_to_tweet", tweet_id: tweetId, result: "ok", extra: data.data as Json });
    return this.toolOk(data.data);
  }

  private async quoteTweet(tweetId: string, text: string) {
    this.politicalFilter.assertAllowed(text);
    const data = await this.client.postTweet({ text, quote_tweet_id: tweetId });
    this.engagementLog.log({ action: "quote_tweet", tweet_id: tweetId, result: "ok", extra: data.data as Json });
    return this.toolOk(data.data);
  }

  private async postThread(tweets: string[]) {
    const parts = splitThreadTexts(tweets);
    let previousId: string | undefined;
    const results: Json[] = [];
    for (const text of parts) {
      const response = await this.client.postTweet(previousId ? { text, reply: { in_reply_to_tweet_id: previousId } } : { text });
      const data = response.data as Json;
      previousId = String((data.data as Json).id);
      results.push(data);
    }
    this.engagementLog.log({ action: "post_thread", result: "ok", extra: { count: results.length } });
    return this.toolOk({ tweets: results });
  }

  private async userMutation(method: string, suffix: string, jsonBody: Json | undefined, endpointKey: string) {
    const response = await this.client.request(method, `https://api.twitter.com/2/users/${this.userId}${suffix}`, {
      endpointKey,
      jsonBody,
    });
    this.engagementLog.log({ action: endpointKey, result: "ok", extra: response.data as Json });
    return this.toolOk(response.data);
  }

  private async searchTweets(query: string, maxResults: number, sortOrder: string) {
    const response = await this.client.request("GET", "https://api.twitter.com/2/tweets/search/recent", {
      endpointKey: "search_tweets",
      query: {
        query,
        max_results: Math.max(10, Math.min(maxResults, 100)),
        sort_order: sortOrder,
        "tweet.fields": "public_metrics,created_at,author_id,conversation_id",
        expansions: "author_id",
        "user.fields": "public_metrics,username,name",
      },
    });
    return this.toolOk(response.data);
  }

  private async followGraph(kind: "followers" | "following", username: string, maxResults: number) {
    const userId = await this.resolveUserId(username);
    return (await this.client.request("GET", `https://api.twitter.com/2/users/${userId}/${kind}`, {
      endpointKey: kind,
      query: { max_results: Math.max(1, Math.min(maxResults, 100)), "user.fields": "public_metrics,description,verified" },
    })).data;
  }

  private async relationshipMutation(kind: "following" | "blocking" | "muting", username: string, action: string) {
    const targetUserId = await this.resolveUserId(username);
    const body = kind === "following" ? { target_user_id: targetUserId } : { target_user_id: targetUserId };
    const response = await this.client.request("POST", `https://api.twitter.com/2/users/${this.userId}/${kind}`, {
      endpointKey: action,
      jsonBody: body,
    });
    this.engagementLog.log({ action, result: "ok", extra: { username } });
    return this.toolOk(response.data);
  }

  private async relationshipDelete(kind: "following", username: string, action: string) {
    const targetUserId = await this.resolveUserId(username);
    const response = await this.client.request("DELETE", `https://api.twitter.com/2/users/${this.userId}/${kind}/${targetUserId}`, {
      endpointKey: action,
    });
    this.engagementLog.log({ action, result: "ok", extra: { username } });
    return this.toolOk(response.data);
  }

  private async uploadImage(filePath: string, altText?: string) {
    const response = await this.client.simpleMediaUpload(filePath);
    const mediaId = String((response.data as Json).media_id_string);
    if (altText) {
      await this.client.mediaAltText(mediaId, altText);
    }
    return this.toolOk({ media_id: mediaId });
  }

  private async listMutation(method: "POST" | "DELETE", listId: string, username: string) {
    const userId = await this.resolveUserId(username);
    const response = await this.client.request(method, `https://api.twitter.com/2/lists/${listId}/members`, {
      endpointKey: `${method.toLowerCase()}_list_member`,
      jsonBody: method === "POST" ? { user_id: userId } : undefined,
      query: method === "DELETE" ? { user_id: userId } : undefined,
    });
    return this.toolOk(response.data);
  }
}
