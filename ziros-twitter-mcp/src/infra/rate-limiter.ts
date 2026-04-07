import type { RateLimitBucket } from "../twitter/types.js";

export class RateLimiter {
  private readonly buckets = new Map<string, RateLimitBucket>();

  updateFromHeaders(endpoint: string, headers: Headers): void {
    const remaining = Number.parseInt(headers.get("x-rate-limit-remaining") ?? "", 10);
    const limit = Number.parseInt(headers.get("x-rate-limit-limit") ?? "", 10);
    const reset = Number.parseInt(headers.get("x-rate-limit-reset") ?? "", 10);
    if (Number.isNaN(remaining) || Number.isNaN(limit) || Number.isNaN(reset)) {
      return;
    }
    this.buckets.set(endpoint, { remaining, limit, reset });
  }

  canProceed(endpoint: string): { allowed: boolean; retryAfterMs?: number } {
    const bucket = this.buckets.get(endpoint);
    if (!bucket) {
      return { allowed: true };
    }
    if (bucket.remaining > 0) {
      return { allowed: true };
    }
    return { allowed: false, retryAfterMs: Math.max(0, bucket.reset * 1000 - Date.now()) };
  }

  snapshot(): Record<string, RateLimitBucket> {
    return Object.fromEntries(this.buckets.entries());
  }
}
