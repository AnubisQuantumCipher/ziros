import { execFileSync } from "node:child_process";

export class BrowserFallback {
  constructor(private readonly scriptsDir: string) {}

  private run(script: string, args: string[]): { ok: boolean; stdout: string } {
    try {
      const stdout = execFileSync("bash", [`${this.scriptsDir}/${script}`, ...args], {
        encoding: "utf8",
      });
      return { ok: true, stdout };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Browser fallback failed for ${script}: ${message}`);
    }
  }

  postViaBrowser(text: string): { ok: boolean; stdout: string } {
    return this.run("twitter-post.sh", [text]);
  }

  replyViaBrowser(tweetUrl: string, text: string): { ok: boolean; stdout: string } {
    return this.run("twitter-reply.sh", [tweetUrl, text]);
  }

  quoteViaBrowser(tweetUrl: string, text: string): { ok: boolean; stdout: string } {
    return this.run("twitter-quote.sh", [tweetUrl, text]);
  }

  postArticleViaBrowser(title: string, body: string): { ok: boolean; stdout: string } {
    return this.run("twitter-article.sh", [title, body]);
  }
}
