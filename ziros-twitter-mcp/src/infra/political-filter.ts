const BLOCKED_KEYWORDS = [
  "trump", "biden", "obama", "hillary", "clinton", "desantis", "pence",
  "pelosi", "aoc", "congress", "senator", "republican", "democrat",
  "gop", "maga", "liberal", "conservative", "left-wing", "right-wing",
  "election", "ballot", "impeach", "indictment", "epstein", "qanon",
  "deep state", "woke", "anti-woke", "groomer", "vaccine mandate",
  "ivermectin", "plandemic", "stolen election", "great replacement",
  "pizzagate", "false flag", "ukraine war", "gaza", "hamas", "hezbollah",
  "nato", "missile strike", "illegal alien", "white supremac", "blm riot",
  "defund the police", "foxnews", "msnbc", "cnn breaking", "breitbart", "infowars",
];

const BLOCKED_AUTHORS = [
  "foxnews", "maborgs", "andweknow", "edkrassen", "laurenoehmke",
  "realdailywire", "tabordengs", "catturd2", "thebabylonbee",
  "occupydemocrats", "patriottakes", "msnbc", "infowars", "oann", "newsmax",
];

export class PoliticalFilter {
  readonly blockedKeywords = BLOCKED_KEYWORDS;
  readonly blockedAuthors = BLOCKED_AUTHORS;

  isPolitical(text: string, author?: string): boolean {
    const lower = text.toLowerCase();
    if (this.blockedKeywords.some((keyword) => lower.includes(keyword))) {
      return true;
    }
    if (!author) {
      return false;
    }
    const normalizedAuthor = author.toLowerCase().replace(/^@/, "");
    return this.blockedAuthors.some((candidate) => normalizedAuthor.includes(candidate));
  }

  assertAllowed(text: string, author?: string): void {
    if (this.isPolitical(text, author)) {
      throw new Error("Political content filter blocked this action.");
    }
  }
}
