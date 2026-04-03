export const PROMPTS = [
  {
    name: "compose-thread",
    description: "Guide thread creation for a technical ZirOS/X thread.",
    arguments: [
      { name: "topic", required: true },
      { name: "key_points", required: true },
      { name: "max_tweets", required: false },
    ],
  },
  {
    name: "engagement-session",
    description: "Run a search/filter/engage workflow for selected topics.",
    arguments: [
      { name: "topics", required: true },
      { name: "session_type", required: true },
    ],
  },
  {
    name: "proof-announcement",
    description: "Format a proof result into a tweet-ready announcement.",
    arguments: [
      { name: "proof_type", required: true },
      { name: "circuit_name", required: true },
      { name: "metrics", required: true },
    ],
  },
] as const;

export function renderPrompt(name: string, args: Record<string, string | undefined>) {
  if (name === "compose-thread") {
    return {
      description: "Compose a concise multi-tweet technical thread.",
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Compose a thread on ${args.topic}. Key points: ${args.key_points}. Max tweets: ${args.max_tweets ?? "6"}.`,
          },
        },
      ],
    };
  }
  if (name === "engagement-session") {
    return {
      description: "Plan a filtered engagement session.",
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Run a ${args.session_type} engagement session on topics: ${args.topics}. Search, filter politics, like selectively, quote sparingly, and log every action.`,
          },
        },
      ],
    };
  }
  return {
    description: "Format a proof announcement.",
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text: `Format a ${args.proof_type} announcement for ${args.circuit_name} with metrics ${args.metrics}.`,
        },
      },
    ],
  };
}
