import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { EngagementLogEntry } from "../twitter/types.js";

export class EngagementLog {
  constructor(private readonly logPath: string) {}

  log(entry: Omit<EngagementLogEntry, "ts">): void {
    mkdirSync(dirname(this.logPath), { recursive: true });
    appendFileSync(
      this.logPath,
      `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`,
      "utf8",
    );
  }

  read(limit = 50, actionFilter?: string): EngagementLogEntry[] {
    if (!existsSync(this.logPath)) {
      return [];
    }
    const lines = readFileSync(this.logPath, "utf8")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .slice(-limit);
    return lines
      .map((line) => JSON.parse(line) as EngagementLogEntry)
      .filter((entry) => !actionFilter || entry.action === actionFilter);
  }
}
