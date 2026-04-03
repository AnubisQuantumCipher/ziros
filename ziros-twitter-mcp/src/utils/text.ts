export function splitThreadTexts(items: string[]): string[] {
  const out: string[] = [];
  for (const item of items) {
    if (item.length <= 280) {
      out.push(item);
      continue;
    }
    const words = item.split(/\s+/);
    let current = "";
    for (const word of words) {
      const candidate = current ? `${current} ${word}` : word;
      if (candidate.length <= 280) {
        current = candidate;
      } else {
        if (current) {
          out.push(current);
        }
        current = word.slice(0, 280);
      }
    }
    if (current) {
      out.push(current);
    }
  }
  return out;
}

export function normalizeHashtag(value: string): string {
  return value.startsWith("#") ? value : `#${value}`;
}
