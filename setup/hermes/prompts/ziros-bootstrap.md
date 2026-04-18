# ZirOS Bootstrap Prompt

The canonical bootstrap prompt for Hermes on ZirOS lives at:

- `/Users/sicarii/Desktop/ZirOS/docs/agent/HERMES_BOOTSTRAP_PROMPT.md`

That repo-tracked prompt is the source of truth. The installed Hermes pack copies it into `~/.hermes/ziros-pack/prompts/` for local use.
When the prompt needs official web discovery or URL repair, it should prefer
`ziros agent --json web fetch --url ...` before any GUI browser path.
When the page is genuinely interactive, it should use `ziros agent --json browser open`
and `ziros agent --json browser eval` rather than raw `open` or ad hoc AppleScript.
