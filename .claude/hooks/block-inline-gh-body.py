#!/usr/bin/env python3
"""PreToolUse hook: block inline-body `gh issue/pr create`.

Long markdown bodies passed inline via --body/-b are fragile in a shell
(quoting, backticks, newlines) and truncate badly. This hook forces the
body to be written to a scratchpad file and passed with --body-file/-F.

Blocks a Bash call only when it BOTH:
  - runs `gh issue create` or `gh pr create`, AND
  - supplies the body inline (--body / -b) without --body-file / -F.

Exit 0 = allow; exit 2 = block (stderr is fed back to the model).
"""

import json
import re
import sys

# `gh ... issue create` / `gh ... pr create` (allows global flags between).
_GH_CREATE = re.compile(r"\bgh\b.*\b(?:issue|pr)\s+create\b", re.DOTALL)
# Body from a file — the sanctioned form.
_BODY_FILE = re.compile(r"(?:^|\s)(?:--body-file(?:[=\s]|$)|-F(?:[=\s]|$))")
# Body inline — the form we reject. `--body` won't match `--body-file`
# because it must be followed by `=`, whitespace, or end-of-string.
_INLINE_BODY = re.compile(r"(?:^|\s)(?:--body(?:[=\s]|$)|-b(?:[=\s]|$))")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError, ValueError:
        return 0  # Malformed input: don't block.

    command = payload.get("tool_input", {}).get("command", "")
    if not command:
        return 0

    if not _GH_CREATE.search(command):
        return 0
    if _BODY_FILE.search(command):
        return 0  # Already using --body-file/-F.
    if not _INLINE_BODY.search(command):
        return 0  # No inline body (e.g. interactive/editor); allow.

    sys.stderr.write(
        "Blocked: `gh issue/pr create` with an inline --body/-b.\n"
        "Write the body to a file in the scratchpad directory, then pass it "
        "with --body-file (-F). Example:\n"
        "  gh issue create --title '...' --body-file \"$SCRATCH/issue-body.md\"\n"
        "This avoids shell quoting/backtick/newline breakage in long bodies."
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
