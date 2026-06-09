---
name: add-to-dictionary
description: Add a word or phrase incorrectly flagged by LTeX+ to the LTeX+ dictionary so it is no longer highlighted. Asks the user whether to add to the project dictionary (.vscode/settings.json) or the user dictionary (%APPDATA%\Code\User\settings.json), defaulting to project. Use when the user wants to silence a false-positive spell or grammar check rather than fix the underlying text.
---

# Add to Dictionary

Add one or more terms to the LTeX+ dictionary so they are no longer flagged across Markdown and LaTeX files.

## How to invoke

```
/add-to-dictionary <term> [<term2> ...]
```

Terms may be passed as arguments, taken from the current IDE selection, or inferred from recent LTeX+ findings discussed in the conversation.

## What to do

1. **Collect the terms** — from the skill arguments, the user's selection, or the most recent LTeX+ findings discussed in the conversation. If none are clear, ask the user to specify.

2. **Ask which dictionary** — unless the user already specified, ask:
   > Add to **project dictionary** (`.vscode/settings.json`, this workspace only) or **user dictionary** (`%APPDATA%\Code\User\settings.json`, all workspaces)?

   Default to **project dictionary** if the user gives no answer or says "yes"/"sure"/etc.

3. **Read the target settings file.**

4. **Merge** the new terms into `ltex.dictionary.en-US` in that file:
   - If the key already exists, append to the array (no duplicates).
   - If `ltex.dictionary` or `ltex.dictionary.en-US` does not exist yet, create it.

5. **Write the updated settings** back, preserving all other settings exactly.

6. **Report** the terms added, which dictionary they went into, and the updated total count of entries in that dictionary.

## Dictionary file paths

| Scope | File |
|---|---|
| Project (this workspace only) | `.vscode/settings.json` in the workspace root |
| User (all workspaces) | `%APPDATA%\Code\User\settings.json` |

## Notes

- Terms are case-sensitive in LTeX+. Add the exact casing as it appears in the document (e.g., `bcrypt` not `Bcrypt`, `PyPI` not `pypi`).
- Hyphenated compounds (e.g., `fire-and-forget`) should be added as a single entry.
- Accented characters (e.g., `Mazières`) are supported — copy them exactly.
- Do not remove or reformat existing entries; only append.
- The dictionary suppresses the LTeX+ squiggle for that exact token. It does not affect Code Spell Checker (`streetsidesoftware.code-spell-checker`), which has its own `cSpell.words` setting.
