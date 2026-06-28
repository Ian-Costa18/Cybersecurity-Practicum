# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Render a Marp deck to PDF (and optionally other formats).

    uv run render-deck.py <deck.md> [--pptx] [--html] [--png] [--watch]

Steps, in order:
  1. Read `theme:` from the deck's front-matter (default "midnight") and find
     themes/<theme>.css next to the deck.
  2. Render every *.mmd beside the deck -> matching .png, recolored with
     themes/<theme>.mermaid.json if present.
  3. Export the deck (PDF by default) with --allow-local-files so embedded
     images aren't dropped.

Needs Node.js on PATH (uses `npx` for marp-cli and mermaid-cli; no Python deps).
`--watch` re-exports the PDF on save but does NOT re-render the .mmd diagrams.
"""
from __future__ import annotations

import argparse
import functools
import re
import shutil
import subprocess
import sys
from pathlib import Path

MARP = "@marp-team/marp-cli@latest"
MMDC = "@mermaid-js/mermaid-cli@latest"


@functools.lru_cache(maxsize=1)
def npx() -> str:
    exe = shutil.which("npx") or shutil.which("npx.cmd")
    if not exe:
        sys.exit("error: 'npx' not found on PATH — install Node.js.")
    return exe


def run_npx(*args: str) -> None:
    subprocess.run([npx(), "--yes", *args], check=True)


def read_theme(deck: Path) -> str:
    """First `theme:` value in the YAML front-matter; default 'midnight'."""
    in_front = False
    for line in deck.read_text(encoding="utf-8").splitlines():
        if line.strip() == "---":
            if in_front:
                break
            in_front = True
            continue
        if in_front:
            m = re.match(r"^theme:\s*([^\s#]+)", line)
            if m:
                return m.group(1)
    return "midnight"


def main() -> None:
    ap = argparse.ArgumentParser(description="Render a Marp deck.")
    ap.add_argument("deck", type=Path, help="path to the deck .md")
    ap.add_argument("--pptx", action="store_true", help="also export PowerPoint")
    ap.add_argument("--html", action="store_true", help="also export HTML")
    ap.add_argument("--png", action="store_true", help="also export one PNG per slide")
    ap.add_argument("--watch", action="store_true", help="re-export PDF on save (diagrams not re-rendered)")
    args = ap.parse_args()

    deck = args.deck.expanduser().resolve()
    if not deck.is_file():
        sys.exit(f"no such deck: {deck}")
    here = deck.parent

    theme = read_theme(deck)
    theme_css = here / "themes" / f"{theme}.css"
    mermaid_cfg = here / "themes" / f"{theme}.mermaid.json"

    theme_args: list[str] = []
    if theme_css.is_file():
        theme_args = ["--theme", str(theme_css)]
    else:
        print(f"warn: themes/{theme}.css not found next to deck; using Marp default", file=sys.stderr)

    # 1. mermaid diagrams -> png
    for mmd in sorted(here.glob("*.mmd")):
        out = mmd.with_suffix(".png")
        cfg = ["-c", str(mermaid_cfg)] if mermaid_cfg.is_file() else []
        run_npx(MMDC, "-i", str(mmd), "-o", str(out), *cfg, "-b", "transparent", "-s", "2")
        print(f"diagram -> {out.name}")

    base = [MARP, str(deck), *theme_args, "--allow-local-files"]

    # 2/3. watch or one-shot export
    if args.watch:
        print(f"watching {deck.name} -> PDF (Ctrl-C to stop; diagrams not re-rendered)")
        run_npx(*base, "--pdf", "--watch")
        return

    exports: list[list[str]] = [["--pdf"]]
    if args.pptx:
        exports.append(["--pptx"])
    if args.html:
        exports.append(["--html"])
    if args.png:
        exports.append(["--images", "png", "--image-scale", "1.5"])

    for fmt in exports:
        run_npx(*base, *fmt)
    print(f"done -> {here}")


if __name__ == "__main__":
    main()
