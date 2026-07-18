# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Render a Marp deck to PDF (and optionally other formats).

    uv run render-deck.py <deck.md> [--pptx] [--html] [--png] [--watch]

    uv run render-deck.py video#_deck.md --pptx --watch

Steps, in order:
  1. Read `theme:` from the deck's front-matter (default "midnight") and find
     themes/<theme>.css next to the deck.
  2. Render every *.mmd beside the deck -> matching .png, recolored with
     themes/<theme>.mermaid.json if present.
  3. Export the deck (PDF by default) with --allow-local-files so embedded
     images aren't dropped.

Needs Node.js on PATH (uses `npx` for marp-cli and mermaid-cli; no Python deps).
`--watch` re-renders on every save (deck, diagrams, or theme). Single-file
outputs render to a staging file and are atomically swapped in, so a target
that's open elsewhere (e.g. the PPTX in PowerPoint) never aborts the render —
the staged copy is swapped in automatically as soon as the file is closed.
"""
from __future__ import annotations

import argparse
import functools
import os
import re
import shutil
import subprocess
import sys
import time
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
    ap.add_argument("--watch", action="store_true", help="re-render on save (deck, diagrams, or theme changes)")
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

    base = [MARP, str(deck), *theme_args, "--allow-local-files"]

    # Single-file formats render to a staging file, then get atomically swapped
    # onto the real output. If the real file is open elsewhere (locked), keep the
    # staged copy and swap it in later. png images render directly.
    single: list[tuple[str, str]] = [("pdf", "--pdf")]
    if args.pptx:
        single.append(("pptx", "--pptx"))
    if args.html:
        single.append(("html", "--html"))
    labels = "+".join([ext for ext, _ in single] + (["png"] if args.png else []))

    pending: dict[Path, Path] = {}  # final -> staging awaiting an unlocked target

    def swap_in(final: Path, staging: Path) -> bool:
        try:
            os.replace(staging, final)  # atomic; fails if `final` is locked/open
            return True
        except OSError:
            return False

    def flush_pending() -> None:
        for final, staging in list(pending.items()):
            if not staging.is_file():
                pending.pop(final, None)
            elif swap_in(final, staging):
                pending.pop(final, None)
                print(f"  swapped in updated {final.name}")

    def render_once() -> None:
        flush_pending()
        for mmd in sorted(here.glob("*.mmd")):  # diagrams first
            out = mmd.with_suffix(".png")
            cfg = ["-c", str(mermaid_cfg)] if mermaid_cfg.is_file() else []
            run_npx(MMDC, "-i", str(mmd), "-o", str(out), *cfg, "-b", "transparent", "-s", "2")
            print(f"diagram -> {out.name}")
        for ext, flag in single:
            final = here / f"{deck.stem}.{ext}"
            staging = here / f"{deck.stem}.tmp.{ext}"
            run_npx(*base, flag, "-o", str(staging))
            if not swap_in(final, staging):
                pending[final] = staging
                print(f"  {final.name} is open - staged the update, will swap in when it closes")
        if args.png:
            run_npx(*base, "--images", "png", "--image-scale", "1.5")

    if not args.watch:
        render_once()
        for final, staging in pending.items():
            print(f"note: {final.name} is open; updated copy left at {staging.name} - close it and rerun, or use --watch")
        print(f"done -> {here}")
        return

    # watch: re-render on save; also retry any staged swap each tick so a locked
    # output (PPTX/PDF open in a viewer) updates the moment it's closed.
    def snapshot() -> dict[Path, float]:
        srcs = [deck, theme_css, mermaid_cfg, *here.glob("*.mmd")]
        return {p: p.stat().st_mtime for p in srcs if p.is_file()}

    print(f"watching {deck.name} -> {labels} (Ctrl-C to stop)")
    render_once()
    print(f"  rendered {time.strftime('%H:%M:%S')}")
    last = snapshot()
    try:
        while True:
            time.sleep(0.7)
            if pending:
                flush_pending()
            current = snapshot()
            if current != last:
                last = current
                try:
                    render_once()
                    print(f"  re-rendered {time.strftime('%H:%M:%S')}")
                except subprocess.CalledProcessError as exc:
                    print(f"  render failed: {exc}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
