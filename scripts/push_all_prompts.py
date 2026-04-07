#!/usr/bin/env python3
"""
Langfuse prompt utility — Langfuse is ALWAYS the source of truth.

Usage:
    # List all prompts and their current version numbers
    python3 scripts/push_all_prompts.py --list

    # Edit a prompt: fetch from Langfuse, open in $EDITOR, push back on save
    python3 scripts/push_all_prompts.py --edit first-light-dns

    # Show current production text of a prompt
    python3 scripts/push_all_prompts.py --show first-light-dns

Do NOT store prompt text locally. Do NOT push-all. Edit in Langfuse UI or via
--edit which fetches live, lets you edit, then pushes only that prompt.
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv(override=True)

from langfuse import Langfuse

KNOWN_PROMPTS = [
    "first-light-firewall-threat",
    "first-light-dns",
    "first-light-network-flow",
    "first-light-infrastructure",
    "first-light-wireless",
    "first-light-validator",
    "first-light-cloudflare",
    "first-light-home-automation",
    "first-light-synthesis",
    "first-light-investigation",
    "first-light-weekly",
]


def get_lf() -> Langfuse:
    return Langfuse()


def cmd_list():
    lf = get_lf()
    print(f"{'Prompt':<45} {'Version':>8}  {'Updated'}")
    print("-" * 70)
    for name in KNOWN_PROMPTS:
        try:
            p = lf.get_prompt(name, label="production")
            updated = getattr(p, "updated_at", "?")
            version = getattr(p, "version", "?")
            print(f"{name:<45} {str(version):>8}  {updated}")
        except Exception as e:
            print(f"{name:<45} {'ERROR':>8}  {e}")


def cmd_show(name: str):
    lf = get_lf()
    try:
        p = lf.get_prompt(name, label="production")
        print(f"=== {name} (version {getattr(p, 'version', '?')}) ===\n")
        print(p.prompt)
    except Exception as e:
        print(f"Error fetching {name}: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_edit(name: str):
    lf = get_lf()
    try:
        p = lf.get_prompt(name, label="production")
        current_text = p.prompt
    except Exception as e:
        print(f"Error fetching {name}: {e}", file=sys.stderr)
        sys.exit(1)

    editor = os.environ.get("EDITOR", "vim")
    with tempfile.NamedTemporaryFile(suffix=".md", mode="w", delete=False) as f:
        f.write(current_text)
        tmp = f.name

    try:
        result = subprocess.run([editor, tmp])
        if result.returncode != 0:
            print("Editor exited with error — aborting.", file=sys.stderr)
            sys.exit(1)

        with open(tmp) as f:
            new_text = f.read()

        if new_text.strip() == current_text.strip():
            print("No changes — nothing pushed.")
            return

        lf.create_prompt(name=name, prompt=new_text.strip(), labels=["production"], config={})
        print(f"✓ {name} updated in Langfuse")
    finally:
        os.unlink(tmp)


def main():
    args = sys.argv[1:]

    if not args or args[0] == "--list":
        cmd_list()
    elif args[0] == "--show" and len(args) == 2:
        cmd_show(args[1])
    elif args[0] == "--edit" and len(args) == 2:
        cmd_edit(args[1])
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
