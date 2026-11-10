#!/usr/bin/env python3
"""Install (or remove) the OPTIONAL push-guard pre-push hook in one git repo.

    python install_hook.py [REPO]              # install
    python install_hook.py [REPO] --uninstall  # remove
    python install_hook.py [REPO] --force      # replace an existing pre-push hook (it is backed up first)

What the hook does: every time you run `git push`, it scans ONLY the commits
you're about to push. If one of them adds a real secret (API key, private
key, password in config, .env file...), the push is stopped and you're told
why. Everything else (yellow warnings) never blocks.

Skip it once:  git push --no-verify
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

MARKER = "# installed-by: push-guard"
HOOK = """#!/bin/sh
# installed-by: push-guard
# Blocks a push only when a commit you're pushing adds a real secret.
# Skip once: git push --no-verify   |   Remove: python install_hook.py --uninstall
HOOK_DIR="$(dirname "$0")"
PY=""
for c in python3 python py; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >/dev/null 2>&1; then
    PY="$c"; break
  fi
done
if [ -z "$PY" ]; then
  echo "push-guard: Python 3.8+ not found, skipping the secret check." >&2
  exit 0
fi
exec "$PY" "$HOOK_DIR/push-guard-scan.py" --hook --remote "$1" .
"""


def git_hooks_dir(repo: str) -> str:
    out = subprocess.run(["git", "rev-parse", "--git-path", "hooks"], cwd=repo,
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"push-guard: {repo} is not a git repository.")
    path = out.stdout.strip()
    return path if os.path.isabs(path) else os.path.join(repo, path)


def main() -> int:
    ap = argparse.ArgumentParser(description="Install the optional push-guard pre-push hook.")
    ap.add_argument("repo", nargs="?", default=".")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--force", action="store_true", help="replace an existing pre-push hook (backs it up first)")
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    hooks = git_hooks_dir(repo)
    hook_path = os.path.join(hooks, "pre-push")
    scanner_copy = os.path.join(hooks, "push-guard-scan.py")
    existing = ""
    if os.path.exists(hook_path):
        with open(hook_path, encoding="utf-8", errors="replace") as fh:
            existing = fh.read()

    if args.uninstall:
        if existing and MARKER not in existing:
            print("push-guard: the pre-push hook here wasn't installed by push-guard. Leaving it alone.")
            return 1
        for p in (hook_path, scanner_copy):
            if os.path.exists(p):
                os.remove(p)
        print("push-guard: hook removed.")
        return 0

    if existing and MARKER not in existing:
        if not args.force:
            print("push-guard: this repo already has a pre-push hook that push-guard didn't create.\n"
                  "Nothing was changed. Re-run with --force to replace it (the old one is backed up).")
            return 1
        n = 1
        while os.path.exists(f"{hook_path}.backup-{n}"):
            n += 1
        shutil.copy2(hook_path, f"{hook_path}.backup-{n}")
        print(f"push-guard: backed up your old hook to pre-push.backup-{n}")

    os.makedirs(hooks, exist_ok=True)
    here = os.path.dirname(os.path.abspath(__file__))
    shutil.copy2(os.path.join(here, "scan.py"), scanner_copy)
    with open(hook_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(HOOK)
    os.chmod(hook_path, 0o755)
    print("push-guard: pre-push hook installed.\n"
          "From now on `git push` is stopped if a commit you're pushing adds a real secret.\n"
          "Skip once with `git push --no-verify`. Remove with `python install_hook.py --uninstall`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
