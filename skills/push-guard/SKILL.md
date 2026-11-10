---
name: push-guard
description: Checks a project before it goes to GitHub and explains, in plain words, what should NOT be made public (API keys, passwords, .env files, private keys, database dumps, real customer data, personal emails/phones/local paths, internal company URLs and IPs, secrets hidden in old commits, .gitignore gaps), then helps fix each one safely. Use this whenever the user is about to commit, push, publish, open-source, or make a repo public, asks "is it safe to push", "can I make this public", "check for secrets/API keys", "did I leak anything", "what should be in .gitignore", mentions a leaked or committed key, or asks to clean a repo before sharing it — even if they never say "secrets" or "push-guard". Also use when a push-guard pre-push hook blocked a push.
---

# push-guard: check before you push

Once something is pushed to a public repo it should be treated as **public forever**: bots scrape GitHub for keys within minutes, and deleting a file later doesn't remove it from git history. Your job is to catch those things *before* the push, explain each one in words a beginner understands, and help fix them, without ever changing anything the user hasn't agreed to.

## Workflow

### 1. Scan

Run the bundled read-only scanner on the project (Python 3.8+, standard library only, uses `gitleaks` too if it happens to be installed):

```bash
python <skill-dir>/scripts/scan.py <project-path>                 # human report
python <skill-dir>/scripts/scan.py <project-path> --format json   # if you want to process findings
```

It checks the files that *would* be pushed (tracked files plus untracked files that aren't ignored, i.e. what `git add .` would pick up), the full git history (including deleted files and whether each bad commit is already on a remote), commit author emails, and .gitignore gaps. Exit code: 0 safe, 1 yellow only, 2 blocked. It never prints a full secret, only a masked preview like `sk-pro…9f3a`. Keep it that way in your answer too.

If the folder isn't a git repo yet, the scanner still checks the files and says history was skipped.

### 2. Apply judgement (the scanner is a starting point, not the verdict)

Regexes can't tell a real key from a test fixture or catch a customer's name in a comment. Before you report, do a short review:

- **Open the lines behind each 🟡 finding** and decide: real problem, or fine? A made-up password in `tests/` is fine. The same password in `settings/production.py` is not. A `C:\Users\<name>` path inside a notebook output may be the user's own name, so ask whether they mind.
- **Context decides severity.** Something that grants access (a key, a password, a private key, a token) in real code/config is 🔴. A sample value in tests, docs or `.env.example` is 🟢. Real people's data (names + emails/phones of customers) is 🔴 even inside `tests/fixtures/`, because privacy laws don't care which folder it's in.
- **Quick manual sweep for what regexes miss.** Skim `git ls-files` for odd files, and glance at README, config, notebooks and fixtures for: real names of customers/colleagues, company/client names the user may not want public, internal project codenames, hardcoded server names, screenshots of internal tools. Mention anything notable as 🟡.
- **Don't cry wolf.** If the scanner over-flags something (a public Firebase key that's meant to ship in a mobile app, a placeholder it didn't recognise), say so and downgrade it. A report full of false alarms trains people to ignore it.
- Read `references/detection-rules.md` if you need details on what each check means or why something was flagged.

### 3. Report

Use this exact structure. Keep it short and in plain words: the reader may be new to git.

```
## push-guard report: <project>

### 🔴 Must fix before pushing
1. **<What it is>** in `<file:line>`: <one line: why it's dangerous, in plain words>
   **Fix:** <concrete steps / commands>
   <If it's a key/password that was ever pushed: "⚠️ Rotate it: <where>. Deleting it isn't enough.">

### 🟡 Check this
1. **<What>** in `<file>`: <why it might matter> → <suggested fix or "fine if…">

### 🟢 Clean
<one line listing what was checked and is fine, e.g. "No private keys, no database files, no large files, history is clean.">

**Verdict: 🛑 PUSH BLOCKED** (fix the red items first)  |  **⚠️ CHECK FIRST**  |  **✅ SAFE TO PUSH**
```

Then end with a short offer, e.g. *"Want me to fix the red items? I'll show you each change before I make it."*

Guidance for the report:
- **One finding = what + where + why + fix.** "Your OpenAI key is in `.env`, which is committed. Anyone who sees it can run up your bill" beats "Secret detected (rule openai-key)".
- **Group duplicates.** Three keys in the same `.env` → one item with three bullet points.
- **Say whether it's already pushed.** The scanner marks findings `ALREADY PUSHED` / `not pushed yet`. This changes the advice completely:
  - *Not pushed yet* → it can still be removed cleanly before pushing; no harm done.
  - *Already pushed* (even to a private repo, or in an old commit) → **rotate the key/password first**. Rewriting history afterwards is optional cleanup; it can't un-leak anything.
- **History matters.** A secret that was committed and later deleted is still downloadable. Call this out explicitly. It's the thing people least expect.
- Mention the ignored test credentials count if relevant ("made-up passwords in tests were ignored, that's fine") so the user knows you looked.

### 4. Fix (only with permission)

Never edit, delete, untrack, commit, or rewrite anything until the user says yes. When they do, prefer the least destructive fix, show what you're about to run, and do one category at a time. Typical fixes (full recipes in `references/fixing.md`):

| Problem | Fix |
|---|---|
| Secret in code | Move it to an env variable (`os.environ["X"]`, `process.env.X`), put the real value in a git-ignored `.env`, commit a `.env.example` with empty values |
| `.env` / key file / junk committed | Add a `.gitignore` rule, then `git rm --cached <file>` (keeps the local copy) and commit |
| Files not ignored yet | Add the `.gitignore` rules the scanner listed |
| Secret in **unpushed** history | Rewrite only the unpushed commits (interactive rebase / `git commit --amend` / `git filter-repo` on a backup). Explain first, and ask |
| Secret in **pushed** history | **Rotate the secret** (give the exact page). Optional history cleanup only if the user wants it, after warning that it rewrites everyone's history and needs a force-push |
| Real customer data in fixtures | Replace with made-up data (`@example.com`, `555-01xx`) |
| Personal paths | Relative paths / `Path.home()` / env variables |
| Personal commit email | Use GitHub's no-reply email for future commits; fixing old commits is a history rewrite → ask |

Things to be careful about:
- **History rewrites are the only truly risky step.** Before any `rebase`, `filter-repo` or `--force` push: explain what it does in one or two sentences, make sure the user has a backup (`git branch backup-before-cleanup`), and get an explicit yes. Never force-push on your own.
- **Never print a secret in full**, not even when moving it. Refer to it by variable name and masked preview.
- **You can't rotate keys for the user.** Give the exact page (the scanner includes it) and tell them it's the most important step.

After fixing, re-run the scanner to prove it's clean and show the new verdict.

### 5. Optional: pre-push hook

If the user wants protection on every push, offer the optional hook. It scans only the commits being pushed and blocks the push **only** when one of them adds a real secret (yellow items never block):

```bash
python <skill-dir>/scripts/install_hook.py <repo>               # install
python <skill-dir>/scripts/install_hook.py <repo> --uninstall   # remove
```

It refuses to overwrite an existing pre-push hook unless `--force` is passed (then it backs the old one up). The user can skip it once with `git push --no-verify`. Ask before installing, since it changes how their `git push` behaves.

If the user arrives because the hook blocked a push: the secret is in a commit that is **not pushed yet**, so the clean fix is to remove it from that commit (amend or interactive rebase). Walk them through it, with their OK at each step.

## False positives

- Add `pushguard:ignore` in a comment on the line, or
- Add a path glob to `.pushguardignore` in the project root (e.g. `tests/fixtures/fake_keys/*`).

Suggest these only for things you've confirmed are not real.
