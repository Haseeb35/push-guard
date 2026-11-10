# Fixing what push-guard found

Step-by-step recipes. Golden rules:

1. **Ask before every change.** Show the exact command or edit first.
2. **Least destructive first.** Untracking (`git rm --cached`) keeps the file on disk; deleting doesn't.
3. **Rotation beats rewriting.** If a secret was ever pushed (even to a private repo, even in a commit that was later deleted), it must be cancelled and replaced at the provider. Rewriting history afterwards is optional tidying.
4. **Backup before any history rewrite:** `git branch backup-before-cleanup`.
5. **Never show the full secret** while fixing it.

Contents
1. Move a secret out of the code
2. Stop tracking a file (and ignore it)
3. Write or extend .gitignore
4. Secret in commits that are NOT pushed yet
5. Secret that IS already pushed
6. Personal info: paths, emails, customer data
7. Commit author email
8. Large files
9. After fixing

---

## 1. Move a secret out of the code

1. Create (or reuse) a `.env` file in the project root with the value: `OPENAI_API_KEY=<the value>`
2. Make sure `.env` is git-ignored (see 3).
3. Replace the hard-coded value with an environment lookup:

| Language | Read it like this |
|---|---|
| Python | `os.environ["OPENAI_API_KEY"]` (load `.env` with `python-dotenv` if needed) |
| Node.js | `process.env.OPENAI_API_KEY` (Node 20+: `node --env-file=.env app.js`, or `dotenv`) |
| Django settings | `SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]` |
| Java / Kotlin | `System.getenv("OPENAI_API_KEY")`; Android: `local.properties` → `BuildConfig` field |
| Go | `os.Getenv("OPENAI_API_KEY")` |
| Docker Compose | `env_file: .env` or `${OPENAI_API_KEY}` |
| GitHub Actions | repository *Settings → Secrets and variables → Actions*, then `${{ secrets.OPENAI_API_KEY }}` |

4. Add a `.env.example` with the same names and **empty or placeholder values**, and commit that instead, so others know what to set.

## 2. Stop tracking a file (and ignore it)

```bash
echo ".env" >> .gitignore          # or edit .gitignore by hand
git rm --cached .env               # stops tracking; your local file stays
git rm -r --cached node_modules    # same for folders
git commit -m "Stop tracking local/secret files"
```

`git rm --cached` only affects **future** commits. The file is still in older commits; see 4 and 5.

To untrack everything that's tracked but now ignored:
```bash
git ls-files -ci --exclude-standard -z | xargs -0 git rm --cached
```

## 3. Write or extend .gitignore

A safe starting block (add the stack-specific lines push-guard listed):

```gitignore
# secrets
.env
.env.*
!.env.example
*.pem
*.key
id_rsa*
id_ed25519*
credentials*.json
*.tfstate*

# junk
*.log
.DS_Store
Thumbs.db

# Node
node_modules/
dist/

# Python
__pycache__/
*.pyc
.venv/
venv/
```

GitHub's templates for every language: https://github.com/github/gitignore

## 4. Secret in commits that are NOT pushed yet

Good news: nobody else has it. Remove it from those commits before pushing. Explain the plan, make a backup branch, then pick one:

**It's only in the latest commit:**
```bash
git branch backup-before-cleanup
# remove/replace the secret in the file (or `git rm --cached .env`), then:
git add -A
git commit --amend --no-edit
```

**It's in an older unpushed commit:** interactive rebase on the unpushed range. Claude can't drive the interactive editor, so use a scripted approach:
```bash
git branch backup-before-cleanup
# find the first unpushed commit that has the secret
git log --oneline @{u}..HEAD          # or: git log --oneline --not --remotes
# simplest robust method: squash all unpushed commits into one clean commit
git reset --soft @{u}                  # keeps all changes staged, removes the unpushed commits
git rm --cached .env                   # or fix the file
git commit -m "<message>"
```
(If there's no upstream yet, use the remote branch name, e.g. `git reset --soft origin/main`. If the branch was never pushed at all, `git reset --soft <first-commit>^` or rebuild from scratch.)

**A file in many unpushed commits, or a whole new repo that was never pushed:** use `git filter-repo` (needs `pip install git-filter-repo`; ask first):
```bash
git filter-repo --invert-paths --path .env               # remove a file from all history
git filter-repo --replace-text replacements.txt           # replace a secret string everywhere
```
`replacements.txt` contains lines like `<the secret>==>REMOVED` (write it to a temp folder, delete it afterwards, never commit it).

Re-run push-guard afterwards; the history section must be clean.

## 5. Secret that IS already pushed

1. **Rotate it now.** Open the provider page from the report (OpenAI/Anthropic/AWS/GitHub/Stripe/Google…), create a new key, update it wherever it's used (`.env`, CI secrets, servers), then **delete the old key**. This is the step that actually protects the user.
2. Check the provider's usage/billing page for activity they don't recognise.
3. Fix the code (section 1) so the new key never lands in git.
4. **Optional:** clean the history with `git filter-repo` (section 4) and force-push. Warn clearly:
   - It rewrites every commit after that point. Everyone else must re-clone.
   - Forks, clones, CI caches and GitHub's cached views may still have the old data.
   - Use `git push --force-with-lease`, only with an explicit yes, never on your own.
   - For a public repo where the data was sensitive, GitHub Support can purge cached views: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
5. Turn on GitHub **secret scanning and push protection** for the repo (*Settings → Code security*). It's free for public repos.

## 6. Personal info: paths, emails, customer data

- **Local paths** (`C:\Users\<name>\…`): use relative paths (`Path(__file__).parent / "data"`), `Path.home()`, or an env variable like `DATA_DIR`.
- **Real emails/phones in code or docs**: replace with `someone@example.com` and `+1 555 0100`.
- **Real customer data in fixtures**: replace with generated fake data (e.g. Python `faker`). Remove the real file from git (`git rm --cached`) and, if it was ever pushed, treat it as a data leak (tell the user; it may need to be reported under privacy rules).
- **Internal URLs / server IPs**: move them to config/env variables; in docs use `internal.example.com` and `192.0.2.10`.

## 7. Commit author email

- Find the no-reply address at https://github.com/settings/emails (format `<id>+<username>@users.noreply.github.com`), and tick **Keep my email addresses private** and **Block command line pushes that expose my email**.
- Set it for this repo: `git config user.email "<id>+<username>@users.noreply.github.com"`
- Fixing **unpushed** commits (history rewrite, so ask first):
  ```bash
  git rebase -r <first-unpushed-commit>^ --exec "git commit --amend --no-edit --reset-author"
  # whole repo, never pushed:
  git rebase -r --root --exec "git commit --amend --no-edit --reset-author"
  ```
- Already-pushed commits: usually leave them; rewriting public history for an email is rarely worth it.

## 8. Large files

- Generated files: ignore them and `git rm --cached`.
- Needed binaries (datasets, models, installers): attach them to a **GitHub Release**, or use **Git LFS** (`git lfs track "*.zip"`).
- Already in history and > 100 MB: GitHub will reject the push. Remove it with `git filter-repo --invert-paths --path <file>` (ask first).

## 9. After fixing

1. Re-run `python <skill-dir>/scripts/scan.py <project>` and show the new verdict.
2. Show the user exactly which files will be pushed: `git ls-files` (and `git status` for anything not committed yet).
3. Offer the optional pre-push hook (`scripts/install_hook.py`) so it doesn't happen again.
