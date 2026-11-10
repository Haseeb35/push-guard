<p align="center">
  <img src="assets/banner.svg" alt="push-guard: check before you push" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-4ade80?style=flat-square" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/Claude-Agent%20Skill-2dd4bf?style=flat-square" alt="Claude Agent Skill">
  <img src="https://img.shields.io/badge/needs-git%20%2B%20python-8be9fd?style=flat-square" alt="needs git and python">
  <img src="https://img.shields.io/badge/installs-nothing-facc15?style=flat-square" alt="installs nothing">
  <img src="https://img.shields.io/badge/read--only-yes-2f9e6e?style=flat-square" alt="read-only">
</p>

<h3 align="center">About to make a repo public? Ask Claude first.</h3>

---

## 🤔 The problem

You finish a project, type `git push`, make the repo public… and a few minutes later:

- 💸 a bot finds your **OpenAI / AWS key** and runs up a bill,
- 📧 your **personal email and phone** are in a test file,
- 🗂️ your `C:\Users\<you>\…` **folder paths** are all over the code,
- 🕳️ and the `.env` you *deleted last week* is **still in the git history**, where anyone can download it.

GitHub never forgets. Once it's public, deleting it doesn't take it back.

## ✨ What push-guard does

**push-guard is a skill for Claude that checks your project before it goes public.** Just ask:

> *"is it safe to push this to my public GitHub?"*

Claude scans everything you're about to push, explains in plain words what should **not** go public, and helps you fix it:

- 🔴 **Must fix**: API keys (OpenAI, Anthropic, AWS, Google, Stripe, Slack, GitHub…), passwords in config, private keys, `.env` files, database dumps, real customer data
- 🟡 **Check this**: emails, phone numbers, local paths, server IPs, internal company URLs, logs, `node_modules/`, big files
- 🟢 **Clean**: everything it checked and found fine
- 🚦 **A clear verdict**: `🛑 PUSH BLOCKED`, `⚠️ CHECK FIRST` or `✅ SAFE TO PUSH`

It also digs through your **git history** for secrets you deleted but that are still there, and tells you whether each one was **already pushed**. That changes the fix: an already-pushed key has to be *rotated*; an unpushed one can just be removed.

<p align="center">
  <img src="assets/how-it-works.svg" alt="How it works: you ask, Claude scans, you get a red/yellow/green report, you fix together" width="100%">
</p>

## 🔍 Before / after

**Before:** a small Node app, ready to go public.

```text
quote-bot/
├── .env                 ← committed by accident (OpenAI + Stripe live keys)
├── .gitignore           ← only says "dist/"
├── node_modules/        ← about to be added
├── server.log           ← has your email in it
└── src/server.js
     (and config/aws.json with AWS keys was deleted 2 commits ago… but it's still in history)
```

**You:** *"I'm about to make quote-bot public for my portfolio. Is it ok to push?"*

**push-guard:**

> ### 🔴 Must fix before pushing
> 1. **Your `.env` is committed with 3 real secrets** (`sk-pro…NfnP`, a **live** Stripe key, a database password). It's in your latest commit, **not pushed yet**, so it can be removed cleanly: `git rm --cached .env`, add `.env` to `.gitignore`, amend the commit.
> 2. **AWS keys in your git history** (`config/aws.json`, commit `3fcef1e`, **ALREADY PUSHED**). Deleting the file didn't remove it. ⚠️ **Rotate the key in AWS IAM first**: deleting it from git isn't enough.
>
> ### 🟡 Check this
> 1. `node_modules/` and `server.log` would be added by `git add .` → add them to `.gitignore`
> 2. Your commit email is a personal Gmail → use GitHub's no-reply address if you want it private
>
> ### 🟢 Clean
> No private keys, no database files, no large files.
>
> **Verdict: 🛑 PUSH BLOCKED** (fix the 2 red items first)
>
> *Want me to fix the red items? I'll show you each change before I make it.*

**After:** you say yes, Claude fixes things one at a time, re-runs the scan, and:

> **Verdict: ✅ SAFE TO PUSH**

## 🚀 Install (2 minutes)

### Claude Code: two commands

Type these inside Claude Code:

```
/plugin marketplace add Haseeb35/push-guard
/plugin install push-guard@push-guard
```

Done. To update later: `/plugin marketplace update push-guard`.

### Or install it by hand

**1. Download it**

```bash
git clone https://github.com/Haseeb35/push-guard.git
```

**2. Give it to Claude**

| Where you use Claude | What to do |
|---|---|
| **Claude Code**, all projects | Copy `push-guard/skills/push-guard` into `~/.claude/skills/` |
| **Claude Code**, one project | Copy it into `.claude/skills/` inside that project |
| **Claude.ai / desktop app** | Zip the `skills/push-guard` folder and upload it in *Settings → Capabilities → Skills* |
| **Claude API** | Upload the `skills/push-guard` folder as a custom skill ([Skills API guide](https://docs.claude.com/en/api/skills-guide)) |

### Then just ask

*"Can I push this?"*, *"check my repo for secrets"*, *"I want to open-source this"*. You don't need to say "push-guard"; Claude uses it automatically.

**You need:** `git` and Python 3.8+. **Nothing to install**: the scanner uses only Python's standard library. If you happen to have [gitleaks](https://github.com/gitleaks/gitleaks), push-guard uses it as an extra detector.

## 🛡️ Optional: block bad pushes automatically

Want a safety net? Install the pre-push hook in any repo:

```bash
python skills/push-guard/scripts/install_hook.py path/to/your/repo
```

Now every `git push` checks **only the commits you're pushing**. If one of them adds a real secret, the push stops and tells you why. Yellow warnings never block. Skip it once with `git push --no-verify`; remove it with `--uninstall`.

## ❓ FAQ: is it safe?

| Question | Answer |
|---|---|
| Will it change or delete my files? | **No, not unless you say yes.** The scanner is read-only. Claude asks before every fix and shows you the exact change first. |
| Will it rewrite my git history or force-push? | **Never on its own.** History rewrites are explained, backed up, and only done with your explicit OK. |
| Does it print my secrets? | **No.** Secrets are always masked, like `sk-pro…9f3a`. |
| Does it upload my code anywhere? | **The scanner doesn't use the internet at all.** It runs on your computer. Claude sees the scan report and the files it reads, the same as any other Claude task. |
| Does it need an API key or account? | **No.** |
| What about fake passwords in my tests? | **Fine.** It understands context: `password = "test123"` in `tests/` is ignored, and the same thing in `settings/production.py` is flagged. |
| A false alarm? | Add `pushguard:ignore` in a comment on that line, or put the path in a `.pushguardignore` file. |
| Can it promise I'm 100% safe? | **No tool can.** It catches the common leaks and tells you what it checked. For extra protection, also turn on GitHub's free *secret scanning & push protection*. |

## 🔎 What it checks

<details>
<summary><b>The full list</b> (click to open)</summary>

- **API keys & tokens**: OpenAI, Anthropic, AWS, Google / Firebase / GCP service accounts, GitHub, GitLab, Stripe, Slack, Discord, Telegram, Twilio, SendGrid, Mailgun, npm, PyPI, Hugging Face, Shopify, DigitalOcean, Azure, JWTs, plus random-looking secret strings
- **Passwords**: `password=`, `SECRET_KEY = "…"`, `postgres://user:pass@host` and friends
- **Files that should never be pushed**: `.env`, `id_rsa`, `*.pem`, `*.key`, `credentials.json`, `*.keystore`, `*.tfstate`, `.npmrc` tokens, SQLite/DB files, SQL dumps, logs
- **Junk**: `node_modules/`, `venv/`, `__pycache__/`, `dist/`, `build/`, `.idea/`, big files (10 MB+), zips and binaries
- **Personal info**: emails, phone numbers, `C:\Users\<name>` / `/home/<name>` paths, your computer's username, credit card numbers, bulk customer data in fixtures
- **Company info**: internal hostnames (`*.internal`, `*.corp`, `jira.…`, `*.atlassian.net`), private and public server IPs
- **Git history**: secrets and secret files that were committed and later deleted, plus whether each was already pushed
- **.gitignore**: missing rules for your stack, and files that are ignored but still tracked
- **Commit emails**: personal emails that GitHub will show on every commit

Details and the reasoning behind each rule: [`references/detection-rules.md`](skills/push-guard/references/detection-rules.md)
</details>

## 🧪 Tested, not just vibes

We built 4 throwaway repos full of **fake** planted problems: a committed `.env`, an AWS key hidden in an old *already-pushed* commit, real-looking customer data in test fixtures, internal company URLs, an SSH key, a clean repo (to catch false alarms), and more. Then we asked Claude about each one **with and without** push-guard.

| | With push-guard | Without |
|---|---|---|
| Checks passed (32) | **32/32** | 31/32 |
| Secrets always masked | **every time** | printed a password in full once |
| Same 🔴 / 🟡 / 🟢 + verdict format | **every time** | different every time |
| Fix matches "already pushed" vs "not pushed yet" | **every time** | sometimes "rotate everything" + "delete the repo" |
| False alarms on the clean repo | **none** | none |

Honest note: the model is already good at this. push-guard makes it **consistent, faster to read, and safe by default**. The test cases live in [`skills/push-guard/evals/`](skills/push-guard/evals) if you want to run them yourself.

## 🧰 Power users: run the scanner directly

```bash
python skills/push-guard/scripts/scan.py path/to/repo                  # readable report
python skills/push-guard/scripts/scan.py path/to/repo --format json    # for scripts / CI
python skills/push-guard/scripts/scan.py path/to/repo --no-history     # skip the history scan
```

Exit codes: `0` safe, `1` check the yellow items, `2` push blocked. Drop it into CI if you like.

## 📁 What's inside

```
.claude-plugin/marketplace.json    ← lets Claude Code install it with /plugin
skills/push-guard/
├── SKILL.md                       ← the instructions Claude follows
├── scripts/scan.py                ← the read-only scanner (Python standard library only)
├── scripts/install_hook.py        ← optional pre-push hook
├── references/detection-rules.md  ← what is checked and why
├── references/fixing.md           ← step-by-step fix recipes
└── evals/                         ← test cases (repos are built with fake secrets at runtime)
```

## 🤝 Contributing

Ideas and pull requests are welcome! Good first contributions:

- More key formats (with a fake example in the tests, never a real one)
- Fewer false alarms in a language or framework you use
- Translations of the report

## 📄 License

MIT. Free to use, change and share.

<p align="center"><sub>Made with 🛡️ by <a href="https://github.com/Haseeb35">Haseeb</a>. Also by me: <a href="https://github.com/Haseeb35/git-why">git-why</a>, which asks your code why it exists. If push-guard saved you from leaking a key, give it a ⭐</sub></p>
