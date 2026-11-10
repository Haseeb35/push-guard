# What push-guard looks for (and why)

This is the detailed list behind `scripts/scan.py`. Read it when you need to explain a finding, judge a borderline case, or decide whether something is a false positive.

Contents
1. Severity and context rules
2. API keys and tokens
3. Passwords, connection strings, random-looking strings
4. Files that should never be pushed
5. Junk, build output, large and binary files
6. Personal info
7. Company info
8. Git history
9. .gitignore checks
10. Commit author emails
11. Known limits

---

## 1. Severity and context rules

| Colour | Meaning | Examples |
|---|---|---|
| 🔴 | Grants access, costs money, or exposes real people. Must be fixed before pushing | API keys, passwords in config, private keys, `.env` with values, DB dumps, real customer data, a secret in history |
| 🟡 | Might be a problem; a human should look | Emails, phone numbers, local paths, server IPs, internal URLs, logs, junk folders, large files, test-mode keys, JWTs |
| 🟢 | Checked and fine | |

**Context changes the colour.** The scanner guesses a file's role from its path:

- **test**: inside `test/`, `tests/`, `__tests__/`, `spec/`, `fixtures/`, `mocks/`, `testdata/`, `examples/`, `samples/`, `demo/`, `e2e/`, or named `test_*.py`, `*_test.go`, `*.test.js`, `*.spec.ts`, `conftest.py`
- **example**: names ending `.example`, `.sample`, `.template`, `.dist` (e.g. `.env.example`)
- **docs**: `*.md`, `*.rst`, `docs/`
- **code**: everything else

Rules:
- Generic `password = "..."` style values in test/example/docs files are **ignored** (counted, not reported). Test suites need fake credentials.
- Provider-specific keys (they have a recognisable shape) in test/docs files become 🟡, because a real key pasted into a test is still leaked. Stripe **live** keys stay 🔴 everywhere.
- Real people's data stays 🔴 even in `tests/fixtures/`.
- Values that look like placeholders are never flagged: they contain `example`, `your`, `changeme`, `xxxx`, `dummy`, `redacted`, `<...>`, `${...}`, `{{...}}`, `_here`, `...`, or are common defaults (`password`, `postgres`, `admin`, `root`, `secret`, `test`), or are one repeated character.
- Values that are references, not secrets, are never flagged: `os.environ[...]`, `process.env.X`, `getenv(...)`, `${VAR}`, `config.secret`, code with parentheses, dependency versions (`"js-tokens": "^4.0.0"`), identifiers like `"push_token"`, and constants named `KEY_...`, `TAG_...`, `PREF_...` (they name a key, they don't hold one).

## 2. API keys and tokens

Recognised by their shape. Each finding includes where to **rotate** (cancel and replace) the key.

| Provider | Shape (prefix) | Rotate at |
|---|---|---|
| Anthropic | `sk-ant-api03-…`, `sk-ant-admin01-…` | console.anthropic.com/settings/keys |
| OpenAI | `sk-…`, `sk-proj-…`, `sk-svcacct-…` | platform.openai.com/api-keys |
| AWS access key ID | `AKIA` / `ASIA` + 16 capitals/digits | IAM → Users → Security credentials |
| AWS secret key | 40 chars next to `aws_secret_access_key` | same |
| GitHub | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` | github.com/settings/tokens |
| GitLab | `glpat-` | GitLab → Access tokens |
| Stripe | `sk_live_`, `rk_live_` (🔴), `sk_test_` (🟡), `whsec_` | dashboard.stripe.com/apikeys |
| Google | `AIza` + 35 chars, `GOCSPX-`, service-account JSON | console.cloud.google.com/apis/credentials |
| Slack | `xoxb-`, `xoxp-`, … and `hooks.slack.com/services/…` | api.slack.com/apps |
| Discord | webhook URLs `discord.com/api/webhooks/…` | channel → Integrations |
| Telegram | `<digits>:AA…` bot tokens | @BotFather → /revoke |
| Twilio | `SK` + 32 hex | Twilio console |
| SendGrid | `SG.` + two parts | SendGrid → API keys |
| Mailgun | `key-` + 32 | Mailgun → API security |
| npm / PyPI | `npm_…`, `pypi-AgEI…` | npm / PyPI token settings |
| Hugging Face | `hf_…` | huggingface.co/settings/tokens |
| Shopify, DigitalOcean, Azure storage | `shpat_…`, `dop_v1_…`, `AccountKey=…` | their consoles |
| JWT | `eyJ….eyJ….…` (🟡: may be expired or a sample) | n/a |

A match must also look random enough (Shannon entropy ≥ 3.0) so that `sk-xxxxxxxxxxxxxxxxxxxx` isn't flagged.

**Firebase / Google Maps keys in mobile apps** (`google-services.json`, `GoogleService-Info.plist`) are designed to ship inside the app. They are 🟡, not 🔴: the fix is restricting the key (by app/bundle ID or HTTP referrer) in the Google console, not hiding it.

## 3. Passwords, connection strings, random-looking strings

- **Assignments** where the name contains password / passwd / pwd / secret / api_key / access_key / private_key / token / auth_token / client_secret / credentials / connection_string, e.g. `DB_PASSWORD=…`, `"password": "…"`, `SECRET_KEY = "…"`. In code files only quoted literal values count; in config files (`.env`, `.yml`, `.json`, `.ini`, `.properties`, `.toml`, …) unquoted values count too. Names like `password_field`, `token_type`, `secret_name` are skipped.
- **Connection URLs with a password**: `postgres://user:pass@host`, `mongodb+srv://…`, `redis://:pass@…`, `https://user:pass@…`. Skipped when the password is a placeholder or the host is a local docker name with a default user.
- **Random-looking strings** (≥ 32 chars, high entropy) on a line that mentions key/secret/token/auth/password → 🟡. Lines about hashes, checksums, integrity, commit IDs or versions are skipped.

## 4. Files that should never be pushed

| File | Colour | Why |
|---|---|---|
| `.env`, `.env.local`, `.env.production`, … | 🔴 if it has real values; 🟡 if only empty/placeholder values (rename to `.env.example`) | holds real secrets |
| `.env.example`, `.env.sample`, `.env.template` | fine | the right way to share config names |
| `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa` | 🔴 | SSH private keys |
| `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.ppk`, `*.p8` | 🔴 (a `.pem` with only a public CERTIFICATE is fine) | private keys / signing keys |
| `credentials.json`, `client_secret*.json`, `service-account*.json`, `*-credentials.json`, `firebase-adminsdk*.json` | 🔴 | cloud credentials |
| `.netrc`, `.git-credentials`, `.htpasswd`, `.pgpass`, `.my.cnf` | 🔴 | stored passwords |
| `.npmrc`, `.pypirc` | 🟡 | may contain a publish token |
| `*.tfstate` | 🔴 | Terraform state holds every infra secret in plain text |
| `*.tfvars`, `secrets.yml`, `*.ovpn`, `local.properties` | 🟡 | often hold secrets or local details |
| `*.sqlite`, `*.sqlite3`, `*.db`, `*.mdb` | 🔴 | real data |
| `*.dump`, `*.bak`, `*.backup`, `*dump*.sql`, `*backup*.sql`, `.sql` with ≥ 20 `INSERT INTO` lines | 🔴 | data dumps (plain migrations/schema `.sql` files are fine) |
| `*.log`, `npm-debug.log*` | 🟡 | logs capture tokens, emails, paths |
| `.DS_Store`, `Thumbs.db`, `desktop.ini` | 🟡 | OS clutter |

## 5. Junk, build output, large and binary files

- **Folders reported once (with file count)**: `node_modules/`, `__pycache__/`, `.venv/`, `venv/` (any folder with `pyvenv.cfg`), `.tox/`, `dist/`, `build/`, `target/`, `.next/`, `.nuxt/`, `coverage/`, `.gradle/`, `.cxx/`, `.terraform/`, `.idea/`, `.vs/`, `Pods/`, `DerivedData/`, caches. 🟡
- **Size**: ≥ 10 MB 🟡, ≥ 50 MB 🔴 (GitHub warns at 50 MB and rejects files over 100 MB).
- **Binaries/archives**: `.exe .dll .so .dylib .msi .dmg .iso .apk .aab .ipa .zip .7z .rar .tar .gz .whl .class .o .pyc` 🟡. Grouped into one finding when there are many.

## 6. Personal info (🟡 unless it's bulk data)

- **Emails**: skipped for `example.com/org/net`, `*.test`, GitHub no-reply, role addresses (`support@`, `info@`, `security@`, `noreply@`, …), `git@github.com`, image names like `logo@2x.png`, and files that are *meant* to name people (`LICENSE`, `AUTHORS`, `CONTRIBUTORS`, `CODEOWNERS`, `CHANGELOG`, `SECURITY.md`, `CITATION`).
- **Phone numbers**: international `+CC …` (9 to 15 digits), US `(555) 123-4567`, Pakistani `03xx-xxxxxxx`. The fictional 555-01xx range is skipped.
- **Bulk data**: a data-ish file (`.csv .tsv .json .sql .xml .yaml`, or anything in tests/fixtures) with ≥ 5 distinct emails/phones → 🔴 "looks like real people's data".
- **Local paths**: `C:\Users\<name>\…`, `/Users/<name>/…`, `/home/<name>/…`, plus the current computer's username anywhere. Generic names (`user`, `runner`, `ubuntu`, `<name>`, `$USER`, …) are skipped.
- **Credit card numbers**: only on lines mentioning card/payment, must pass the Luhn checksum, official test cards (4242…) are skipped → 🔴.
- **Real names** can't be detected reliably by a script. Claude should glance at fixtures, notebooks and comments.

## 7. Company info (🟡)

- **Server IPs**: private ranges (10.x, 172.16-31.x, 192.168.x) and public addresses. Skipped: loopback, `0.0.0.0`, documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x), public DNS (8.8.8.8, 1.1.1.1), netmasks, version-number lookalikes.
- **Internal hostnames**: `*.internal`, `*.corp`, `*.local`, `*.lan`, `*.intranet`, `*.home.arpa`; hosts starting with `jira.`, `confluence.`, `wiki.`, `jenkins.`, `grafana.`, `kibana.`, `vault.`, `gitlab.`, `staging.`, `uat.`, `qa.`, `internal.`…; SaaS tenants like `*.atlassian.net`, `*.sharepoint.com`, `*.slack.com`, `*.zendesk.com`.
- **Customer data in fixtures**: see "bulk data" above.

## 8. Git history

Runs `git log --all -p` (newest 2000 commits by default) and scans every **added** line:
- Provider keys, private keys, passwords in connection URLs, and `password=`-style values in config files.
- Any sensitive *file* (`.env`, key files, credentials, DB files) that was ever added.
- Findings that still exist in the current files are reported once (in the file section), not twice.
- Each history finding says whether the commit is **already on a remote** (`git branch -r --contains`). With no remote configured, everything counts as "not pushed yet".
- Shallow clones are reported (older history can't be checked).

## 9. .gitignore checks

- **Missing rules** for the detected stack (always `.env`, `.env.*`, `*.pem`, `*.key`, `*.log`, `.DS_Store`; plus `node_modules/`, `dist/` for Node; `__pycache__/`, `.venv/` for Python; `build/`, `.gradle/`, `local.properties`, `*.jks`, `*.keystore` for Android/Gradle; `target/` for Rust/Maven; `bin/`, `obj/` for .NET; `*.tfstate`, `.terraform/` for Terraform), tested with `git check-ignore`.
- **Tracked but ignored**: files committed *before* the rule was added. `.gitignore` doesn't affect them; they need `git rm --cached`.

## 10. Commit author emails

Every commit's author email is public on GitHub. Any author email that isn't a GitHub no-reply address is 🟡, with instructions to switch to `<id>+<username>@users.noreply.github.com`.

## 11. Known limits (say so when relevant)

- It can't know if a key is still *valid*, only that it looks real.
- It can't detect real names, company names or confidential business logic. That's why Claude does a manual sweep.
- It scans text files up to 2 MB (bigger files are only size-checked) and the newest 2000 commits (`--max-commits` to change).
- If `gitleaks` is installed it runs as an extra detector (with `--redact`), and its findings are merged in.
