#!/usr/bin/env python3
"""push-guard scanner: find what should NOT go public before you push.

Read-only. It never edits, deletes, commits or rewrites anything.
Python 3.8+ standard library only. If `gitleaks` is installed it is used as
an extra detector; if not, everything still works.

Usage:
    python scan.py [PATH]                 # scan a project (default: current folder)
    python scan.py PATH --format json     # machine-readable output
    python scan.py PATH --no-history      # skip the git history scan
    python scan.py PATH --hook            # pre-push mode (reads refs on stdin)

Exit codes: 0 = safe to push, 1 = check the yellow items, 2 = push blocked.
In --hook mode: 0 = allow the push, 1 = block it (a real secret is being pushed).

Silence a false positive: put `pushguard:ignore` in a comment on that line,
or add a path glob to a `.pushguardignore` file in the project root.
"""
from __future__ import annotations

import argparse
import fnmatch
import getpass
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

VERSION = "1.0.0"

# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------


def run(cmd: List[str], cwd: str, stdin: Optional[str] = None) -> Tuple[int, str]:
    try:
        p = subprocess.run(
            cmd, cwd=cwd, input=stdin, capture_output=True,
            encoding="utf-8", errors="replace",
        )
        return p.returncode, p.stdout
    except (OSError, ValueError):
        return 127, ""


def git(args: List[str], cwd: str) -> Tuple[int, str]:
    return run(["git", "-c", "core.quotepath=off"] + args, cwd)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def mask(s: str) -> str:
    """Show just enough of a secret to recognise it, never the whole thing."""
    s = s.strip()
    if len(s) <= 8:
        return s[:2] + "…"
    keep = 4 if len(s) < 20 else 6
    return f"{s[:keep]}…{s[-4:]}"


PLACEHOLDER_PARTS = (
    "example", "placeholder", "your", "changeme", "change_me", "change-me", "xxxx",
    "dummy", "redacted", "replace", "insert", "todo", "fixme", "<", ">", "${", "{{",
    "%(", "sample", "_here", "-here", "...", "…", "***", "foobar", "lorem",
)
COMMON_DEFAULTS = {
    "password", "passwd", "secret", "test", "testing", "admin", "root", "postgres",
    "mysql", "guest", "user", "pass", "123456", "12345678", "default", "none", "null",
    "nil", "true", "false", "changeit", "qwerty", "letmein", "demo", "undefined",
    "required", "optional", "string", "str", "env", "secret123", "password123",
}


def is_placeholder(v: str) -> bool:
    lv = v.lower().strip()
    if lv in COMMON_DEFAULTS:
        return True
    if any(p in lv for p in PLACEHOLDER_PARTS):
        return True
    core = re.sub(r"[-_.:/]", "", lv)
    if len(set(core)) <= 2:  # "aaaaaaaa", "00000000", "xxxx-xxxx"
        return True
    return False


REFERENCE_RE = re.compile(
    r"^(?:\$|%|@|\{\{|process\.env|os\.environ|os\.getenv|getenv|env\(|ENV\[|config\(|"
    r"settings\.|import\.meta\.env|System\.getenv|Environment\.)"
)


def looks_like_reference(v: str) -> bool:
    return bool(REFERENCE_RE.match(v.strip()))


VERSION_RE = re.compile(r"[\^~<>=v*\s]*\d+(?:\.[\dx*]+)*(?:[\-+.][\w.]+)?(?:\s*(?:\|\||-|<|>|=)+\s*[\^~<>=v]*\d[\w.\-]*)*")
CONST_NAME_RE = re.compile(r"(?i)^(?:key|tag|pref|prefs|extra|arg|action|intent|bundle|column|col|param|field|header|claim|attr|label|msg|event|route|path|endpoint|table|cookie|storage|cache|query)[_\-.]")


def not_a_secret_value(v: str, name: str = "") -> bool:
    """Values that sit next to a word like 'token' but are clearly not secrets."""
    v = v.strip()
    if VERSION_RE.fullmatch(v) or v.startswith(("npm:", "file:", "workspace:", "link:", "git+", "github:", "http://", "https://")):
        return True  # dependency version or URL ("js-tokens": "^4.0.0")
    if re.search(r"[A-Za-z_]\w*\s*\(", v) and v.rstrip().endswith((")", "(")) or re.search(r"\w\[[\"'\w]", v)             or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", v):
        return True  # code, e.g. properties.getProperty("x") or config.secret
    if re.fullmatch(r"[a-z]+(?:[_.\-][a-z]+)+", v):
        return True  # an identifier like "push_token" / "driver.token" (a key NAME, not a value)
    if name and CONST_NAME_RE.match(name):
        return True  # KEY_TOKEN = "...": Android/JS constant that names a key
    return False


# --------------------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------------------

CHECKS = {
    "secrets": "API keys & tokens",
    "passwords": "Passwords in code & config",
    "keys": "Private keys & certificates",
    "files": "Secret files (.env, credentials)",
    "data": "Databases & data dumps",
    "junk": "Junk, build & dependency folders",
    "large": "Large & binary files",
    "personal": "Personal info (emails, phones, local paths)",
    "company": "Company info (internal URLs, server IPs)",
    "history": "Git history (deleted but not gone)",
    "gitignore": ".gitignore gaps & tracked-but-ignored files",
    "authors": "Commit author emails",
}

# Checks whose red findings block a push in --hook mode (real secrets only).
BLOCKING_CHECKS = {"secrets", "passwords", "keys", "files", "history"}


@dataclass
class Finding:
    severity: str            # "red" | "yellow"
    check: str               # key of CHECKS
    title: str
    file: str = ""
    line: int = 0
    status: str = ""         # tracked | untracked | history | repo
    preview: str = ""        # masked secret or short excerpt
    why: str = ""
    fix: List[str] = field(default_factory=list)
    commit: str = ""
    pushed: Optional[bool] = None
    rule: str = ""
    extra: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------
# Detection rules
# --------------------------------------------------------------------------------------

ROTATE = {
    "anthropic": "https://console.anthropic.com/settings/keys",
    "openai": "https://platform.openai.com/api-keys",
    "aws": "AWS console → IAM → Users → Security credentials",
    "github": "https://github.com/settings/tokens",
    "gitlab": "GitLab → Preferences → Access tokens",
    "stripe": "https://dashboard.stripe.com/apikeys",
    "google": "https://console.cloud.google.com/apis/credentials",
    "slack": "https://api.slack.com/apps",
    "discord": "Discord → Server settings → Integrations / Developer portal",
    "telegram": "@BotFather → /revoke",
    "twilio": "Twilio console → API keys",
    "sendgrid": "SendGrid → Settings → API keys",
    "mailgun": "Mailgun → API security",
    "npm": "https://www.npmjs.com/settings/~/tokens",
    "pypi": "https://pypi.org/manage/account/token/",
    "huggingface": "https://huggingface.co/settings/tokens",
    "shopify": "Shopify admin → Apps → Develop apps",
    "digitalocean": "DigitalOcean → API → Tokens",
    "azure": "Azure portal → Storage account → Access keys",
}

# (rule id, human name, regex, severity, rotate key, why)
RULES = [
    ("anthropic-key", "Anthropic API key", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,}", "red", "anthropic",
     "Anyone with this key can use your Anthropic account and you pay the bill."),
    ("openai-key", "OpenAI API key", r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}", "red", "openai",
     "Anyone with this key can use your OpenAI account and you pay the bill."),
    ("aws-access-key", "AWS access key ID", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", "red", "aws",
     "AWS keys are scanned by bots within minutes and used to run up huge bills."),
    ("aws-secret-key", "AWS secret access key",
     r"(?i)(?:aws)?_?secret_?(?:access)?_?key[\"']?\s*[:=]\s*[\"']?(?P<s>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])",
     "red", "aws", "With this, anyone can control your AWS account."),
    ("github-token", "GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b", "red", "github",
     "Gives access to your GitHub account and repositories."),
    ("github-pat", "GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{60,}", "red", "github",
     "Gives access to your GitHub account and repositories."),
    ("gitlab-token", "GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20,}", "red", "gitlab",
     "Gives access to your GitLab account."),
    ("stripe-live", "Stripe LIVE secret key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}", "red", "stripe",
     "Can move real money and read your customers' payment data."),
    ("stripe-test", "Stripe test-mode key", r"\b(?:sk|rk)_test_[A-Za-z0-9]{20,}", "yellow", "stripe",
     "Test-mode only (no real money), but it still opens your Stripe test account."),
    ("stripe-webhook", "Stripe webhook secret", r"\bwhsec_[A-Za-z0-9]{24,}", "red", "stripe",
     "Lets someone fake Stripe events (like 'payment succeeded') to your app."),
    ("google-api-key", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "red", "google",
     "Can be used to run up charges on your Google Cloud / Maps account."),
    ("google-oauth-secret", "Google OAuth client secret", r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b", "red", "google",
     "Lets someone impersonate your app when users sign in with Google."),
    ("slack-token", "Slack token", r"\bxox[abposr]-[A-Za-z0-9\-]{10,}", "red", "slack",
     "Can read and post messages in your Slack workspace."),
    ("slack-webhook", "Slack webhook URL",
     r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+", "red", "slack",
     "Anyone can post messages into your Slack channel."),
    ("discord-webhook", "Discord webhook URL",
     r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+", "red", "discord",
     "Anyone can post messages into your Discord channel."),
    ("telegram-bot", "Telegram bot token", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b", "red", "telegram",
     "Gives full control of your Telegram bot."),
    ("twilio-key", "Twilio API key", r"\bSK[0-9a-fA-F]{32}\b", "red", "twilio",
     "Can send SMS and make calls on your Twilio bill."),
    ("sendgrid-key", "SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "red", "sendgrid",
     "Can send email as you (spam from your domain)."),
    ("mailgun-key", "Mailgun API key", r"\bkey-[0-9a-zA-Z]{32}\b", "red", "mailgun",
     "Can send email as you."),
    ("npm-token", "npm token", r"\bnpm_[A-Za-z0-9]{36}\b", "red", "npm",
     "Can publish malicious versions of your npm packages."),
    ("pypi-token", "PyPI token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", "red", "pypi",
     "Can publish malicious versions of your Python packages."),
    ("huggingface-token", "Hugging Face token", r"\bhf_[A-Za-z0-9]{34,}\b", "red", "huggingface",
     "Gives access to your Hugging Face models and datasets."),
    ("shopify-token", "Shopify token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", "red", "shopify",
     "Gives access to your Shopify store."),
    ("digitalocean-token", "DigitalOcean token", r"\bdo[pro]_v1_[a-f0-9]{64}\b", "red", "digitalocean",
     "Can create and destroy servers on your bill."),
    ("azure-storage-key", "Azure storage account key", r"AccountKey=(?P<s>[A-Za-z0-9+/=]{60,})", "red", "azure",
     "Gives full access to the files in your Azure storage."),
    ("jwt", "JWT / session token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "yellow", "",
     "Might be a real login token. If it is still valid, anyone can use it to act as that user."),
]
COMPILED_RULES = [(rid, name, re.compile(rx), sev, rot, why) for rid, name, rx, sev, rot, why in RULES]

PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")
CONN_URL_RE = re.compile(
    r"\b(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]{1,20})://(?P<user>[^\s:/@'\"`<>]+):(?P<s>[^\s@/'\"`<>]+)@(?P<host>[^\s/'\"`:<>]+)"
)

KW = (r"(?:pass(?:word|wd|phrase)?|pwd|secret|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|"
      r"auth[_\-]?token|access[_\-]?token|refresh[_\-]?token|bearer|client[_\-]?secret|token|"
      r"credentials?|conn(?:ection)?[_\-]?str(?:ing)?)")
KW_RE = re.compile(KW, re.I)
ASSIGN_RE = re.compile(
    r"[\"']?(?P<name>[A-Za-z0-9_.\-]*" + KW + r"[A-Za-z0-9_.\-]*)[\"']?\s*(?::=|=>|=|:)\s*"
    r"(?:(?P<q>[\"'`])(?P<qv>[^\"'`\n]*)(?P=q)|(?P<uv>[^\s,;#'\"`\]\)}]+))",
    re.I,
)
OK_NAME_TAILS = {"", "s", "key", "keybase", "value", "val", "str", "string", "b64", "base64", "plain", "raw"}
HIGH_ENTROPY_RE = re.compile(r"[\"'`]([A-Za-z0-9+/=_\-]{32,})[\"'`]")
KEYISH_RE = re.compile(r"(?i)key|secret|token|auth|credential|signature|private|password|bearer")
HASHISH_RE = re.compile(r"(?i)integrity|sha\d*|hash|checksum|digest|nonce|etag|commit|uuid|guid|fingerprint|version")

EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
PHONE_RE = re.compile(
    r"(?<![\w.+/-])(?:\+\d{1,3}(?:[ .\-]?\(?\d{1,5}\)?){2,5}|\(\d{3}\)\s?\d{3}-\d{4}|03\d{2}-\d{7})(?![\w.])"
)
WIN_PATH_RE = re.compile(r"(?i)\b[a-z]:(?:\\\\|\\|/)(?:users|documents and settings)(?:\\\\|\\|/)([^\\/\s\"'<>|:*?]+)")
NIX_PATH_RE = re.compile(r"(?<![\w.])/(?:Users|home)/([A-Za-z0-9._\-]+)/")
IP_RE = re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])")
URL_HOST_RE = re.compile(r"\b(?:https?|wss?|ftp)://([A-Za-z0-9.\-]+)")
CARD_RE = re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)(?:[ \-]?\d{4}){2}[ \-]?\d{3,4}\b")

GENERIC_USERS = {
    "user", "username", "users", "runner", "ubuntu", "root", "me", "you", "name", "yourname",
    "your-name", "your_name", "ec2-user", "node", "app", "vagrant", "travis", "circleci", "jenkins",
    "docker", "shared", "public", "default", "all users", "admin", "administrator", "john", "jane",
    "johndoe", "jdoe", "foo", "bar", "example", "test", "runneradmin", "vscode", "codespace", "linuxbrew",
    "x", "someone", "myuser", "<user>", "dev", "developer", "home", "username1",
}
SAFE_EMAIL_DOMAINS = (
    "example.com", "example.org", "example.net", "test.com", "test", "invalid", "localhost",
    "users.noreply.github.com", "noreply.github.com", "email.com", "domain.com", "yourdomain.com",
    "company.com", "acme.com", "sentry.io", "anthropic.com",
)
ROLE_LOCALS = {
    "noreply", "no-reply", "donotreply", "do-not-reply", "support", "info", "hello", "contact", "admin",
    "security", "team", "privacy", "abuse", "help", "sales", "press", "legal", "git", "webmaster", "postmaster",
}
SAFE_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "255.255.255.255"}
TEST_CARDS = {
    "4242424242424242", "4000056655665556", "5555555555554444", "2223003122003222", "5200828282828210",
    "5105105105105100", "378282246310005", "371449635398431", "6011111111111117", "4111111111111111",
    "4012888888881881", "5431111111111111", "4000000000000002", "4000000000009995",
}
INTERNAL_TLDS = (".internal", ".corp", ".local", ".lan", ".intranet", ".intra", ".private", ".home.arpa", ".localdomain")
INTERNAL_PREFIX_RE = re.compile(
    r"^(?:jira|confluence|wiki|intranet|internal|jenkins|grafana|kibana|vault|sharepoint|gitlab|sonar|nexus|"
    r"artifactory|admin|staging|stage|uat|qa|preprod|dev-api|internal-api)[.\-]"
)
INTERNAL_SUFFIXES = (".atlassian.net", ".sharepoint.com", ".slack.com", ".zendesk.com", ".service-now.com")
PUBLIC_SUBDOMAINS = {
    "api.slack.com", "hooks.slack.com", "app.slack.com", "status.slack.com", "www.atlassian.net",
    "support.atlassian.com", "developer.atlassian.com",
}
PUBLIC_HOST_ALLOW = (
    "github.com", "gitlab.com", "githubusercontent.com", "atlassian.com", "slack.com", "google.com", "microsoft.com",
)

# --------------------------------------------------------------------------------------
# File classification
# --------------------------------------------------------------------------------------

TEST_DIRS = {
    "test", "tests", "__tests__", "spec", "specs", "fixtures", "fixture", "__fixtures__", "mocks", "mock",
    "__mocks__", "testdata", "test-data", "test_data", "examples", "example", "samples", "sample", "demo",
    "demos", "e2e", "cypress", "stories", "testing", "evals", "eval",
}
CONFIG_EXTS = {
    ".env", ".ini", ".cfg", ".conf", ".properties", ".yaml", ".yml", ".toml", ".json", ".xml", ".config",
    ".tfvars", ".plist", ".npmrc", ".pypirc", ".netrc", ".htpasswd", ".gradle", ".sh", ".bat", ".ps1",
    ".txt", ".ipynb", ".csv", ".tf", ".hcl", ".service",
}
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock", "cargo.lock",
    "composer.lock", "gemfile.lock", "go.sum", "packages.lock.json", "bun.lockb", "flake.lock", "uv.lock",
}
NO_PII_SCAN_EXTS = {".svg", ".map", ".lock", ".min.js", ".min.css"}
INTENTIONAL_PII_FILES = re.compile(
    r"(?i)^(license|licence|copying|authors|contributors|maintainers|codeowners|code_of_conduct|security|"
    r"citation|funding|notice|changelog|history)(\.[a-z]+)?$"
)

JUNK_DIRS = {
    "node_modules": "installed npm packages (anyone can re-install them with `npm install`)",
    "bower_components": "installed packages",
    "__pycache__": "Python cache files",
    ".venv": "a Python virtual environment",
    "venv": "a Python virtual environment",
    ".tox": "test environments",
    ".pytest_cache": "test cache",
    ".mypy_cache": "type-checker cache",
    ".ruff_cache": "linter cache",
    ".next": "Next.js build output",
    ".nuxt": "Nuxt build output",
    ".svelte-kit": "SvelteKit build output",
    ".parcel-cache": "build cache",
    ".turbo": "build cache",
    "dist": "build output",
    "build": "build output",
    "target": "build output",
    "coverage": "test coverage reports",
    ".nyc_output": "test coverage data",
    ".gradle": "Gradle cache",
    ".terraform": "Terraform plugins and possibly state",
    ".idea": "JetBrains editor settings (often contain local paths)",
    ".vs": "Visual Studio settings",
    "DerivedData": "Xcode build output",
    ".cxx": "Android native (CMake) build output",
    ".externalNativeBuild": "Android native build output",
    ".dart_tool": "Dart/Flutter build cache",
    "Pods": "installed CocoaPods (re-install with `pod install`)",
}

SECRET_FILE_RULES: List[Tuple[re.Pattern, str, str, str, str]] = [
    # (filename regex, severity, check, title, why)
    (re.compile(r"(?i)^\.env(\..+)?$"), "red", "files", ".env file",
     "Environment files hold your real passwords and API keys. They should never be in git."),
    (re.compile(r"(?i)^id_(rsa|dsa|ecdsa|ed25519)$"), "red", "keys", "SSH private key",
     "This is the key to your servers / GitHub account. Anyone who has it can log in as you."),
    (re.compile(r"(?i)\.(pem|key|p12|pfx|jks|keystore|ppk|p8|asc|gpg)$"), "red", "keys", "Private key / certificate file",
     "Key files let someone sign as you, decrypt your traffic or log in to your servers."),
    (re.compile(r"(?i)^(credentials|client_secrets?|service[-_]?account.*|.*-credentials|firebase-adminsdk.*|.*serviceaccountkey)\.json$"),
     "red", "files", "Credentials file", "Cloud credential files give full access to the account they belong to."),
    (re.compile(r"(?i)^(google-services\.json|googleservice-info\.plist)$"), "yellow", "files", "Firebase config file",
     "Contains API keys. They are semi-public for mobile apps, but lock them down (API restrictions) before publishing."),
    (re.compile(r"(?i)^(\.netrc|_netrc|\.git-credentials|\.htpasswd|\.pgpass|\.my\.cnf)$"), "red", "files", "Password file",
     "This file stores login passwords."),
    (re.compile(r"(?i)^(\.npmrc|\.pypirc|\.dockercfg)$"), "yellow", "files", "Package registry config",
     "Often contains a publish token. If it does, anyone could publish packages as you."),
    (re.compile(r"(?i)\.tfstate(\.backup)?$"), "red", "files", "Terraform state file",
     "Terraform state stores every secret of your infrastructure in plain text."),
    (re.compile(r"(?i)\.tfvars$"), "yellow", "files", "Terraform variables file",
     "Usually holds environment-specific values and sometimes secrets."),
    (re.compile(r"(?i)^(kubeconfig|.*\.kubeconfig)$"), "red", "files", "Kubernetes config",
     "Gives access to your Kubernetes cluster."),
    (re.compile(r"(?i)\.(ovpn)$"), "yellow", "files", "VPN config", "May contain VPN keys and company network details."),
    (re.compile(r"(?i)^(secrets?|credentials?)\.(ya?ml|json|toml|ini|txt|cfg)$"), "yellow", "files", "Secrets file",
     "The name says it holds secrets. Check what's inside."),
    (re.compile(r"(?i)^local\.properties$"), "yellow", "files", "local.properties",
     "Android local file: has your local SDK path and sometimes signing passwords."),
    (re.compile(r"(?i)\.(sqlite3?|db|mdb|accdb|db3)$"), "red", "data", "Database file",
     "A database file usually contains real data: users, emails, password hashes."),
    (re.compile(r"(?i)\.(dump|bak|backup)$"), "red", "data", "Backup / dump file",
     "Backups and dumps usually contain real data."),
    (re.compile(r"(?i)(^|[-_.])(dump|backup|bak|prod|production)[-_.].*\.sql$|\.sql\.gz$"), "red", "data", "Database dump",
     "SQL dumps contain real data: users, emails, password hashes."),
    (re.compile(r"(?i)(\.log|npm-debug\.log.*|yarn-error\.log.*)$"), "yellow", "junk", "Log file",
     "Logs are noise in git and often capture tokens, emails or local paths."),
    (re.compile(r"(?i)^(\.ds_store|thumbs\.db|desktop\.ini|ehthumbs\.db)$"), "yellow", "junk", "OS junk file",
     "Created by your operating system. It's harmless but it is clutter, and it can reveal folder names."),
    (re.compile(r"(?i)\.(exe|dll|so|dylib|msi|dmg|iso|apk|aab|ipa|zip|7z|rar|tar|tgz|gz|bz2|xz|whl|egg|class|o|obj|pyc)$"),
     "yellow", "large", "Binary / archive file",
     "Built or zipped files don't belong in git. Publish them as a GitHub Release instead."),
]
ENV_FILE_OK_SUFFIX = re.compile(r"(?i)\.(example|sample|template|dist|defaults|schema|tmpl|tpl)$")


def path_context(rel: str) -> str:
    """Rough guess at what a file is for: code, test, example or docs."""
    parts = rel.lower().replace("\\", "/").split("/")
    name = parts[-1]
    if any(p in TEST_DIRS for p in parts[:-1]):
        return "test"
    if re.search(r"(^test_|_test\.|\.test\.|\.spec\.|_spec\.|^conftest\.py$|^tests?\.py$)", name):
        return "test"
    if ENV_FILE_OK_SUFFIX.search(name) or re.search(r"\.(example|sample|template)\.", name):
        return "example"
    if name.endswith((".md", ".rst", ".adoc")) or any(p in ("docs", "doc") for p in parts[:-1]):
        return "docs"
    return "code"


def file_ext(rel: str) -> str:
    name = os.path.basename(rel).lower()
    if name.startswith(".env"):
        return ".env"
    if name.endswith(".min.js"):
        return ".min.js"
    if name.endswith(".min.css"):
        return ".min.css"
    if name.startswith(".") and "." not in name[1:]:
        return name  # .npmrc, .netrc
    return os.path.splitext(name)[1]


# --------------------------------------------------------------------------------------
# The scanner
# --------------------------------------------------------------------------------------


class Scanner:
    def __init__(self, root: str, history: bool = True, max_commits: int = 2000,
                 use_gitleaks: bool = True, hook_revs: Optional[List[str]] = None):
        self.root = os.path.abspath(root)
        self.history = history
        self.max_commits = max_commits
        self.use_gitleaks = use_gitleaks
        self.hook_revs = hook_revs
        self.findings: List[Finding] = []
        self.notes: List[str] = []
        self.ignored_test_creds = 0
        self.ignored_by_file = 0
        self.current_secret_values: Set[str] = set()
        self.is_repo = False
        self.toplevel = self.root
        self.has_remote = False
        self.stats = {"files": 0, "commits": 0}
        self.gitleaks = "not installed"
        self.ignore_globs: List[str] = []
        self._seen: Set[Tuple[str, int, str, str]] = set()
        self._pushed_cache: Dict[str, bool] = {}
        self._key_files: Set[str] = set()
        self._binaries: List[Tuple[str, str]] = []
        self.os_user = ""
        try:
            u = getpass.getuser()
            if u and len(u) >= 4 and u.lower() not in GENERIC_USERS:
                self.os_user = u
        except Exception:
            pass

    # ---------- bookkeeping ----------

    def add(self, f: Finding) -> None:
        key = (f.file, f.line, f.rule or f.title, f.preview)
        if key in self._seen:
            return
        if f.file and self._ignored_path(f.file):
            self.ignored_by_file += 1
            return
        self._seen.add(key)
        self.findings.append(f)

    def _ignored_path(self, rel: str) -> bool:
        return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel, g.rstrip("/") + "/*") for g in self.ignore_globs)

    def _load_ignore_file(self) -> None:
        p = os.path.join(self.root, ".pushguardignore")
        if os.path.isfile(p):
            with open(p, encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln and not ln.startswith("#"):
                        self.ignore_globs.append(ln)

    # ---------- git ----------

    def _detect_repo(self) -> None:
        code, out = git(["rev-parse", "--show-toplevel"], self.root)
        if code == 0 and out.strip():
            self.is_repo = True
            self.toplevel = os.path.abspath(out.strip())
            code, out = git(["remote"], self.toplevel)
            self.has_remote = bool(out.strip())

    def commit_pushed(self, sha: str) -> bool:
        if not self.has_remote:
            return False
        if sha not in self._pushed_cache:
            code, out = git(["branch", "-r", "--contains", sha], self.toplevel)
            self._pushed_cache[sha] = code == 0 and bool(out.strip())
        return self._pushed_cache[sha]

    def file_pushed(self, rel: str) -> bool:
        if not self.has_remote:
            return False
        code, out = git(["log", "--remotes", "-1", "--format=%H", "--", rel], self.toplevel)
        return code == 0 and bool(out.strip())

    def list_files(self) -> Tuple[List[str], Set[str]]:
        """Return (all files that would be pushed by `git add .`, set of already-tracked files)."""
        if self.is_repo:
            _, tracked_out = git(["ls-files", "-z", "--cached"], self.toplevel)
            _, untracked_out = git(["ls-files", "-z", "--others", "--exclude-standard"], self.toplevel)
            tracked = [p for p in tracked_out.split("\0") if p]
            untracked = [p for p in untracked_out.split("\0") if p]
            rel_root = os.path.relpath(self.root, self.toplevel).replace("\\", "/")
            prefix = "" if rel_root == "." else rel_root + "/"
            files = []
            for p in tracked + untracked:
                if prefix and not p.startswith(prefix):
                    continue
                if os.path.isfile(os.path.join(self.toplevel, p)):
                    files.append(p)
            return sorted(set(files)), set(tracked)
        files = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                files.append(os.path.relpath(full, self.root).replace("\\", "/"))
        return sorted(files), set()

    def abspath(self, rel: str) -> str:
        return os.path.join(self.toplevel if self.is_repo else self.root, rel)

    # ---------- main entry ----------

    def scan(self) -> None:
        self._load_ignore_file()
        self._detect_repo()
        if self.hook_revs is not None:
            self.scan_history(self.hook_revs)
            return
        files, tracked = self.list_files()
        self.stats["files"] = len(files)
        self.scan_files(files, tracked)
        if self.is_repo:
            self.scan_tracked_but_ignored()
            self.scan_gitignore_gaps(files)
            if self.history:
                self.scan_history(["--all"])
                self.scan_author_emails()
        else:
            self.notes.append("This folder is not a git repository yet, so history and .gitignore checks were skipped.")
        if self.use_gitleaks:
            self.run_gitleaks()

    # ---------- files ----------

    def scan_files(self, files: List[str], tracked: Set[str]) -> None:
        junk_groups: Dict[str, List[str]] = {}
        for rel in files:
            parts = rel.split("/")
            junk_dir = None
            for i, p in enumerate(parts[:-1]):
                if p in JUNK_DIRS:
                    junk_dir = "/".join(parts[: i + 1])
                    break
                if os.path.isfile(self.abspath("/".join(parts[: i + 1]) + "/pyvenv.cfg")):
                    junk_dir = "/".join(parts[: i + 1])
                    break
            if junk_dir:
                junk_groups.setdefault(junk_dir, []).append(rel)
                continue
            status = "tracked" if rel in tracked else "untracked"
            self.check_filename(rel, status)
            self.check_size(rel, status)
            self.scan_content(rel, status)

        if len(self._binaries) <= 3:
            for rel, st in self._binaries:
                ext_ = os.path.splitext(rel)[1]
                self.add(Finding("yellow", "large", "Binary / archive file", rel, 0, st,
                                 why="Built or zipped files don't belong in git. Share them as a GitHub Release instead.",
                                 fix=[f"Add `{os.path.basename(rel)}` (or `*{ext_}`) to .gitignore"] +
                                     ([f"Stop tracking it: `git rm --cached {rel}`"] if st == "tracked" else []),
                                 rule="binary"))
        else:
            by_ext: Dict[str, int] = {}
            for rel, _ in self._binaries:
                e = os.path.splitext(rel)[1].lower()
                by_ext[e] = by_ext.get(e, 0) + 1
            self.add(Finding("yellow", "large", f"{len(self._binaries)} binary / archive files", "", 0,
                             "tracked" if any(st == "tracked" for _, st in self._binaries) else "untracked",
                             why="Built, compiled or zipped files usually don't belong in git (they're big and can't be reviewed). Some, like app icons' sources or test data, may be intentional.",
                             fix=["Check the list; for generated ones add the pattern to .gitignore and `git rm --cached` them"],
                             rule="binary", extra=[", ".join(f"{n}× {e}" for e, n in sorted(by_ext.items(), key=lambda x: -x[1]))]
                             + [f"e.g. {r}" for r, _ in self._binaries[:3]]))
        for d, members in sorted(junk_groups.items()):
            name = d.split("/")[-1]
            desc = JUNK_DIRS.get(name, "a Python virtual environment")
            st = "tracked" if any(m in tracked for m in members) else "untracked"
            self.add(Finding(
                "yellow", "junk", f"`{d}/` folder ({len(members)} files)", d + "/", 0, st,
                why=f"This is {desc}. It's generated on each computer and shouldn't be in git.",
                fix=[f"Add `{name}/` to .gitignore"] + ([f"Stop tracking it: `git rm -r --cached {d}`"] if st == "tracked" else []),
                rule="junk-dir",
            ))
            # A secret can still hide in a junk folder (for example a .env inside build/).
            for rel in members:
                base = os.path.basename(rel)
                if re.match(r"(?i)^\.env(\..+)?$", base) and not ENV_FILE_OK_SUFFIX.search(base):
                    self.check_filename(rel, "tracked" if rel in tracked else "untracked")

    def check_filename(self, rel: str, status: str) -> None:
        base = os.path.basename(rel)
        ctx = path_context(rel)
        for rx, sev, check, title, why in SECRET_FILE_RULES:
            if not rx.search(base):
                continue
            if title == "Binary / archive file":
                self._binaries.append((rel, status))
                return
            fix: List[str] = []
            extra: List[str] = []
            if check == "files" and base.lower().startswith(".env"):
                if ENV_FILE_OK_SUFFIX.search(base):
                    return  # .env.example is the right way to do it
                values = self._env_values(rel)
                real = [k for k, v in values if v and not is_placeholder(v) and not looks_like_reference(v)]
                if not real:
                    sev = "yellow"
                    why = "Environment file with only empty or placeholder values. Fine, but call it `.env.example` so nobody puts real values in it later."
                    fix = [f"Rename it: `git mv {rel} {rel}.example`" if status == "tracked" else f"Rename it to `{base}.example`"]
                else:
                    extra.append(f"{len(real)} real-looking value(s): " + ", ".join(real[:6]) + (" …" if len(real) > 6 else ""))
                    fix = [f"Add `{base if base == '.env' else '.env*'}` and `!.env.example` to .gitignore",
                           "Commit a `.env.example` with the same names but empty values, so others know what to set"]
            elif check == "keys" and re.search(r"(?i)\.(pem|asc|gpg|key)$", base):
                head = self._read_head(rel, 4096)
                if head is None:
                    return
                if "PRIVATE KEY" not in head and not base.lower().endswith(".key"):
                    return  # public cert / public key: fine
                if "PRIVATE KEY" in head:
                    self.current_secret_values.add("pk:" + rel)
            if check == "keys":
                self._key_files.add(rel)
                self.current_secret_values.add("pk:" + rel)
                fix = ["Move the key out of the project folder (e.g. into ~/.ssh/) or add it to .gitignore",
                       "If it was ever pushed or shared: make a new key and remove the old public key wherever it's trusted (servers, GitHub)"]
            elif check == "data" and base.lower().endswith(".sql"):
                pass
            if ctx in ("test", "example") and sev == "red" and check in ("keys", "files"):
                sev = "yellow"
                why += " It's in a test/example folder. If it's a throwaway test key that's OK; if it's real, treat it as red."
            if status == "tracked":
                fix.append(f"Stop tracking it (keeps your local copy): `git rm --cached {rel}`")
            if not fix:
                ext_ = os.path.splitext(base)[1]
                fix.append(f"Add `{base}`" + (f" (or a pattern like `*{ext_}`)" if ext_ else "") + " to .gitignore")
            pushed = None
            if sev == "red" and status == "tracked" and self.is_repo:
                pushed = self.file_pushed(rel)
                if pushed:
                    fix.append("It's already on GitHub: treat everything inside as leaked and change those passwords/keys")
            self.add(Finding(sev, check, title, rel, 0, status, why=why, fix=fix, pushed=pushed,
                             rule="file:" + title, extra=extra))
            return

    def _env_values(self, rel: str) -> List[Tuple[str, str]]:
        out = []
        txt = self._read_text(rel)
        if txt is None:
            return out
        for ln in txt.splitlines():
            m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$", ln)
            if m:
                v = m.group(2).strip().strip("\"'")
                v = re.split(r"\s+#", v)[0].strip()
                out.append((m.group(1), v))
        return out

    def check_size(self, rel: str, status: str) -> None:
        try:
            size = os.path.getsize(self.abspath(rel))
        except OSError:
            return
        mb = size / (1024 * 1024)
        if mb >= 50:
            self.add(Finding("red", "large", f"Very large file ({mb:.0f} MB)", rel, 0, status,
                             why="GitHub rejects files over 100 MB and warns over 50 MB. It also makes the repo slow for everyone.",
                             fix=["Remove it from git and share it another way (GitHub Releases, Git LFS, cloud storage)",
                                  f"`git rm --cached {rel}` and add it to .gitignore"], rule="large"))
        elif mb >= 10:
            self.add(Finding("yellow", "large", f"Large file ({mb:.0f} MB)", rel, 0, status,
                             why="Big files make the repo slow to clone. Is it needed in git?",
                             fix=["Consider Git LFS or a GitHub Release instead"], rule="large"))

    def _read_head(self, rel: str, n: int) -> Optional[str]:
        try:
            with open(self.abspath(rel), "rb") as fh:
                data = fh.read(n)
        except OSError:
            return None
        return data.decode("utf-8", errors="replace")

    def _read_text(self, rel: str, limit: int = 2 * 1024 * 1024) -> Optional[str]:
        p = self.abspath(rel)
        try:
            if os.path.getsize(p) > limit:
                return None
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            return None
        if b"\0" in data[:8192]:
            return None
        return data.decode("utf-8", errors="replace")

    def scan_content(self, rel: str, status: str) -> None:
        txt = self._read_text(rel)
        if txt is None:
            return
        base = os.path.basename(rel).lower()
        ext = file_ext(rel)
        ctx = path_context(rel)
        is_lock = base in LOCKFILES
        lines = txt.splitlines()

        if ext == ".json" and '"type": "service_account"' in txt and '"private_key"' in txt:
            self.add(Finding("red" if ctx not in ("test", "example") else "yellow", "secrets",
                             "Google Cloud service-account key", rel, 1, status,
                             why="This JSON file is a full login for a Google Cloud service account.",
                             fix=["Delete it from the project, keep it outside the repo, and point to it with an env variable (GOOGLE_APPLICATION_CREDENTIALS)",
                                  "Disable this key in Google Cloud console → IAM → Service accounts"], rule="gcp-sa"))

        sql_inserts = 0
        pii: Dict[str, List[Tuple[int, str]]] = {"email": [], "phone": [], "path": [], "ip": [], "host": [], "card": []}
        emails_seen: Set[str] = set()
        skip_pii = is_lock or ext in NO_PII_SCAN_EXTS or bool(INTENTIONAL_PII_FILES.match(base))

        for i, line in enumerate(lines, 1):
            if len(line) > 5000:  # minified / data blob: only look for strong secrets
                line_for_pii = ""
            else:
                line_for_pii = line
            if "pushguard:ignore" in line:
                continue
            if ext == ".sql" and line.lstrip().upper().startswith("INSERT INTO"):
                sql_inserts += 1
            hit_secret = self.scan_line_secrets(rel, i, line, status, ctx, ext, is_lock)
            if skip_pii or not line_for_pii or hit_secret:
                continue
            self.collect_pii(line_for_pii, i, pii, emails_seen, ctx)

        if sql_inserts >= 20:
            self.add(Finding("red", "data", f"SQL file with {sql_inserts} rows of data", rel, 0, status,
                             why="Looks like a data dump, not just a schema. It may contain real users' data.",
                             fix=["Keep only the schema / migrations in git; share data dumps privately",
                                  f"`git rm --cached {rel}` and add it to .gitignore"], rule="sql-dump"))
        self.report_pii(rel, status, ctx, ext, pii, emails_seen)

    def scan_line_secrets(self, rel: str, ln: int, line: str, status: str, ctx: str, ext: str, is_lock: bool) -> bool:
        found = False
        soft = ctx in ("test", "example", "docs")
        for rid, name, rx, sev, rot, why in COMPILED_RULES:
            for m in rx.finditer(line):
                secret = m.group("s") if "s" in rx.groupindex else m.group(0)
                if is_placeholder(secret) or entropy(secret) < 3.0:
                    continue
                self.current_secret_values.add(secret)
                s = sev
                w = why
                if soft and s == "red" and rid != "stripe-live":
                    s = "yellow"
                    w += f" It's in a {ctx} file. If it's a made-up key, mark the line with `pushguard:ignore`; if it's real, it's leaked."
                fix = self.secret_fix(rel, rot, status)
                self.add(Finding(s, "secrets", name, rel, ln, status, preview=mask(secret), why=w, fix=fix, rule=rid))
                found = True
        if PRIVATE_KEY_RE.search(line) and rel not in self._key_files:
            self.current_secret_values.add("pk:" + rel)
            s = "yellow" if ctx in ("test", "example") else "red"
            self.add(Finding(s, "keys", "Private key", rel, ln, status, preview=line.strip()[:40],
                             why="A private key lets someone log in to your servers, sign code or decrypt data as you.",
                             fix=["Remove the key from the repo and keep it in a safe place (ssh-agent, a secrets manager)",
                                  "Generate a new key pair and remove the old public key from wherever it's trusted (servers, GitHub)"],
                             rule="private-key"))
            found = True
        for m in CONN_URL_RE.finditer(line):
            pw = m.group("s")
            if is_placeholder(pw) or looks_like_reference(pw) or pw.startswith(("$", "{")) or len(pw) < 4:
                continue
            if m.group("host").lower() in ("localhost", "127.0.0.1", "0.0.0.0", "db", "postgres", "mysql", "redis", "mongo") and (soft or is_placeholder(m.group("user"))):
                continue
            self.current_secret_values.add(pw)
            s = "yellow" if soft else "red"
            self.add(Finding(s, "passwords", f"Password inside a {m.group('scheme')}:// URL", rel, ln, status,
                             preview=f"{m.group('scheme')}://{m.group('user')}:{mask(pw)}@{m.group('host')}",
                             why="The connection string contains a real-looking password. Anyone could connect to that database/service.",
                             fix=["Read the URL from an environment variable (e.g. DATABASE_URL) instead",
                                  "Change that database password if this was ever pushed"], rule="conn-url"))
            found = True
        if found:
            return True
        if is_lock:
            return False

        # Generic "password = ..." style assignments
        is_code = ext not in CONFIG_EXTS
        for m in ASSIGN_RE.finditer(line):
            name = m.group("name")
            val = m.group("qv") if m.group("q") else m.group("uv")
            if val is None:
                continue
            if is_code and not m.group("q"):
                continue  # in code, only literal strings count
            kws = list(KW_RE.finditer(name))
            if not kws:
                continue
            tail = re.sub(r"[_.\-]", "", name[kws[-1].end():].lower())
            if tail not in OK_NAME_TAILS:
                continue
            if re.search(r"(?i)(^|[_.\-])(type|field|label|name|url|uri|path|file|length|len|min|max|regex|pattern|hint|placeholder|input|prompt|reset|confirm|policy|expires?|expiry|count|header|param|endpoint|env|var|ttl|id|mode|method|scope|form|error|message|msg|text|title|button|validator|rules?|hash|salt|limit)([_.\-]|$)", name[: kws[-1].start()]):
                continue
            v = val.strip()
            if len(v) < 6 or is_placeholder(v) or looks_like_reference(v) or not_a_secret_value(v, name):
                continue
            if is_code and m.group(0).lstrip()[:1] in "\"'" and "=" in m.group(0).split(val)[0][-6:] and ":" not in m.group(0).split(val)[0][-6:]:
                continue  # "name" = ... inside code is string concatenation, not an assignment
            if " " in v and re.fullmatch(r"[A-Za-z][A-Za-z &,.'/()\-]+", v):
                continue  # a UI label like "Enter your password" or "API keys & tokens"
            if re.fullmatch(r"[\w.\-/\\]+\.(pem|key|json|txt|crt|p12|env)", v) or v.startswith(("./", "/", "~", "../")):
                continue  # a file path, not a secret
            if re.fullmatch(r"[A-Z][A-Z0-9_]+", v):
                continue  # an env var NAME, e.g. token_env = "GITHUB_TOKEN"
            if ctx in ("test", "example", "docs"):
                self.ignored_test_creds += 1
                return False
            self.current_secret_values.add(v)
            self.add(Finding("red", "passwords", f"Secret written directly in the file (`{name}`)", rel, ln, status,
                             preview=f"{name} = {mask(v)}",
                             why="A password or key typed straight into a file. Once it's on GitHub, anyone can read it.",
                             fix=self.secret_fix(rel, "", status, var=re.sub(r'[^A-Z0-9_]', '_', name.upper())),
                             rule="assign:" + name.lower()))
            return True

        # High-entropy strings next to key-ish words
        if ctx not in ("test", "example", "docs") and KEYISH_RE.search(line) and not HASHISH_RE.search(line):
            for m in HIGH_ENTROPY_RE.finditer(line):
                tok = m.group(1)
                hexy = re.fullmatch(r"[0-9a-fA-F]+", tok) is not None
                if is_placeholder(tok) or (hexy and entropy(tok) < 3.2) or (not hexy and entropy(tok) < 4.3):
                    continue
                if re.fullmatch(r"[A-Za-z_\-]+", tok):
                    continue  # just a long identifier
                self.current_secret_values.add(tok)
                self.add(Finding("yellow", "secrets", "Random-looking secret string", rel, ln, status, preview=mask(tok),
                                 why="This looks like a random key or token sitting next to the word key/secret/token. Check whether it's real.",
                                 fix=["If it's real: move it to an environment variable and rotate it",
                                      "If it's not a secret: mark the line with `pushguard:ignore`"], rule="entropy"))
                return True
        return False

    def secret_fix(self, rel: str, rot: str, status: str, var: str = "") -> List[str]:
        base = os.path.basename(rel)
        fix: List[str] = []
        if base.lower().startswith(".env"):
            fix.append("Keep it in `.env`, but make sure `.env` is in .gitignore and not tracked")
        else:
            v = var or "MY_SECRET"
            fix.append(f"Move it out of the code into an environment variable (e.g. `{v}` in a git-ignored `.env`) and read it with `os.environ[\"{v}\"]` / `process.env.{v}`")
        if status == "tracked":
            fix.append(f"It's already committed: after removing it, the old value is still in git history (see the history section)")
        if rot and rot in ROTATE:
            fix.append(f"If it was ever pushed or shared: rotate (cancel + replace) the key → {ROTATE[rot]}")
        elif rot or status == "tracked":
            fix.append("If it was ever pushed or shared: change it at the provider; deleting it from the file is not enough")
        return fix

    # ---------- personal & company info ----------

    def collect_pii(self, line: str, ln: int, pii: Dict[str, List[Tuple[int, str]]], emails_seen: Set[str], ctx: str) -> None:
        for m in EMAIL_RE.finditer(line):
            e = m.group(0).lower()
            local, _, dom = e.partition("@")
            if any(c in local for c in "%{}$<") or dom.endswith(SAFE_EMAIL_DOMAINS) or local in ROLE_LOCALS or local.startswith(("noreply", "no-reply")):
                continue
            if re.search(r"\.(png|jpe?g|gif|svg|webp|js|css|ts)$", e) or re.match(r"^\d+(\.\d+)*$", dom.split(".")[0]):
                continue  # retina image names like logo@2x.png, package@1.2.3
            if line[max(0, m.start() - 4): m.start()].endswith(("git@", "ssh://")) or local == "git":
                continue
            emails_seen.add(e)
            pii["email"].append((ln, e))
        for m in PHONE_RE.finditer(line):
            num = re.sub(r"\D", "", m.group(0))
            if not 9 <= len(num) <= 15 or "555" in num[:7] or len(set(num)) <= 2 or re.search(r"(?i)version|v\d|\d{4}-\d{2}-\d{2}", line):
                continue
            pii["phone"].append((ln, m.group(0)))
        for rx in (WIN_PATH_RE, NIX_PATH_RE):
            for m in rx.finditer(line):
                who = m.group(1)
                if who.lower() in GENERIC_USERS or any(c in who for c in "<>${}%") or who.startswith("."):
                    continue
                pii["path"].append((ln, m.group(0) + ("…" if not m.group(0).endswith(("/", "\\")) else "")))
        if self.os_user and not any(l == ln for l, _ in pii["path"]):
            if re.search(r"(?i)(?<![A-Za-z0-9])" + re.escape(self.os_user) + r"(?![A-Za-z0-9])", line):
                pii["path"].append((ln, f"your computer username '{self.os_user}'"))
        for m in IP_RE.finditer(line):
            ip_s = m.group(0)
            pre = line[max(0, m.start() - 9): m.start()].lower()
            if ip_s in SAFE_IPS or "version" in pre or pre.endswith("v"):
                continue
            try:
                ip = ipaddress.ip_address(ip_s)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
                continue
            if any(ip in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
                continue  # documentation ranges
            if ip_s.endswith(".0") or ip_s.startswith("255."):
                continue  # network address / netmask
            pii["ip"].append((ln, f"{ip_s} ({'private network' if ip.is_private else 'public server'})"))
        for m in URL_HOST_RE.finditer(line):
            host = m.group(1).lower().rstrip(".")
            if host in PUBLIC_SUBDOMAINS or (host.endswith(PUBLIC_HOST_ALLOW) and not host.endswith(INTERNAL_SUFFIXES)):
                continue
            if host.endswith(INTERNAL_TLDS) or host.endswith(INTERNAL_SUFFIXES) or INTERNAL_PREFIX_RE.match(host):
                if host in ("localhost",) or host.endswith(("example.com", "example.org")):
                    continue
                pii["host"].append((ln, host))
        if re.search(r"(?i)card|cc_?num|pan\b|visa|master|amex|payment", line):
            for m in CARD_RE.finditer(line):
                digits = re.sub(r"\D", "", m.group(0))
                if digits in TEST_CARDS or not luhn_ok(digits):
                    continue
                pii["card"].append((ln, mask(digits)))

    def report_pii(self, rel: str, status: str, ctx: str, ext: str, pii: Dict[str, List[Tuple[int, str]]], emails_seen: Set[str]) -> None:
        def sample(items: List[Tuple[int, str]], n: int = 3) -> List[str]:
            seen, out = set(), []
            for ln, v in items:
                if v in seen:
                    continue
                seen.add(v)
                out.append(f"line {ln}: {v}")
                if len(out) >= n:
                    break
            more = len({v for _, v in items}) - len(out)
            if more > 0:
                out.append(f"…and {more} more")
            return out

        data_like = ext in (".csv", ".tsv", ".json", ".sql", ".xml", ".xlsx", ".jsonl", ".yaml", ".yml") or ctx == "test"
        n_people = len(emails_seen) + len({v for _, v in pii["phone"]})
        if n_people >= 5 and data_like:
            self.add(Finding("red", "personal", f"Looks like real people's data ({len(emails_seen)} emails, {len({v for _, v in pii['phone']})} phone numbers)",
                             rel, pii["email"][0][0] if pii["email"] else pii["phone"][0][0], status,
                             why="Real customer/user details must not be published (privacy laws like GDPR apply). Test data should be made up.",
                             fix=["Replace it with fake data (names like Jane Doe, emails @example.com, phones 555-01xx)",
                                  f"Or remove the file from git: `git rm --cached {rel}`"],
                             rule="pii-bulk", extra=sample(pii["email"] + pii["phone"])))
        else:
            if pii["email"]:
                self.add(Finding("yellow", "personal", "Email address", rel, pii["email"][0][0], status,
                                 why="Is this a real person's email? Public repos get scraped by spammers.",
                                 fix=["Replace with a fake one like `someone@example.com`, or remove it",
                                      "If it's your own and you're fine sharing it, ignore this"],
                                 rule="pii-email", extra=sample(pii["email"])))
            if pii["phone"]:
                self.add(Finding("yellow", "personal", "Phone number", rel, pii["phone"][0][0], status,
                                 why="Is this a real person's phone number?",
                                 fix=["Replace it with a fake one (for example 555-0100) or remove it"],
                                 rule="pii-phone", extra=sample(pii["phone"])))
        if pii["path"]:
            self.add(Finding("yellow", "personal", "Path from your computer (shows your username)", rel, pii["path"][0][0], status,
                             why="Paths like C:\\Users\\<name>\\… reveal your username and folder layout, and the code won't work on anyone else's machine.",
                             fix=["Use a relative path, or build it at runtime (`Path.home()`, `os.path.expanduser('~')`, an env variable)"],
                             rule="pii-path", extra=sample(pii["path"])))
        if pii["card"]:
            self.add(Finding("red", "personal", "Credit card number", rel, pii["card"][0][0], status,
                             why="Looks like a real card number (it passes the checksum and isn't a known test card).",
                             fix=["Remove it. Use official test cards like 4242 4242 4242 4242 for testing"],
                             rule="pii-card", extra=sample(pii["card"])))
        if pii["ip"]:
            self.add(Finding("yellow", "company", "Server IP address", rel, pii["ip"][0][0], status,
                             why="IP addresses show where your servers live and help attackers find them.",
                             fix=["Move server addresses into config / environment variables",
                                  "Use documentation IPs (192.0.2.x) in examples"],
                             rule="ip", extra=sample(pii["ip"])))
        if pii["host"]:
            self.add(Finding("yellow", "company", "Internal company URL", rel, pii["host"][0][0], status,
                             why="Internal hostnames (Jira, staging, *.corp, *.internal) reveal your company's private systems.",
                             fix=["Remove it, or replace it with a placeholder like `https://internal.example.com`"],
                             rule="host", extra=sample(pii["host"])))

    # ---------- .gitignore ----------

    def scan_tracked_but_ignored(self) -> None:
        code, out = git(["ls-files", "-z", "-ci", "--exclude-standard"], self.toplevel)
        files = [p for p in out.split("\0") if p] if code == 0 else []
        if not files:
            return
        groups: Dict[str, int] = {}
        for p in files:
            top = p.split("/")[0] + ("/" if "/" in p else "")
            groups[top] = groups.get(top, 0) + 1
        shown = [f"{g} ({n} file{'s' if n > 1 else ''})" for g, n in sorted(groups.items(), key=lambda x: -x[1])]
        self.add(Finding("yellow", "gitignore", f"{len(files)} file(s) are in .gitignore but still tracked", "", 0, "tracked",
                         why=".gitignore only works for NEW files. These were committed before the rule was added, so they still get pushed.",
                         fix=["Stop tracking them (your local copies stay): `git rm -r --cached <path>` for each, then commit"],
                         rule="tracked-ignored", extra=shown[:8]))

    def scan_gitignore_gaps(self, files: List[str]) -> None:
        names = {os.path.basename(f).lower() for f in files}
        exts = {os.path.splitext(f)[1].lower() for f in files}
        rules = [(".env", ".env"), (".env.*", ".env.local"), ("*.pem", "x.pem"), ("*.key", "x.key"), ("*.log", "x.log"), (".DS_Store", ".DS_Store")]
        exists = lambda n: os.path.exists(os.path.join(self.toplevel, n))  # noqa: E731
        if "package.json" in names:
            rules += [("node_modules/", "node_modules/x"), ("dist/", "dist/x"), ("npm-debug.log*", "npm-debug.log")]
        if ".py" in exts or "requirements.txt" in names or "pyproject.toml" in names:
            rules += [("__pycache__/", "__pycache__/x"), (".venv/", ".venv/x")]
        if "build.gradle" in names or "build.gradle.kts" in names:
            rules += [("build/", "build/x"), (".gradle/", ".gradle/x"), ("local.properties", "local.properties"), ("*.jks", "x.jks"), ("*.keystore", "x.keystore")]
        if "cargo.toml" in names or "pom.xml" in names:
            rules += [("target/", "target/x")]
        if ".tf" in exts:
            rules += [("*.tfstate", "x.tfstate"), (".terraform/", ".terraform/x")]
        if any(n.endswith((".csproj", ".sln")) for n in names):
            rules += [("bin/", "bin/x"), ("obj/", "obj/x")]
        missing = []
        for rule, sample_path in rules:
            code, _ = git(["check-ignore", "-q", "--no-index", "--", sample_path], self.toplevel)
            if code != 0:
                missing.append(rule)
        has_gitignore = exists(".gitignore")
        if not has_gitignore:
            self.add(Finding("yellow", "gitignore", "No .gitignore file", ".gitignore", 0, "repo",
                             why="Without a .gitignore, `git add .` adds everything, including secrets and junk.",
                             fix=["Create a .gitignore with these lines: " + " ".join(f"`{r}`" for r in missing)], rule="no-gitignore"))
        elif missing:
            self.add(Finding("yellow", "gitignore", ".gitignore is missing some safety rules", ".gitignore", 0, "repo",
                             why="These patterns aren't ignored yet. Adding them stops future accidents.",
                             fix=["Add these lines to .gitignore: " + " ".join(f"`{r}`" for r in missing)], rule="gitignore-gaps"))

    # ---------- history ----------

    def scan_history(self, revs: List[str]) -> None:
        if not self.is_repo:
            return
        code, out = git(["rev-list", "--count"] + revs, self.toplevel)
        if code != 0:
            return
        total = int(out.strip() or 0)
        self.stats["commits"] = total
        if total == 0:
            return
        if total > self.max_commits:
            self.notes.append(f"History has {total} commits; only the newest {self.max_commits} were scanned (use --max-commits to change).")
        shallow = git(["rev-parse", "--is-shallow-repository"], self.toplevel)[1].strip() == "true"
        if shallow:
            self.notes.append("This is a shallow clone, so older history could not be checked (`git fetch --unshallow`).")
        cmd = ["git", "-c", "core.quotepath=off", "log"] + revs + [
            f"--max-count={self.max_commits}", "-p", "--no-color", "--no-ext-diff", "-U0", "--no-renames",
            "--format=%x01%H%x02%ad%x02%an", "--date=short",
        ]
        try:
            proc = subprocess.Popen(cmd, cwd=self.toplevel, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except OSError:
            return
        current_files = set(self.list_files()[0]) if self.hook_revs is None else set()
        commit = date = ""
        path = ""
        new_file = False
        hist: Dict[str, Finding] = {}
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            if line.startswith("\x01"):
                commit, date, _author = (line[1:].split("\x02") + ["", ""])[:3]
                continue
            if line.startswith("diff --git "):
                m = re.match(r'diff --git "?a/(.*?)"? "?b/(.*?)"?$', line)
                path = m.group(2) if m else ""
                new_file = False
                continue
            if line.startswith("new file mode"):
                new_file = True
                self._history_file(path, commit, date, current_files, hist)
                continue
            if line.startswith("+++") or line.startswith("---") or not line.startswith("+"):
                continue
            text = line[1:]
            if "pushguard:ignore" in text or len(text) > 5000:
                continue
            self._history_line(path, text, commit, date, hist)
        proc.wait()
        for f in hist.values():
            self.add(f)

    def _history_file(self, path: str, commit: str, date: str, current_files: Set[str], hist: Dict[str, Finding]) -> None:
        if not path or path in current_files and self.hook_revs is None:
            return
        base = os.path.basename(path)
        for rx, sev, check, title, why in SECRET_FILE_RULES:
            if rx.search(base) and sev == "red" and check in ("files", "keys", "data"):
                if base.lower().startswith(".env") and ENV_FILE_OK_SUFFIX.search(base):
                    return
                if path_context(path) in ("test", "example"):
                    return
                key = "file:" + path
                pushed = self.commit_pushed(commit)
                f = Finding("red", "history",
                            f"{title} was committed" + (" earlier and later deleted" if self.hook_revs is None else " in a commit you're about to push"),
                            path, 0, "history", commit=commit[:7], pushed=pushed,
                            why="Deleting a file doesn't remove it from git history. Anyone who clones the repo can still get it with one command.",
                            fix=self.history_fix(pushed), rule="hist-file", extra=[f"added in commit {commit[:7]} ({date})"])
                hist[key] = f  # git log is newest-first, so the last write is the oldest commit
                return

    def _history_line(self, path: str, text: str, commit: str, date: str, hist: Dict[str, Finding]) -> None:
        ctx = path_context(path)
        if ctx in ("test", "example", "docs"):
            return
        hits: List[Tuple[str, str, str]] = []
        for rid, name, rx, sev, rot, _why in COMPILED_RULES:
            if sev != "red":
                continue
            for m in rx.finditer(text):
                secret = m.group("s") if "s" in rx.groupindex else m.group(0)
                if not is_placeholder(secret) and entropy(secret) >= 3.0:
                    hits.append((secret, name, rot))
        if PRIVATE_KEY_RE.search(text):
            hits.append(("pk:" + path, "Private key", ""))
        for m in CONN_URL_RE.finditer(text):
            pw = m.group("s")
            if not (is_placeholder(pw) or looks_like_reference(pw) or len(pw) < 4):
                hits.append((pw, "Password in a connection URL", ""))
        if not hits and file_ext(path) in CONFIG_EXTS and os.path.basename(path).lower() not in LOCKFILES:
            for m in ASSIGN_RE.finditer(text):
                val = (m.group("qv") if m.group("q") else m.group("uv")) or ""
                kws = list(KW_RE.finditer(m.group("name")))
                if not kws or re.sub(r"[_.\-]", "", m.group("name")[kws[-1].end():].lower()) not in OK_NAME_TAILS:
                    continue
                if (len(val) >= 6 and not is_placeholder(val) and not looks_like_reference(val)
                        and not re.fullmatch(r"[A-Z][A-Z0-9_]+", val) and not not_a_secret_value(val, m.group("name"))):
                    hits.append((val, f"Password/secret (`{m.group('name')}`)", ""))
                    break
        for secret, name, rot in hits:
            if self.hook_revs is None and secret in self.current_secret_values:
                continue  # still in the current files: already reported there
            pushed = self.commit_pushed(commit)
            fix = self.history_fix(pushed)
            if rot in ROTATE:
                fix.insert(0, f"Rotate (cancel + replace) this key first → {ROTATE[rot]}")
            prev = None if secret.startswith("pk:") else mask(secret)
            title = f"{name} in git history" + (" (deleted from the files, but still in history)" if self.hook_revs is None else " (in a commit you're about to push)")
            hist[secret] = Finding("red", "history", title, path, 0, "history", preview=prev or "", commit=commit[:7],
                                   pushed=pushed,
                                   why="A secret was committed. Even if a later commit removed it, anyone can still find it in the history.",
                                   fix=fix, rule="hist-secret", extra=[f"commit {commit[:7]} ({date})"])

    def history_fix(self, pushed: Optional[bool]) -> List[str]:
        if pushed:
            return ["This commit is ALREADY on GitHub: assume the secret is leaked and rotate it. Rewriting history alone can't un-leak it",
                    "Optionally clean history afterwards with `git filter-repo` (ask first: it rewrites commits for everyone)"]
        return ["This commit has NOT been pushed yet, so you can still remove it from history before pushing",
                "Rewrite the unpushed commits (e.g. `git rebase -i` and edit that commit, or `git filter-repo`). Ask Claude to walk you through it; nothing is changed without your OK"]

    def scan_author_emails(self) -> None:
        code, out = git(["log", "--all", f"--max-count={self.max_commits}", "--format=%ae"], self.toplevel)
        if code != 0:
            return
        emails = sorted({e.strip().lower() for e in out.splitlines() if e.strip()})
        private = [e for e in emails if not e.endswith("noreply.github.com") and "@" in e and not e.endswith(SAFE_EMAIL_DOMAINS[:3])]
        if private:
            self.add(Finding("yellow", "authors", "Commit author email will be public", "", 0, "history",
                             why="Every commit shows the author's email on GitHub. If you don't want your email public, use GitHub's private no-reply address.",
                             fix=["Set it for this repo: `git config user.email \"<id>+<username>@users.noreply.github.com\"` (find it at github.com/settings/emails)",
                                  "Turn on 'Block command line pushes that expose my email' on that page",
                                  "Old unpushed commits can be fixed with `git rebase -r --root --exec \"git commit --amend --no-edit --reset-author\"` (ask first)"],
                             rule="author-email", extra=private[:5]))

    # ---------- gitleaks ----------

    def run_gitleaks(self) -> None:
        exe = shutil.which("gitleaks")
        if not exe:
            return
        fd, report = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            args = [exe, "detect", "--source", self.toplevel if self.is_repo else self.root, "--redact",
                    "--no-banner", "--report-format", "json", "--report-path", report, "--exit-code", "0"]
            if not self.is_repo or not self.history:
                args.append("--no-git")
            code, _ = run(args, self.root)
            self.gitleaks = "used"
            with open(report, encoding="utf-8") as fh:
                data = json.load(fh) or []
        except (OSError, ValueError):
            self.gitleaks = "installed, but failed to run"
            return
        finally:
            try:
                os.remove(report)
            except OSError:
                pass
        have = {(f.file, f.line) for f in self.findings}
        for item in data:
            rel = (item.get("File") or "").replace("\\", "/")
            ln = int(item.get("StartLine") or 0)
            if (rel, ln) in have or path_context(rel) in ("test", "example", "docs"):
                continue
            commit = (item.get("Commit") or "")[:7]
            in_history = bool(commit) and not os.path.exists(self.abspath(rel))
            pushed = self.commit_pushed(item["Commit"]) if commit else None
            self.add(Finding("red", "history" if in_history else "secrets",
                             f"{item.get('Description') or item.get('RuleID', 'Secret')} (found by gitleaks)", rel, ln,
                             "history" if in_history else "tracked", commit=commit, pushed=pushed,
                             why="gitleaks recognised this as a secret.",
                             fix=self.history_fix(pushed) if in_history else self.secret_fix(rel, "", "tracked"),
                             rule="gitleaks:" + str(item.get("RuleID"))))


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# --------------------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------------------


def verdict(findings: Iterable[Finding]) -> Tuple[str, int]:
    fs = list(findings)
    red = sum(1 for f in fs if f.severity == "red")
    yellow = sum(1 for f in fs if f.severity == "yellow")
    if red:
        return f"🛑 PUSH BLOCKED: fix the {red} red item{'s' if red > 1 else ''} first.", 2
    if yellow:
        return f"⚠️ CHECK FIRST: no secrets found, but look at the {yellow} yellow item{'s' if yellow > 1 else ''} before you push.", 1
    return "✅ SAFE TO PUSH: nothing sensitive found.", 0


def where(f: Finding) -> str:
    loc = f.file + (f":{f.line}" if f.line else "")
    tag = {
        "tracked": "already committed",
        "untracked": "not committed yet; `git add .` would include it",
        "history": "in git history" + (f", commit {f.commit}" if f.commit else ""),
        "repo": "",
    }.get(f.status, f.status)
    if f.pushed is True:
        tag += ", ALREADY PUSHED"
    elif f.pushed is False and f.status in ("history", "tracked"):
        tag += ", not pushed yet"
    parts = [p for p in (f"`{loc}`" if loc else "", f"({tag})" if tag else "") if p]
    return " ".join(parts)


def render_markdown(sc: Scanner) -> str:
    order = {"red": 0, "yellow": 1}
    fs = sorted(sc.findings, key=lambda f: (order.get(f.severity, 2), list(CHECKS).index(f.check), f.file, f.line))
    name = os.path.basename(sc.toplevel if sc.is_repo else sc.root)
    out = [f"# push-guard report: {name}", ""]
    meta = f"Scanned {sc.stats['files']} file{'s' if sc.stats['files'] != 1 else ''}"
    if sc.is_repo:
        meta += f" and {sc.stats['commits']} commit{'s' if sc.stats['commits'] != 1 else ''}"
    meta += f" · gitleaks: {sc.gitleaks}"
    out += [meta, ""]
    n = 0
    for sev, head in (("red", "## 🔴 Must fix"), ("yellow", "## 🟡 Check this")):
        group = [f for f in fs if f.severity == sev]
        if not group:
            continue
        out += [f"{head} ({len(group)})", ""]
        for f in group:
            n += 1
            title = f"**{n}. {f.title}**"
            w = where(f)
            out.append(f"{title}  {w}".rstrip())
            if f.preview:
                out.append(f"   - Found: `{f.preview}`")
            for e in f.extra:
                out.append(f"   - {e}")
            if f.why:
                out.append(f"   - Why it matters: {f.why}")
            for x in f.fix:
                out.append(f"   - Fix: {x}")
            out.append("")
    hit = {f.check for f in fs}
    clean = [label for key, label in CHECKS.items() if key not in hit and (sc.is_repo or key not in ("history", "gitignore", "authors"))]
    if clean:
        out += ["## 🟢 Clean", ""] + [f"- ✓ {c}" for c in clean] + [""]
    if sc.ignored_test_creds:
        out += [f"_Ignored {sc.ignored_test_creds} made-up password(s) in test/example/docs files (that's fine)._", ""]
    if sc.ignored_by_file:
        out += [f"_Skipped {sc.ignored_by_file} finding(s) in paths listed in `.pushguardignore` ({', '.join(sc.ignore_globs)})._", ""]
    for note in sc.notes:
        out += [f"_Note: {note}_", ""]
    v, _ = verdict(fs)
    out += [f"## Verdict: {v}", ""]
    out.append("_push-guard only reads files. It didn't change, delete or commit anything._")
    return "\n".join(out)


def render_json(sc: Scanner) -> str:
    v, code = verdict(sc.findings)
    return json.dumps({
        "tool": "push-guard", "version": VERSION,
        "project": os.path.basename(sc.toplevel if sc.is_repo else sc.root),
        "is_git_repo": sc.is_repo, "has_remote": sc.has_remote, "gitleaks": sc.gitleaks,
        "stats": sc.stats, "verdict": v, "exit_code": code,
        "ignored_test_credentials": sc.ignored_test_creds, "ignored_by_pushguardignore": sc.ignored_by_file,
        "pushguardignore": sc.ignore_globs, "notes": sc.notes,
        "findings": [asdict(f) for f in sc.findings],
    }, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------------------
# Hook mode
# --------------------------------------------------------------------------------------

ZERO = re.compile(r"^0+$")


def hook_revs_from_stdin(root: str) -> List[str]:
    revs: List[str] = []
    data = "" if sys.stdin is None or sys.stdin.isatty() else sys.stdin.read()
    for ln in data.splitlines():
        parts = ln.split()
        if len(parts) != 4:
            continue
        _lref, lsha, _rref, rsha = parts
        if ZERO.match(lsha):
            continue  # deleting a branch: nothing new is pushed
        if ZERO.match(rsha):
            revs += [lsha, "--not", "--remotes"]
        else:
            revs += [f"{rsha}..{lsha}"]
    if not revs:
        revs = ["HEAD", "--not", "--remotes"]
    return revs


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="push-guard: check before you push (read-only).")
    ap.add_argument("path", nargs="?", default=".", help="project folder (default: current folder)")
    ap.add_argument("--format", choices=("markdown", "json"), default="markdown")
    ap.add_argument("--no-history", action="store_true", help="skip the git history scan")
    ap.add_argument("--max-commits", type=int, default=2000)
    ap.add_argument("--no-gitleaks", action="store_true", help="don't use gitleaks even if installed")
    ap.add_argument("--hook", action="store_true", help="pre-push hook mode")
    ap.add_argument("--remote", default="", help=argparse.SUPPRESS)
    ap.add_argument("--version", action="version", version=f"push-guard {VERSION}")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.path):
        print(f"push-guard: folder not found: {args.path}", file=sys.stderr)
        return 2

    if args.hook:
        sc = Scanner(args.path, history=True, max_commits=args.max_commits, use_gitleaks=False,
                     hook_revs=hook_revs_from_stdin(args.path))
        sc.scan()
        blocking = [f for f in sc.findings if f.severity == "red" and f.check in BLOCKING_CHECKS]
        if not blocking:
            return 0
        print("\n🛑 push-guard blocked this push: a secret is in the commits you're pushing.\n", file=sys.stderr)
        for f in blocking:
            print(f"  🔴 {f.title}: {f.file} (commit {f.commit}) {f.preview}", file=sys.stderr)
        print("\nWhat to do:", file=sys.stderr)
        print("  1. Remove the secret and rewrite the commit (it isn't pushed yet, so that's safe).", file=sys.stderr)
        print("     Ask Claude: \"push-guard blocked my push, help me fix it\".", file=sys.stderr)
        print("  2. If it's a false alarm, add `pushguard:ignore` to that line or the path to .pushguardignore.", file=sys.stderr)
        print("  3. To push anyway (not recommended): git push --no-verify\n", file=sys.stderr)
        return 1

    sc = Scanner(args.path, history=not args.no_history, max_commits=args.max_commits, use_gitleaks=not args.no_gitleaks)
    sc.scan()
    print(render_json(sc) if args.format == "json" else render_markdown(sc))
    return verdict(sc.findings)[1]


if __name__ == "__main__":
    sys.exit(main())
