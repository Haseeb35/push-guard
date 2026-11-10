#!/usr/bin/env python3
"""Build a throwaway git repo for a push-guard test case.

    python make_repo.py <case-name> <destination-folder>

Every "secret" in these repos is FAKE. Keys are assembled at runtime from
pieces (and contain the word FAKE), so this file itself contains no
key-shaped strings and is safe to publish.
"""
import os
import random
import shutil
import subprocess
import sys

R = random.Random(35)
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def rnd(n, alphabet=ALNUM):
    return "".join(R.choice(alphabet) for _ in range(n))


def fake(prefix, n, alphabet=ALNUM):
    """prefix + 'FAKE' + random tail. Obviously fake, but shaped like the real thing."""
    return prefix + "FAKE" + rnd(n - 4, alphabet)


def at(user, domain):
    return user + "@" + domain


def git(dest, *args, date=None):
    env = dict(os.environ)
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date + "T10:00:00"
    subprocess.run(["git", *args], cwd=dest, check=True, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write(dest, rel, text, mode="w"):
    p = os.path.join(dest, rel)
    os.makedirs(os.path.dirname(p) or dest, exist_ok=True)
    if isinstance(text, bytes):
        with open(p, "wb") as fh:
            fh.write(text)
    else:
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)


def init(dest, name, email):
    os.makedirs(dest, exist_ok=True)
    git(dest, "init", "-q", "-b", "main")
    git(dest, "config", "user.name", name)
    git(dest, "config", "user.email", email)
    git(dest, "config", "core.autocrlf", "false")
    git(dest, "config", "commit.gpgsign", "false")


def commit(dest, msg, date):
    git(dest, "add", "-A")
    git(dest, "commit", "-q", "-m", msg, date=date)


def fake_private_key():
    body = "\n".join(rnd(70, ALNUM + "+/") for _ in range(6))
    kind = "OPENSSH PRIVATE KEY"
    return "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----\n"


# ----------------------------------------------------------------------------- cases

def case_node_app_env_and_history(dest):
    """Node app: tracked .env with live-looking keys, AWS key deleted but still in
    (already pushed) history, node_modules + log not ignored."""
    init(dest, "Sam Rivera", at("sam.rivera.codes", "gmail.com"))
    write(dest, "package.json", '{\n  "name": "quote-bot",\n  "version": "1.0.0",\n  "main": "src/server.js",\n'
                                '  "dependencies": { "express": "^4.19.2", "openai": "^4.52.0" }\n}\n')
    write(dest, ".gitignore", "dist/\n")
    write(dest, "README.md", "# quote-bot\n\nA tiny Express app that writes motivational quotes with OpenAI.\n")
    aws_id = "AKIA" + "FAKE" + rnd(12, UPPER)
    aws_secret = "FAKE" + rnd(36, ALNUM + "/+")
    write(dest, "config/aws.json", '{\n  "region": "us-east-1",\n  "accessKeyId": "%s",\n  "secretAccessKey": "%s",\n'
                                   '  "bucket": "quote-bot-uploads"\n}\n' % (aws_id, aws_secret))
    write(dest, "src/server.js", "const express = require('express');\nconst aws = require('../config/aws.json');\n"
                                 "const app = express();\napp.get('/', (req, res) => res.send('hi'));\napp.listen(3000);\n")
    commit(dest, "first version", "2026-09-01")
    os.remove(os.path.join(dest, "config/aws.json"))
    write(dest, "src/server.js", "const express = require('express');\nconst OpenAI = require('openai');\n"
                                 "const app = express();\nconst openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n"
                                 "app.get('/', async (req, res) => res.send('hi'));\napp.listen(process.env.PORT || 3000);\n")
    commit(dest, "remove aws config, add openai", "2026-09-03")
    # Simulate GitHub: push the first two commits to a local bare "origin"
    remote = dest.rstrip("/\\") + "-origin.git"
    if os.path.exists(remote):
        shutil.rmtree(remote)
    subprocess.run(["git", "init", "-q", "--bare", remote], check=True, stdout=subprocess.DEVNULL)
    git(dest, "remote", "add", "origin", remote)
    git(dest, "push", "-q", "origin", "main")
    # New, unpushed work: a committed .env
    pw = "FAKE" + rnd(14)
    write(dest, ".env", "PORT=3000\nOPENAI_API_KEY=%s\nSTRIPE_SECRET_KEY=%s\nDATABASE_URL=postgres://quotebot:%s@db-prod-01.internal:5432/quotes\n"
          % (fake("sk-proj-", 48, ALNUM + "_-"), fake("sk_" + "live_", 30), pw))
    write(dest, "src/billing.js", "const Stripe = require('stripe');\nconst stripe = Stripe(process.env.STRIPE_SECRET_KEY);\n"
                                  "module.exports = { charge: (amt) => stripe.paymentIntents.create({ amount: amt, currency: 'usd' }) };\n")
    commit(dest, "add billing", "2026-09-05")
    # Untracked, not ignored
    for n in ("express/index.js", "express/package.json", "openai/index.js", "stripe/index.js"):
        write(dest, "node_modules/" + n, "// dependency code\n")
    write(dest, "server.log", "2026-09-05 10:01:02 INFO listening on 3000\n2026-09-05 10:02:11 ERROR openai 401 for user "
          + at("sam.rivera.codes", "gmail.com") + "\n")


def case_python_test_context(dest):
    """Django-ish project: real-looking secrets in production settings, fake
    passwords in tests, placeholders in docs. Tests context judgement."""
    init(dest, "Lena Okafor", "1234567+lenaokafor@users.noreply.github.com")
    write(dest, ".gitignore", ".env\n.env.*\n!.env.example\n__pycache__/\n*.pyc\n.venv/\n*.log\n*.pem\n*.key\n.DS_Store\n")
    write(dest, "README.md", "# recipe-share\n\nShare recipes with friends.\n\n## Setup\n\nSee [docs/setup.md](docs/setup.md).\n")
    write(dest, "requirements.txt", "django==5.1\npsycopg[binary]==3.2\n")
    write(dest, ".env.example", "SECRET_KEY=\nDATABASE_PASSWORD=\nOPENAI_API_KEY=\n")
    write(dest, "recipes/settings/base.py", "import os\n\nINSTALLED_APPS = ['recipes']\nSECRET_KEY = os.environ['SECRET_KEY']\n"
                                           "DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql', 'NAME': 'recipes',\n"
                                           "    'PASSWORD': os.environ.get('DATABASE_PASSWORD')}}\n")
    django_key = "django-insecure-" + "FAKE" + rnd(46, ALNUM + "!@#%^&*(-_=+)")
    db_pw = "Rcp" + "FAKE" + rnd(10) + "!"
    write(dest, "recipes/settings/production.py",
          "from .base import *  # noqa\n\nDEBUG = False\nALLOWED_HOSTS = ['recipeshare.app']\n"
          "SECRET_KEY = \"%s\"\nDATABASES['default']['HOST'] = 'db.recipeshare.app'\nDATABASE_PASSWORD = \"%s\"\n"
          "DATABASES['default']['PASSWORD'] = DATABASE_PASSWORD\n" % (django_key, db_pw))
    write(dest, "recipes/ai.py", "import os\nfrom openai import OpenAI\n\nclient = OpenAI(api_key=os.environ['OPENAI_API_KEY'])\n")
    write(dest, "tests/test_auth.py",
          "from django.test import TestCase\n\n\nclass LoginTests(TestCase):\n    def setUp(self):\n"
          "        self.password = \"hunter2-test-only\"\n        self.api_key = \"test-key-not-real-123\"\n"
          "        self.user = User.objects.create_user('alice', password=self.password)\n\n"
          "    def test_login(self):\n        self.assertTrue(self.client.login(username='alice', password='correct-horse-battery'))\n")
    write(dest, "tests/fixtures/users.json", '[{"username": "alice", "email": "%s", "password": "fixture-pass-1"}]\n'
          % at("alice", "example.com"))
    write(dest, "docs/setup.md", "# Setup\n\n```bash\nexport OPENAI_API_KEY=\"sk-your-key-here\"\nexport DATABASE_PASSWORD=\"<your-db-password>\"\n```\n")
    commit(dest, "initial commit", "2026-10-01")
    commit_extra = "recipes/views.py"
    write(dest, commit_extra, "from django.http import HttpResponse\n\n\ndef home(request):\n    return HttpResponse('recipes')\n")
    commit(dest, "add home view", "2026-10-02")


def case_personal_and_company_info(dest):
    """Analytics project: personal paths, a fixture with real-looking customer data,
    internal hostnames and server IPs, an untracked SSH key, a zip, personal commit email."""
    init(dest, "Zara Ahmed", at("zara.ahmed.dev", "gmail.com"))
    write(dest, ".gitignore", "__pycache__/\n")
    write(dest, "README.md", "# churn-analysis\n\nChurn model for our retail client.\n")
    write(dest, "analysis/load_data.py",
          "import pandas as pd\n\nDATA_DIR = r\"C:\\Users\\zara.ahmed\\OneDrive - Northwind\\clients\\retail\\exports\"\n\n"
          "def load():\n    return pd.read_csv(DATA_DIR + r\"\\customers_2026.csv\")\n")
    people = [("Bilal Hussain", "bilal.hussain92", "gmail.com", "+92 300 4417820"),
              ("Maria Lopez", "maria.lopez.home", "yahoo.com", "+1 415 867 2231"),
              ("Tom Becker", "t.becker", "outlook.com", "+49 151 2345 6789"),
              ("Aiko Tanaka", "aiko.t", "gmail.com", "+81 90 1234 5678"),
              ("Omar Farouk", "ofarouk", "hotmail.com", "+44 7700 912345"),
              ("Priya Nair", "priya.nair.85", "gmail.com", "+91 98450 12345"),
              ("Lucas Silva", "lucas.silva", "proton.me", "+55 11 98765 4321")]
    rows = ["customer_id,name,email,phone,lifetime_value"]
    for i, (n, u, d, ph) in enumerate(people, 1):
        rows.append("%d,%s,%s,%s,%d" % (1000 + i, n, at(u, d), ph, 120 * i))
    write(dest, "tests/fixtures/customers_sample.csv", "\n".join(rows) + "\n")
    write(dest, "config/deploy.yml",
          "app: churn-api\nserver: 10.20.30.41\nreplica: 52.14.88.203\n"
          "tickets: https://jira.northwind-internal.corp/browse/DATA-412\n"
          "dashboard: https://grafana.northwind.internal/d/churn\n")
    write(dest, "model/train.py", "import json\n\nwith open('/home/zara/models/params.json') as f:\n    PARAMS = json.load(f)\n")
    commit(dest, "churn analysis v1", "2026-08-20")
    # Untracked, not ignored
    write(dest, "id_rsa", fake_private_key())
    write(dest, "model_backup.zip", b"PK\x03\x04" + bytes(R.randrange(256) for _ in range(2048)))


def case_clean_repo(dest):
    """Well-kept small project. A good scanner should NOT cry wolf here."""
    init(dest, "Lena Okafor", "1234567+lenaokafor@users.noreply.github.com")
    write(dest, ".gitignore", ".env\n.env.*\n!.env.example\n__pycache__/\n*.pyc\n.venv/\nvenv/\n*.log\n*.pem\n*.key\n.DS_Store\nnode_modules/\ndist/\n")
    write(dest, "README.md", "# weather-cli\n\nPrint today's weather.\n\n```bash\ncp .env.example .env   # then add your key\npython -m weather Lahore\n```\n\n"
                             "Questions? Open an issue or email " + at("support", "example.com") + ".\n")
    write(dest, "LICENSE", "MIT License\n\nCopyright (c) 2026 Lena Okafor\n")
    write(dest, ".env.example", "WEATHER_API_KEY=your_api_key_here\n")
    write(dest, "weather/__main__.py", "import os\nimport sys\nimport urllib.request\n\nAPI_KEY = os.environ.get('WEATHER_API_KEY')\n"
                                       "BASE = 'https://api.weather.example.com/v1'\n\n\ndef main():\n    city = sys.argv[1]\n"
                                       "    url = f\"{BASE}/today?city={city}&key={API_KEY}\"\n    print(urllib.request.urlopen(url).read().decode())\n\n\n"
                                       "if __name__ == '__main__':\n    main()\n")
    write(dest, "tests/test_main.py", "def test_url():\n    api_key = \"dummy-test-key-123\"\n    assert api_key\n")
    commit(dest, "weather cli", "2026-10-10")
    write(dest, "weather/units.py", "def c_to_f(c):\n    return c * 9 / 5 + 32\n")
    commit(dest, "add unit conversion", "2026-10-11")


CASES = {
    "node-app-env-and-history": case_node_app_env_and_history,
    "python-test-context": case_python_test_context,
    "personal-and-company-info": case_personal_and_company_info,
    "clean-repo-no-false-alarms": case_clean_repo,
}

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in CASES:
        print("usage: make_repo.py <%s> <dest>" % "|".join(CASES))
        sys.exit(2)
    dest = os.path.abspath(sys.argv[2])
    if os.path.isdir(os.path.join(dest, ".git")):
        print("refusing: %s is already a git repo" % dest)
        sys.exit(1)
    CASES[sys.argv[1]](dest)
    print("built %s in %s" % (sys.argv[1], dest))
