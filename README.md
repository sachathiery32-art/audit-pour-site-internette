# AutoSecAudit

**Automated Security Assessment Tool** for web applications and infrastructure.

AutoSecAudit discovers the attack surface, runs a wide range of non-destructive
security checks, validates findings with controlled probes, and produces a
detailed report (HTML, JSON, Markdown) at the end.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> ⚠️ **Authorized testing only.** This tool is intended exclusively for systems
> you own or for which you have explicit written authorization to test. The
> tool refuses to scan without an explicit `YES` confirmation from the user.

## Quick start

Clone the repository (GitHub: **cameleonnbss**):

```bash
# Linux / macOS
git clone https://github.com/cameleonnbss/autosecaudit.git
cd autosecaudit
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 autosecaudit.py
```

```powershell
# Windows (PowerShell or cmd)
git clone https://github.com/cameleonnbss/autosecaudit.git
cd autosecaudit
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
py autosecaudit.py
```

Or simply double-click `run.bat` on Windows (it uses the `py` launcher and
falls back to `python`).

> Created by **cameleonnbss** (aka *camzzz*) —
> [github.com/cameleonnbss](https://github.com/cameleonnbss) — see
> [LICENSE](LICENSE) (MIT, 2026).

## Features

- **CLI interface** with interactive mode selection
- **Authorization gate** — refuses to run without explicit `YES` confirmation
- **Modular architecture** — 24+ detection module families
- **Site OSINT** — hosting provider, geolocation, ISP/ASN, registrar, domain age,
  expiration, nameservers, public emails (WHOIS/RDAP + mailto links on pages),
  **SPF/DKIM/DMARC/MX/CAA DNS records**, reverse DNS, first archived snapshot,
  protections
- **Full surface in reports** — every discovered page, API endpoint, URL parameter,
  subdomain and alive-subdomain detail is listed (HTML table + Markdown + JSON),
  plus a post-scan **Surface + OSINT viewer** in the menu
- **Red-team adaptive engine** — modules self-enable based on what discovery finds
- **Auto-exploitation pass** (`--exploit`) — confirms each HIGH/CRITICAL finding
  with a safe PoC (XSS, SQLi, open redirect, SSTI, cmd injection, exposed files...)
- **Controlled brute force** (`--brute-force`) — rate-limited password test on
  discovered login forms with a small wordlist (capped at 100 attempts)
- **Non-destructive payloads** — every test is designed to detect, never to destroy or modify data
- **Anti-false-positive** logic — SPA catch-all detection, baseline comparison,
  multiple checks, confidence scoring
- **Severity scoring** (CRITICAL / HIGH / MEDIUM / LOW / INFO) with CVSS mapping
- **CVE correlation** against a built-in knowledge base
- **Reports** in HTML (visual, with OSINT table), JSON (structured), and Markdown (readable)
- **Logging** with automatic secret redaction
- **Rate limiting**, timeouts, retries, caching, deduplication
- **Graceful CTRL+C** handling

## Architecture

```
autosecaudit/
├── autosecaudit.py          # main entry point / orchestrator
├── config/
│   └── __init__.py          # config loader (YAML -> ScanConfig)
├── modules/
│   ├── base.py              # abstract BaseModule
│   ├── http_client.py       # rate-limited, retrying HTTP client
│   ├── ui.py                # ANSI color console output
│   ├── logger.py            # secret-redacting logger
│   ├── discovery/           # DNS, HTTP, robots, sitemap, JS, forms, ports
│   ├── headers/             # security headers, TLS, cookies, methods
│   ├── injection/           # XSS, SQLi, NoSQLi, cmdi, LDAP, SSTI, XPath, traversal
│   ├── access_control/      # IDOR/BOLA, unauthenticated access, admin endpoints
│   ├── auth/                # CSRF, session, logout, fixation
│   ├── api/                 # OpenAPI, CORS, unauth endpoints, data exposure
│   ├── files/               # sensitive paths, dir listing, secrets
│   ├── infrastructure/      # ports, services, banners, TLS
│   ├── cve/                 # version-to-CVE correlation
│   └── reporting/           # HTML / JSON / Markdown generators
├── reports/                 # generated reports
├── logs/                    # scan logs (secrets auto-redacted)
├── wordlists/              # brute-force data (see below)
├── templates/
├── requirements.txt
├── config.yaml
└── run.bat
```

## Installation

```bash
# On Windows, use the py launcher (or python3 on macOS/Linux)
py -m pip install -r requirements.txt
```

## Usage

### Windows (double-click `run.bat`)

The `run.bat` file automatically uses the `py` launcher and falls back to
`python` if unavailable.

### Wordlists (brute force)

The brute-force pass loads passwords **French-first**, interleaving real
data with name+date generations:

| File | Content | Lines |
|------|---------|-------|
| `french_real_passwords.txt` | real leaked FR passwords (SecLists Language-Specific) | ~20k |
| `french_top.txt` | `Prénom+Année` / `Nom+Année` combos from real names | 10k |
| `french_good.txt` | medium-tier French name patterns | 30k |
| `french_combos.txt` / `french_master.txt` | full generated tiers | ~500k |
| `names_real.txt` / `last_names_real.txt` | real name pools (n0kovo, FR-filtered) | |
| `data/names/` | real n0kovo name lists (62k + 80k first, 297k last) | |
| `data/passwords/` | FR leaked lists, FR vocabulary, Top207/Top1575, usernames | |

Generation combines: real French names extracted from leaked passwords,
440k+ real n0kovo names (French-filtered), birth years 1940-2011, full dates,
capitals, leet, separators (`. _ - @`), email-style candidates
(`prenom.nom@orange.fr`), and initials — with an interleave that keeps
world-top passwords (`123456`, `password123`) inside the capped budget.

Regenerate anytime:

```bash
py wordlists/generate_french.py
py wordlists/generate_wordlists.py
```

### Auto-exploitation & brute force

```bash
# Confirm each HIGH/CRITICAL finding with a safe PoC
py autosecaudit.py https://example.com --mode deep --exploit --yes

# Also test login forms with a small wordlist (capped, rate-limited)
py autosecaudit.py https://example.com --mode deep --exploit --brute-force --yes
```

The auto-exploitation pass re-executes a safe proof-of-concept for each
HIGH/CRITICAL finding (markers only — no data modification), raises
confidence to 95%+ on confirmed ones, and labels them `[CONFIRMED]`.
Brute force is opt-in, capped at 100 attempts, rate-limited, and only
runs against login forms discovered in scope.

### Post-scan action menu

After a scan finishes, an interactive menu offers follow-up actions
(auto-enabled in a real terminal; skip with `--no-menu`):

```text
        POST-SCAN ACTION MENU
  ┌─ ATTACK OPTIONS ─────────────────────────────┐
  │ [1]  Targeted re-test      probe an endpoint │
  │      (XSS/SQLi/SSTI/CMDi/NoSQLi/traversal…) │
  │ [2]  Exploit pass          safe PoCs         │
  │ [3]  DDoS assessment       resilience check  │
  │ [4]  Credential test       capped, opt-in    │
  │ [5]  Full assault          all vectors, all  │
  │      endpoints (safe probes)                 │
  │ [6]  SSRF canary           URL-fetch check   │
  │ [7]  JWT analysis          token hardening    │
  │ [8]  CORS exploit check    origin reflection │
  │ [9]  Clickjacking PoC      frame test        │
  └──────────────────────────────────────────────┘
  ┌─ ANALYSIS ───────────────────────────────────┐
  │ [10] Findings details    evidence & fixes    │
  │ [11] Attack graph        visualization      │
  │ [12] Reports             open reports        │
  └──────────────────────────────────────────────┘
  [13] New scan             restart new target
  [14] Quit
```

Each attack action opens with its own ASCII art banner. Every action
stays within the safety policy: probes use harmless markers, brute
force is capped and rate-limited, and DDoS assessment only measures
resilience without attacking.

### Any platform

```bash
# Windows
py autosecaudit.py

# macOS / Linux
python3 autosecaudit.py
```

### With arguments

```bash
py autosecaudit.py https://example.com --mode standard
```

### Interactive flow

```
╔══════════════════════════════════════════════╗
║              AUTOSECAUDIT                    ║
║     Automated Security Assessment Tool       ║
╚══════════════════════════════════════════════╝

Target URL / IP : https://example.com

Scan mode:
  [1] Quick        — fastest, safest checks only
  [2] Standard     — balanced web checks
  [3] Deep         — thorough, all injection vectors
  [4] Infrastructure — ports & services on in-scope hosts
  [5] Full Audit   — every module
Choice: 2

AUTHORIZED TEST ONLY

I confirm that I have explicit permission to test this target.
Type YES to continue: YES
```

## Scan Modes

| Mode | Description |
|------|-------------|
| `quick` | Fastest — headers, TLS, cookies, robots, files only |
| `standard` | Balanced web checks including XSS, SQLi, traversal, CSRF, API |
| `deep` | All injection vectors including NoSQLi, cmdi, LDAP, SSTI, XPath |
| `infrastructure` | Ports, services, banners, TLS on in-scope hosts |
| `full` | Every module enabled |

## Configuration (`config.yaml`)

```yaml
target:
  url: "https://example.com"
  allowed_hosts: ["example.com", "www.example.com"]

scan:
  mode: standard
  threads: 5
  timeout: 10
  rate_limit: 2

modules:
  discovery: true
  headers: true
  xss: true
  # ...

safety:
  authorized_only: true
  destructive_tests: false
  brute_force: false
```

**Destructive options are disabled by default and cannot be toggled on accidentally.**

## Checks Performed

### Configuration
- HTTPS enforcement, TLS certificate validity & hostname match
- HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Cookie flags (Secure, HttpOnly, SameSite)
- Server / X-Powered-By banner disclosure
- Dangerous HTTP methods (PUT, DELETE, TRACE)
- Verbose error responses

### Injection (non-destructive)
- Reflected XSS, Stored XSS (read-only)
- SQL injection (error-based + boolean-based)
- NoSQL injection
- Command injection (echo marker)
- LDAP injection
- Server-Side Template Injection (SSTI)
- XPath injection
- Path traversal

### Access Control
- IDOR / BOLA via numeric ID manipulation
- Unauthenticated access to sensitive endpoints
- Exposed admin interfaces

### Auth & Sessions
- Missing CSRF tokens on POST forms
- Session cookie expiry behavior
- Logout via GET (CSRF-on-logout)
- Session fixation markers

### API
- Exposed OpenAPI/Swagger documentation
- Permissive CORS (origin reflection + credentials)
- Unauthenticated API endpoints
- Excessive data exposure (sensitive fields in JSON)
- Unexpected HTTP methods
- Mass-assignment risk indicators

### Files
- 30+ sensitive paths (.env, .git, backups, configs, logs)
- Directory listing
- Secret patterns in public responses (AWS keys, GitHub tokens, JWTs, private keys)

### Infrastructure
- Port scan (common ports) on in-scope hosts
- Service & version identification via banners
- Insecure/deprecated services (FTP, Telnet, Redis, etc.)
- TLS protocol & cipher suite validation

### Subdomains
- Enumeration via Certificate Transparency (crt.sh) + DNS wordlist
- Per-subdomain probing: HTTP/HTTPS reachability, server banner, technologies
- **Login page discovery** on each subdomain (the classic forgotten `login.example.com`)
- Admin / management surface detection
- Sensitive file checks (`/.env`, `/.git/config`), API docs exposure
- Missing security headers on every alive subdomain
- CNAME subdomain takeover fingerprints
- Results wired into the attack graph and the HTML/JSON/Markdown reports

### CVE
- Correlation against a built-in KB (Log4Shell, Spring4Shell, Struts, Joomla, etc.)
- Findings always marked as potential — manual verification required

## Reports

Generated in `reports/`:

- **HTML** — visual report with severity cards, bar chart, detailed findings
- **JSON** — fully structured for programmatic consumption
- **Markdown** — human-readable, version-control friendly

## Safety Guarantees

- ❌ No destructive payloads
- ❌ No data modification
- ❌ No brute force by default
- ❌ No mass file download
- ✅ Explicit authorization required
- ✅ Rate limiting & timeouts
- ✅ Secret redaction in logs
- ✅ CTRL+C graceful stop

## Testing

```bash
# Linux / macOS
python3 -m pytest tests/ -v

# Windows
py -m pytest tests/ -v
```

## License

MIT © 2026 **cameleonnbss** (camzzz) — see [LICENSE](LICENSE).

[![GitHub](https://img.shields.io/badge/GitHub-cameleonnbss-181717?logo=github)](https://github.com/cameleonnbss)

Use responsibly and only on systems you own or are authorized to test.
