# Nyxora

**Zero-Dependency Bug Bounty Reconnaissance Framework**

> Pure bash. No installs. No noise. Just findings.

---

## Overview

Nyxora is an **unauthenticated, external reconnaissance and vulnerability discovery framework** written entirely in bash. It requires no credentials, no session cookies, and no target-side access — it operates purely from the outside, the same way an attacker on the internet would.

It is designed as your **first pass before manual testing** — not a replacement for it.

### What kind of scan does it run?

| Property | Value |
|---|---|
| Authentication | None — fully unauthenticated |
| Perspective | External attacker (black-box) |
| Protocol | HTTP / HTTPS only |
| Interaction | Passive recon + active probing |
| Credentials sent | None |
| Target-side agent | None required |

### What Nyxora does

It maps the external attack surface of a domain end-to-end: discovering subdomains, fingerprinting live hosts, crawling URLs, extracting parameters, and then running automated detection passes against that surface. It is not a fuzzer and not a full scanner — it is a precision recon tool with lightweight detection logic layered on top.

In a single run it covers what normally takes several separate tools chained together: subdomain enumeration, HTTP probing, JS secret scanning, security header auditing, subdomain takeover fingerprinting, URL crawling, parameter normalization, and detection passes for IDOR, XSS, SQLi, open redirects, SSRF, and CORS misconfigurations — all with confidence scoring so you know what to look at first.

### What it finds

Nyxora operates on the **publicly reachable surface** — everything accessible without credentials. These vulnerability classes exist on both authenticated and unauthenticated surfaces; Nyxora catches them specifically on endpoints it can reach without logging in:

- Exposed subdomains and dangling DNS records
- Reflected XSS on public pages (search, login forms, error pages, contact forms)
- SQL error leakage on public endpoints (login forms, search boxes, listing pages)
- IDOR on public APIs that expose resources by ID without requiring a session
- Open redirects on pre-auth parameters (`?next=`, `?return=`, `?redirect_uri=`)
- SSRF on publicly accessible URL/webhook/callback parameters
- CORS misconfigurations on public APIs (origin reflection, wildcard + credentials)
- Missing security headers across all live hosts
- Hardcoded secrets in publicly served JavaScript files
- Subdomain takeover candidates (unclaimed cloud infrastructure)

### What it will not find

The limitation is not the vulnerability type — it is **reachability**. If an endpoint requires a valid session to respond, Nyxora never sees it, regardless of what vulnerability lives behind it.

- Any endpoint that returns 401/403 to unauthenticated requests — Nyxora moves on
- Authenticated IDOR (accessing another user's resources after login)
- Stored XSS (requires a session to submit the payload and trigger it)
- CSRF (requires an active session to be exploitable)
- Privilege escalation and account takeover flows
- Business logic flaws that depend on application state
- Vulnerabilities exclusively behind WAF rules that block anonymous traffic
- Chained vulnerabilities that require multiple authenticated steps

### Where it fits in your workflow

```
Nyxora  →  unauthenticated recon + surface mapping + quick wins
   ↓
Manual authenticated testing on surfaced endpoints
   ↓
Deep business logic and chained vulnerability review
```

Run Nyxora first. Let it map the surface, grab low-hanging fruit (exposed secrets, takeovers, unauthenticated reflections), and produce a prioritized shortlist. Then log in and do the work Nyxora cannot.

---

## Why Nyxora Exists

Most recon tools have a problem: they bury you in data without helping you find bugs.

You run a tool, get 10,000 URLs, 300 subdomains, and a pile of raw output — then you're left doing the actual work yourself: filtering, triaging, and manually testing every endpoint hoping something is exploitable.

On top of that, modern recon stacks require Go, Python, Docker, 15 different binaries, version conflicts, and a 30-minute setup ritual before you even scan a single domain.

**Nyxora was built to solve both problems.**

It uses only the tools already on your system — `bash`, `curl`, `awk`, `grep` — zero installs, zero configuration. And instead of dumping raw recon data on you, it runs automated detection logic to surface real vulnerability candidates: IDOR, XSS, SQLi, SSRF, open redirects, CORS misconfigurations, JS secrets, and subdomain takeovers — with confidence scoring, so you know exactly where to spend your time.

**Signal over noise. Real bugs over raw data. Minimal setup, maximum output.**

---

## What Makes Nyxora Different

| Other Tools | Nyxora |
|---|---|
| Require Go, Python, Docker | Pure bash — works on any Linux/macOS out of the box |
| Dump thousands of raw URLs | Smart normalization and pattern-based deduplication |
| No vulnerability logic | Active detection: IDOR, XSS, SQLi, SSRF, secrets, takeover |
| Binary yes/no findings | Confidence scoring: HIGH / MEDIUM / LOW on every finding |
| Silent false positives | Baseline comparison + encoding validation before flagging |
| Scope drift | `--scope-file` flag restricts scanning to in-scope hosts only |
| Generic text dumps | Structured HTML dashboard, Markdown report, and JSON stats |

---

## What It Actually Does

When you run `bash nyxora.sh target.com`, here is exactly what happens:

**Step 1 — Subdomain Enumeration**
Nyxora queries 6+ passive sources (crt.sh, AlienVault OTX, HackerTarget, RapidDNS, Wayback Machine, ThreatCrowd) and resolves which subdomains actually exist. Wildcard IPs are auto-detected and filtered so you don't chase phantom hosts.

**Step 2 — DNS Resolution & Wildcard Pruning**
Each discovered subdomain is resolved via HTTP and compared against the wildcard IP fingerprint. Only genuinely distinct, live hosts proceed to the next stage.

**Step 3 — HTTP Probing**
Live hosts are identified in parallel. Status codes, page titles, server headers, and tech stack are fingerprinted — including Apache, Nginx, IIS, WordPress, Drupal, Cloudflare, AWS, GCP, and Azure.

**Step 4 — Security Header Audit**
Every live host is tested for CORS misconfigurations (wildcard, origin reflection, credential leaks) and missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy). Cookie flags (Secure, HttpOnly, SameSite) are also checked.

**Step 5 — JS Secret Scanner**
JavaScript files are fetched and scanned for 12 secret patterns: AWS keys, Google API keys, Slack tokens, GitHub tokens, Stripe keys, Twilio SIDs, bearer tokens, private keys, Firebase configs, Heroku API keys, SendGrid keys, and Mailchimp credentials.

**Step 6 — Subdomain Takeover Fingerprinting**
All resolved subdomains are checked against known takeover signatures for Heroku, GitHub Pages, Azure, Fastly, Shopify, Bitbucket, Tumblr, and AWS S3.

**Step 7 — URL Discovery & Crawling**
Historical URLs from the Wayback Machine are pulled. Live pages are crawled for endpoints (configurable depth 1–3). JavaScript files are parsed for hidden API routes. All static assets are filtered out.

**Step 8 — Parameter Normalization**
Duplicate URL patterns are collapsed with `FUZZ` placeholders. Noise parameters (pagination, analytics, tracking, session tokens) are filtered. You test one URL per behavioral pattern, not a thousand near-identical ones.

**Step 9 — Baseline Validation**
Each normalized URL is probed to confirm it returns a live 200 response with real content. Image, video, and audio responses are dropped. JSON API endpoints are tracked in a separate file.

**Step 10 — Diff Engine**
Three distinct mutation probes are sent per URL and compared by MD5 hash and response size. Parameters where all three mutations produce different, non-trivial responses are flagged as genuinely dynamic.

**Step 11 — IDOR Detection**
Dynamic parameters are tested with ID swaps (1, 2, 100, 9999999). Parameters whose responses diverge in size and content are flagged. ID parameter name heuristics (`user_id`, `account`, `order_id`, etc.) boost confidence to HIGH automatically.

**Step 12 — XSS Reflection Detection**
A unique canary value is injected and the response checked for unencoded reflection in an HTML context. Entity-encoded reflections are discarded. X-XSS-Protection blocking headers are respected. Reflection context (html / attr / script) is recorded.

**Step 13 — Open Redirect Detection**
Only parameters matching known redirect patterns (`redirect=`, `next=`, `url=`, `goto=`, etc.) are tested. An external marker URL is injected and curl's effective URL is checked for follow-through.

**Step 14 — SQLi Error Heuristic**
A safe baseline request is sent first. If the baseline response already contains SQL error strings, the URL is skipped entirely. Injection payloads are then sent and compared against 14 database error patterns across MySQL, PostgreSQL, Oracle, SQLite, MSSQL, and Java JDBC.

**Step 15 — SSRF Detection**
Parameters matching known SSRF patterns (`url=`, `host=`, `fetch=`, `webhook=`, `callback=`, etc.) are collected. An optional `--oob` flag sends active OOB probes to a Burp Collaborator or interactsh URL.

**Reporting**
Results are written to structured output files with confidence labels. An interactive HTML dashboard, a Markdown summary, a plain-text report, and a JSON stats file are generated automatically.

**Total runtime:** 4–12 minutes depending on target size and scan mode.

---

## Features

### Recon
- Passive subdomain enumeration from 6 sources (9 in deep mode)
- DNS resolution with automatic wildcard IP pruning
- Parallel HTTP/HTTPS probing with status, title, size, and tech fingerprinting
- Tech detection: Apache, Nginx, IIS, PHP, ASP.NET, WordPress, Drupal, Cloudflare, AWS, GCP, Azure
- Wayback Machine historical URL extraction (up to 5,000 URLs)
- On-site crawling with configurable depth (2 standard, 3 deep mode)
- JavaScript endpoint extraction and API route discovery
- JSON API endpoint tracking in a dedicated output file
- Scope restriction via `--scope-file`

### Analysis
- Parameter normalization with noise filtering (analytics, pagination, session tokens)
- Pattern-based URL deduplication — one test per behavioral variant
- Baseline validation gate — only 200-responding, content-rich URLs proceed
- 3-probe diff engine for dynamic parameter identification

### Vulnerability Detection
- **IDOR** — ID swapping with response size and hash comparison; name heuristic boosts to HIGH
- **XSS** — Canary injection with HTML context detection and encoding validation gate
- **SQLi** — 5 payloads against 14 database error patterns; baseline comparison prevents FPs
- **SSRF** — URL/host/callback parameter identification; optional OOB active probe (`--oob`)
- **Open Redirects** — Pattern-matched parameters only; marker URL follow-through confirmation
- **CORS** — Origin reflection, wildcard, and credential leak detection
- **Security Headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, cookie flags
- **JS Secrets** — 12 pattern types: AWS, Google, Slack, GitHub, Stripe, Twilio, Bearer, Private Key, Firebase, Heroku, SendGrid, Mailchimp
- **Subdomain Takeover** — 8 service signatures: Heroku, GitHub Pages, Azure, Fastly, Shopify, Bitbucket, Tumblr, AWS S3
- **Confidence Scoring** — Every finding rated HIGH / MEDIUM / LOW based on evidence strength

### Reporting
- Interactive HTML dashboard (searchable, filterable, paginated, color-coded by severity)
- Markdown report (GitHub-ready, auto-generated per scan)
- Plain-text summary with severity grouping
- JSON stats file for CI/CD pipeline integration
- Structured, predictable output directory for easy scripting

---

## Best Targets & When to Use Nyxora

### Where Nyxora performs best

**Web applications with a broad external surface**
Large apps with many subdomains, multiple API endpoints, and JavaScript-heavy frontends give Nyxora the most to work with. More surface = more parameters = more detection opportunities.

**Bug bounty programs with wide scope**
Programs that allow `*.target.com` or list dozens of in-scope domains are ideal. Nyxora is built to handle breadth — run it across the full scope and let it surface the endpoints worth investigating manually.

**API-heavy targets**
Applications that expose REST or GraphQL APIs publicly (no auth required to reach the endpoints) are strong candidates. Nyxora tracks JSON API endpoints separately and runs all detection passes against them.

**Targets with known tech debt**
Older applications, acquired subsidiaries, legacy subdomains, and staging/dev environments tend to have weak headers, exposed secrets, dangling CNAMEs, and misconfigured CORS — exactly what Nyxora is built to catch.

**Targets running on cloud infrastructure**
AWS, GCP, and Azure deployments are fingerprinted automatically. Subdomain takeover via unclaimed S3 buckets, Heroku dynos, or Azure slots is one of Nyxora's most consistent high-value findings.

---

### Where bug hunters should use it

| Scenario | Use Nyxora? | Why |
|---|---|---|
| Starting recon on a new target | Yes | Full surface map in one run |
| Wide-scope `*.domain.com` programs | Yes | Built for breadth, handles many subdomains |
| Public APIs with no login required | Yes | Parameter detection runs without auth |
| Programs with VDP or new acquisitions | Yes | Legacy infra tends to have low-hanging fruit |
| Scheduled monitoring of known targets | Yes | CI/CD integration catches new exposure over time |
| Narrow single-page app with no subdomains | Limited | Less surface to enumerate, fewer parameters |
| Targets fully behind login walls | Limited | Only the pre-auth surface is visible |
| Mobile API backends (no web frontend) | Limited | No JS files or HTML to crawl |
| Internal / private network targets | No | Requires network access; Nyxora runs externally |

---

### Program types where Nyxora consistently finds bugs

**VDP (Vulnerability Disclosure Programs)**
Often have older, unmaintained infrastructure. JS secret exposure, subdomain takeover, and missing security headers are common findings that VDPs accept readily.

**Tech company programs with acquired domains**
Acquisitions often inherit poorly maintained subdomains, expired cloud resources, and hardcoded credentials in legacy JS bundles.

**Financial and fintech programs**
Tend to expose REST APIs publicly for partner integrations. CORS misconfigurations and SSRF on webhook/callback parameters are high-frequency findings.

**SaaS platforms with multi-tenant architecture**
IDOR candidates surface frequently on platforms where resources are referenced by numeric or sequential IDs in URL parameters.

---

### Best practice: pair Nyxora with manual testing

Nyxora is your first pass. It maps the surface, grabs quick wins, and hands you a prioritized list. Manual authenticated testing on the endpoints it surfaces is where the deeper bugs live.

```
Phase 1 — Nyxora (unauthenticated, ~5–12 min)
  → Subdomains, live hosts, parameters, quick vulnerability checks

Phase 2 — Manual review of Nyxora output (~30–60 min)
  → Validate findings, investigate IDOR/XSS/SQLi candidates

Phase 3 — Authenticated manual testing on surfaced endpoints
  → Business logic, auth bypass, chained vulnerabilities
```

---

## Who This Tool Is For

- **Bug bounty hunters** who want faster triage with fewer false positives
- **Penetration testers** who need a portable, zero-setup recon drop
- **Security researchers** who want real vulnerability signals, not raw URL lists
- **Beginners** who want serious automation without managing a complex toolchain
- **Anyone** who has wasted hours setting up Go environments just to run a single scan

---

## Quick Start

Run using bash (no chmod required in most cases)

```bash
git clone https://github.com/thivyas111-pixel/nyxora

cd nyxora

bash nyxora.sh target.com

# Deep scan (more sources, crawl depth 3)
bash nyxora.sh target.com --deep

# With OOB SSRF probe (Burp Collaborator, interactsh, etc.)
bash nyxora.sh target.com --oob your.interactsh.url

# Restrict to in-scope hosts
bash nyxora.sh target.com --scope-file scope.txt

# Custom threads and timeout
bash nyxora.sh target.com --threads 30 --timeout 8

# Save to custom output directory
bash nyxora.sh target.com --out ~/bounty/target
```

> **Note for contributors:** If you re-download the raw file manually instead of cloning, run `chmod +x nyxora.sh` once before use. The executable bit is stored in git and preserved for all cloners automatically.

---

## Options

| Flag | Description | Default |
|---|---|---|
| `--deep` | More passive sources, crawl depth 3, extended Wayback lookups | off |
| `--oob <url>` | Active SSRF probe with out-of-band callback URL | off |
| `--scope-file <file>` | Restrict scanning to in-scope hosts listed in file | off |
| `--out <dir>` | Custom output directory | `~/nyxora-{domain}-{timestamp}` |
| `--no-report` | Skip HTML report generation | off |
| `--threads <n>` | Parallel worker count | 20 |
| `--timeout <n>` | Per-request timeout in seconds | 6 |
| `--help`, `-h` | Show usage | — |

---

## Example Output

```
[nyxora] Target        : api.example.com
[nyxora] Mode          : deep | threads=20 | timeout=6s
[nyxora] Started       : 2025-04-20 14:30:11

[RECON]  Subdomains found    : 67
[RECON]  Live hosts          : 38
[RECON]  URLs crawled        : 3,891
[RECON]  Parameters found    : 156 unique patterns

[ENGINE] IDOR candidates
  HIGH   /api/v2/users/{id}/profile          param=user_id    (ID param heuristic match)
  HIGH   /account/orders/{id}                param=order_id   (numeric ID, direct object ref)

[ENGINE] XSS reflection
  HIGH   /search?q=FUZZ                      reflected in <title>, unencoded   [ctx:html]
  HIGH   /feedback?msg=FUZZ                  reflected in response body         [ctx:attr]

[ENGINE] SQLi candidates
  HIGH   /products?category=FUZZ             MySQL error pattern, baseline delta confirmed
                                              [payload: ']

[ENGINE] Open redirects
  MEDIUM /login?next=FUZZ                    302 redirect to injected marker URL

[ENGINE] SSRF candidates
  MEDIUM /fetch?url=FUZZ                     URL parameter matched; OOB probe sent

[ENGINE] JS secrets
  HIGH   /static/app.js                      [SECRET:AWS_ACCESS_KEY] AKIAxxxxxxxxxxxxxxxxx
  MEDIUM /static/config.js                   [SECRET:BEARER_TOKEN] Bearer eyJhbGci...

[ENGINE] Subdomain takeover
  HIGH   staging.example.com                 [TAKEOVER:AWS S3] nosuchbucket response

[ENGINE] CORS misconfiguration
  HIGH   api.example.com                     [CORS:REFLECTS_ORIGIN] + [CORS:CREDS_LEAK]

[ENGINE] Security headers
  INFO   app.example.com                     [MISSING:CSP] [MISSING:HSTS] [COOKIE:no-Secure]

[REPORT] HTML     → ~/nyxora-example.com-20250420-1430/final/report.html
[REPORT] Markdown → ~/nyxora-example.com-20250420-1430/final/report.md
[REPORT] TXT      → ~/nyxora-example.com-20250420-1430/final/report.txt

[nyxora] Completed in 11m 43s
```

---

## Output Structure

```
~/nyxora-example.com-20250420-1430/
├── subs/
│   ├── raw.txt                         # All discovered subdomains (deduplicated, cleaned)
│   ├── resolved.txt                    # DNS-resolved, wildcard-filtered subdomains
│   └── wildcard_ips.txt                # Detected wildcard IPs (filtered out)
├── http/
│   ├── live.txt                        # Live host URLs
│   └── probe_full.txt                  # Full probe output: URL, status, size, title, tech
├── crawl/
│   ├── crawled_urls.txt                # All discovered URLs (live crawl + Wayback)
│   ├── urls_with_params.txt            # Parameterized URLs only
│   └── params_normalized.txt           # Deduplicated FUZZ-normalized patterns
├── engine/
│   ├── diff/
│   │   └── dynamic.txt                 # Parameters confirmed as behaviorally dynamic
│   ├── behavior/
│   │   ├── idor.txt                    # CRITICAL — IDOR candidates with confidence score
│   │   └── open_redirects.txt          # MEDIUM — Confirmed open redirect endpoints
│   ├── reflection/
│   │   ├── xss_candidates.txt          # HIGH — XSS reflection points with context tag
│   │   ├── sqli_candidates.txt         # HIGH — SQLi error patterns with payload label
│   │   ├── ssrf_candidates.txt         # MEDIUM — SSRF-prone parameter URLs
│   │   └── ssrf_oob_log.txt            # OOB probe log (when --oob is used)
│   ├── headers/
│   │   ├── audit.txt                   # Full header audit results
│   │   ├── cors_issues.txt             # CORS misconfiguration findings
│   │   └── missing_headers.txt         # Missing / weak security header findings
│   ├── secrets/
│   │   ├── js_urls.txt                 # All JS file URLs discovered
│   │   └── findings.txt                # CRITICAL — Secret matches with source URL
│   ├── takeover/
│   │   └── candidates.txt              # CRITICAL — Takeover candidates with service label
│   ├── valid_params.txt                # Baseline-validated HTML parameter URLs
│   └── valid_params_json.txt           # Baseline-validated JSON API parameter URLs
├── final/
│   ├── report.html                     # Interactive HTML dashboard
│   ├── report.md                       # Markdown summary (GitHub-ready)
│   └── report.txt                      # Plain-text severity-grouped report
└── logs/
    ├── run.log                         # Full timestamped execution log
    └── stats.json                      # Pipeline statistics (CI/CD ready)
```

---

## Detection Engine Reference

### Diff Engine
Sends three distinct mutation probes per URL and compares MD5 hashes and response sizes. All three mutations must produce different responses — with a non-trivial size spread — before a parameter is flagged dynamic. Single-mutation tools produce far more false positives.

### IDOR Engine
Swaps parameter values to 1, 2, 100, and 9999999. If the first three responses diverge in hash and size, and the out-of-range value (9999999) returns significantly less content, the parameter is flagged. Parameter name heuristics (`id`, `user_id`, `account`, `order_id`, `invoice`, `ticket`, `record`, etc.) automatically elevate confidence to HIGH.

### XSS Engine
Injects a timestamped canary value and checks for unencoded reflection in an HTML content-type response. Entity-encoded or attribute-encoded reflections are discarded. X-XSS-Protection blocking headers are respected. Reflection context is recorded as `html`, `attr`, or `script`.

### SQLi Engine
Sends a safe baseline first. If the baseline response already contains any of 14 SQL error patterns (MySQL, PostgreSQL, Oracle, SQLite, MSSQL, JDBC), the URL is skipped. Five payloads are then tested: `'`, `1'--`, `1 AND 1=2--`, `"`, `1"--`. All payloads are URL-encoded before sending.

### SSRF Engine
Performs keyword matching on parameter names against a list of 20+ SSRF-prone names (`url`, `uri`, `host`, `src`, `file`, `resource`, `image`, `data`, `load`, `fetch`, `open`, `proxy`, `service`, `server`, `backend`, `endpoint`, `webhook`, `callback`, `api`, `target`, `link`, `redirect`, `location`). Optional `--oob` flag sends curl requests substituting the OOB callback URL for active DNS/HTTP confirmation.

### Header & CORS Engine
Sends requests with `Origin: https://evil.com` and inspects the response for CORS reflection. Checks for wildcard origin, origin reflection, and credential leak (reflected origin + `Access-Control-Allow-Credentials: true`). Also audits five missing header types and three cookie flag issues per host.

### JS Secret Engine
Downloads every JS file reachable from live hosts. Scans each file against 12 compiled regex patterns. Matches are truncated to 60 characters in output to avoid storing live credentials at full length.

### Takeover Engine
Fetches each resolved subdomain and checks for 8 service-specific body signatures. Returns with no finding if the HTTP status is 200 or 403, since those typically indicate the resource is still claimed.

---

## Performance

| Metric | Standard | Deep |
|---|---|---|
| Subdomains found | ~45 | ~67 |
| Live hosts | ~23 | ~38 |
| URLs crawled | ~1,200 | ~3,900 |
| Dynamic parameters | ~89 | ~156 |
| Runtime | ~4–5 min | ~11–13 min |

*Benchmarked on a 4-core system with a 100 Mbps connection, 20 threads, 6s timeout.*

### Scan Profiles

```bash
# Balanced (default)
bash nyxora.sh target.com --threads 20 --timeout 6

# Fast — high-resource environment
bash nyxora.sh target.com --threads 50 --timeout 5

# Stealth — low footprint
bash nyxora.sh target.com --threads 5 --timeout 15
```

---

## Workflow Integration

### Bug Bounty Workflow

```bash
# 1. Run recon
bash nyxora.sh target.com --deep

# 2. Review the HTML report
open ~/nyxora-target.com-*/final/report.html

# 3. Triage by severity — start critical
cat ~/nyxora-target.com-*/engine/secrets/findings.txt
cat ~/nyxora-target.com-*/engine/takeover/candidates.txt
cat ~/nyxora-target.com-*/engine/headers/cors_issues.txt
cat ~/nyxora-target.com-*/engine/behavior/idor.txt

# 4. Review high-severity findings
cat ~/nyxora-target.com-*/engine/reflection/xss_candidates.txt
cat ~/nyxora-target.com-*/engine/reflection/sqli_candidates.txt

# 5. Pipe parameterized URLs into manual tools
cat ~/nyxora-target.com-*/crawl/urls_with_params.txt | ffuf -w - ...

# 6. Use resolved subdomains for further recon
cat ~/nyxora-target.com-*/subs/resolved.txt | ...
```

---

## Requirements

Nyxora requires only tools that ship with every Linux and macOS system by default:

`bash` (v4.0+) · `curl` · `awk` · `grep` · `sort` · `sed` · `tr` · `wc` · `md5sum`

**Supported platforms:** Linux (all distributions) · macOS · WSL · Git Bash on Windows

Nyxora runs a dependency check on startup and reports any missing tool before doing anything else. On modern Linux and macOS, this check always passes.

---

## Troubleshooting

**Permission denied** *(only if you downloaded the raw file manually, not via git clone)*
```bash
chmod +x nyxora.sh 
bash nyxora.sh target.com
```

**No subdomains found**
```bash
bash nyxora.sh target.com --deep
```

**Timeout errors on slow targets**
```bash
bash nyxora.sh target.com --timeout 15 --threads 10
```

**Restrict to in-scope hosts only**
```bash
echo "api.target.com" > scope.txt
echo "app.target.com" >> scope.txt
bash nyxora.sh target.com --scope-file scope.txt
```

**Confirm SSRF findings with OOB**
```bash
bash nyxora.sh target.com --oob your.interactsh.url
```

---

## Philosophy

Most security tools optimize for coverage. Nyxora optimizes for precision.

A finding you have to manually verify is half a finding. A false positive you have to chase costs time you could spend on a real bug. Nyxora runs stricter validation gates at every stage — baseline comparison before injection, encoding checks before flagging reflection, heuristic name matching before assigning confidence — so that when something is labelled HIGH, it is worth opening.

The goal is not to scan everything. The goal is to find bugs.

---

## Responsible Use

Nyxora is for authorized security testing only.

- Use only on targets you have explicit permission to test
- Follow the rules of the bug bounty program you are participating in
- Respect rate limits and service terms of use
- Do not use for unauthorized access, data exfiltration, or service disruption

---

## License

Provided for educational and authorized security research purposes.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

---


