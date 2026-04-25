<div align="center">

```
  ███╗   ██╗██╗   ██╗██╗  ██╗ ██████╗ ██████╗  █████╗
  ████╗  ██║╚██╗ ██╔╝╚██╗██╔╝██╔═══██╗██╔══██╗██╔══██╗
  ██╔██╗ ██║ ╚████╔╝  ╚███╔╝ ██║   ██║██████╔╝███████║
  ██║╚██╗██║  ╚██╔╝   ██╔██╗ ██║   ██║██╔══██╗██╔══██║
  ██║ ╚████║   ██║   ██╔╝ ██╗╚██████╔╝██║  ██║██║  ██║
  ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

**v3.1 · Zero-Dependency Bug Bounty Recon Framework**

[![Bash](https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-blue)](#requirements)
[![Version](https://img.shields.io/badge/Version-3.1.0-red)](https://github.com/thivyas111-pixel/nyxora)

*curl · bash · awk · grep*

</div>

---

## Overview

**Nyxora** is a fully self-contained bug bounty recon framework written in pure Bash. It performs comprehensive reconnaissance on a target domain — from subdomain discovery through active vulnerability scanning — using only tools that ship with every standard Linux system. No Python, no Go binaries, no pip packages: just `curl`, `bash`, `awk`, `grep`, `sort`, `sed`, `tr`, `wc`, and `md5sum`.

v3.1 adds **authenticated scanning** via `--cookie` and `--header` flags, meaning every probe function now carries your session credentials — unlocking targets behind login walls. It also tightens XSS detection with a second-request confirmation probe and HTML comment context gate to cut false positives.

---

## Installation

```bash
git clone https://github.com/thivyas111-pixel/nyxora.git
cd nyxora
```

No `chmod`, no build step. Run directly with bash:

```bash
bash nyxora.sh <domain> [options]
```

---

## Quick Start

```bash
# Basic scan
bash nyxora.sh example.com

# Deep scan
bash nyxora.sh example.com --deep

# Authenticated — session cookie
bash nyxora.sh example.com --cookie "session=abc123; csrf=xyz789"

# Authenticated — Bearer token
bash nyxora.sh example.com --header "Authorization: Bearer eyJhbGci..."

# Authenticated — cookie + multiple headers
bash nyxora.sh example.com \
  --cookie "session=abc123" \
  --header "Authorization: Bearer TOKEN" \
  --header "X-API-Key: mykey"

# Throttled scan, 200ms between requests per worker
bash nyxora.sh example.com --rate-limit 200

# OOB SSRF confirmation
bash nyxora.sh example.com --oob your.burpcollaborator.net

# Custom output dir, 30 threads, 8s timeout
bash nyxora.sh example.com --out /tmp/recon/example --threads 30 --timeout 8

# Scoped — only test subdomains listed in file
bash nyxora.sh example.com --scope-file in_scope.txt

# Skip HTML report for faster results
bash nyxora.sh example.com --no-report
```

> **Getting your session cookie:** open browser DevTools → Network tab → click any authenticated request → copy the full value of the `Cookie:` request header.

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--deep` | off | More subdomain sources, crawl depth 3 |
| `--out <dir>` | `~/nyxora-<domain>-<ts>` | Custom output directory |
| `--no-report` | off | Skip HTML report generation |
| `--threads <n>` | `20` | Parallel worker count |
| `--timeout <n>` | `6` | Per-request timeout in seconds |
| `--rate-limit <ms>` | `0` | Sleep (ms) between requests per worker |
| `--scope-file <file>` | none | Only test subdomains listed in file (one per line) |
| `--oob <host>` | none | OOB callback host for blind SSRF probes |
| `--cookie <string>` | none | Session cookie(s) for authenticated scanning |
| `--header <string>` | none | Extra auth header — repeat once per header |
| `--help` | — | Show usage and exit |

---

## Features

### Reconnaissance

- **Subdomain Enumeration** — 12 passive sources in standard mode: crt.sh, AlienVault OTX, HackerTarget, URLScan, Wayback Machine, ThreatCrowd, SecurityTrails, ThreatMiner, DNSBufferOver, Riddler, RapidDNS, Anubis DB. Deep mode adds Certspotter, TLS BufferOver, SonarSearch, SynapsInt, and extended Wayback + crt.sh queries.
- **DNS Resolution & Wildcard Pruning** — 4-probe consensus with body-hash comparison. Falls back to `dig`/`host` when HTTP resolution returns nothing.
- **HTTP Probing** — Status codes, page size gating, 404-canary validation, technology fingerprinting (PHP, ASP.NET, Nginx, Apache, WordPress, Drupal, Joomla, Cloudflare, AWS, GCP, Azure, Fastly, Sucuri, Lighttpd, Tomcat, IIS).
- **URL Crawling** — Recursive depth-2/3 crawler across all live hosts combined with Wayback Machine passive URLs. Filters out static assets automatically.

### Vulnerability Scanning

All 17 probe functions carry your `--cookie` / `--header` credentials on every request.

- **JS Secret Scanner** — 30 patterns: AWS, Google, Firebase, Slack, GitHub, Stripe, Twilio, Heroku, SendGrid, Mailchimp, Mailgun, PayPal/Braintree, Square, DigitalOcean, Shopify, Okta, JWT, private keys, generic secrets. Skips CDN/analytics noise.
- **Subdomain Takeover** — 35 service fingerprints (Heroku, GitHub Pages, Azure, Fastly, Shopify, AWS S3, Tumblr, Bitbucket, Ghost, Netlify, Vercel, Webflow, Zendesk, Intercom, Surge, Cargo, Ngrok, WP Engine, Wix, UserVoice, GitLab Pages, Pantheon, AgileCRM, ReadMe.io, and more) plus CNAME-dangling detection.
- **Security Header Audit** — Missing HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, Permissions-Policy, COOP. Insecure cookie flags. Server version disclosure.
- **CORS Misconfiguration** — Wildcard, reflected origin, null-origin, and credential-leaking CORS. Standard + pre-flight OPTIONS probes.
- **XSS Detection** — Random-byte canary, three encoding gates (HTML entities, URL, Unicode), HTML comment context gate, second-request confirmation probe (eliminates non-deterministic reflections), context classification (`html` / `attr` / `script`), CSP nonce/hash confidence downgrade.
- **SQL Injection** — 8 payloads, 20 error signatures across MySQL, PostgreSQL, Oracle, SQLite, MSSQL, JDBC, PDO, ActiveRecord. WAF pre-detection to skip blocked targets.
- **LFI / Path Traversal** — 8 payloads including null-byte, double-encoding, `php://filter`. Pre-filtered to file/path/template/include parameters.
- **Host Header Injection** — 7 injection headers. Body reflection and redirect-chain confirmation.
- **Open Redirect** — Keyword-filtered parameters, three payload schemes (`https://`, `http://`, `//`), follows up to 5 hops.
- **SSRF Detection** — 25+ parameter keywords, OOB-confirmed mode with redirect-chain following.
- **IDOR Detection** — Baseline size gate, numeric probes (0/1/2/100/9999999), UUID probes, confidence scoring (MEDIUM/HIGH), semantic parameter name boosting.
- **GraphQL Discovery** — 14 common paths, introspection schema detection.
- **HTTP Method Enumeration** — OPTIONS `Allow` header analysis, active PUT/DELETE/PATCH/TRACE probes, TRACE XST canary confirmation.
- **API Version Probing** — 18 patterns: `/v1/`–`/v4/`, `/api/`, `/rest/`, `/internal/`, `/private/`, `/admin/api/`, `/rpc/`, `/jsonrpc/`.
- **Cache Poisoning Hints** — Header reflection and `X-Forwarded-Scheme` status-change probes.
- **Behavior Diffing** — 4-probe differential analysis with md5 hashing and size-spread gate to surface truly dynamic parameters.

### Reporting

| Format | Path | Description |
|--------|------|-------------|
| **HTML** | `final/report.html` | Interactive, filterable, paginated tables with severity badges |
| **Markdown** | `final/report.md` | For GitHub / Notion / Obsidian |
| **Text** | `final/report.txt` | Plain-text summary, pipeable |
| **JSON** | `logs/stats.json` | Machine-readable stats for CI/CD |

---

## Requirements

Verified at startup — all ship with every standard Linux distribution:

| Tool | Purpose |
|------|---------|
| `curl` | All HTTP requests |
| `bash` | Script runtime (≥ 4.0) |
| `awk` | Text processing |
| `grep` | Pattern matching |
| `sort` | Deduplication |
| `sed` | Stream editing |
| `tr` | Character translation |
| `wc` | Line/byte counting |
| `md5sum` | Body hashing for wildcard detection |

Optional (used when available): `dig`, `host`, `bc`

---

## Output Structure

```
~/nyxora-<domain>-<YYYYMMDD-HHMM>/
├── subs/
│   ├── raw.txt                   # All discovered subdomains
│   ├── resolved.txt              # DNS-resolved, wildcard-filtered
│   └── wildcard_ips.txt          # Detected wildcard IPs
├── http/
│   ├── live.txt                  # Live HTTP/HTTPS hosts
│   └── probe_full.txt            # Status, size, title, tech per host
├── crawl/
│   ├── crawled_urls.txt          # All crawled URLs
│   ├── urls_with_params.txt      # URLs with query parameters
│   └── params_normalized.txt     # FUZZ-substituted param patterns
├── engine/
│   ├── secrets/findings.txt      # JS secret matches
│   ├── takeover/candidates.txt   # Takeover fingerprint matches
│   ├── headers/
│   │   ├── cors_issues.txt       # CORS misconfigurations
│   │   └── missing_headers.txt   # Missing security headers
│   ├── reflection/
│   │   ├── xss_candidates.txt    # XSS with ctx + confidence
│   │   ├── sqli_candidates.txt   # SQLi error-based
│   │   └── ssrf_candidates.txt   # SSRF pattern matches
│   ├── behavior/
│   │   ├── idor.txt              # IDOR with confidence score
│   │   ├── open_redirects.txt
│   │   └── api_endpoints.txt
│   ├── lfi/candidates.txt
│   ├── hostinj/findings.txt
│   ├── graphql/endpoints.txt     # With introspection status
│   ├── methods/findings.txt
│   ├── cache/hints.txt
│   └── diff/dynamic.txt          # Dynamic parameter URLs
├── final/
│   ├── report.html
│   ├── report.md
│   └── report.txt
└── logs/
    ├── run.log
    └── stats.json
```

---

## Severity Classification

| Severity | Findings |
|----------|---------|
| 🔴 **CRITICAL** | JS Secrets, Subdomain Takeover, CORS credential leak, IDOR |
| 🟠 **HIGH** | XSS, SQLi, LFI, Host Header Injection, CORS wildcard/reflected |
| 🟡 **MEDIUM** | GraphQL endpoints, HTTP method issues, Cache hints, Open redirects, SSRF |
| 🔵 **INFO** | API version endpoints, missing headers, server disclosure |

---

## Changelog

### v3.1.0
- **ADD** `--cookie` flag: session cookie for authenticated scanning
- **ADD** `--header` flag: arbitrary auth header, repeatable
- **ADD** `_acurl` helper: all 17 probe functions now carry auth on every request
- **ADD** `AUTH_HEADERS_FILE`: array serialized to temp file for correct subshell export
- **FIX** XSS: second-request confirmation probe eliminates non-deterministic reflections
- **FIX** XSS: HTML comment context gate — canary inside comments no longer flagged
- **FIX** XSS: context (`html`/`attr`/`script`) detected before confidence assignment
- **FIX** `_acurl` applied consistently across all probe functions: `_http_probe`, `_header_audit`, `_takeover_check`, `_js_scan`, `_graphql_probe`, `_method_check`, `_hostinj_check`, `_cache_hint`, `_api_version_probe`, `_baseline_check`, `_diff_check`, `_idor_check`, `_xss_check`, `_redirect_check`, `_sqli_check`, `_lfi_check`, `_ssrf_oob_probe`

### v3.0.0
- See script header for full v3.0 changelog (30+ fixes and additions over v2.0)

---

## Legal Notice

Nyxora is intended for use only on systems you own or have **explicit written permission** to test. Unauthorized use against third-party systems may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, or equivalent laws in your jurisdiction. Always operate within your bug bounty program scope.

---

---

<div align="center">
<sub>curl · bash · awk · grep </sub>
</div>
