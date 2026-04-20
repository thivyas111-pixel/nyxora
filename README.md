# PRECISE RECON v4

> **Maximum signal · Minimum false positives · Full HTML dashboard**

A battle-tested bug bounty recon framework focused on finding real, reportable vulnerabilities — not noise. Built for speed, precision, and a clean hacker workflow.

```
  ██████╗ ██████╗ ███████╗ ██████╗██╗███████╗███████╗
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝██╔════╝
  ██████╔╝██████╔╝█████╗  ██║     ██║███████╗█████╗
  ██╔═══╝ ██╔══██╗██╔══╝  ██║     ██║╚════██║██╔══╝
  ██║     ██║  ██║███████╗╚██████╗██║███████║███████╗
  ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝╚══════╝╚══════╝
          R E C O N   v 4 . 0
```

---

## Features

| Module | What it does |
|--------|-------------|
| **Subdomain Enumeration** | subfinder + assetfinder + crt.sh + OTX + HackerTarget + optional amass |
| **Wildcard Pruning** | Probes nonexistent subdomain, blocks IPs that resolve to wildcard catch-alls |
| **HTTP Probing** | httpx with status, title, tech-detect, redirect-follow |
| **URL Collection** | katana crawl + optional gau (deep mode) |
| **Diff Engine** | 3-probe hash+size delta strategy — confirms parameters that actually reflect state |
| **IDOR Detection** | Sequential ID probing (1/2/100/9999999) with consistent hash divergence gate |
| **XSS Reflection** | HTML/attr/script context canary — checks encoding, content-type, DOCTYPE |
| **SQLi Heuristic** | Error string detection with quote/comment payloads |
| **Open Redirect** | Interactsh-based redirect following with keyword filter |
| **SSRF Tagging** | URL/host param pattern matching for manual follow-up |
| **HTML Report** | Single-file dashboard with sidebar nav, paginated findings, copy-all |

---

## Requirements

### Required
```bash
subfinder      # go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
assetfinder    # go install github.com/tomnomnom/assetfinder@latest
dnsx           # go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
httpx          # go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
katana         # go install github.com/projectdiscovery/katana/cmd/katana@latest
curl sort awk grep md5sum wc   # standard UNIX tools
```

### Optional (enhances results)
```bash
parallel       # apt install parallel  /  brew install parallel
amass          # go install -v github.com/owasp-amass/amass/v4/...@master  (deep mode)
gau            # go install github.com/lc/gau/v2/cmd/gau@latest             (deep mode)
```

### Quick install (Go tools)
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

---

## Installation

```bash
git clone https://github.com/your-handle/precise-recon
cd precise-recon
chmod +x precise_recon.sh
```

---

## Usage

```bash
# Standard scan
./precise_recon.sh target.com

# Deep scan (amass + gau + deeper crawl)
./precise_recon.sh target.com --deep

# Custom output directory
./precise_recon.sh target.com --out /tmp/recon-target

# Tune threading
./precise_recon.sh target.com --threads-dns 80 --threads-http 40 --threads-curl 20

# Skip HTML report (faster, text only)
./precise_recon.sh target.com --no-report

# Show help
./precise_recon.sh --help
```

---

## Output Structure

```
~/recon-target.com-20240120-1430/
├── subs/
│   ├── raw.txt                  # All collected subdomains
│   ├── resolved_raw.txt         # dnsx output with IPs
│   ├── resolved.txt             # Wildcard-filtered hostnames
│   └── wildcard_ips.txt         # Blocked wildcard IPs
├── http/
│   ├── probe_full.txt           # Full httpx output (status, title, tech)
│   └── live.txt                 # Live host URLs only
├── crawl/
│   ├── katana.txt               # Raw crawled URLs
│   ├── urls_with_params.txt     # URLs with query parameters
│   └── params_normalized.txt   # Deduplicated FUZZ patterns
├── engine/
│   ├── valid_params.txt         # Passed baseline validation
│   ├── diff/
│   │   └── dynamic.txt          # Confirmed dynamic parameters
│   ├── behavior/
│   │   ├── idor.txt             # IDOR candidates
│   │   └── open_redirects.txt   # Open redirect candidates
│   └── reflection/
│       ├── xss_candidates.txt   # XSS candidates [ctx:html/attr/script]
│       ├── sqli_candidates.txt  # SQLi error heuristic
│       └── ssrf_candidates.txt  # SSRF-prone param patterns
├── final/
│   ├── report.html              # ← Open this in browser
│   └── report.txt               # Text summary
└── logs/
    ├── run.log                  # Full timestamped log
    └── stats.json               # Machine-readable stats
```

---

## HTML Report

Open `final/report.html` in any browser — no server needed, fully offline.

- **Dashboard** — stat cards, pipeline timeline, findings summary  
- **Per-category views** — paginated findings tables with copy-all  
- **Host browser** — live hosts with status codes and tech tags  
- **Subdomain & parameter lists** — filterable, searchable  

---

## False Positive Philosophy

Every detection engine has multiple gates before flagging a finding:

- **Diff Engine**: 3-probe strategy (A/B/C) — all three must hash differently AND agree on direction
- **IDOR**: Requires ≥2 of 3 hash diffs OR consistent size gap vs invalid ID
- **XSS**: Requires HTML content-type + DOCTYPE present + canary not entity-encoded
- **SQLi**: Matches known DB error strings, not generic server errors
- **Wildcard**: Probes a random nonexistent subdomain first, blocks matching IPs

---

## Ethical Use

This tool is intended for:
- Bug bounty programs where you have explicit scope permission
- Security testing on systems you own or are authorized to test
- Educational purposes in controlled lab environments

**Do not use against systems you don't have permission to test.**

---

## Changelog

**v4.0**
- Added SQLi error heuristic engine
- Added SSRF parameter tagging
- Added OTX + HackerTarget passive subdomain sources
- Full HTML dashboard report with sidebar navigation
- Colored terminal output
- Full CLI argument parser (--deep, --out, --threads-*, --no-report)
- Stats JSON output
- search/filter noise params extended

**v3.0** (original)
- Core diff/behavior/reflection engines
- Wildcard pruning
- Parallel/xargs dual-mode execution

---

## License

MIT — use freely, contribute back.
