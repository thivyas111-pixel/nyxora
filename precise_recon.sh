#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  PRECISE RECON v5  —  Zero-Dependency Bug Bounty Recon Framework
#  Requires ONLY: bash curl awk grep sort sed tr wc md5sum
#  All built-in to every Linux/macOS system. Nothing to install.
# ═══════════════════════════════════════════════════════════════════════

set -uo pipefail
IFS=$'\n\t'

# ── COLORS ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; DIM='\033[2m'
RESET='\033[0m'

# ── BANNER ─────────────────────────────────────────────────────────────
print_banner() {
cat << 'EOF'

  ██████╗ ██████╗ ███████╗ ██████╗██╗███████╗███████╗
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝██╔════╝
  ██████╔╝██████╔╝█████╗  ██║     ██║███████╗█████╗
  ██╔═══╝ ██╔══██╗██╔══╝  ██║     ██║╚════██║██╔══╝
  ██║     ██║  ██║███████╗╚██████╗██║███████║███████╗
  ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝╚══════╝╚══════╝
  R E C O N  v5  ·  Zero Dependency Edition

EOF
  echo -e "  ${DIM}curl · bash · awk · grep — that's it. Nothing to install.${RESET}"
  echo -e "  ${DIM}────────────────────────────────────────────────────────${RESET}"
  echo
}

usage() {
  echo -e "${BOLD}Usage:${RESET}  $0 <domain> [options]"
  echo
  echo -e "${BOLD}Options:${RESET}"
  echo "  --deep            Deeper crawl (more passive sources, depth 3)"
  echo "  --out <dir>       Custom output directory"
  echo "  --no-report       Skip HTML report generation"
  echo "  --threads <n>     Parallel workers (default: 20)"
  echo "  --timeout <n>     Per-request timeout seconds (default: 6)"
  echo "  --help            Show this help"
  echo
  echo -e "${BOLD}Requirements:${RESET} curl bash awk grep — nothing else"
  echo
  exit 0
}

# ── ARGS ───────────────────────────────────────────────────────────────
DOMAIN=""
DEEP_MODE=false
CUSTOM_OUT=""
SKIP_REPORT=false
THREADS=20
TIMEOUT=6

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deep)       DEEP_MODE=true; shift ;;
    --no-report)  SKIP_REPORT=true; shift ;;
    --out)        CUSTOM_OUT="$2"; shift 2 ;;
    --threads)    THREADS="$2"; shift 2 ;;
    --timeout)    TIMEOUT="$2"; shift 2 ;;
    --help|-h)    print_banner; usage ;;
    -*)           echo "Unknown option: $1"; exit 1 ;;
    *)            [[ -z "$DOMAIN" ]] && DOMAIN="$1" || { echo "Unexpected: $1"; exit 1; }; shift ;;
  esac
done

[[ -z "$DOMAIN" ]] && { print_banner; usage; }

# ── SANITY CHECK ───────────────────────────────────────────────────────
command -v curl &>/dev/null || { echo -e "${RED}[!] curl not found. Install curl and retry.${RESET}"; exit 1; }

# ── SETUP ──────────────────────────────────────────────────────────────
DOMAIN="${DOMAIN,,}"
DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"

START_TS=$(date +%s)
START_DATE=$(date '+%Y-%m-%d %H:%M:%S')

if [[ -n "$CUSTOM_OUT" ]]; then
  OUT="$CUSTOM_OUT"
else
  OUT="$HOME/recon-$DOMAIN-$(date +%Y%m%d-%H%M)"
fi

mkdir -p "$OUT"/{subs,http,crawl,engine/{diff,behavior,reflection},final,logs}

LOGFILE="$OUT/logs/run.log"
STATS_FILE="$OUT/logs/stats.json"

# ── LOGGING ────────────────────────────────────────────────────────────
log()  {
  local ts="[$(date +%T)]"
  echo -e "${CYAN}${ts}${RESET} ${GREEN}[+]${RESET} $*"
  echo "$ts [+] $*" >> "$LOGFILE"
}
warn() {
  local ts="[$(date +%T)]"
  echo -e "${CYAN}${ts}${RESET} ${ORANGE}[!]${RESET} $*"
  echo "$ts [!] $*" >> "$LOGFILE"
}
section() {
  echo
  echo -e "${BOLD}${BLUE}┌──────────────────────────────────────────────────┐${RESET}"
  echo -e "${BOLD}${BLUE}│  $*${RESET}"
  echo -e "${BOLD}${BLUE}└──────────────────────────────────────────────────┘${RESET}"
}
die()        { warn "$*"; exit 1; }
count_safe() { [[ -f "$1" ]] && wc -l < "$1" || echo "0"; }

# ── PURE BASH PARALLEL RUNNER ──────────────────────────────────────────
# Reads lines from stdin, fires $fn for each line with up to $n concurrent jobs
_parallel() {
  local n="$1"; shift
  local fn="$1"; shift
  local extra_args=("$@")
  local jobs=0
  local -a pids=()

  while IFS= read -r line; do
    "$fn" "$line" "${extra_args[@]}" &
    pids+=($!)
    jobs=$(( jobs + 1 ))
    if (( jobs >= n )); then
      wait "${pids[0]}" 2>/dev/null || true
      pids=("${pids[@]:1}")
      jobs=$(( jobs - 1 ))
    fi
  done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
}

# ── curl helpers ───────────────────────────────────────────────────────
_curl() {
  curl -skL \
    --max-time "$TIMEOUT" \
    --retry 1 --retry-delay 0 \
    --connect-timeout 4 \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
    "$@" 2>/dev/null
}

print_banner

# ════════════════════════════════════════════════════════════════════════
# STEP 0 — DEPENDENCY CHECK
# ════════════════════════════════════════════════════════════════════════
section "STEP 0 ─ Dependency Check (no install needed)"
ALL_OK=true
for tool in curl bash awk grep sort sed tr wc md5sum; do
  if command -v "$tool" &>/dev/null; then
    echo -e "  ${GREEN}✓${RESET} $tool"
  else
    echo -e "  ${RED}✗${RESET} $tool — MISSING"
    ALL_OK=false
  fi
done
$ALL_OK || die "Missing system tools above. These ship with every Linux distro — check your environment."
echo -e "\n  ${GREEN}${BOLD}All dependencies satisfied. Starting scan...${RESET}"

log "Target     : ${BOLD}$DOMAIN${RESET}"
log "Output dir : $OUT"
log "Deep mode  : $DEEP_MODE"
log "Threads    : $THREADS  Timeout: ${TIMEOUT}s"

# ════════════════════════════════════════════════════════════════════════
# STEP 1 — SUBDOMAIN ENUMERATION
# Sources: crt.sh · OTX · HackerTarget · RapidDNS · Wayback · ThreatCrowd
# All via pure curl — no subfinder / assetfinder needed
# ════════════════════════════════════════════════════════════════════════
section "STEP 1 ─ Subdomain Enumeration (pure curl, 6+ sources)"

touch "$OUT/subs/raw.txt"

log "crt.sh..."
_curl "https://crt.sh/?q=%25.$DOMAIN&output=json" \
  | grep -oP '"name_value":"\K[^"]+' \
  | tr ',' '\n' \
  | sed 's/^\*\.//' \
  >> "$OUT/subs/raw.txt" &

log "AlienVault OTX..."
_curl "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" \
  | grep -oP '"hostname":"\K[^"]+' \
  | grep "\.$DOMAIN$" \
  >> "$OUT/subs/raw.txt" &

log "HackerTarget..."
_curl "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" \
  | cut -d',' -f1 \
  | grep "\.$DOMAIN$" \
  >> "$OUT/subs/raw.txt" &

log "RapidDNS..."
_curl "https://rapiddns.io/subdomain/$DOMAIN?full=1&down=1" \
  | grep -oP '(?<=<td>)[a-z0-9._-]+\.'$DOMAIN'(?=</td>)' \
  >> "$OUT/subs/raw.txt" &

log "Wayback Machine..."
_curl "https://web.archive.org/cdx/search/cdx?url=*.$DOMAIN&output=text&fl=original&collapse=urlkey" \
  | grep -oP 'https?://\K[^/]+' \
  | grep "\.$DOMAIN$" \
  >> "$OUT/subs/raw.txt" &

log "ThreatCrowd..."
_curl "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$DOMAIN" \
  | grep -oP '"[a-z0-9._-]+\.'$DOMAIN'"' \
  | tr -d '"' \
  >> "$OUT/subs/raw.txt" &

if [[ "$DEEP_MODE" == true ]]; then
  log "Certspotter (deep)..."
  _curl "https://api.certspotter.com/v1/issuances?domain=$DOMAIN&include_subdomains=true&expand=dns_names" \
    | grep -oP '"[a-z0-9._-]+\.'$DOMAIN'"' | tr -d '"' >> "$OUT/subs/raw.txt" &

  log "URLScan (deep)..."
  _curl "https://urlscan.io/api/v1/search/?q=domain:$DOMAIN&size=100" \
    | grep -oP '"[a-z0-9._-]+\.'$DOMAIN'"' | tr -d '"' >> "$OUT/subs/raw.txt" &
fi

wait

# Deduplicate + validate
sort -u "$OUT/subs/raw.txt" 2>/dev/null \
  | tr '[:upper:]' '[:lower:]' \
  | grep -E "^[a-z0-9][a-z0-9._-]*\.$DOMAIN$" \
  | grep -v '\.\.' \
  | grep -v "^$DOMAIN$" \
  | sort -u > "$OUT/subs/raw_clean.txt"
mv "$OUT/subs/raw_clean.txt" "$OUT/subs/raw.txt"

log "Raw subdomains: $(count_safe "$OUT/subs/raw.txt")"

# ════════════════════════════════════════════════════════════════════════
# STEP 2 — DNS RESOLUTION + WILDCARD PRUNING (via curl, pure bash)
# ════════════════════════════════════════════════════════════════════════
section "STEP 2 ─ DNS Resolution + Wildcard Pruning"

# Probe a random nonexistent subdomain to detect wildcard IPs
RAND_SUB="nonexistent-pr5-$$-$(date +%s).$DOMAIN"
WILDCARD_IP=$(curl -sk --max-time 4 --connect-timeout 3 \
  -o /dev/null -w "%{remote_ip}" \
  "http://$RAND_SUB" 2>/dev/null || true)

if [[ -n "$WILDCARD_IP" && "$WILDCARD_IP" != "0.0.0.0" && "$WILDCARD_IP" != "" ]]; then
  warn "Wildcard IP detected: $WILDCARD_IP — will be filtered"
  echo "$WILDCARD_IP" > "$OUT/subs/wildcard_ips.txt"
else
  touch "$OUT/subs/wildcard_ips.txt"
  WILDCARD_IP=""
fi

export TIMEOUT WILDCARD_IP

_resolve_and_filter() {
  local host="$1"
  local ip
  ip=$(curl -sk --max-time 4 --connect-timeout 3 \
    -o /dev/null -w "%{remote_ip}" \
    "http://$host" 2>/dev/null || true)

  [[ -z "$ip" || "$ip" == "0.0.0.0" || "$ip" == "" ]] && return
  [[ -n "$WILDCARD_IP" && "$ip" == "$WILDCARD_IP" ]] && return
  echo "$host $ip"
}
export -f _resolve_and_filter

log "Resolving ${THREADS} at a time..."
cat "$OUT/subs/raw.txt" | _parallel "$THREADS" _resolve_and_filter \
  2>/dev/null \
  | sort -u > "$OUT/subs/resolved_raw.txt"

# Detect catch-all IPs (resolve to >8 different subdomains)
awk '{print $2}' "$OUT/subs/resolved_raw.txt" \
  | sort | uniq -c | sort -rn \
  | awk '$1 > 8 {print $2}' \
  >> "$OUT/subs/wildcard_ips.txt"
sort -u "$OUT/subs/wildcard_ips.txt" -o "$OUT/subs/wildcard_ips.txt"

if [[ -s "$OUT/subs/wildcard_ips.txt" ]] && grep -qE '^[0-9]' "$OUT/subs/wildcard_ips.txt" 2>/dev/null; then
  grep -vFf <(grep -E '^[0-9]' "$OUT/subs/wildcard_ips.txt") "$OUT/subs/resolved_raw.txt" \
    | awk '{print $1}' | sort -u > "$OUT/subs/resolved.txt"
else
  awk '{print $1}' "$OUT/subs/resolved_raw.txt" | sort -u > "$OUT/subs/resolved.txt"
fi

log "Resolved (wildcard-filtered): $(count_safe "$OUT/subs/resolved.txt")"

# ════════════════════════════════════════════════════════════════════════
# STEP 3 — HTTP PROBING (pure curl, parallel)
# Detects status, content-type, title, tech stack — no httpx needed
# ════════════════════════════════════════════════════════════════════════
section "STEP 3 ─ HTTP Probing (pure curl, tech detection)"

export TIMEOUT

_http_probe() {
  local host="$1"
  for scheme in https http; do
    local url="${scheme}://${host}"
    local raw status size title tech

    raw=$(curl -sk \
      --max-time "$TIMEOUT" --connect-timeout 4 \
      --retry 1 --retry-delay 0 \
      -L --max-redirs 3 \
      -D - \
      -w "\n__STATUS__%{http_code}__SIZE__%{size_download}" \
      -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
      "$url" 2>/dev/null) || continue

    status=$(echo "$raw" | grep -oP '__STATUS__\K[0-9]+' | tail -1)
    [[ -z "$status" || "$status" == "000" ]] && continue
    echo "$status" | grep -qE '^(200|201|301|302|307|401|403|500)$' || continue

    size=$(echo "$raw" | grep -oP '__SIZE__\K[0-9]+' | tail -1)
    [[ "${size:-0}" -lt 200 ]] && continue

    title=$(echo "$raw" | grep -oiP '(?<=<title>)[^<]+' | head -1 | tr -d '\r\n' | sed 's/  */ /g')
    title="${title:0:60}"

    tech=""
    echo "$raw" | grep -qi "x-powered-by: php"     && tech="${tech}[PHP]"
    echo "$raw" | grep -qi "x-powered-by: asp"     && tech="${tech}[ASP.NET]"
    echo "$raw" | grep -qi "server: nginx"          && tech="${tech}[nginx]"
    echo "$raw" | grep -qi "server: apache"         && tech="${tech}[Apache]"
    echo "$raw" | grep -qi "server: iis"            && tech="${tech}[IIS]"
    echo "$raw" | grep -qi "wp-content"             && tech="${tech}[WordPress]"
    echo "$raw" | grep -qi "drupal"                 && tech="${tech}[Drupal]"
    echo "$raw" | grep -qi "cf-ray:"                && tech="${tech}[Cloudflare]"
    echo "$raw" | grep -qi "x-amz-"                && tech="${tech}[AWS]"

    echo "${url} [${status}] [${size}b] ${title:+[$title]} ${tech}"
    echo "${url}" >> /tmp/pr5_live_$$
    return
  done
}
export -f _http_probe

cat "$OUT/subs/resolved.txt" | _parallel "$THREADS" _http_probe \
  2>/dev/null \
  | sort -u > "$OUT/http/probe_full.txt"

[[ -f /tmp/pr5_live_$$ ]] && sort -u /tmp/pr5_live_$$ > "$OUT/http/live.txt"
rm -f /tmp/pr5_live_$$

log "Live hosts: $(count_safe "$OUT/http/live.txt")"
[[ ! -s "$OUT/http/live.txt" ]] && die "No live hosts found. Check domain or connectivity."

# ════════════════════════════════════════════════════════════════════════
# STEP 4 — URL CRAWL (pure curl, HTML + JS link extraction)
# No katana / gau. Parses <a href>, <form action>, JS fetch/axios/XHR
# + Wayback Machine passive URL harvest
# ════════════════════════════════════════════════════════════════════════
section "STEP 4 ─ URL Crawl (pure curl, HTML/JS extraction + Wayback)"

CRAWL_DEPTH=2
[[ "$DEEP_MODE" == true ]] && CRAWL_DEPTH=3

export TIMEOUT DOMAIN CRAWL_DEPTH

_extract_urls() {
  local body="$1" base="$2"
  local base_origin
  base_origin=$(echo "$base" | grep -oP 'https?://[^/]+')
  echo "$body" \
    | grep -oP '(?<=href=["'"'"'])[^"'"'"'#?][^"'"'"']*|(?<=action=["'"'"'])[^"'"'"']+|(?<=src=["'"'"'])[^"'"'"']+\.js[^"'"'"']*' \
    | sed "s|^/|${base_origin}/|g" \
    | grep -E "^https?://" \
    | grep "$DOMAIN" \
    | grep -vE '\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf|mp4|mp3|pdf|zip|eot)(\?|$)' \
    | sed 's/#.*//' \
    | sort -u
}
export -f _extract_urls

_crawl_host() {
  local start="$1"
  local vis="/tmp/pr5_vis_$$_${RANDOM}"
  local q="/tmp/pr5_q_$$_${RANDOM}"
  local found="/tmp/pr5_f_$$_${RANDOM}"
  touch "$vis" "$q" "$found"
  echo "$start" > "$q"

  local depth=0
  while [[ -s "$q" && $depth -lt $CRAWL_DEPTH ]]; do
    local nq="/tmp/pr5_nq_$$_${RANDOM}"
    touch "$nq"
    while IFS= read -r url; do
      grep -qxF "$url" "$vis" && continue
      echo "$url" >> "$vis"
      local body
      body=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
        "$url" 2>/dev/null) || continue
      echo "$url" >> "$found"
      while IFS= read -r nu; do
        grep -qxF "$nu" "$vis" && continue
        echo "$nu" >> "$nq"
        echo "$nu" >> "$found"
      done < <(_extract_urls "$body" "$url")
    done < "$q"
    mv "$nq" "$q"
    depth=$(( depth + 1 ))
  done

  cat "$found"
  rm -f "$vis" "$q" "$found"
}
export -f _crawl_host

cat "$OUT/http/live.txt" | _parallel "$THREADS" _crawl_host \
  2>/dev/null \
  | sort -u > "$OUT/crawl/crawled_urls.txt"

# Passive URL harvest from Wayback
log "Wayback passive URL harvest..."
_curl "https://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=text&fl=original&collapse=urlkey&limit=5000" \
  | grep -E "^https?://" \
  | grep "$DOMAIN" \
  | grep -vE '\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf|mp4|mp3|pdf|zip|eot)(\?|$)' \
  >> "$OUT/crawl/crawled_urls.txt"

sort -u "$OUT/crawl/crawled_urls.txt" -o "$OUT/crawl/crawled_urls.txt"

# Parameterized subset
grep '=' "$OUT/crawl/crawled_urls.txt" \
  | grep -vE '\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf)(\?|$)' \
  | sort -u > "$OUT/crawl/urls_with_params.txt"

log "Crawled URLs: $(count_safe "$OUT/crawl/crawled_urls.txt")"
log "With params:  $(count_safe "$OUT/crawl/urls_with_params.txt")"

# ════════════════════════════════════════════════════════════════════════
# STEP 5 — PARAM NORMALIZATION + NOISE REDUCTION
# ════════════════════════════════════════════════════════════════════════
section "STEP 5 ─ Parameter Normalization + Noise Reduction"

NOISE='(page=|lang=|limit=|offset=|sort=|order=|locale=|currency=|ref=|utm_|_ga=|fbclid=|gclid=|tracking=|ver=|v=|rev=|nocache=|timestamp=|nonce=|csrf|_=|s=|search=|keyword=|token=|__cf|session=|debug=|cache=|_t=|format=|type=|style=|theme=|view=)'

sed 's/=[^&?#]*/=FUZZ/g; s/#.*//' "$OUT/crawl/urls_with_params.txt" \
  | sort -u \
  | grep -Evi "$NOISE" \
  > "$OUT/crawl/params_normalized.txt"

log "Normalized param patterns: $(count_safe "$OUT/crawl/params_normalized.txt")"

# ════════════════════════════════════════════════════════════════════════
# STEP 6 — BASELINE VALIDATION
# Only URLs returning 200 with real HTML body (>300b, not JSON/media)
# ════════════════════════════════════════════════════════════════════════
section "STEP 6 ─ Baseline Validation"

export TIMEOUT

_baseline_check() {
  local url="$1"
  local raw status ct size
  raw=$(curl -sk \
    --max-time "$TIMEOUT" --connect-timeout 4 \
    -w "\n__STATUS__%{http_code}__CT__%{content_type}__SIZE__%{size_download}" \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
    "$(echo "$url" | sed 's/FUZZ/baseline_pr5/g')" 2>/dev/null) || return

  status=$(echo "$raw" | grep -oP '__STATUS__\K[0-9]+')
  ct=$(echo "$raw"     | grep -oP '__CT__\K[^_]+')
  size=$(echo "$raw"   | grep -oP '__SIZE__\K[0-9]+')

  [[ "$status" != "200" ]]                  && return
  [[ "${size:-0}" -lt 300 ]]                && return
  echo "$ct" | grep -qi "application/json"  && return
  echo "$ct" | grep -qiE "image/|video/|audio/|font/" && return
  echo "$url"
}
export -f _baseline_check

if [[ -s "$OUT/crawl/params_normalized.txt" ]]; then
  cat "$OUT/crawl/params_normalized.txt" | _parallel "$THREADS" _baseline_check \
    2>/dev/null \
    | sort -u > "$OUT/engine/valid_params.txt"
  log "Valid params: $(count_safe "$OUT/engine/valid_params.txt")"
else
  touch "$OUT/engine/valid_params.txt"
  warn "No normalized params — detection engines will be skipped."
fi

# ════════════════════════════════════════════════════════════════════════
# STEP 7 — DIFF ENGINE (Dynamic Parameter Detection)
# 3-probe strategy: all three FUZZ values must produce distinct responses
# Size variance gate eliminates random/CDN noise
# ════════════════════════════════════════════════════════════════════════
section "STEP 7 ─ Diff Engine (Dynamic Param Detection)"

FUZZ_A="pr5xAa"; FUZZ_B="pr5xBb"; FUZZ_C="pr5xCc"
export FUZZ_A FUZZ_B FUZZ_C TIMEOUT

_diff_check() {
  local url="$1"
  local b0 b1 b2 b3
  b0=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" "$url" 2>/dev/null)
  b1=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" "$(echo "$url" | sed "s/FUZZ/$FUZZ_A/g")" 2>/dev/null)
  b2=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" "$(echo "$url" | sed "s/FUZZ/$FUZZ_B/g")" 2>/dev/null)
  b3=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" "$(echo "$url" | sed "s/FUZZ/$FUZZ_C/g")" 2>/dev/null)

  local h0 h1 h2 h3
  h0=$(printf '%s' "$b0" | md5sum | cut -d' ' -f1)
  h1=$(printf '%s' "$b1" | md5sum | cut -d' ' -f1)
  h2=$(printf '%s' "$b2" | md5sum | cut -d' ' -f1)
  h3=$(printf '%s' "$b3" | md5sum | cut -d' ' -f1)

  # All three fuzzed hashes must be distinct
  [[ "$h1" == "$h2" || "$h1" == "$h3" || "$h2" == "$h3" ]] && return
  # And must differ from baseline
  [[ "$h0" == "$h1" && "$h0" == "$h2" ]] && return

  # Size gate: reject extreme variance (randomised pages / CDN noise)
  local s0=${#b0} s1=${#b1} s2=${#b2} s3=${#b3}
  local max_s min_s
  max_s=$(( s1 > s2 ? (s1 > s3 ? s1 : s3) : (s2 > s3 ? s2 : s3) ))
  min_s=$(( s1 < s2 ? (s1 < s3 ? s1 : s3) : (s2 < s3 ? s2 : s3) ))
  local spread=$(( max_s - min_s ))
  local threshold=$(( (s0 + 1) * 40 / 100 ))
  [[ "$spread" -gt "$threshold" && "$spread" -gt 2000 ]] && return

  echo "$url"
}
export -f _diff_check

if [[ -s "$OUT/engine/valid_params.txt" ]]; then
  cat "$OUT/engine/valid_params.txt" | _parallel "$THREADS" _diff_check \
    2>/dev/null \
    | sort -u > "$OUT/engine/diff/dynamic.txt"
  log "Dynamic params confirmed: $(count_safe "$OUT/engine/diff/dynamic.txt")"
else
  touch "$OUT/engine/diff/dynamic.txt"
fi

# ════════════════════════════════════════════════════════════════════════
# STEP 8 — IDOR DETECTION
# Sequential probing with hash-diff + size-gap gate
# Requires ≥2/3 hash diffs AND invalid ID returns smaller body
# ════════════════════════════════════════════════════════════════════════
section "STEP 8 ─ IDOR Detection"

export TIMEOUT

_idor_check() {
  local url="$1"
  local r1 r2 r3 r4
  r1=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 "$(echo "$url" | sed 's/FUZZ/1/')" 2>/dev/null)
  r2=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 "$(echo "$url" | sed 's/FUZZ/2/')" 2>/dev/null)
  r3=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 "$(echo "$url" | sed 's/FUZZ/100/')" 2>/dev/null)
  r4=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 "$(echo "$url" | sed 's/FUZZ/9999999/')" 2>/dev/null)

  local h1 h2 h3
  h1=$(printf '%s' "$r1" | md5sum | cut -d' ' -f1)
  h2=$(printf '%s' "$r2" | md5sum | cut -d' ' -f1)
  h3=$(printf '%s' "$r3" | md5sum | cut -d' ' -f1)

  local diff=0
  [[ "$h1" != "$h2" ]] && diff=$(( diff + 1 ))
  [[ "$h2" != "$h3" ]] && diff=$(( diff + 1 ))
  [[ "$h1" != "$h3" ]] && diff=$(( diff + 1 ))

  local s1=${#r1} s2=${#r2} s3=${#r3} s4=${#r4}
  local avg=$(( (s1 + s2 + s3) / 3 ))
  local gap=$(( avg > s4 ? avg - s4 : s4 - avg ))

  # Strong IDOR signal: ≥2 distinct valid responses AND invalid ID gives smaller body
  [[ "$diff" -ge 2 && "$gap" -gt 300 && "$s4" -lt "$avg" ]] && echo "$url"
}
export -f _idor_check

if [[ -s "$OUT/engine/diff/dynamic.txt" ]]; then
  cat "$OUT/engine/diff/dynamic.txt" | _parallel "$THREADS" _idor_check \
    2>/dev/null \
    | sort -u > "$OUT/engine/behavior/idor.txt"
  log "IDOR candidates: $(count_safe "$OUT/engine/behavior/idor.txt")"
else
  touch "$OUT/engine/behavior/idor.txt"
fi

# ════════════════════════════════════════════════════════════════════════
# STEP 9 — XSS REFLECTION DETECTION
# Canary injection → HTML content-type → DOCTYPE gate → encoding check → context tagging
# ════════════════════════════════════════════════════════════════════════
section "STEP 9 ─ XSS Reflection Detection"

CANARY="pr5xss$(date +%s)"
export CANARY TIMEOUT

_xss_check() {
  local url="$1"
  local test_url raw ct body ctx="html"

  test_url=$(echo "$url" | sed "s/FUZZ/${CANARY}/g")
  raw=$(curl -sk \
    --max-time "$TIMEOUT" --connect-timeout 4 \
    -D - \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
    "$test_url" 2>/dev/null) || return

  ct=$(echo "$raw" | grep -iP '^content-type:' | head -1)
  echo "$ct" | grep -qiE "text/html"        || return
  echo "$ct" | grep -qi "application/json"  && return

  # Separate body from headers
  body=$(echo "$raw" | awk '/^\r?$/{found=1;next} found{print}')

  echo "$body" | grep -q "$CANARY"          || return
  echo "$body" | grep -qi '<!doctype\|<html' || return

  # Encoding check — if the canary appears entity-encoded, it's not injectable
  echo "$body" | grep -qP '&[a-z]+;|&#[0-9]+;' && \
    echo "$body" | grep -q "$(printf '%s' "$CANARY" | sed 's/[0-9]/\\&#[0-9]+;/g')" && return

  echo "$body" | grep -P "=[\"'][^\"']*${CANARY}" &>/dev/null && ctx="attr"
  echo "$body" | grep -B3 -A3 "$CANARY" | grep -qi '<script\|javascript:' && ctx="script"

  echo "$url [ctx:${ctx}]"
}
export -f _xss_check

if [[ -s "$OUT/engine/diff/dynamic.txt" ]]; then
  cat "$OUT/engine/diff/dynamic.txt" | _parallel "$THREADS" _xss_check \
    2>/dev/null \
    | sort -u > "$OUT/engine/reflection/xss_candidates.txt"
  log "XSS candidates: $(count_safe "$OUT/engine/reflection/xss_candidates.txt")"
else
  touch "$OUT/engine/reflection/xss_candidates.txt"
fi

# ════════════════════════════════════════════════════════════════════════
# STEP 10 — OPEN REDIRECT DETECTION
# Keyword-gated → follow redirects → check final URL for marker
# No interactsh dependency — uses a self-resolving marker pattern
# ════════════════════════════════════════════════════════════════════════
section "STEP 10 ─ Open Redirect Detection"

REDIR_MARKER="pr5redir.example.com"
export REDIR_MARKER TIMEOUT

_redirect_check() {
  local url="$1"
  echo "$url" | grep -qiE '(redirect=|return=|next=|url=|goto=|dest=|target=|location=|forward=|redir=|callback=|continue=|returnto=)' || return

  local test_url final_url
  test_url=$(echo "$url" | sed "s|FUZZ|https://$REDIR_MARKER|g")
  final_url=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 \
    -o /dev/null -w "%{url_effective}" \
    -L --max-redirs 5 \
    -H "User-Agent: Mozilla/5.0" \
    "$test_url" 2>/dev/null) || return

  echo "$final_url" | grep -q "$REDIR_MARKER" && echo "$url"
}
export -f _redirect_check

if [[ -s "$OUT/engine/diff/dynamic.txt" ]]; then
  cat "$OUT/engine/diff/dynamic.txt" | _parallel "$THREADS" _redirect_check \
    2>/dev/null \
    | sort -u > "$OUT/engine/behavior/open_redirects.txt"
  log "Open redirects: $(count_safe "$OUT/engine/behavior/open_redirects.txt")"
else
  touch "$OUT/engine/behavior/open_redirects.txt"
fi

# ════════════════════════════════════════════════════════════════════════
# STEP 11 — SQLi ERROR HEURISTIC
# Inject quote/comment payloads → match DB error string patterns
# ════════════════════════════════════════════════════════════════════════
section "STEP 11 ─ SQLi Error Heuristic"

SQLI_ERRORS='sql syntax|mysql_fetch|ORA-[0-9]+|sqlite_|pg_exec|SQLSTATE|unclosed quotation|syntax error.*SQL|mysql_num_rows|Warning.*mysql|supplied argument.*mysql|PostgreSQL.*ERROR|Microsoft OLE DB|ODBC.*Driver'
export SQLI_ERRORS TIMEOUT

_sqli_check() {
  local url="$1"
  for payload in "'" "1'--" "1 AND 1=2--" '"'; do
    # Simple percent-encoding for the payload
    local enc
    enc=$(printf '%s' "$payload" | \
      awk '{for(i=1;i<=length($0);i++){c=substr($0,i,1);
        if(c~/[a-zA-Z0-9._~-]/){printf c}else{printf "%%%02X",ord(c)}}}
        function ord(c,    r){for(r=0;r<256;r++)if(sprintf("%c",r)==c)return r}')

    local test_url body
    test_url=$(echo "$url" | sed "s/FUZZ/${enc}/g")
    body=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 \
      -H "User-Agent: Mozilla/5.0" \
      "$test_url" 2>/dev/null) || continue

    if echo "$body" | grep -qiE "$SQLI_ERRORS"; then
      echo "$url [payload:${payload:0:8}]"
      return
    fi
  done
}
export -f _sqli_check

if [[ -s "$OUT/engine/diff/dynamic.txt" ]]; then
  cat "$OUT/engine/diff/dynamic.txt" | _parallel "$THREADS" _sqli_check \
    2>/dev/null \
    | sort -u > "$OUT/engine/reflection/sqli_candidates.txt"
  log "SQLi candidates: $(count_safe "$OUT/engine/reflection/sqli_candidates.txt")"
else
  touch "$OUT/engine/reflection/sqli_candidates.txt"
fi

# ════════════════════════════════════════════════════════════════════════
# STEP 12 — SSRF PARAMETER TAGGING
# Pattern match param names commonly used for URL/host inputs
# ════════════════════════════════════════════════════════════════════════
section "STEP 12 ─ SSRF Parameter Tagging"

grep -Ei '(url=|uri=|path=|dest=|host=|src=|file=|resource=|image=|data=|load=|fetch=|open=|proxy=|service=|server=|backend=|endpoint=|webhook=|callback=|api=|target=)' \
  "$OUT/engine/valid_params.txt" 2>/dev/null \
  | sort -u > "$OUT/engine/reflection/ssrf_candidates.txt" || true

log "SSRF-prone patterns: $(count_safe "$OUT/engine/reflection/ssrf_candidates.txt")"

# ════════════════════════════════════════════════════════════════════════
# STEP 13 — STATS
# ════════════════════════════════════════════════════════════════════════
END_TS=$(date +%s)
ELAPSED=$(( END_TS - START_TS ))
ELAPSED_FMT="$((ELAPSED/60))m $((ELAPSED%60))s"

cat > "$STATS_FILE" << STATS_EOF
{
  "target":         "$DOMAIN",
  "date":           "$START_DATE",
  "mode":           "$(${DEEP_MODE} && echo deep || echo standard)",
  "elapsed":        "$ELAPSED_FMT",
  "subs_raw":       $(count_safe "$OUT/subs/raw.txt"),
  "subs_resolved":  $(count_safe "$OUT/subs/resolved.txt"),
  "live_hosts":     $(count_safe "$OUT/http/live.txt"),
  "crawled_urls":   $(count_safe "$OUT/crawl/crawled_urls.txt"),
  "param_urls":     $(count_safe "$OUT/crawl/urls_with_params.txt"),
  "param_patterns": $(count_safe "$OUT/crawl/params_normalized.txt"),
  "valid_params":   $(count_safe "$OUT/engine/valid_params.txt"),
  "dynamic_params": $(count_safe "$OUT/engine/diff/dynamic.txt"),
  "idor":           $(count_safe "$OUT/engine/behavior/idor.txt"),
  "open_redirects": $(count_safe "$OUT/engine/behavior/open_redirects.txt"),
  "xss":            $(count_safe "$OUT/engine/reflection/xss_candidates.txt"),
  "sqli":           $(count_safe "$OUT/engine/reflection/sqli_candidates.txt"),
  "ssrf":           $(count_safe "$OUT/engine/reflection/ssrf_candidates.txt")
}
STATS_EOF

# ════════════════════════════════════════════════════════════════════════
# STEP 14 — HTML REPORT
# ════════════════════════════════════════════════════════════════════════
if [[ "$SKIP_REPORT" != true ]]; then
  section "STEP 14 ─ HTML Report"

  HTML_REPORT="$OUT/final/report.html"

  _js_array() {
    local file="$1" var="$2"
    printf 'const %s=[' "$var"
    [[ -s "$file" ]] && while IFS= read -r l; do
      l="${l//\\/\\\\}"; l="${l//\"/\\\"}"
      printf '"%s",' "$l"
    done < "$file"
    printf '];'
  }

  IDOR_JS=$(_js_array "$OUT/engine/behavior/idor.txt"              "IDOR_D")
  REDIR_JS=$(_js_array "$OUT/engine/behavior/open_redirects.txt"   "REDIR_D")
  XSS_JS=$(_js_array  "$OUT/engine/reflection/xss_candidates.txt"  "XSS_D")
  SQLI_JS=$(_js_array "$OUT/engine/reflection/sqli_candidates.txt" "SQLI_D")
  SSRF_JS=$(_js_array "$OUT/engine/reflection/ssrf_candidates.txt" "SSRF_D")
  SUBS_JS=$(_js_array "$OUT/subs/resolved.txt"                     "SUBS_D")
  LIVE_JS=$(_js_array "$OUT/http/probe_full.txt"                   "LIVE_D")
  DYN_JS=$(_js_array  "$OUT/engine/diff/dynamic.txt"              "DYN_D")

  SR=$(count_safe "$OUT/subs/raw.txt")
  SN=$(count_safe "$OUT/subs/resolved.txt")
  LN=$(count_safe "$OUT/http/live.txt")
  CN=$(count_safe "$OUT/crawl/crawled_urls.txt")
  PN=$(count_safe "$OUT/crawl/params_normalized.txt")
  VN=$(count_safe "$OUT/engine/valid_params.txt")
  DN=$(count_safe "$OUT/engine/diff/dynamic.txt")
  IN=$(count_safe "$OUT/engine/behavior/idor.txt")
  RN=$(count_safe "$OUT/engine/behavior/open_redirects.txt")
  XN=$(count_safe "$OUT/engine/reflection/xss_candidates.txt")
  QN=$(count_safe "$OUT/engine/reflection/sqli_candidates.txt")
  FN=$(count_safe "$OUT/engine/reflection/ssrf_candidates.txt")

  IDOR_HOT=""; [[ $IN -gt 0 ]] && IDOR_HOT=" hot"
  XSS_HOT="";  [[ $XN -gt 0 ]] && XSS_HOT=" hot"
  SQLI_HOT=""; [[ $QN -gt 0 ]] && SQLI_HOT=" hot"
  IDOR_CLS=""; [[ $IN -gt 0 ]] && IDOR_CLS=" alert"
  XSS_CLS="";  [[ $XN -gt 0 ]] && XSS_CLS=" warn"
  SQLI_CLS=""; [[ $QN -gt 0 ]] && SQLI_CLS=" warn"

  cat > "$HTML_REPORT" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRECISE RECON v5</title>
<style>
:root{--bg:#0a0c0f;--bg1:#111318;--bg2:#181b22;--bg3:#1e2129;--border:#272b35;--border2:#2f3440;--text:#e2e4ea;--text2:#8b90a0;--text3:#555b6a;--mono:'Courier New',monospace;--sans:system-ui,sans-serif;--red:#ff4d6a;--orange:#ff8c42;--yellow:#ffd166;--green:#06d6a0;--cyan:#48cae4;--blue:#4361ee;--red-bg:rgba(255,77,106,.08);--ora-bg:rgba(255,140,66,.08);--yel-bg:rgba(255,209,102,.08);--cyn-bg:rgba(72,202,228,.08)}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;min-height:100vh}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:var(--bg1)}::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
.shell{display:grid;grid-template-columns:220px 1fr;min-height:100vh}
.sidebar{background:var(--bg1);border-right:1px solid var(--border);position:sticky;top:0;height:100vh;overflow-y:auto;padding:24px 0;display:flex;flex-direction:column}
.main{padding:40px 48px;max-width:1100px}
.logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:20px}
.logo-title{font-family:var(--mono);font-size:11px;font-weight:700;color:var(--cyan);letter-spacing:2px;text-transform:uppercase}
.logo-sub{font-size:11px;color:var(--text3);margin-top:4px;font-family:var(--mono)}
.nav-section{padding:0 12px;margin-bottom:8px}
.nav-label{font-size:10px;font-family:var(--mono);color:var(--text3);letter-spacing:1.5px;text-transform:uppercase;padding:0 8px;margin-bottom:4px}
.nav-item{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:6px;cursor:pointer;color:var(--text2);font-size:13px;font-weight:500;text-decoration:none;transition:all .15s;border:1px solid transparent}
.nav-item:hover{background:var(--bg3);color:var(--text)}.nav-item.active{background:var(--bg3);color:var(--text);border-color:var(--border2)}
.nav-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dot-red{background:var(--red);box-shadow:0 0 6px var(--red)}.dot-orange{background:var(--orange);box-shadow:0 0 6px var(--orange)}.dot-yellow{background:var(--yellow);box-shadow:0 0 6px var(--yellow)}.dot-green{background:var(--green);box-shadow:0 0 6px var(--green)}.dot-cyan{background:var(--cyan);box-shadow:0 0 6px var(--cyan)}.dot-gray{background:var(--text3)}
.nav-badge{margin-left:auto;font-family:var(--mono);font-size:10px;padding:2px 6px;border-radius:4px;background:var(--bg2);color:var(--text2)}
.nav-badge.hot{background:var(--red-bg);color:var(--red);border:1px solid rgba(255,77,106,.2)}
.sidebar-footer{margin-top:auto;padding:16px 20px 0;border-top:1px solid var(--border);font-size:11px;color:var(--text3);font-family:var(--mono)}
.view{display:none}.view.active{display:block}
.page-header{margin-bottom:36px;padding-bottom:24px;border-bottom:1px solid var(--border)}
.page-eyebrow{font-family:var(--mono);font-size:11px;color:var(--cyan);letter-spacing:2px;text-transform:uppercase;margin-bottom:8px}
.page-title{font-family:var(--mono);font-size:26px;font-weight:700;color:var(--text);margin-bottom:8px}
.page-title span{color:var(--cyan)}
.page-meta{display:flex;gap:20px;flex-wrap:wrap;margin-top:12px}
.meta-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text2);font-family:var(--mono)}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:36px}
.stat-card{background:var(--bg1);border:1px solid var(--border);border-radius:10px;padding:16px 18px;transition:border-color .2s}
.stat-card:hover{border-color:var(--border2)}.stat-card.alert{border-color:rgba(255,77,106,.3);background:var(--red-bg)}.stat-card.warn{border-color:rgba(255,140,66,.3);background:var(--ora-bg)}
.stat-num{font-family:var(--mono);font-size:28px;font-weight:700;color:var(--text);line-height:1;margin-bottom:6px}
.stat-card.alert .stat-num{color:var(--red)}.stat-card.warn .stat-num{color:var(--orange)}
.stat-label{font-size:11px;color:var(--text2);font-weight:500}
.sec-header{display:flex;align-items:center;gap:12px;margin-bottom:16px;margin-top:36px}
.sec-title{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:1px}
.pill{font-size:10px;font-family:var(--mono);padding:3px 8px;border-radius:4px;font-weight:700;letter-spacing:.5px}
.pill-crit{background:var(--red-bg);color:var(--red);border:1px solid rgba(255,77,106,.25)}
.pill-high{background:var(--ora-bg);color:var(--orange);border:1px solid rgba(255,140,66,.25)}
.pill-med{background:var(--yel-bg);color:var(--yellow);border:1px solid rgba(255,209,102,.25)}
.ftable{width:100%;border-collapse:collapse;margin-bottom:8px}
.ftable th{text-align:left;font-family:var(--mono);font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;padding:8px 12px;border-bottom:1px solid var(--border);background:var(--bg2)}
.ftable td{padding:10px 12px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px;vertical-align:top}
.ftable td.url{color:var(--cyan);word-break:break-all}.ftable tr:hover td{background:var(--bg2)}
.notice{background:var(--bg2);border-left:3px solid var(--border2);padding:12px 16px;border-radius:0 6px 6px 0;font-size:12px;color:var(--text2);margin-bottom:16px}
.empty{color:var(--text3);font-family:var(--mono);font-size:13px;padding:20px 0}
.toolbar{display:flex;align-items:center;gap:12px;margin-bottom:12px}
.si{background:var(--bg2);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:8px 12px;font-size:13px;font-family:var(--mono);outline:none;width:280px}
.si:focus{border-color:var(--cyan)}
.cbtn{background:var(--bg3);border:1px solid var(--border2);color:var(--text2);padding:7px 14px;border-radius:6px;cursor:pointer;font-size:12px;font-family:var(--mono)}
.cbtn:hover{color:var(--text)}
.cblock{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:var(--mono);font-size:12px;color:var(--text2);white-space:pre-wrap;word-break:break-all;max-height:400px;overflow-y:auto;line-height:1.8}
.pag{display:flex;align-items:center;gap:12px;margin-top:8px;font-size:12px;font-family:var(--mono);color:var(--text3)}
.pbtn{background:var(--bg3);border:1px solid var(--border2);color:var(--text2);padding:5px 12px;border-radius:5px;cursor:pointer;font-size:12px;font-family:var(--mono)}
.pbtn:hover:not([disabled]){color:var(--text)}.pbtn[disabled]{opacity:.3;cursor:default}
.hgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px}
.hcard{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.hurl{font-family:var(--mono);font-size:12px;color:var(--cyan);word-break:break-all;margin-bottom:6px}
.htags{display:flex;flex-wrap:wrap;gap:4px}
.htag{font-size:10px;font-family:var(--mono);padding:2px 7px;border-radius:4px;background:var(--bg3);color:var(--text2)}
.c200{background:rgba(6,214,160,.12);color:var(--green)}.c403{background:rgba(255,77,106,.12);color:var(--red)}.c301{background:rgba(255,209,102,.12);color:var(--yellow)}
.tl{margin:24px 0}
.tli{display:flex;align-items:flex-start;gap:14px;padding:10px 0;border-bottom:1px solid var(--border)}
.tld{width:10px;height:10px;border-radius:50%;background:var(--cyan);flex-shrink:0;margin-top:4px}
.tll{font-family:var(--mono);font-size:12px;color:var(--text);font-weight:600}
.tlc{font-family:var(--mono);font-size:11px;color:var(--text3)}
</style>
</head>
<body>
<div class="shell">
<nav class="sidebar">
  <div class="logo">
    <div class="logo-title">PRECISE RECON</div>
    <div class="logo-sub" id="sb-domain"></div>
    <div class="logo-sub" id="sb-date"></div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Overview</div>
    <a class="nav-item active" onclick="show('dash')"><span class="nav-dot dot-cyan"></span>Dashboard</a>
    <a class="nav-item" onclick="show('hosts')"><span class="nav-dot dot-green"></span>Live Hosts<span class="nav-badge" id="nb-live"></span></a>
    <a class="nav-item" onclick="show('subs')"><span class="nav-dot dot-gray"></span>Subdomains<span class="nav-badge" id="nb-subs"></span></a>
    <a class="nav-item" onclick="show('params')"><span class="nav-dot dot-gray"></span>Dynamic Params<span class="nav-badge" id="nb-dyn"></span></a>
  </div>
  <div class="nav-section">
    <div class="nav-label">Findings</div>
    <a class="nav-item" onclick="show('idor')"><span class="nav-dot dot-red"></span>IDOR<span class="nav-badge" id="nb-idor"></span></a>
    <a class="nav-item" onclick="show('xss')"><span class="nav-dot dot-orange"></span>XSS<span class="nav-badge" id="nb-xss"></span></a>
    <a class="nav-item" onclick="show('sqli')"><span class="nav-dot dot-orange"></span>SQLi<span class="nav-badge" id="nb-sqli"></span></a>
    <a class="nav-item" onclick="show('redir')"><span class="nav-dot dot-yellow"></span>Open Redirects<span class="nav-badge" id="nb-redir"></span></a>
    <a class="nav-item" onclick="show('ssrf')"><span class="nav-dot dot-yellow"></span>SSRF Patterns<span class="nav-badge" id="nb-ssrf"></span></a>
  </div>
  <div class="sidebar-footer" id="sb-footer"></div>
</nav>

<main class="main">
<div id="view-dash" class="view active">
  <div class="page-header">
    <div class="page-eyebrow">PRECISE RECON v5 · Zero Dependency</div>
    <div class="page-title">Recon report for <span id="dh-domain"></span></div>
    <div class="page-meta" id="dh-meta"></div>
  </div>
  <div class="stats-grid" id="stat-grid"></div>
  <div class="sec-header"><div class="sec-title">Pipeline Timeline</div></div>
  <div class="tl" id="tl"></div>
</div>
<div id="view-hosts" class="view"><div class="page-header"><div class="page-eyebrow">Overview</div><div class="page-title">Live <span>Hosts</span></div></div><div id="hosts-body"></div></div>
<div id="view-subs" class="view"><div class="page-header"><div class="page-eyebrow">Enumeration</div><div class="page-title"><span>Subdomains</span></div></div><div id="subs-body"></div></div>
<div id="view-params" class="view"><div class="page-header"><div class="page-eyebrow">Diff Engine</div><div class="page-title">Dynamic <span>Parameters</span></div></div><div id="params-body"></div></div>
<div id="view-idor" class="view"><div class="page-header"><div class="page-eyebrow">Critical</div><div class="page-title">IDOR <span>Findings</span></div></div><div class="notice">Sequential ID probing confirmed hash divergence + size gap. Verify manually for real data exposure.</div><div id="idor-body"></div></div>
<div id="view-xss" class="view"><div class="page-header"><div class="page-eyebrow">High</div><div class="page-title">XSS <span>Candidates</span></div></div><div class="notice">Input reflected unencoded in HTML context. Verify context is exploitable before reporting.</div><div id="xss-body"></div></div>
<div id="view-sqli" class="view"><div class="page-header"><div class="page-eyebrow">High</div><div class="page-title">SQLi Error <span>Heuristic</span></div></div><div class="notice">DB error strings detected. Confirm with manual payload before reporting.</div><div id="sqli-body"></div></div>
<div id="view-redir" class="view"><div class="page-header"><div class="page-eyebrow">Medium</div><div class="page-title">Open <span>Redirects</span></div></div><div id="redir-body"></div></div>
<div id="view-ssrf" class="view"><div class="page-header"><div class="page-eyebrow">Medium</div><div class="page-title">SSRF-Prone <span>Parameters</span></div></div><div class="notice">Test with out-of-band callbacks (Burp Collaborator / interactsh).</div><div id="ssrf-body"></div></div>
</main>
</div>

<script>
HTMLEOF

  # Inject data + closing JS inline (avoids heredoc escaping issues with backticks)
  {
    echo "$IDOR_JS"
    echo "$REDIR_JS"
    echo "$XSS_JS"
    echo "$SQLI_JS"
    echo "$SSRF_JS"
    echo "$SUBS_JS"
    echo "$LIVE_JS"
    echo "$DYN_JS"

    cat << JSEOF
const META={domain:"$DOMAIN",date:"$START_DATE",mode:"$(${DEEP_MODE} && echo deep || echo standard)",elapsed:"$ELAPSED_FMT",subs_raw:$SR,subs_res:$SN,live:$LN,crawl:$CN,params:$PN,valid:$VN,dyn:$DN,idor:$IN,redir:$RN,xss:$XN,sqli:$QN,ssrf:$FN};

// ── BOOT ─────────────────────────────────────────────────────────────
document.getElementById('sb-domain').textContent='v5 · '+META.domain;
document.getElementById('sb-date').textContent=META.date;
document.getElementById('nb-live').textContent=META.live;
document.getElementById('nb-subs').textContent=META.subs_res;
document.getElementById('nb-dyn').textContent=META.dyn;

function badge(id,n){const el=document.getElementById(id);if(!el)return;el.textContent=n;if(n>0)el.classList.add('hot');}
badge('nb-idor',META.idor);badge('nb-xss',META.xss);badge('nb-sqli',META.sqli);badge('nb-redir',META.redir);badge('nb-ssrf',META.ssrf);
document.getElementById('dh-domain').textContent=META.domain;
document.getElementById('dh-meta').innerHTML=
  '<div class="meta-item">📅 '+META.date+'</div>'+
  '<div class="meta-item">⏱ '+META.elapsed+'</div>'+
  '<div class="meta-item">'+(META.mode==='deep'?'🔴 Deep mode':'🟢 Standard mode')+'</div>'+
  '<div class="meta-item">⚙️ Zero deps</div>';
document.getElementById('sb-footer').innerHTML='Runtime: '+META.elapsed+'<br>Zero deps · curl only';

document.getElementById('stat-grid').innerHTML=[
  ['stat-card','subs_raw','Raw Subdomains'],
  ['stat-card','subs_res','Resolved Hosts'],
  ['stat-card','live','Live HTTP Hosts'],
  ['stat-card','crawl','Crawled URLs'],
  ['stat-card','valid','Valid Params'],
  ['stat-card','dyn','Dynamic Params'],
  ['stat-card'+(META.idor>0?' alert':''),'idor','IDOR Findings'],
  ['stat-card'+(META.xss>0?' warn':''),'xss','XSS Candidates'],
  ['stat-card'+(META.sqli>0?' warn':''),'sqli','SQLi Findings'],
  ['stat-card','redir','Open Redirects'],
  ['stat-card','ssrf','SSRF Patterns'],
].map(([cls,key,lbl])=>'<div class="'+cls+'"><div class="stat-num">'+META[key]+'</div><div class="stat-label">'+lbl+'</div></div>').join('');

document.getElementById('tl').innerHTML=[
  ['Subdomain Enumeration',META.subs_raw+' raw → '+META.subs_res+' resolved'],
  ['HTTP Probing',META.live+' live hosts found'],
  ['Crawl + Wayback',META.crawl+' URLs, '+META.params+' with params'],
  ['Baseline + Diff Engine',META.valid+' valid → '+META.dyn+' dynamic'],
  ['Detection Engines','IDOR:'+META.idor+'  XSS:'+META.xss+'  SQLi:'+META.sqli+'  Redirect:'+META.redir+'  SSRF:'+META.ssrf],
].map(([l,c])=>'<div class="tli"><div class="tld"></div><div><div class="tll">'+l+'</div><div class="tlc">'+c+'</div></div></div>').join('');

// ── NAVIGATION ───────────────────────────────────────────────────────
function show(name){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.getElementById('view-'+name).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>{if(n.getAttribute('onclick')&&n.getAttribute('onclick').includes("'"+name+"'"))n.classList.add('active');});
  if(name==='hosts')  renderHosts();
  if(name==='subs')   renderList('subs-body',SUBS_D);
  if(name==='params') renderList('params-body',DYN_D);
  if(name==='idor')   renderF('idor-body',IDOR_D,'pill-crit','CRITICAL');
  if(name==='xss')    renderF('xss-body',XSS_D,'pill-high','HIGH');
  if(name==='sqli')   renderF('sqli-body',SQLI_D,'pill-high','HIGH');
  if(name==='redir')  renderF('redir-body',REDIR_D,'pill-med','MEDIUM');
  if(name==='ssrf')   renderF('ssrf-body',SSRF_D,'pill-med','MEDIUM');
}

function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function renderF(id,data,pill,label){
  const el=document.getElementById(id);
  if(!el||el.dataset.r)return;el.dataset.r='1';
  if(!data.length){el.innerHTML='<div class="empty">No findings.</div>';return;}
  const PAGE=50;let page=0;let filtered=data;
  function render(){
    el.innerHTML='<div class="toolbar"><input class="si" placeholder="Filter..." id="'+id+'-s"><button class="cbtn" onclick="copyF(\''+id+'\')">Copy All</button></div>';
    document.getElementById(id+'-s').addEventListener('input',function(){filtered=data.filter(d=>d.toLowerCase().includes(this.value.toLowerCase()));page=0;rp();});
    rp();
  }
  function rp(){
    el.querySelector('.tbl')?.remove();el.querySelector('.pag')?.remove();
    const slice=filtered.slice(page*PAGE,(page+1)*PAGE);
    const total=Math.ceil(filtered.length/PAGE);
    const d=document.createElement('div');d.className='tbl';
    d.innerHTML='<table class="ftable"><thead><tr><th>#</th><th>URL / Pattern</th><th>Severity</th></tr></thead><tbody>'+
      slice.map((u,i)=>'<tr><td style="color:var(--text3);width:40px">'+(page*PAGE+i+1)+'</td><td class="url">'+esc(u)+'</td><td><span class="pill '+pill+'">'+label+'</span></td></tr>').join('')+
      '</tbody></table>';
    el.appendChild(d);
    if(total>1){const p=document.createElement('div');p.className='pag';
      p.innerHTML='<span style="color:var(--text3)">'+filtered.length+' items</span><button class="pbtn" '+(page===0?'disabled':'')+'id="'+id+'-pv">‹</button><span>Page '+(page+1)+' / '+total+'</span><button class="pbtn" '+(page>=total-1?'disabled':'')+'id="'+id+'-nx">›</button>';
      el.appendChild(p);
      document.getElementById(id+'-pv').onclick=()=>{if(page>0){page--;rp();}};
      document.getElementById(id+'-nx').onclick=()=>{if(page<total-1){page++;rp();}};
    }
  }
  render();
}

function renderList(id,data){
  const el=document.getElementById(id);
  if(!el||el.dataset.r)return;el.dataset.r='1';
  if(!data.length){el.innerHTML='<div class="empty">Empty.</div>';return;}
  const PAGE=100;let page=0;let filtered=data;
  function render(){
    el.innerHTML='<div class="toolbar"><input class="si" placeholder="Filter..." id="'+id+'-s"><button class="cbtn" onclick="copyL(\''+id+'\')">Copy All</button></div>';
    document.getElementById(id+'-s').addEventListener('input',function(){filtered=data.filter(d=>d.toLowerCase().includes(this.value.toLowerCase()));page=0;rp();});
    rp();
  }
  function rp(){
    el.querySelector('.cblock')?.remove();el.querySelector('.pag')?.remove();
    const d=document.createElement('div');d.className='cblock';
    d.textContent=filtered.slice(page*PAGE,(page+1)*PAGE).join('\n');
    el.appendChild(d);
    const total=Math.ceil(filtered.length/PAGE);
    if(total>1){const p=document.createElement('div');p.className='pag';
      p.innerHTML='<span style="color:var(--text3)">'+filtered.length+' items</span><button class="pbtn" '+(page===0?'disabled':'')+'id="'+id+'-pv">‹</button><span>Page '+(page+1)+' / '+total+'</span><button class="pbtn" '+(page>=total-1?'disabled':'')+'id="'+id+'-nx">›</button>';
      el.appendChild(p);
      document.getElementById(id+'-pv').onclick=()=>{if(page>0){page--;rp();}};
      document.getElementById(id+'-nx').onclick=()=>{if(page<total-1){page++;rp();}};
    }
  }
  render();
}

function renderHosts(){
  const el=document.getElementById('hosts-body');
  if(!el||el.dataset.r)return;el.dataset.r='1';
  const g=document.createElement('div');g.className='hgrid';
  LIVE_D.forEach(line=>{
    const p=line.split(' ');const url=p[0];const tags=p.slice(1);
    const ct=tags.find(t=>/^\[\d+\]$/.test(t))||'';const code=ct.replace(/[\[\]]/g,'');
    const cls=code==='200'?'c200':code==='403'?'c403':['301','302','307'].includes(code)?'c301':'';
    g.innerHTML+='<div class="hcard"><div class="hurl">'+esc(url)+'</div><div class="htags">'+tags.map(t=>'<span class="htag '+(t.includes(code)?cls:'')+'">'+esc(t)+'</span>').join('')+'</div></div>';
  });
  el.appendChild(g);
}

function copyF(id){const rows=document.querySelectorAll('#'+id+' td.url');navigator.clipboard.writeText(Array.from(rows).map(r=>r.textContent).join('\n'));}
function copyL(id){const b=document.querySelector('#'+id+' .cblock');if(b)navigator.clipboard.writeText(b.textContent);}
JSEOF
  } >> "$HTML_REPORT"

  echo "</script></body></html>" >> "$HTML_REPORT"

  log "HTML report: $HTML_REPORT"
fi

# ════════════════════════════════════════════════════════════════════════
# STEP 15 — TEXT REPORT
# ════════════════════════════════════════════════════════════════════════
REPORT="$OUT/final/report.txt"
{
printf '%s\n' "╔══════════════════════════════════════════════════════════════════╗"
printf '%s\n' "║      PRECISE RECON v5 — ZERO DEPENDENCY EDITION                 ║"
printf '%s\n' "╚══════════════════════════════════════════════════════════════════╝"
echo "  Target  : $DOMAIN"
echo "  Date    : $START_DATE"
echo "  Mode    : $(${DEEP_MODE} && echo deep || echo standard)"
echo "  Runtime : $ELAPSED_FMT"
echo "  Deps    : curl bash awk grep — nothing else required"
echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  🔴  CRITICAL — IDOR / Logic Flaws"
echo "══════════════════════════════════════════════════════════════════"
[[ -s "$OUT/engine/behavior/idor.txt" ]] && cat "$OUT/engine/behavior/idor.txt" || echo "  (none)"
echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  🟠  HIGH — XSS Candidates"
echo "══════════════════════════════════════════════════════════════════"
[[ -s "$OUT/engine/reflection/xss_candidates.txt" ]] && cat "$OUT/engine/reflection/xss_candidates.txt" || echo "  (none)"
echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  🟠  HIGH — SQLi Error Heuristic"
echo "══════════════════════════════════════════════════════════════════"
[[ -s "$OUT/engine/reflection/sqli_candidates.txt" ]] && cat "$OUT/engine/reflection/sqli_candidates.txt" || echo "  (none)"
echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  🟡  MEDIUM — Open Redirects"
echo "══════════════════════════════════════════════════════════════════"
[[ -s "$OUT/engine/behavior/open_redirects.txt" ]] && cat "$OUT/engine/behavior/open_redirects.txt" || echo "  (none)"
echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  🟡  MEDIUM — SSRF-Prone Parameters"
echo "══════════════════════════════════════════════════════════════════"
[[ -s "$OUT/engine/reflection/ssrf_candidates.txt" ]] && cat "$OUT/engine/reflection/ssrf_candidates.txt" || echo "  (none)"
echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  📊  PIPELINE STATS"
echo "══════════════════════════════════════════════════════════════════"
echo "  Subdomains (raw)       : $(count_safe "$OUT/subs/raw.txt")"
echo "  Subdomains (resolved)  : $(count_safe "$OUT/subs/resolved.txt")"
echo "  Live HTTP hosts        : $(count_safe "$OUT/http/live.txt")"
echo "  Crawled URLs           : $(count_safe "$OUT/crawl/crawled_urls.txt")"
echo "  Parameterized URLs     : $(count_safe "$OUT/crawl/urls_with_params.txt")"
echo "  Normalized patterns    : $(count_safe "$OUT/crawl/params_normalized.txt")"
echo "  Valid (baseline)       : $(count_safe "$OUT/engine/valid_params.txt")"
echo "  Dynamic params         : $(count_safe "$OUT/engine/diff/dynamic.txt")"
echo "  IDOR findings          : $(count_safe "$OUT/engine/behavior/idor.txt")"
echo "  Open redirects         : $(count_safe "$OUT/engine/behavior/open_redirects.txt")"
echo "  XSS candidates         : $(count_safe "$OUT/engine/reflection/xss_candidates.txt")"
echo "  SQLi candidates        : $(count_safe "$OUT/engine/reflection/sqli_candidates.txt")"
echo "  SSRF patterns          : $(count_safe "$OUT/engine/reflection/ssrf_candidates.txt")"
echo ""
echo "  All data → $OUT"
[[ "$SKIP_REPORT" != true ]] && echo "  HTML     → $OUT/final/report.html"
echo "══════════════════════════════════════════════════════════════════"
} | tee "$REPORT"

echo
echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║  ✓ DONE  Runtime: $ELAPSED_FMT             ${RESET}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════╝${RESET}"
echo
[[ "$SKIP_REPORT" != true ]] && echo -e "  ${CYAN}HTML:${RESET} ${BOLD}$OUT/final/report.html${RESET}"
echo -e "  ${CYAN}TXT: ${RESET} ${BOLD}$REPORT${RESET}"
echo -e "  ${CYAN}Data:${RESET} ${BOLD}$OUT/${RESET}"
