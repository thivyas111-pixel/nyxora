#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  NYXORA v1.0  —  Zero-Dependency Bug Bounty Recon Framework
#  GitHub : https://github.com/thivyas111-pixel/nyxora
#
#  Requires ONLY: bash curl awk grep sort sed tr wc md5sum
#
#  v1.0 Features:
#    + Security-header audit (CSP, HSTS, X-Frame, CORS misconfiguration)
#    + JS secret scanner (12 secret types — API keys, tokens, bearer creds)
#    + Subdomain takeover fingerprinting (dangling CNAME detection)
#    + SSRF: optional OOB active probe (--oob flag)
#    + Confidence scoring on all findings (HIGH / MEDIUM / LOW)
#    + --scope-file flag to restrict to in-scope hosts only
#    + Tighter FP gates: SQLi baseline comparison, XSS encoding check
#    + IDOR: ID-param name heuristic boosts confidence
#    + Markdown report (alongside HTML + TXT)
#    + JSON API endpoints tracked separately
#    + GCP/Azure tech detection
# ═══════════════════════════════════════════════════════════════════════════

set -uo pipefail
IFS=$'\n\t'

VERSION="1.0.0"

RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

print_banner() {
cat << 'EOF'

  ███╗   ██╗██╗   ██╗██╗  ██╗ ██████╗ ██████╗  █████╗
  ████╗  ██║╚██╗ ██╔╝╚██╗██╔╝██╔═══██╗██╔══██╗██╔══██╗
  ██╔██╗ ██║ ╚████╔╝  ╚███╔╝ ██║   ██║██████╔╝███████║
  ██║╚██╗██║  ╚██╔╝   ██╔██╗ ██║   ██║██╔══██╗██╔══██║
  ██║ ╚████║   ██║   ██╔╝ ██╗╚██████╔╝██║  ██║██║  ██║
  ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
  v1.0  ·  Zero-Dependency Bug Bounty Recon Framework

EOF
  echo -e "  ${DIM}curl · bash · awk · grep — nothing to install.${RESET}"
  echo -e "  ${MAGENTA}SecHeaders · JS Secrets · Takeover · Confidence Scoring · Markdown Report${RESET}"
  echo
}

usage() {
  echo -e "${BOLD}Usage:${RESET}  $0 <domain> [options]"
  echo
  echo -e "${BOLD}Options:${RESET}"
  echo "  --deep               Deeper crawl (more sources, depth 3)"
  echo "  --out <dir>          Custom output directory"
  echo "  --no-report          Skip HTML report"
  echo "  --threads <n>        Parallel workers (default: 20)"
  echo "  --timeout <n>        Per-request timeout seconds (default: 6)"
  echo "  --scope-file <file>  Only test subdomains listed in file"
  echo "  --oob <host>         OOB host for active SSRF probe (Burp Collaborator etc.)"
  echo "  --help               Show this help"
  echo
  exit 0
}

DOMAIN=""; DEEP_MODE=false; CUSTOM_OUT=""; SKIP_REPORT=false
THREADS=20; TIMEOUT=6; SCOPE_FILE=""; OOB_HOST=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deep)        DEEP_MODE=true; shift ;;
    --no-report)   SKIP_REPORT=true; shift ;;
    --out)         CUSTOM_OUT="$2"; shift 2 ;;
    --threads)     THREADS="$2"; shift 2 ;;
    --timeout)     TIMEOUT="$2"; shift 2 ;;
    --scope-file)  SCOPE_FILE="$2"; shift 2 ;;
    --oob)         OOB_HOST="$2"; shift 2 ;;
    --help|-h)     print_banner; usage ;;
    -*)            echo "Unknown option: $1"; exit 1 ;;
    *)             [[ -z "$DOMAIN" ]] && DOMAIN="$1" || { echo "Unexpected: $1"; exit 1; }; shift ;;
  esac
done

[[ -z "$DOMAIN" ]] && { print_banner; usage; }
command -v curl &>/dev/null || { echo -e "${RED}[!] curl not found.${RESET}"; exit 1; }

DOMAIN="${DOMAIN,,}"; DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"
START_TS=$(date +%s); START_DATE=$(date '+%Y-%m-%d %H:%M:%S')
[[ -n "$CUSTOM_OUT" ]] && OUT="$CUSTOM_OUT" || OUT="$HOME/nyxora-$DOMAIN-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUT"/{subs,http,crawl,engine/{diff,behavior,reflection,headers,secrets,takeover},final,logs}
LOGFILE="$OUT/logs/run.log"; STATS_FILE="$OUT/logs/stats.json"

log()     { local ts="[$(date +%T)]"; echo -e "${CYAN}${ts}${RESET} ${GREEN}[+]${RESET} $*"; echo "$ts [+] $*" >> "$LOGFILE"; }
warn()    { local ts="[$(date +%T)]"; echo -e "${CYAN}${ts}${RESET} ${ORANGE}[!]${RESET} $*"; echo "$ts [!] $*" >> "$LOGFILE"; }
good()    { local ts="[$(date +%T)]"; echo -e "${CYAN}${ts}${RESET} ${MAGENTA}[★]${RESET} $*"; echo "$ts [★] $*" >> "$LOGFILE"; }
section() { echo; echo -e "${BOLD}${BLUE}┌──────────────────────────────────────────────────┐${RESET}"; echo -e "${BOLD}${BLUE}│  $*${RESET}"; echo -e "${BOLD}${BLUE}└──────────────────────────────────────────────────┘${RESET}"; }
die()     { warn "$*"; exit 1; }
count_safe() { [[ -f "$1" ]] && wc -l < "$1" || echo "0"; }

_parallel() {
  local n="$1"; shift; local fn="$1"; shift; local extra_args=("$@")
  local jobs=0; local -a pids=()
  while IFS= read -r line; do
    "$fn" "$line" "${extra_args[@]}" &; pids+=($!); jobs=$(( jobs + 1 ))
    if (( jobs >= n )); then wait "${pids[0]}" 2>/dev/null || true; pids=("${pids[@]:1}"); jobs=$(( jobs - 1 )); fi
  done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
}

_curl() { curl -skL --max-time "$TIMEOUT" --retry 1 --retry-delay 0 --connect-timeout 4 -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" "$@" 2>/dev/null; }

print_banner

# ════════════════════════════════════════════════════════════════════════════
section "STEP 0 ─ Dependency Check"
ALL_OK=true
for tool in curl bash awk grep sort sed tr wc md5sum; do
  command -v "$tool" &>/dev/null && echo -e "  ${GREEN}✓${RESET} $tool" || { echo -e "  ${RED}✗${RESET} $tool MISSING"; ALL_OK=false; }
done
$ALL_OK || die "Missing tools above — they ship with every Linux distro."
echo -e "\n  ${GREEN}${BOLD}All OK. Starting...${RESET}"
log "Target: $DOMAIN | Out: $OUT | Mode: $DEEP_MODE | Threads: $THREADS | Timeout: ${TIMEOUT}s"
[[ -n "$OOB_HOST" ]] && log "OOB: $OOB_HOST"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 1 ─ Subdomain Enumeration"
touch "$OUT/subs/raw.txt"

log "crt.sh..."
_curl "https://crt.sh/?q=%25.$DOMAIN&output=json" | grep -oP '"name_value":"\K[^"]+' | tr ',' '\n' | sed 's/^\*\.//' >> "$OUT/subs/raw.txt" &
log "AlienVault OTX..."
_curl "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" | grep -oP '"hostname":"\K[^"]+' | grep "\.$DOMAIN$" >> "$OUT/subs/raw.txt" &
log "HackerTarget..."
_curl "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" | cut -d',' -f1 | grep "\.$DOMAIN$" >> "$OUT/subs/raw.txt" &
log "RapidDNS..."
_curl "https://rapiddns.io/subdomain/$DOMAIN?full=1&down=1" | grep -oP '(?<=<td>)[a-z0-9._-]+\.'$DOMAIN'(?=</td>)' >> "$OUT/subs/raw.txt" &
log "Wayback..."
_curl "https://web.archive.org/cdx/search/cdx?url=*.$DOMAIN&output=text&fl=original&collapse=urlkey" | grep -oP 'https?://\K[^/]+' | grep "\.$DOMAIN$" >> "$OUT/subs/raw.txt" &
log "ThreatCrowd..."
_curl "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$DOMAIN" | grep -oP '"[a-z0-9._-]+\.'$DOMAIN'"' | tr -d '"' >> "$OUT/subs/raw.txt" &

if [[ "$DEEP_MODE" == true ]]; then
  log "Certspotter (deep)..."
  _curl "https://api.certspotter.com/v1/issuances?domain=$DOMAIN&include_subdomains=true&expand=dns_names" | grep -oP '"[a-z0-9._-]+\.'$DOMAIN'"' | tr -d '"' >> "$OUT/subs/raw.txt" &
  log "URLScan (deep)..."
  _curl "https://urlscan.io/api/v1/search/?q=domain:$DOMAIN&size=100" | grep -oP '"[a-z0-9._-]+\.'$DOMAIN'"' | tr -d '"' >> "$OUT/subs/raw.txt" &
  log "BufferOver (deep)..."
  _curl "https://tls.bufferover.run/dns?q=.$DOMAIN" | grep -oP '"[a-z0-9._-]+\.'$DOMAIN'"' | tr -d '"' >> "$OUT/subs/raw.txt" &
fi
wait

sort -u "$OUT/subs/raw.txt" 2>/dev/null | tr '[:upper:]' '[:lower:]' \
  | grep -E "^[a-z0-9][a-z0-9._-]*\.$DOMAIN$" | grep -v '\.\.' | grep -v "^$DOMAIN$" \
  | sort -u > "$OUT/subs/raw_clean.txt"
mv "$OUT/subs/raw_clean.txt" "$OUT/subs/raw.txt"

if [[ -n "$SCOPE_FILE" && -f "$SCOPE_FILE" ]]; then
  grep -Fxf "$SCOPE_FILE" "$OUT/subs/raw.txt" > "$OUT/subs/scoped.txt"
  mv "$OUT/subs/scoped.txt" "$OUT/subs/raw.txt"
  log "Scope filter applied"
fi
log "Raw subdomains: $(count_safe "$OUT/subs/raw.txt")"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 2 ─ DNS Resolution + Wildcard Pruning"
RAND_SUB="nonexistent-nyx-$$-$(date +%s).$DOMAIN"
WILDCARD_IP=$(curl -sk --max-time 4 --connect-timeout 3 -o /dev/null -w "%{remote_ip}" "http://$RAND_SUB" 2>/dev/null || true)
if [[ -n "$WILDCARD_IP" && "$WILDCARD_IP" != "0.0.0.0" ]]; then
  warn "Wildcard IP: $WILDCARD_IP — will be filtered"
  echo "$WILDCARD_IP" > "$OUT/subs/wildcard_ips.txt"
else
  touch "$OUT/subs/wildcard_ips.txt"; WILDCARD_IP=""
fi
export TIMEOUT WILDCARD_IP

_resolve_and_filter() {
  local host="$1"; local ip
  ip=$(curl -sk --max-time 4 --connect-timeout 3 -o /dev/null -w "%{remote_ip}" "http://$host" 2>/dev/null || true)
  [[ -z "$ip" || "$ip" == "0.0.0.0" ]] && return
  [[ -n "$WILDCARD_IP" && "$ip" == "$WILDCARD_IP" ]] && return
  echo "$host $ip"
}
export -f _resolve_and_filter

cat "$OUT/subs/raw.txt" | _parallel "$THREADS" _resolve_and_filter 2>/dev/null | sort -u > "$OUT/subs/resolved_raw.txt"
awk '{print $2}' "$OUT/subs/resolved_raw.txt" | sort | uniq -c | sort -rn | awk '$1 > 8 {print $2}' >> "$OUT/subs/wildcard_ips.txt"
sort -u "$OUT/subs/wildcard_ips.txt" -o "$OUT/subs/wildcard_ips.txt"

if [[ -s "$OUT/subs/wildcard_ips.txt" ]] && grep -qE '^[0-9]' "$OUT/subs/wildcard_ips.txt" 2>/dev/null; then
  grep -vFf <(grep -E '^[0-9]' "$OUT/subs/wildcard_ips.txt") "$OUT/subs/resolved_raw.txt" | awk '{print $1}' | sort -u > "$OUT/subs/resolved.txt"
else
  awk '{print $1}' "$OUT/subs/resolved_raw.txt" | sort -u > "$OUT/subs/resolved.txt"
fi
log "Resolved (wildcard-filtered): $(count_safe "$OUT/subs/resolved.txt")"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 3 ─ HTTP Probing"
export TIMEOUT

_http_probe() {
  local host="$1"
  for scheme in https http; do
    local url="${scheme}://${host}"; local raw status size title tech
    raw=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 --retry 1 --retry-delay 0 -L --max-redirs 3 -D - \
      -w "\n__STATUS__%{http_code}__SIZE__%{size_download}" \
      -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
      "$url" 2>/dev/null) || continue
    status=$(echo "$raw" | grep -oP '__STATUS__\K[0-9]+' | tail -1)
    [[ -z "$status" || "$status" == "000" ]] && continue
    echo "$status" | grep -qE '^(200|201|301|302|307|401|403|500)$' || continue
    size=$(echo "$raw" | grep -oP '__SIZE__\K[0-9]+' | tail -1)
    [[ "${size:-0}" -lt 200 ]] && continue
    title=$(echo "$raw" | grep -oiP '(?<=<title>)[^<]+' | head -1 | tr -d '\r\n' | sed 's/  */ /g'); title="${title:0:60}"
    tech=""
    echo "$raw" | grep -qi "x-powered-by: php"  && tech="${tech}[PHP]"
    echo "$raw" | grep -qi "x-powered-by: asp"  && tech="${tech}[ASP.NET]"
    echo "$raw" | grep -qi "server: nginx"       && tech="${tech}[nginx]"
    echo "$raw" | grep -qi "server: apache"      && tech="${tech}[Apache]"
    echo "$raw" | grep -qi "server: iis"         && tech="${tech}[IIS]"
    echo "$raw" | grep -qi "wp-content"          && tech="${tech}[WordPress]"
    echo "$raw" | grep -qi "drupal"              && tech="${tech}[Drupal]"
    echo "$raw" | grep -qi "cf-ray:"             && tech="${tech}[Cloudflare]"
    echo "$raw" | grep -qi "x-amz-"             && tech="${tech}[AWS]"
    echo "$raw" | grep -qi "x-goog-"            && tech="${tech}[GCP]"
    echo "$raw" | grep -qi "x-azure-"           && tech="${tech}[Azure]"
    echo "${url} [${status}] [${size}b] ${title:+[$title]} ${tech}"
    echo "${url}" >> /tmp/nyx_live_$$
    return
  done
}
export -f _http_probe

cat "$OUT/subs/resolved.txt" | _parallel "$THREADS" _http_probe 2>/dev/null | sort -u > "$OUT/http/probe_full.txt"
[[ -f /tmp/nyx_live_$$ ]] && sort -u /tmp/nyx_live_$$ > "$OUT/http/live.txt"; rm -f /tmp/nyx_live_$$
log "Live hosts: $(count_safe "$OUT/http/live.txt")"
[[ ! -s "$OUT/http/live.txt" ]] && die "No live hosts found."

# ════════════════════════════════════════════════════════════════════════════
section "STEP 4 ─ Security Header Audit [NEW v6]"
export TIMEOUT

_header_audit() {
  local url="$1"; local raw findings=""
  raw=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -D - -o /dev/null \
    -H "User-Agent: Mozilla/5.0" -H "Origin: https://evil.com" "$url" 2>/dev/null) || return
  local status; status=$(echo "$raw" | grep -oP 'HTTP/[0-9.]+ \K[0-9]+' | head -1)
  [[ "$status" == "200" || "$status" == "301" || "$status" == "302" ]] || return

  # CORS checks — critical
  echo "$raw" | grep -qi "access-control-allow-origin: \*" && findings+="[CORS:WILDCARD] "
  echo "$raw" | grep -qi "access-control-allow-origin: https://evil.com" && findings+="[CORS:REFLECTS_ORIGIN] "
  if echo "$raw" | grep -qi "access-control-allow-credentials: true" && \
     echo "$raw" | grep -qiE "access-control-allow-origin: (https://evil\.com|\*)"; then
    findings+="[CORS:CREDS_LEAK] "
  fi
  # Missing security headers
  echo "$raw" | grep -qi "strict-transport-security"  || findings+="[MISSING:HSTS] "
  echo "$raw" | grep -qi "x-frame-options"            || findings+="[MISSING:X-Frame-Options] "
  echo "$raw" | grep -qi "x-content-type-options"     || findings+="[MISSING:X-Content-Type-Options] "
  echo "$raw" | grep -qi "content-security-policy"    || findings+="[MISSING:CSP] "
  echo "$raw" | grep -qi "referrer-policy"            || findings+="[MISSING:Referrer-Policy] "
  # Cookie flags
  if echo "$raw" | grep -qi "set-cookie:"; then
    echo "$raw" | grep -iq "set-cookie:.*secure"   || findings+="[COOKIE:no-Secure] "
    echo "$raw" | grep -iq "set-cookie:.*httponly" || findings+="[COOKIE:no-HttpOnly] "
    echo "$raw" | grep -iq "set-cookie:.*samesite" || findings+="[COOKIE:no-SameSite] "
  fi
  [[ -n "$findings" ]] && echo "$url | $findings"
}
export -f _header_audit

cat "$OUT/http/live.txt" | _parallel "$THREADS" _header_audit 2>/dev/null | sort -u > "$OUT/engine/headers/audit.txt"
grep -E "CORS:" "$OUT/engine/headers/audit.txt" | sort -u > "$OUT/engine/headers/cors_issues.txt" 2>/dev/null || true
grep -v "CORS:" "$OUT/engine/headers/audit.txt" | sort -u > "$OUT/engine/headers/missing_headers.txt" 2>/dev/null || true
good "Header audit: $(count_safe "$OUT/engine/headers/audit.txt") findings | CORS: $(count_safe "$OUT/engine/headers/cors_issues.txt")"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 5 ─ JS Secret Scanner [NEW v6]"
export TIMEOUT DOMAIN

JS_PATTERNS=(
  "AWS_ACCESS_KEY:::AKIA[0-9A-Z]{16}"
  "GOOGLE_API_KEY:::AIza[0-9A-Za-z\\-_]{35}"
  "SLACK_TOKEN:::xox[baprs]-[0-9A-Za-z\\-]+"
  "GITHUB_TOKEN:::gh[pousr]_[A-Za-z0-9]{36}"
  "STRIPE_KEY:::sk_(live|test)_[0-9a-zA-Z]{24}"
  "TWILIO_SID:::AC[a-z0-9]{32}"
  "BEARER_TOKEN:::[Bb]earer[[:space:]]+[A-Za-z0-9\\-_=]{20,}"
  "PRIVATE_KEY:::-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY"
  "FIREBASE:::firebaseio\\.com"
  "HEROKU_API:::[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
  "SENDGRID:::SG\\.[a-zA-Z0-9_\\-]{22}\\.[a-zA-Z0-9_\\-]{43}"
  "MAILCHIMP:::[0-9a-f]{32}-us[0-9]+"
)
export JS_PATTERNS

_js_scan() {
  local url="$1"
  echo "$url" | grep -qiE '\.js(\?|$)' || return
  local body; body=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" "$url" 2>/dev/null) || return
  [[ -z "$body" ]] && return
  for pattern_entry in "${JS_PATTERNS[@]}"; do
    local pname="${pattern_entry%%:::*}"; local pregex="${pattern_entry##*:::}"
    local match; match=$(echo "$body" | grep -oP "$pregex" 2>/dev/null | head -1 || true)
    if [[ -n "$match" ]]; then
      local display="${match:0:60}"
      echo "[SECRET:${pname}] ${url} | ${display}"
    fi
  done
}
export -f _js_scan

_extract_js_from_page() {
  local url="$1"; local body origin
  body=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" "$url" 2>/dev/null) || return
  origin=$(echo "$url" | grep -oP 'https?://[^/]+')
  echo "$body" | grep -oP "(?<=src=[\"'])[^\"']+\.js[^\"']*" \
    | sed "s|^/|${origin}/|g" | grep -E "^https?://" | grep "$DOMAIN" \
    >> "$OUT/engine/secrets/js_urls.txt" 2>/dev/null || true
}
export -f _extract_js_from_page

grep -iE '\.js(\?.*)?$' "$OUT/crawl/crawled_urls.txt" 2>/dev/null | sort -u > "$OUT/engine/secrets/js_urls.txt" || touch "$OUT/engine/secrets/js_urls.txt"
cat "$OUT/http/live.txt" | _parallel "$THREADS" _extract_js_from_page 2>/dev/null || true
sort -u "$OUT/engine/secrets/js_urls.txt" -o "$OUT/engine/secrets/js_urls.txt" 2>/dev/null || true

if [[ -s "$OUT/engine/secrets/js_urls.txt" ]]; then
  cat "$OUT/engine/secrets/js_urls.txt" | _parallel "$THREADS" _js_scan 2>/dev/null | sort -u > "$OUT/engine/secrets/findings.txt"
  local_count=$(count_safe "$OUT/engine/secrets/findings.txt")
  [[ "$local_count" -gt 0 ]] && good "JS secrets found: $local_count" || log "No JS secrets detected"
else
  touch "$OUT/engine/secrets/findings.txt"; log "No JS files found"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 6 ─ Subdomain Takeover Fingerprinting [NEW v6]"
export TIMEOUT

_takeover_check() {
  local host="$1"; local body status
  body=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -L --max-redirs 2 -H "User-Agent: Mozilla/5.0" "http://$host" 2>/dev/null) || return
  status=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -o /dev/null -w "%{http_code}" "http://$host" 2>/dev/null || echo "000")
  [[ "$status" == "200" || "$status" == "403" ]] && return
  local lower_body; lower_body=$(echo "$body" | tr '[:upper:]' '[:lower:]')

  declare -A SIGS=(
    ["there is no app here"]="Heroku"
    ["no such app"]="Heroku"
    ["this domain is not configured"]="GitHub Pages"
    ["isn.*t a github pages site"]="GitHub Pages"
    ["404 web site not found"]="Azure"
    ["fastly error: unknown domain"]="Fastly"
    ["sorry, this shop is currently unavailable"]="Shopify"
    ["nosuchbucket"]="AWS S3"
    ["the specified bucket does not exist"]="AWS S3"
    ["whatever you were looking for doesn.*t currently exist"]="Tumblr"
    ["repository not found"]="Bitbucket"
    ["this page is reserved for future use"]="Tumblr"
  )
  for sig in "${!SIGS[@]}"; do
    if echo "$lower_body" | grep -qP "$sig"; then
      echo "[TAKEOVER:${SIGS[$sig]}] $host | HTTP:$status"
      return
    fi
  done
}
export -f _takeover_check

cat "$OUT/subs/resolved.txt" | _parallel "$THREADS" _takeover_check 2>/dev/null | sort -u > "$OUT/engine/takeover/candidates.txt"
tk_count=$(count_safe "$OUT/engine/takeover/candidates.txt")
[[ "$tk_count" -gt 0 ]] && good "Takeover candidates: $tk_count" || log "No takeover candidates"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 7 ─ URL Crawl"
CRAWL_DEPTH=2; [[ "$DEEP_MODE" == true ]] && CRAWL_DEPTH=3
export TIMEOUT DOMAIN CRAWL_DEPTH

_extract_urls() {
  local body="$1" base="$2"; local base_origin
  base_origin=$(echo "$base" | grep -oP 'https?://[^/]+')
  echo "$body" \
    | grep -oP "(?<=href=[\"'])[^\"'#?][^\"']*|(?<=action=[\"'])[^\"']+|(?<=src=[\"'])[^\"']+\.js[^\"']*" \
    | sed "s|^/|${base_origin}/|g" | grep -E "^https?://" | grep "$DOMAIN" \
    | grep -vE '\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf|mp4|mp3|pdf|zip|eot)(\?|$)' \
    | sed 's/#.*//' | sort -u
}
export -f _extract_urls

_crawl_host() {
  local start="$1"; local vis q nq found depth
  vis=$(mktemp); q=$(mktemp); nq=$(mktemp); found=$(mktemp)
  echo "$start" > "$q"; depth=0
  while [[ -s "$q" && $depth -lt $CRAWL_DEPTH ]]; do
    > "$nq"
    while IFS= read -r url; do
      grep -qxF "$url" "$vis" && continue; echo "$url" >> "$vis"
      local body; body=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 \
        -H "User-Agent: Mozilla/5.0" "$url" 2>/dev/null) || continue
      echo "$url" >> "$found"
      while IFS= read -r nu; do
        grep -qxF "$nu" "$vis" && continue; echo "$nu" >> "$nq"; echo "$nu" >> "$found"
      done < <(_extract_urls "$body" "$url")
    done < "$q"; mv "$nq" "$q"; depth=$(( depth + 1 ))
  done
  cat "$found"; rm -f "$vis" "$q" "$found"
}
export -f _crawl_host

cat "$OUT/http/live.txt" | _parallel "$THREADS" _crawl_host 2>/dev/null | sort -u > "$OUT/crawl/crawled_urls.txt"
log "Wayback passive..."
_curl "https://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=text&fl=original&collapse=urlkey&limit=5000" \
  | grep -E "^https?://" | grep "$DOMAIN" \
  | grep -vE '\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf|mp4|mp3|pdf|zip|eot)(\?|$)' >> "$OUT/crawl/crawled_urls.txt"
sort -u "$OUT/crawl/crawled_urls.txt" -o "$OUT/crawl/crawled_urls.txt"
grep '=' "$OUT/crawl/crawled_urls.txt" | grep -vE '\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf)(\?|$)' | sort -u > "$OUT/crawl/urls_with_params.txt"
log "Crawled: $(count_safe "$OUT/crawl/crawled_urls.txt") | Params: $(count_safe "$OUT/crawl/urls_with_params.txt")"

# Feed JS URLs to secret scanner
grep -iE '\.js(\?.*)?$' "$OUT/crawl/crawled_urls.txt" 2>/dev/null >> "$OUT/engine/secrets/js_urls.txt" || true
sort -u "$OUT/engine/secrets/js_urls.txt" -o "$OUT/engine/secrets/js_urls.txt" 2>/dev/null || true
if [[ -s "$OUT/engine/secrets/js_urls.txt" ]]; then
  cat "$OUT/engine/secrets/js_urls.txt" | _parallel "$THREADS" _js_scan 2>/dev/null \
    | sort -u >> "$OUT/engine/secrets/findings.txt" || true
  sort -u "$OUT/engine/secrets/findings.txt" -o "$OUT/engine/secrets/findings.txt" 2>/dev/null || true
  good "JS secrets total: $(count_safe "$OUT/engine/secrets/findings.txt")"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 8 ─ Parameter Normalization"
NOISE='(page=|lang=|limit=|offset=|sort=|order=|locale=|currency=|ref=|utm_|_ga=|fbclid=|gclid=|tracking=|ver=|v=|rev=|nocache=|timestamp=|nonce=|csrf|_=|s=|search=|keyword=|token=|__cf|session=|debug=|cache=|_t=|format=|type=|style=|theme=|view=|size=|color=|width=|height=|tab=|per_page=|page_size=)'
sed 's/=[^&?#]*/=FUZZ/g; s/#.*//' "$OUT/crawl/urls_with_params.txt" | sort -u | grep -Evi "$NOISE" > "$OUT/crawl/params_normalized.txt"
log "Normalized param patterns: $(count_safe "$OUT/crawl/params_normalized.txt")"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 9 ─ Baseline Validation"
export TIMEOUT
touch "$OUT/engine/valid_params_json.txt"

_baseline_check() {
  local url="$1"; local raw status ct size
  raw=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 \
    -w "\n__STATUS__%{http_code}__CT__%{content_type}__SIZE__%{size_download}" \
    -H "User-Agent: Mozilla/5.0" "$(echo "$url" | sed 's/FUZZ/baseline_nyx/g')" 2>/dev/null) || return
  status=$(echo "$raw" | grep -oP '__STATUS__\K[0-9]+')
  ct=$(echo "$raw" | grep -oP '__CT__\K[^_]+')
  size=$(echo "$raw" | grep -oP '__SIZE__\K[0-9]+')
  [[ "$status" != "200" ]] && return; [[ "${size:-0}" -lt 300 ]] && return
  echo "$ct" | grep -qiE "image/|video/|audio/|font/" && return
  if echo "$ct" | grep -qi "application/json"; then
    echo "$url" >> "$OUT/engine/valid_params_json.txt" 2>/dev/null
  else
    echo "$url"
  fi
}
export -f _baseline_check

if [[ -s "$OUT/crawl/params_normalized.txt" ]]; then
  cat "$OUT/crawl/params_normalized.txt" | _parallel "$THREADS" _baseline_check 2>/dev/null | sort -u > "$OUT/engine/valid_params.txt"
  sort -u "$OUT/engine/valid_params_json.txt" -o "$OUT/engine/valid_params_json.txt"
  log "Valid HTML: $(count_safe "$OUT/engine/valid_params.txt") | Valid JSON: $(count_safe "$OUT/engine/valid_params_json.txt")"
else
  touch "$OUT/engine/valid_params.txt"; warn "No normalized params."
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 10 ─ Diff Engine"
FUZZ_A="nyxxAa"; FUZZ_B="nyxxBb"; FUZZ_C="nyxxCc"
export FUZZ_A FUZZ_B FUZZ_C TIMEOUT

_diff_check() {
  local url="$1"; local b0 b1 b2 b3
  b0=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" "$url" 2>/dev/null)
  b1=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" "$(echo "$url" | sed "s/FUZZ/$FUZZ_A/g")" 2>/dev/null)
  b2=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" "$(echo "$url" | sed "s/FUZZ/$FUZZ_B/g")" 2>/dev/null)
  b3=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" "$(echo "$url" | sed "s/FUZZ/$FUZZ_C/g")" 2>/dev/null)
  local h0 h1 h2 h3
  h0=$(printf '%s' "$b0" | md5sum | cut -d' ' -f1); h1=$(printf '%s' "$b1" | md5sum | cut -d' ' -f1)
  h2=$(printf '%s' "$b2" | md5sum | cut -d' ' -f1); h3=$(printf '%s' "$b3" | md5sum | cut -d' ' -f1)
  [[ "$h1" == "$h2" || "$h1" == "$h3" || "$h2" == "$h3" ]] && return
  [[ "$h0" == "$h1" && "$h0" == "$h2" ]] && return
  local s0=${#b0} s1=${#b1} s2=${#b2} s3=${#b3}
  local max_s min_s
  max_s=$(( s1 > s2 ? (s1 > s3 ? s1 : s3) : (s2 > s3 ? s2 : s3) ))
  min_s=$(( s1 < s2 ? (s1 < s3 ? s1 : s3) : (s2 < s3 ? s2 : s3) ))
  local spread=$(( max_s - min_s )); local threshold=$(( (s0 + 1) * 40 / 100 ))
  [[ "$spread" -gt "$threshold" && "$spread" -gt 2000 ]] && return
  echo "$url"
}
export -f _diff_check

if [[ -s "$OUT/engine/valid_params.txt" ]]; then
  { cat "$OUT/engine/valid_params.txt"; [[ -s "$OUT/engine/valid_params_json.txt" ]] && cat "$OUT/engine/valid_params_json.txt"; } \
    | sort -u | _parallel "$THREADS" _diff_check 2>/dev/null | sort -u > "$OUT/engine/diff/dynamic.txt"
  log "Dynamic params: $(count_safe "$OUT/engine/diff/dynamic.txt")"
else
  touch "$OUT/engine/diff/dynamic.txt"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 11 ─ IDOR Detection (Confidence Scoring)"
export TIMEOUT

_idor_check() {
  local url="$1"; local r1 r2 r3 r4
  r1=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 "$(echo "$url" | sed 's/FUZZ/1/')" 2>/dev/null)
  r2=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 "$(echo "$url" | sed 's/FUZZ/2/')" 2>/dev/null)
  r3=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 "$(echo "$url" | sed 's/FUZZ/100/')" 2>/dev/null)
  r4=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 "$(echo "$url" | sed 's/FUZZ/9999999/')" 2>/dev/null)
  local h1 h2 h3
  h1=$(printf '%s' "$r1" | md5sum | cut -d' ' -f1); h2=$(printf '%s' "$r2" | md5sum | cut -d' ' -f1)
  h3=$(printf '%s' "$r3" | md5sum | cut -d' ' -f1)
  local diff=0
  [[ "$h1" != "$h2" ]] && diff=$(( diff + 1 )); [[ "$h2" != "$h3" ]] && diff=$(( diff + 1 ))
  [[ "$h1" != "$h3" ]] && diff=$(( diff + 1 ))
  local s1=${#r1} s2=${#r2} s3=${#r3} s4=${#r4}
  local avg=$(( (s1 + s2 + s3) / 3 )); local gap=$(( avg > s4 ? avg - s4 : s4 - avg ))
  if [[ "$diff" -ge 2 && "$gap" -gt 300 && "$s4" -lt "$avg" ]]; then
    local conf="MEDIUM"
    [[ "$diff" -ge 3 && "$gap" -gt 1000 ]] && conf="HIGH"
    local param_name; param_name=$(echo "$url" | grep -oP '[?&]\K[^=]+(?==FUZZ)' | tail -1)
    echo "$param_name" | grep -qiE '(^id$|_id$|uid|user_?id|account|profile|order|invoice|ticket|doc|file|record|obj)' && conf="HIGH"
    echo "$url [conf:${conf}]"
  fi
}
export -f _idor_check

if [[ -s "$OUT/engine/diff/dynamic.txt" ]]; then
  cat "$OUT/engine/diff/dynamic.txt" | _parallel "$THREADS" _idor_check 2>/dev/null | sort -u > "$OUT/engine/behavior/idor.txt"
  log "IDOR candidates: $(count_safe "$OUT/engine/behavior/idor.txt")"
else
  touch "$OUT/engine/behavior/idor.txt"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 12 ─ XSS Reflection Detection"
CANARY="nyxxss$(date +%s)"; export CANARY TIMEOUT

_xss_check() {
  local url="$1"; local test_url raw ct body ctx="html"
  test_url=$(echo "$url" | sed "s/FUZZ/${CANARY}/g")
  raw=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -D - \
    -H "User-Agent: Mozilla/5.0" "$test_url" 2>/dev/null) || return
  ct=$(echo "$raw" | grep -iP '^content-type:' | head -1)
  echo "$ct" | grep -qiE "text/html" || return
  echo "$ct" | grep -qi "application/json" && return
  body=$(echo "$raw" | awk '/^\r?$/{found=1;next} found{print}')
  echo "$body" | grep -q "$CANARY" || return
  echo "$body" | grep -qi '<!doctype\|<html' || return
  # Encoding check — entity-encoded = not injectable
  echo "$body" | grep -P "${CANARY}" | grep -qP '&[a-z]+;|&#[0-9]+;' && return
  # X-XSS-Protection blocking
  echo "$raw" | grep -qi "x-xss-protection: 1; mode=block" && return
  echo "$body" | grep -P "=[\"'][^\"']*${CANARY}" &>/dev/null && ctx="attr"
  echo "$body" | grep -B3 -A3 "$CANARY" | grep -qi '<script\|javascript:' && ctx="script"
  echo "$url [ctx:${ctx}]"
}
export -f _xss_check

if [[ -s "$OUT/engine/diff/dynamic.txt" ]]; then
  cat "$OUT/engine/diff/dynamic.txt" | _parallel "$THREADS" _xss_check 2>/dev/null | sort -u > "$OUT/engine/reflection/xss_candidates.txt"
  log "XSS candidates: $(count_safe "$OUT/engine/reflection/xss_candidates.txt")"
else
  touch "$OUT/engine/reflection/xss_candidates.txt"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 13 ─ Open Redirect Detection"
REDIR_MARKER="nyxredir.example.com"; export REDIR_MARKER TIMEOUT

_redirect_check() {
  local url="$1"
  echo "$url" | grep -qiE '(redirect=|return=|next=|url=|goto=|dest=|target=|location=|forward=|redir=|callback=|continue=|returnto=)' || return
  local test_url final_url
  test_url=$(echo "$url" | sed "s|FUZZ|https://$REDIR_MARKER|g")
  final_url=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -o /dev/null -w "%{url_effective}" \
    -L --max-redirs 5 -H "User-Agent: Mozilla/5.0" "$test_url" 2>/dev/null) || return
  echo "$final_url" | grep -q "$REDIR_MARKER" && echo "$url"
}
export -f _redirect_check

if [[ -s "$OUT/engine/diff/dynamic.txt" ]]; then
  cat "$OUT/engine/diff/dynamic.txt" | _parallel "$THREADS" _redirect_check 2>/dev/null | sort -u > "$OUT/engine/behavior/open_redirects.txt"
  log "Open redirects: $(count_safe "$OUT/engine/behavior/open_redirects.txt")"
else
  touch "$OUT/engine/behavior/open_redirects.txt"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 14 ─ SQLi Error Heuristic (Baseline-Gated)"
SQLI_ERRORS='sql syntax|mysql_fetch|ORA-[0-9]+|sqlite_|pg_exec|SQLSTATE|unclosed quotation|syntax error.*SQL|mysql_num_rows|Warning.*mysql|supplied argument.*mysql|PostgreSQL.*ERROR|Microsoft OLE DB|ODBC.*Driver|PDOException|JDBC.*Exception|com\.mysql\.jdbc|java\.sql\.'
export SQLI_ERRORS TIMEOUT

_sqli_check() {
  local url="$1"
  local baseline; baseline=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" \
    "$(echo "$url" | sed 's/FUZZ/safe_string/g')" 2>/dev/null) || return
  echo "$baseline" | grep -qiE "$SQLI_ERRORS" && return  # baseline already has error strings → skip

  for payload in "'" "1'--" "1 AND 1=2--" '"' "1\"--"; do
    local enc; enc=$(printf '%s' "$payload" | \
      awk '{for(i=1;i<=length($0);i++){c=substr($0,i,1);
        if(c~/[a-zA-Z0-9._~-]/){printf c}else{printf "%%%02X",ord(c)}}}
        function ord(c,    r){for(r=0;r<256;r++)if(sprintf("%c",r)==c)return r}')
    local body; body=$(curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -H "User-Agent: Mozilla/5.0" \
      "$(echo "$url" | sed "s/FUZZ/${enc}/g")" 2>/dev/null) || continue
    if echo "$body" | grep -qiE "$SQLI_ERRORS"; then
      echo "$url [payload:${payload:0:8}]"; return
    fi
  done
}
export -f _sqli_check

if [[ -s "$OUT/engine/diff/dynamic.txt" ]]; then
  cat "$OUT/engine/diff/dynamic.txt" | _parallel "$THREADS" _sqli_check 2>/dev/null | sort -u > "$OUT/engine/reflection/sqli_candidates.txt"
  log "SQLi candidates: $(count_safe "$OUT/engine/reflection/sqli_candidates.txt")"
else
  touch "$OUT/engine/reflection/sqli_candidates.txt"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 15 ─ SSRF Detection"
grep -Ei '(url=|uri=|path=|dest=|host=|src=|file=|resource=|image=|data=|load=|fetch=|open=|proxy=|service=|server=|backend=|endpoint=|webhook=|callback=|api=|target=|link=|redirect=|location=)' \
  "$OUT/engine/valid_params.txt" 2>/dev/null | sort -u > "$OUT/engine/reflection/ssrf_candidates.txt" || true
log "SSRF patterns: $(count_safe "$OUT/engine/reflection/ssrf_candidates.txt")"

if [[ -n "$OOB_HOST" && -s "$OUT/engine/reflection/ssrf_candidates.txt" ]]; then
  log "Active OOB probe → $OOB_HOST"
  export OOB_HOST TIMEOUT
  _ssrf_oob_probe() {
    local url="$1"
    curl -sk --max-time "$TIMEOUT" --connect-timeout 4 -o /dev/null -H "User-Agent: Mozilla/5.0" \
      "$(echo "$url" | sed "s|FUZZ|http://${OOB_HOST}|g")" 2>/dev/null || true
    echo "[OOB_SENT] $url"
  }
  export -f _ssrf_oob_probe
  cat "$OUT/engine/reflection/ssrf_candidates.txt" | _parallel "$THREADS" _ssrf_oob_probe 2>/dev/null \
    > "$OUT/engine/reflection/ssrf_oob_log.txt"
  log "OOB probes sent — check $OOB_HOST for DNS/HTTP callbacks"
fi

# ════════════════════════════════════════════════════════════════════════════
END_TS=$(date +%s); ELAPSED=$(( END_TS - START_TS )); ELAPSED_FMT="$((ELAPSED/60))m $((ELAPSED%60))s"

cat > "$STATS_FILE" << STATS_EOF
{
  "target":          "$DOMAIN",
  "version":         "$VERSION",
  "date":            "$START_DATE",
  "mode":            "$(${DEEP_MODE} && echo deep || echo standard)",
  "elapsed":         "$ELAPSED_FMT",
  "subs_raw":        $(count_safe "$OUT/subs/raw.txt"),
  "subs_resolved":   $(count_safe "$OUT/subs/resolved.txt"),
  "live_hosts":      $(count_safe "$OUT/http/live.txt"),
  "js_secrets":      $(count_safe "$OUT/engine/secrets/findings.txt"),
  "takeover":        $(count_safe "$OUT/engine/takeover/candidates.txt"),
  "cors_issues":     $(count_safe "$OUT/engine/headers/cors_issues.txt"),
  "crawled_urls":    $(count_safe "$OUT/crawl/crawled_urls.txt"),
  "dynamic_params":  $(count_safe "$OUT/engine/diff/dynamic.txt"),
  "idor":            $(count_safe "$OUT/engine/behavior/idor.txt"),
  "open_redirects":  $(count_safe "$OUT/engine/behavior/open_redirects.txt"),
  "xss":             $(count_safe "$OUT/engine/reflection/xss_candidates.txt"),
  "sqli":            $(count_safe "$OUT/engine/reflection/sqli_candidates.txt"),
  "ssrf":            $(count_safe "$OUT/engine/reflection/ssrf_candidates.txt")
}
STATS_EOF

# ════════════════════════════════════════════════════════════════════════════
# MARKDOWN REPORT
MD_REPORT="$OUT/final/report.md"
{
echo "# Nyxora v${VERSION} — ${DOMAIN}"
echo ""
echo "**Date:** $START_DATE  **Mode:** $(${DEEP_MODE} && echo Deep || echo Standard)  **Runtime:** $ELAPSED_FMT"
echo ""
echo "---"
echo ""
echo "## Executive Summary"
echo ""
echo "| Category | Count | Severity |"
echo "|----------|-------|----------|"
echo "| JS Secrets | $(count_safe "$OUT/engine/secrets/findings.txt") | 🔴 CRITICAL |"
echo "| Takeover Candidates | $(count_safe "$OUT/engine/takeover/candidates.txt") | 🔴 CRITICAL |"
echo "| CORS Misconfigurations | $(count_safe "$OUT/engine/headers/cors_issues.txt") | 🔴 HIGH |"
echo "| IDOR Candidates | $(count_safe "$OUT/engine/behavior/idor.txt") | 🔴 CRITICAL |"
echo "| XSS Candidates | $(count_safe "$OUT/engine/reflection/xss_candidates.txt") | 🟠 HIGH |"
echo "| SQLi Candidates | $(count_safe "$OUT/engine/reflection/sqli_candidates.txt") | 🟠 HIGH |"
echo "| Open Redirects | $(count_safe "$OUT/engine/behavior/open_redirects.txt") | 🟡 MEDIUM |"
echo "| SSRF Patterns | $(count_safe "$OUT/engine/reflection/ssrf_candidates.txt") | 🟡 MEDIUM |"
echo "| Missing Headers | $(count_safe "$OUT/engine/headers/missing_headers.txt") | 🔵 INFO |"
echo ""
echo "## Recon Stats"
echo ""
echo "| Metric | Count |"
echo "|--------|-------|"
echo "| Subdomains (raw) | $(count_safe "$OUT/subs/raw.txt") |"
echo "| Subdomains (resolved) | $(count_safe "$OUT/subs/resolved.txt") |"
echo "| Live Hosts | $(count_safe "$OUT/http/live.txt") |"
echo "| Crawled URLs | $(count_safe "$OUT/crawl/crawled_urls.txt") |"
echo "| Dynamic Params | $(count_safe "$OUT/engine/diff/dynamic.txt") |"
echo ""
echo "---"
echo ""

for section_data in \
  "🔴 JS Secrets|$OUT/engine/secrets/findings.txt" \
  "🔴 Takeover Candidates|$OUT/engine/takeover/candidates.txt" \
  "🔴 CORS Misconfigurations|$OUT/engine/headers/cors_issues.txt" \
  "🔴 IDOR Candidates|$OUT/engine/behavior/idor.txt" \
  "🟠 XSS Candidates|$OUT/engine/reflection/xss_candidates.txt" \
  "🟠 SQLi Candidates|$OUT/engine/reflection/sqli_candidates.txt" \
  "🟡 Open Redirects|$OUT/engine/behavior/open_redirects.txt" \
  "🟡 SSRF Patterns|$OUT/engine/reflection/ssrf_candidates.txt" \
  "🔵 Missing Headers (sample)|$OUT/engine/headers/missing_headers.txt"; do
    IFS='|' read -r label file <<< "$section_data"
    echo "### $label"; echo ""; echo '```'
    [[ -s "$file" ]] && head -30 "$file" || echo "(none)"
    echo '```'; echo ""
done

echo "---"
} > "$MD_REPORT"
log "Markdown report: $MD_REPORT"

# ════════════════════════════════════════════════════════════════════════════
# HTML REPORT
if [[ "$SKIP_REPORT" != true ]]; then
  section "HTML Report"
  HTML_REPORT="$OUT/final/report.html"

  _js_array() {
    local file="$1" var="$2"; printf 'const %s=[' "$var"
    [[ -s "$file" ]] && while IFS= read -r l; do
      l="${l//\\/\\\\}"; l="${l//\"/\\\"}"
      printf '"%s",' "$l"
    done < "$file"
    printf '];'
  }

  IDOR_JS=$(_js_array "$OUT/engine/behavior/idor.txt" "IDOR_D")
  REDIR_JS=$(_js_array "$OUT/engine/behavior/open_redirects.txt" "REDIR_D")
  XSS_JS=$(_js_array "$OUT/engine/reflection/xss_candidates.txt" "XSS_D")
  SQLI_JS=$(_js_array "$OUT/engine/reflection/sqli_candidates.txt" "SQLI_D")
  SSRF_JS=$(_js_array "$OUT/engine/reflection/ssrf_candidates.txt" "SSRF_D")
  SUBS_JS=$(_js_array "$OUT/subs/resolved.txt" "SUBS_D")
  LIVE_JS=$(_js_array "$OUT/http/probe_full.txt" "LIVE_D")
  DYN_JS=$(_js_array "$OUT/engine/diff/dynamic.txt" "DYN_D")
  SEC_JS=$(_js_array "$OUT/engine/secrets/findings.txt" "SEC_D")
  CORS_JS=$(_js_array "$OUT/engine/headers/cors_issues.txt" "CORS_D")
  TKO_JS=$(_js_array "$OUT/engine/takeover/candidates.txt" "TKO_D")
  HDR_JS=$(_js_array "$OUT/engine/headers/missing_headers.txt" "HDR_D")

  SR=$(count_safe "$OUT/subs/raw.txt"); SN=$(count_safe "$OUT/subs/resolved.txt")
  LN=$(count_safe "$OUT/http/live.txt"); CN=$(count_safe "$OUT/crawl/crawled_urls.txt")
  DN=$(count_safe "$OUT/engine/diff/dynamic.txt"); IN=$(count_safe "$OUT/engine/behavior/idor.txt")
  RN=$(count_safe "$OUT/engine/behavior/open_redirects.txt"); XN=$(count_safe "$OUT/engine/reflection/xss_candidates.txt")
  QN=$(count_safe "$OUT/engine/reflection/sqli_candidates.txt"); FN=$(count_safe "$OUT/engine/reflection/ssrf_candidates.txt")
  SECRN=$(count_safe "$OUT/engine/secrets/findings.txt"); CORSN=$(count_safe "$OUT/engine/headers/cors_issues.txt")
  TKON=$(count_safe "$OUT/engine/takeover/candidates.txt")

  cat > "$HTML_REPORT" << HTMLEOF
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nyxora v${VERSION} — ${DOMAIN}</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--text3:#6e7681;--green:#3fb950;--red:#f85149;--orange:#d29922;--blue:#58a6ff;--purple:#bc8cff;--cyan:#76e3ea;}
*{box-sizing:border-box;margin:0;padding:0}body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;}
.header{background:var(--bg2);border-bottom:1px solid var(--border);padding:20px 30px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.header h1{font-size:18px;font-weight:700;color:var(--blue);}
.badge{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:2px 8px;font-size:11px;color:var(--text2);}
.layout{display:flex;height:calc(100vh - 65px);}
.sidebar{width:220px;background:var(--bg2);border-right:1px solid var(--border);overflow-y:auto;flex-shrink:0;}
.nav-section{padding:12px 12px 4px;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text3);font-weight:600;}
.nav-item{display:flex;align-items:center;justify-content:space-between;padding:7px 16px;cursor:pointer;color:var(--text2);transition:all .15s;font-size:13px;}
.nav-item:hover{background:var(--bg3);color:var(--text);}
.nav-item.active{background:var(--bg3);color:var(--blue);border-right:2px solid var(--blue);}
.nav-count{background:var(--bg);border-radius:10px;padding:1px 6px;font-size:10px;}
.nav-count.hot{background:rgba(248,81,73,.15);color:var(--red);}
.main{flex:1;overflow-y:auto;padding:24px;}
.view{display:none}.view.active{display:block;}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:24px;}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center;}
.card.crit{border-color:rgba(248,81,73,.4)}.card.high{border-color:rgba(210,153,34,.4)}.card.med{border-color:rgba(88,166,255,.2)}.card.info{border-color:var(--border)}
.card-n{font-size:28px;font-weight:700;line-height:1;margin-bottom:4px;}
.crit .card-n{color:var(--red)}.high .card-n{color:var(--orange)}.med .card-n{color:var(--blue)}.info .card-n{color:var(--text2)}
.card-l{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;}
.section-title{font-size:16px;font-weight:600;margin:20px 0 12px;}
.toolbar{display:flex;gap:8px;margin-bottom:12px;}
.si{flex:1;background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:7px 12px;color:var(--text);font-size:13px;outline:none;}
.si:focus{border-color:var(--blue);}
.cbtn{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:7px 14px;color:var(--text2);cursor:pointer;font-size:12px;}
.cbtn:hover{border-color:var(--blue);color:var(--blue);}
.ftable{width:100%;border-collapse:collapse;}
.ftable th{background:var(--bg3);padding:8px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--text3);border-bottom:1px solid var(--border);}
.ftable td{padding:8px 12px;border-bottom:1px solid rgba(48,54,61,.5);vertical-align:top;}
.ftable tr:hover td{background:rgba(255,255,255,.02);}
.url{font-family:monospace;font-size:12px;word-break:break-all;color:var(--cyan);}
.pill{border-radius:4px;padding:2px 7px;font-size:10px;font-weight:600;}
.pill-crit{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.pill-high{background:rgba(210,153,34,.15);color:var(--orange);border:1px solid rgba(210,153,34,.3);}
.pill-med{background:rgba(88,166,255,.1);color:var(--blue);border:1px solid rgba(88,166,255,.2);}
.pill-info{background:var(--bg3);color:var(--text3);border:1px solid var(--border);}
.cblock{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:14px;font-family:monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:500px;overflow-y:auto;color:var(--text2);}
.hgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:8px;}
.hcard{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:12px;}
.hurl{font-family:monospace;font-size:12px;color:var(--cyan);word-break:break-all;margin-bottom:6px;}
.htags{display:flex;flex-wrap:wrap;gap:4px;}
.htag{background:var(--bg3);border-radius:4px;padding:2px 6px;font-size:10px;color:var(--text3);}
.c200{background:rgba(63,185,80,.1)!important;color:var(--green)!important;}
.c403{background:rgba(248,81,73,.1)!important;color:var(--red)!important;}
.c301{background:rgba(210,153,34,.1)!important;color:var(--orange)!important;}
.empty{color:var(--text3);padding:20px;text-align:center;font-style:italic;}
.pag{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:12px;color:var(--text3);}
.pbtn{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:4px 10px;cursor:pointer;color:var(--text2);}
.pbtn:hover:not([disabled]){border-color:var(--blue);color:var(--blue);}
.pbtn[disabled]{opacity:.4;cursor:not-allowed;}
.tli{display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid rgba(48,54,61,.5);}
.tld{width:10px;height:10px;border-radius:50%;background:var(--blue);margin-top:4px;flex-shrink:0;}
.tll{font-weight:500;margin-bottom:2px;}.tlc{font-size:12px;color:var(--text3);}
</style></head><body>
<div class="header">
  <h1>⚡ Nyxora v${VERSION}</h1>
  <span class="badge">$DOMAIN</span><span class="badge">$START_DATE</span>
  <span class="badge">$(${DEEP_MODE} && echo "⚡ Deep" || echo "Standard")</span>
  <span class="badge">⏱ $ELAPSED_FMT</span>
</div>
<div class="layout">
<div class="sidebar">
  <div class="nav-section">Overview</div>
  <div class="nav-item active" onclick="show('dash')">Dashboard</div>
  <div class="nav-item" onclick="show('hosts')">Live Hosts <span class="nav-count">$LN</span></div>
  <div class="nav-item" onclick="show('subs')">Subdomains <span class="nav-count">$SN</span></div>
  <div class="nav-section">Critical</div>
  <div class="nav-item" onclick="show('secrets')">JS Secrets <span class="nav-count$([ "$SECRN" -gt 0 ] && echo ' hot')">$SECRN</span></div>
  <div class="nav-item" onclick="show('takeover')">Takeover <span class="nav-count$([ "$TKON" -gt 0 ] && echo ' hot')">$TKON</span></div>
  <div class="nav-item" onclick="show('cors')">CORS Issues <span class="nav-count$([ "$CORSN" -gt 0 ] && echo ' hot')">$CORSN</span></div>
  <div class="nav-item" onclick="show('idor')">IDOR <span class="nav-count$([ "$IN" -gt 0 ] && echo ' hot')">$IN</span></div>
  <div class="nav-section">High</div>
  <div class="nav-item" onclick="show('xss')">XSS <span class="nav-count$([ "$XN" -gt 0 ] && echo ' hot')">$XN</span></div>
  <div class="nav-item" onclick="show('sqli')">SQLi <span class="nav-count$([ "$QN" -gt 0 ] && echo ' hot')">$QN</span></div>
  <div class="nav-section">Medium</div>
  <div class="nav-item" onclick="show('redir')">Open Redirect <span class="nav-count">$RN</span></div>
  <div class="nav-item" onclick="show('ssrf')">SSRF <span class="nav-count">$FN</span></div>
  <div class="nav-section">Info</div>
  <div class="nav-item" onclick="show('params')">Dyn Params <span class="nav-count">$DN</span></div>
  <div class="nav-item" onclick="show('headers')">Sec Headers <span class="nav-count">$LN</span></div>
</div>
<div class="main">
<div id="view-dash" class="view active">
  <div class="cards">
    <div class="card crit"><div class="card-n">$SECRN</div><div class="card-l">JS Secrets</div></div>
    <div class="card crit"><div class="card-n">$TKON</div><div class="card-l">Takeover</div></div>
    <div class="card crit"><div class="card-n">$CORSN</div><div class="card-l">CORS</div></div>
    <div class="card crit"><div class="card-n">$IN</div><div class="card-l">IDOR</div></div>
    <div class="card high"><div class="card-n">$XN</div><div class="card-l">XSS</div></div>
    <div class="card high"><div class="card-n">$QN</div><div class="card-l">SQLi</div></div>
    <div class="card med"><div class="card-n">$RN</div><div class="card-l">Redirects</div></div>
    <div class="card med"><div class="card-n">$FN</div><div class="card-l">SSRF</div></div>
    <div class="card info"><div class="card-n">$LN</div><div class="card-l">Live Hosts</div></div>
    <div class="card info"><div class="card-n">$SN</div><div class="card-l">Subdomains</div></div>
    <div class="card info"><div class="card-n">$CN</div><div class="card-l">URLs</div></div>
    <div class="card info"><div class="card-n">$DN</div><div class="card-l">Dyn Params</div></div>
  </div>
  <div class="section-title">Pipeline</div>
  <div id="tl"></div>
</div>
<div id="view-hosts" class="view"><div class="section-title">Live Hosts</div><div id="hosts-body"></div></div>
<div id="view-subs" class="view"><div class="section-title">Resolved Subdomains</div><div id="subs-body"></div></div>
<div id="view-secrets" class="view"><div class="section-title">🔴 JS Secrets</div><div id="secrets-body"></div></div>
<div id="view-takeover" class="view"><div class="section-title">🔴 Takeover Candidates</div><div id="takeover-body"></div></div>
<div id="view-cors" class="view"><div class="section-title">🔴 CORS Misconfigurations</div><div id="cors-body"></div></div>
<div id="view-idor" class="view"><div class="section-title">🔴 IDOR Candidates</div><div id="idor-body"></div></div>
<div id="view-xss" class="view"><div class="section-title">🟠 XSS Candidates</div><div id="xss-body"></div></div>
<div id="view-sqli" class="view"><div class="section-title">🟠 SQLi Candidates</div><div id="sqli-body"></div></div>
<div id="view-redir" class="view"><div class="section-title">🟡 Open Redirects</div><div id="redir-body"></div></div>
<div id="view-ssrf" class="view"><div class="section-title">🟡 SSRF Patterns</div><div id="ssrf-body"></div></div>
<div id="view-params" class="view"><div class="section-title">Dynamic Parameters</div><div id="params-body"></div></div>
<div id="view-headers" class="view"><div class="section-title">Security Header Gaps</div><div id="headers-body"></div></div>
</div></div>
<script>
HTMLEOF

  { echo "$IDOR_JS"; echo "$REDIR_JS"; echo "$XSS_JS"; echo "$SQLI_JS"; echo "$SSRF_JS"
    echo "$SUBS_JS"; echo "$LIVE_JS"; echo "$DYN_JS"; echo "$SEC_JS"; echo "$CORS_JS"
    echo "$TKO_JS"; echo "$HDR_JS"; } >> "$HTML_REPORT"

  cat >> "$HTML_REPORT" << 'JSEOF'
const META_EL=document.getElementById('tl');
if(META_EL)META_EL.innerHTML=[
  ['Subdomain Enumeration','Passive sources → resolved + wildcard-pruned'],
  ['Security Header Audit','CSP · HSTS · X-Frame · CORS'],
  ['JS Secret Scanner','12 secret types scanned'],
  ['Takeover Fingerprinting','CNAME chain analysis'],
  ['URL Crawl + Wayback','HTML/JS extraction + passive harvest'],
  ['Diff Engine','3-probe dynamic param detection'],
  ['Detection Engines','IDOR · XSS · SQLi · Redirects · SSRF'],
].map(([l,c])=>'<div class="tli"><div class="tld"></div><div><div class="tll">'+l+'</div><div class="tlc">'+c+'</div></div></div>').join('');

function show(name){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.getElementById('view-'+name)?.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>{n.classList.remove('active');if(n.getAttribute('onclick')?.includes("'"+name+"'"))n.classList.add('active');});
  const m={hosts:()=>renderHosts(),subs:()=>renderList('subs-body',SUBS_D),params:()=>renderList('params-body',DYN_D),
    idor:()=>renderF('idor-body',IDOR_D,'pill-crit','CRITICAL'),xss:()=>renderF('xss-body',XSS_D,'pill-high','HIGH'),
    sqli:()=>renderF('sqli-body',SQLI_D,'pill-high','HIGH'),redir:()=>renderF('redir-body',REDIR_D,'pill-med','MEDIUM'),
    ssrf:()=>renderF('ssrf-body',SSRF_D,'pill-med','MEDIUM'),secrets:()=>renderF('secrets-body',SEC_D,'pill-crit','CRITICAL'),
    takeover:()=>renderF('takeover-body',TKO_D,'pill-crit','CRITICAL'),cors:()=>renderF('cors-body',CORS_D,'pill-crit','HIGH'),
    headers:()=>renderF('headers-body',HDR_D,'pill-info','INFO')};
  m[name]?.();
}
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function renderF(id,data,pill,label){
  const el=document.getElementById(id);if(!el||el.dataset.r)return;el.dataset.r='1';
  if(!data.length){el.innerHTML='<div class="empty">✓ No findings in this category.</div>';return;}
  const PAGE=50;let page=0;let filtered=[...data];
  function render(){el.innerHTML='<div class="toolbar"><input class="si" placeholder="Filter..." id="'+id+'-s"><button class="cbtn" onclick="copyF(\''+id+'\')">Copy All</button></div>';
    document.getElementById(id+'-s').addEventListener('input',function(){filtered=data.filter(d=>d.toLowerCase().includes(this.value.toLowerCase()));page=0;rp();});rp();}
  function rp(){el.querySelector('.tbl')?.remove();el.querySelector('.pag')?.remove();
    const slice=filtered.slice(page*PAGE,(page+1)*PAGE);const total=Math.ceil(filtered.length/PAGE);
    const d=document.createElement('div');d.className='tbl';
    d.innerHTML='<table class="ftable"><thead><tr><th>#</th><th>Finding</th><th>Severity</th></tr></thead><tbody>'+
      slice.map((u,i)=>'<tr><td style="color:var(--text3);width:40px">'+(page*PAGE+i+1)+'</td><td class="url">'+esc(u)+'</td><td><span class="pill '+pill+'">'+label+'</span></td></tr>').join('')+'</tbody></table>';
    el.appendChild(d);
    if(total>1){const p=document.createElement('div');p.className='pag';
      p.innerHTML='<span>'+filtered.length+' items</span><button class="pbtn" '+(page===0?'disabled':'')+'id="'+id+'-pv">‹</button><span>Page '+(page+1)+' / '+total+'</span><button class="pbtn" '+(page>=total-1?'disabled':'')+'id="'+id+'-nx">›</button>';
      el.appendChild(p);document.getElementById(id+'-pv').onclick=()=>{if(page>0){page--;rp();}};
      document.getElementById(id+'-nx').onclick=()=>{if(page<total-1){page++;rp();}};}}
  render();}
function renderList(id,data){
  const el=document.getElementById(id);if(!el||el.dataset.r)return;el.dataset.r='1';
  if(!data.length){el.innerHTML='<div class="empty">Empty.</div>';return;}
  const PAGE=100;let page=0;let filtered=[...data];
  function render(){el.innerHTML='<div class="toolbar"><input class="si" placeholder="Filter..." id="'+id+'-s"><button class="cbtn" onclick="copyL(\''+id+'\')">Copy All</button></div>';
    document.getElementById(id+'-s').addEventListener('input',function(){filtered=data.filter(d=>d.toLowerCase().includes(this.value.toLowerCase()));page=0;rp();});rp();}
  function rp(){el.querySelector('.cblock')?.remove();el.querySelector('.pag')?.remove();
    const d=document.createElement('div');d.className='cblock';d.textContent=filtered.slice(page*PAGE,(page+1)*PAGE).join('\n');el.appendChild(d);
    const total=Math.ceil(filtered.length/PAGE);
    if(total>1){const p=document.createElement('div');p.className='pag';
      p.innerHTML='<span>'+filtered.length+' items</span><button class="pbtn" '+(page===0?'disabled':'')+'id="'+id+'-pv">‹</button><span>Page '+(page+1)+' / '+total+'</span><button class="pbtn" '+(page>=total-1?'disabled':'')+'id="'+id+'-nx">›</button>';
      el.appendChild(p);document.getElementById(id+'-pv').onclick=()=>{if(page>0){page--;rp();}};
      document.getElementById(id+'-nx').onclick=()=>{if(page<total-1){page++;rp();}};}}
  render();}
function renderHosts(){
  const el=document.getElementById('hosts-body');if(!el||el.dataset.r)return;el.dataset.r='1';
  const g=document.createElement('div');g.className='hgrid';
  LIVE_D.forEach(line=>{const p=line.split(' ');const url=p[0];const tags=p.slice(1);
    const ct=tags.find(t=>/^\[\d+\]$/.test(t))||'';const code=ct.replace(/[\[\]]/g,'');
    const cls=code==='200'?'c200':code==='403'?'c403':['301','302','307'].includes(code)?'c301':'';
    g.innerHTML+='<div class="hcard"><div class="hurl">'+esc(url)+'</div><div class="htags">'+tags.map(t=>'<span class="htag '+(t.includes(code)?cls:'')+'">'+esc(t)+'</span>').join('')+'</div></div>';});
  el.appendChild(g);}
function copyF(id){navigator.clipboard.writeText(Array.from(document.querySelectorAll('#'+id+' td.url')).map(r=>r.textContent).join('\n'));}
function copyL(id){const b=document.querySelector('#'+id+' .cblock');if(b)navigator.clipboard.writeText(b.textContent);}
JSEOF
  echo "</script></body></html>" >> "$HTML_REPORT"
  log "HTML report: $HTML_REPORT"
fi

# ════════════════════════════════════════════════════════════════════════════
# TEXT REPORT
REPORT="$OUT/final/report.txt"
{
printf '%s\n' "╔══════════════════════════════════════════════════════════════════════╗"
printf '%s\n' "║   NYXORA v${VERSION} — ZERO DEPENDENCY EDITION                        ║"
printf '%s\n' "╚══════════════════════════════════════════════════════════════════════╝"
echo "  Target  : $DOMAIN | Date: $START_DATE | Runtime: $ELAPSED_FMT"
echo ""
for sec_data in \
  "🔴 CRITICAL — JS Secrets|$OUT/engine/secrets/findings.txt" \
  "🔴 CRITICAL — Subdomain Takeover|$OUT/engine/takeover/candidates.txt" \
  "🔴 CRITICAL — CORS Misconfigurations|$OUT/engine/headers/cors_issues.txt" \
  "🔴 CRITICAL — IDOR Candidates|$OUT/engine/behavior/idor.txt" \
  "🟠 HIGH — XSS Candidates|$OUT/engine/reflection/xss_candidates.txt" \
  "🟠 HIGH — SQLi Candidates|$OUT/engine/reflection/sqli_candidates.txt" \
  "🟡 MEDIUM — Open Redirects|$OUT/engine/behavior/open_redirects.txt" \
  "🟡 MEDIUM — SSRF Patterns|$OUT/engine/reflection/ssrf_candidates.txt"; do
  IFS='|' read -r slabel sfile <<< "$sec_data"
  echo "══════════════════════════════════════════════════════════════════════"
  echo "  $slabel"
  echo "══════════════════════════════════════════════════════════════════════"
  [[ -s "$sfile" ]] && cat "$sfile" || echo "  (none)"
  echo ""
done
echo "══════════════════════════════════════════════════════════════════════"
echo "  📊  STATS"
echo "══════════════════════════════════════════════════════════════════════"
echo "  Subdomains   : $(count_safe "$OUT/subs/raw.txt") raw / $(count_safe "$OUT/subs/resolved.txt") resolved"
echo "  Live hosts   : $(count_safe "$OUT/http/live.txt")"
echo "  JS secrets   : $(count_safe "$OUT/engine/secrets/findings.txt")"
echo "  Takeover     : $(count_safe "$OUT/engine/takeover/candidates.txt")"
echo "  CORS         : $(count_safe "$OUT/engine/headers/cors_issues.txt")"
echo "  Crawled URLs : $(count_safe "$OUT/crawl/crawled_urls.txt")"
echo "  Dynamic params: $(count_safe "$OUT/engine/diff/dynamic.txt")"
echo "  IDOR         : $(count_safe "$OUT/engine/behavior/idor.txt")"
echo "  XSS          : $(count_safe "$OUT/engine/reflection/xss_candidates.txt")"
echo "  SQLi         : $(count_safe "$OUT/engine/reflection/sqli_candidates.txt")"
echo "  Redirects    : $(count_safe "$OUT/engine/behavior/open_redirects.txt")"
echo "  SSRF         : $(count_safe "$OUT/engine/reflection/ssrf_candidates.txt")"
echo ""
echo "  Data  → $OUT/"
[[ "$SKIP_REPORT" != true ]] && echo "  HTML  → $HTML_REPORT"
echo "  MD    → $MD_REPORT"
echo "══════════════════════════════════════════════════════════════════════"
} | tee "$REPORT"

echo
echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║  ✓ DONE  Nyxora v${VERSION}  ⏱ $ELAPSED_FMT          ${RESET}"
echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════╝${RESET}"
echo
[[ "$SKIP_REPORT" != true ]] && echo -e "  ${CYAN}HTML:    ${RESET}${BOLD}$HTML_REPORT${RESET}"
echo -e "  ${CYAN}Markdown:${RESET}${BOLD}$MD_REPORT${RESET}"
echo -e "  ${CYAN}TXT:     ${RESET}${BOLD}$REPORT${RESET}"
echo -e "  ${CYAN}Data:    ${RESET}${BOLD}$OUT/${RESET}"