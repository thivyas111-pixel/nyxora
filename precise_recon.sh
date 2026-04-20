#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  PRECISE RECON v4  —  Bug Bounty Recon Framework
#  Maximum signal · Minimum false positives · Full HTML report
#  github.com/your-handle/precise-recon
# ═══════════════════════════════════════════════════════════════

set -euo pipefail
IFS=$'\n\t'

# ── COLORS ────────────────────────────────────────────────────
RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; DIM='\033[2m'
RESET='\033[0m'; BG_RED='\033[41m'; BG_GREEN='\033[42m'

# ── ARGS & CONFIG ─────────────────────────────────────────────
print_banner() {
cat << 'EOF'
                                                              
  ██████╗ ██████╗ ███████╗ ██████╗██╗███████╗███████╗        
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝██╔════╝        
  ██████╔╝██████╔╝█████╗  ██║     ██║███████╗█████╗          
  ██╔═══╝ ██╔══██╗██╔══╝  ██║     ██║╚════██║██╔══╝          
  ██║     ██║  ██║███████╗╚██████╗██║███████║███████╗        
  ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝╚══════╝╚══════╝        
                                                              
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗                
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║                
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║                
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║                
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║                
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝  v4.0          
                                                              
EOF
  echo -e "  ${DIM}Bug Bounty Recon Framework · Maximum signal, minimum noise${RESET}"
  echo -e "  ${DIM}──────────────────────────────────────────────────────────${RESET}"
  echo
}

usage() {
  echo -e "${BOLD}Usage:${RESET}  $0 <domain> [options]"
  echo
  echo -e "${BOLD}Options:${RESET}"
  echo "  --deep        Deep crawl (depth 4, enables amass, gau)"
  echo "  --out <dir>   Custom output directory"
  echo "  --no-report   Skip HTML report generation"
  echo "  --threads-dns <n>   DNS threads  (default: 50)"
  echo "  --threads-http <n>  HTTP threads (default: 30)"
  echo "  --threads-curl <n>  Curl threads (default: 15)"
  echo "  --help        Show this help"
  echo
  echo -e "${BOLD}Examples:${RESET}"
  echo "  $0 example.com"
  echo "  $0 example.com --deep"
  echo "  $0 example.com --out /tmp/myrecon"
  echo
  exit 0
}

# ── PARSE ARGUMENTS ───────────────────────────────────────────
DOMAIN=""
DEEP_MODE=false
CUSTOM_OUT=""
SKIP_REPORT=false
T_DNS=50; T_HTTP=30; T_CURL=15

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deep)         DEEP_MODE=true; shift ;;
    --no-report)    SKIP_REPORT=true; shift ;;
    --out)          CUSTOM_OUT="$2"; shift 2 ;;
    --threads-dns)  T_DNS="$2"; shift 2 ;;
    --threads-http) T_HTTP="$2"; shift 2 ;;
    --threads-curl) T_CURL="$2"; shift 2 ;;
    --help|-h)      print_banner; usage ;;
    -*)             echo "Unknown option: $1"; exit 1 ;;
    *)              [[ -z "$DOMAIN" ]] && DOMAIN="$1" || { echo "Unexpected argument: $1"; exit 1; }; shift ;;
  esac
done

[[ -z "$DOMAIN" ]] && { print_banner; usage; }

# Sanitize domain
DOMAIN="${DOMAIN,,}"
DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"

RATE_HTTP=30
TIMEOUT_HTTP=8
TIMEOUT_CURL=7
START_TS=$(date +%s)
START_DATE=$(date '+%Y-%m-%d %H:%M:%S')

if [[ -n "$CUSTOM_OUT" ]]; then
  OUT="$CUSTOM_OUT"
else
  OUT="$HOME/recon-$DOMAIN-$(date +%Y%m%d-%H%M)"
fi

mkdir -p "$OUT"/{subs,http,crawl,engine/{diff,behavior,reflection},final,logs}

# ── LOGGING ───────────────────────────────────────────────────
LOGFILE="$OUT/logs/run.log"
STATS_FILE="$OUT/logs/stats.json"

log()  {
  local ts="[$(date +%T)]"
  local msg="$*"
  echo -e "${CYAN}${ts}${RESET} ${GREEN}[+]${RESET} $msg"
  echo "$ts [+] $msg" >> "$LOGFILE"
}
warn() {
  local ts="[$(date +%T)]"
  local msg="$*"
  echo -e "${CYAN}${ts}${RESET} ${ORANGE}[!]${RESET} $msg"
  echo "$ts [!] $msg" >> "$LOGFILE"
}
section() {
  echo
  echo -e "${BOLD}${BLUE}┌─────────────────────────────────────────────────┐${RESET}"
  echo -e "${BOLD}${BLUE}│  $*${RESET}"
  echo -e "${BOLD}${BLUE}└─────────────────────────────────────────────────┘${RESET}"
}
die()  { warn "$*"; exit 1; }
count_safe() { [[ -f "$1" ]] && wc -l < "$1" || echo "0"; }

# ── AUTO-INSTALLER ────────────────────────────────────────────
print_banner
section "CHECKING & INSTALLING DEPENDENCIES"

# Ensure Go is available
ensure_go() {
  if command -v go &>/dev/null; then
    echo -e "  ${GREEN}✓${RESET} go $(go version | awk '{print $3}')"
    return 0
  fi
  echo -e "  ${ORANGE}[*]${RESET} Go not found — installing..."
  local arch; arch=$(uname -m)
  local goarch="amd64"
  [[ "$arch" == "aarch64" || "$arch" == "arm64" ]] && goarch="arm64"
  local GO_VER="1.22.3"
  local tarball="go${GO_VER}.linux-${goarch}.tar.gz"
  curl -fsSL "https://go.dev/dl/$tarball" -o "/tmp/$tarball" || die "Failed to download Go"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "/tmp/$tarball"
  export PATH="$PATH:/usr/local/go/bin"
  echo -e "  ${GREEN}✓${RESET} Go installed"
}

# Install a Go binary tool
install_go_tool() {
  local name="$1" pkg="$2"
  if command -v "$name" &>/dev/null; then
    echo -e "  ${GREEN}✓${RESET} $name"
    return 0
  fi
  echo -e "  ${ORANGE}[*]${RESET} Installing $name..."
  GOPATH="${GOPATH:-$HOME/go}" GOBIN="$HOME/go/bin" \
    /usr/local/go/bin/go install "$pkg" 2>/dev/null \
    || go install "$pkg" 2>/dev/null \
    || { echo -e "  ${RED}✗${RESET} Failed to install $name"; return 1; }
  # Add ~/go/bin to PATH for this session if not already there
  [[ ":$PATH:" != *":$HOME/go/bin:"* ]] && export PATH="$PATH:$HOME/go/bin"
  echo -e "  ${GREEN}✓${RESET} $name installed"
}

# Install apt package quietly
install_apt() {
  local pkg="$1"
  if command -v "$pkg" &>/dev/null; then
    echo -e "  ${GREEN}✓${RESET} $pkg"
    return 0
  fi
  echo -e "  ${ORANGE}[*]${RESET} Installing $pkg via apt..."
  sudo apt-get install -y -qq "$pkg" 2>/dev/null \
    && echo -e "  ${GREEN}✓${RESET} $pkg installed" \
    || echo -e "  ${RED}✗${RESET} Could not install $pkg (non-fatal)"
}

# ── Run installer ──────────────────────────────────────────────
# Add ~/go/bin to PATH now in case tools were previously installed
[[ ":$PATH:" != *":$HOME/go/bin:"* ]] && export PATH="$PATH:$HOME/go/bin"

ensure_go

install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
install_go_tool "dnsx"        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest"
install_apt     "parallel"

# Optional
HAS_PARALLEL=false; command -v parallel &>/dev/null && HAS_PARALLEL=true
HAS_AMASS=false;    command -v amass    &>/dev/null && HAS_AMASS=true
HAS_GAU=false;      command -v gau      &>/dev/null && HAS_GAU=true

# Final check — these must exist by now
MISSING=()
for tool in subfinder assetfinder dnsx httpx katana curl sort awk grep md5sum wc; do
  command -v "$tool" &>/dev/null || MISSING+=("$tool")
done
[[ ${#MISSING[@]} -gt 0 ]] && die "Still missing after install attempt: ${MISSING[*]}"

echo -e "\n  ${GREEN}${BOLD}All tools ready.${RESET}"

echo
log "Target     : ${BOLD}$DOMAIN${RESET}"
log "Output dir : $OUT"
log "Deep mode  : $DEEP_MODE"
log "Threads    : DNS=$T_DNS  HTTP=$T_HTTP  curl=$T_CURL"

# ── STEP 1: SUBDOMAIN ENUMERATION ────────────────────────────
section "STEP 1 ─ Subdomain Enumeration"

{
  subfinder -silent -d "$DOMAIN" -all 2>/dev/null &
  assetfinder --subs-only "$DOMAIN" 2>/dev/null &
  curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null \
    | grep -oP '"name_value":"\K[^"]+' \
    | tr ',' '\n' \
    | sed 's/^\*\.//' &
  # AlienVault OTX passive source
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" 2>/dev/null \
    | grep -oP '"hostname":"\K[^"]+' | grep "\.$DOMAIN$" &
  # Hackertarget API
  curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null \
    | cut -d',' -f1 &
  [[ "$HAS_AMASS" == true && "$DEEP_MODE" == true ]] && \
    amass enum -passive -d "$DOMAIN" -silent 2>/dev/null &
  wait
} | tr '[:upper:]' '[:lower:]' \
  | grep -E "^[a-z0-9._-]+\.$DOMAIN$" \
  | grep -v '\.\.' \
  | sort -u \
  > "$OUT/subs/raw.txt"

log "Raw subdomains: $(count_safe "$OUT/subs/raw.txt")"

# ── STEP 2: DNS RESOLUTION + WILDCARD FILTER ─────────────────
section "STEP 2 ─ DNS Resolution + Wildcard Pruning"

WILD_TEST="nonexistent-pr4-$(date +%s).$DOMAIN"
WILD_IPS=$(dnsx -silent -a -resp -d "$WILD_TEST" 2>/dev/null \
  | awk '{print $NF}' | tr -d '[]' || true)

dnsx -l "$OUT/subs/raw.txt" \
  -silent \
  -threads "$T_DNS" \
  -a -cname \
  -resp \
  2>/dev/null \
> "$OUT/subs/resolved_raw.txt"

{
  echo "$WILD_IPS" | tr ' ' '\n' | grep -E '^[0-9]+\.' || true
  awk '{print $NF}' "$OUT/subs/resolved_raw.txt" \
    | tr -d '[]' \
    | sort | uniq -c | sort -rn \
    | awk '$1 > 8 {print $2}'
} | sort -u | grep -E '^[0-9]' > "$OUT/subs/wildcard_ips.txt" || true

log "Wildcard IPs detected: $(count_safe "$OUT/subs/wildcard_ips.txt")"

if [[ -s "$OUT/subs/wildcard_ips.txt" ]]; then
  grep -vFf "$OUT/subs/wildcard_ips.txt" "$OUT/subs/resolved_raw.txt" \
    | awk '{print $1}' > "$OUT/subs/resolved.txt"
else
  awk '{print $1}' "$OUT/subs/resolved_raw.txt" > "$OUT/subs/resolved.txt"
fi

log "Resolved (after wildcard filter): $(count_safe "$OUT/subs/resolved.txt")"

# ── STEP 3: HTTP PROBING ──────────────────────────────────────
section "STEP 3 ─ HTTP Probing"

httpx -l "$OUT/subs/resolved.txt" \
  -silent \
  -no-color \
  -threads "$T_HTTP" \
  -rate-limit "$RATE_HTTP" \
  -timeout "$TIMEOUT_HTTP" \
  -status-code \
  -content-length \
  -title \
  -tech-detect \
  -follow-redirects \
  -max-redirects 3 \
  -mc 200,201,301,302,307,401,403 \
  -ml 200 \
  2>/dev/null \
> "$OUT/http/probe_full.txt"

awk '{print $1}' "$OUT/http/probe_full.txt" > "$OUT/http/live.txt"

log "Live hosts: $(count_safe "$OUT/http/live.txt")"
[[ ! -s "$OUT/http/live.txt" ]] && die "No live hosts found. Exiting."

# ── STEP 4: URL COLLECTION ────────────────────────────────────
section "STEP 4 ─ URL Collection"

CRAWL_DEPTH=2
[[ "$DEEP_MODE" == true ]] && CRAWL_DEPTH=4

katana -list "$OUT/http/live.txt" \
  -silent \
  -depth "$CRAWL_DEPTH" \
  -concurrency "$T_CRAWL" \
  -timeout "$TIMEOUT_HTTP" \
  -jc \
  -ef jpg,jpeg,png,gif,svg,woff,woff2,ttf,css,ico,mp4,mp3,zip,pdf \
  2>/dev/null \
> "$OUT/crawl/katana.txt" || true

if $HAS_GAU && [[ "$DEEP_MODE" == true ]]; then
  log "Running gau (deep mode)..."
  gau --threads "$T_CRAWL" --blacklist png,jpg,gif,css,svg,ico,woff "$DOMAIN" \
    2>/dev/null >> "$OUT/crawl/katana.txt" || true
fi

sort -u "$OUT/crawl/katana.txt" \
  | grep '=' \
  | grep -Ev '\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf|mp4|mp3|pdf|zip)(\?|$)' \
  > "$OUT/crawl/urls_with_params.txt"

log "Parameterized URLs: $(count_safe "$OUT/crawl/urls_with_params.txt")"

# ── STEP 5: PARAM NORMALIZATION ───────────────────────────────
section "STEP 5 ─ Param Normalization"

sed 's/=[^&]*/=FUZZ/g; s/#.*//' "$OUT/crawl/urls_with_params.txt" \
  | sort -u \
  | grep -Evi '(page|lang|limit|offset|sort|order|locale|currency|ref=|utm_|_ga=|fbclid=|gclid=|tracking|ver=|v=|rev=|nocache|timestamp|nonce|csrf|_=|s=|q=|search=|keyword=)' \
  > "$OUT/crawl/params_normalized.txt"

log "Normalized param patterns: $(count_safe "$OUT/crawl/params_normalized.txt")"
[[ ! -s "$OUT/crawl/params_normalized.txt" ]] && die "No params to test. Exiting."

# ── STEP 6: BASELINE VALIDATION ───────────────────────────────
section "STEP 6 ─ Baseline Validation"

_baseline_check() {
  local url="$1"
  local resp http_code ct size
  resp=$(curl -sk \
    --max-time "$TIMEOUT_CURL" \
    --retry 1 --retry-delay 1 \
    -w "\n__STATUS__%{http_code}__CT__%{content_type}" \
    "$url" 2>/dev/null) || return

  http_code=$(echo "$resp" | grep -oP '__STATUS__\K[0-9]+' || echo "0")
  ct=$(echo "$resp"        | grep -oP '__CT__\K.*'         || echo "")
  size=$(echo "$resp" | wc -c)

  [[ "$http_code" != "200" ]] && return
  [[ "$size" -lt 300 ]] && return
  echo "$ct" | grep -qi "application/json" && return
  echo "$ct" | grep -qiE "image/|video/|audio/|font/" && return

  echo "$url"
}

export -f _baseline_check
export TIMEOUT_CURL

if $HAS_PARALLEL; then
  parallel --jobs "$T_CURL" --no-notice _baseline_check {} \
    < "$OUT/crawl/params_normalized.txt" \
    > "$OUT/engine/valid_params.txt"
else
  xargs -P "$T_CURL" -I{} bash -c '_baseline_check "$@"' _ {} \
    < "$OUT/crawl/params_normalized.txt" \
    > "$OUT/engine/valid_params.txt"
fi

log "Valid params (200, body OK): $(count_safe "$OUT/engine/valid_params.txt")"
[[ ! -s "$OUT/engine/valid_params.txt" ]] && die "Nothing to test after baseline. Exiting."

# ── STEP 7: DIFF ENGINE ───────────────────────────────────────
section "STEP 7 ─ Diff Engine (Dynamic Param Detection)"

FUZZ_A="pr4x1a"; FUZZ_B="pr4x2b"; FUZZ_C="pr4x3c"

_diff_check() {
  local url="$1"
  local body_base body1 body2 body3
  body_base=$(curl -sk --max-time "$TIMEOUT_CURL" "$url" 2>/dev/null)
  body1=$(curl -sk --max-time "$TIMEOUT_CURL" "$(echo "$url" | sed "s/FUZZ/$FUZZ_A/g")" 2>/dev/null)
  body2=$(curl -sk --max-time "$TIMEOUT_CURL" "$(echo "$url" | sed "s/FUZZ/$FUZZ_B/g")" 2>/dev/null)
  body3=$(curl -sk --max-time "$TIMEOUT_CURL" "$(echo "$url" | sed "s/FUZZ/$FUZZ_C/g")" 2>/dev/null)

  local hbase h1 h2 h3
  hbase=$(echo "$body_base" | md5sum | cut -d' ' -f1)
  h1=$(echo "$body1" | md5sum | cut -d' ' -f1)
  h2=$(echo "$body2" | md5sum | cut -d' ' -f1)
  h3=$(echo "$body3" | md5sum | cut -d' ' -f1)

  local s1=${#body1} s2=${#body2} s3=${#body3} sbase=${#body_base}

  [[ "$hbase" == "$h1" && "$hbase" == "$h2" ]] && return
  [[ "$h1" == "$h2" || "$h1" == "$h3" || "$h2" == "$h3" ]] && return

  local max_s min_s size_range threshold
  max_s=$(( s1 > s2 ? (s1 > s3 ? s1 : s3) : (s2 > s3 ? s2 : s3) ))
  min_s=$(( s1 < s2 ? (s1 < s3 ? s1 : s3) : (s2 < s3 ? s2 : s3) ))
  size_range=$(( max_s - min_s ))
  threshold=$(( (sbase + 1) * 40 / 100 ))
  [[ "$size_range" -gt "$threshold" && "$size_range" -gt 2000 ]] && return

  echo "$url"
}

export -f _diff_check
export TIMEOUT_CURL FUZZ_A FUZZ_B FUZZ_C

if $HAS_PARALLEL; then
  parallel --jobs "$T_CURL" --no-notice _diff_check {} \
    < "$OUT/engine/valid_params.txt" > "$OUT/engine/diff/dynamic.txt"
else
  xargs -P "$T_CURL" -I{} bash -c '_diff_check "$@"' _ {} \
    < "$OUT/engine/valid_params.txt" > "$OUT/engine/diff/dynamic.txt"
fi

sort -u "$OUT/engine/diff/dynamic.txt" -o "$OUT/engine/diff/dynamic.txt"
log "Dynamic params confirmed: $(count_safe "$OUT/engine/diff/dynamic.txt")"

# ── STEP 8: BEHAVIOR ENGINE (IDOR) ────────────────────────────
section "STEP 8 ─ Behavior Engine (IDOR / Logic Flaws)"

_behavior_check() {
  local url="$1"
  local r1 r2 r3 r4
  r1=$(curl -sk --max-time "$TIMEOUT_CURL" "$(echo "$url" | sed 's/FUZZ/1/')" 2>/dev/null)
  r2=$(curl -sk --max-time "$TIMEOUT_CURL" "$(echo "$url" | sed 's/FUZZ/2/')" 2>/dev/null)
  r3=$(curl -sk --max-time "$TIMEOUT_CURL" "$(echo "$url" | sed 's/FUZZ/100/')" 2>/dev/null)
  r4=$(curl -sk --max-time "$TIMEOUT_CURL" "$(echo "$url" | sed 's/FUZZ/9999999/')" 2>/dev/null)

  local h1=$(echo "$r1"|md5sum|cut -d' ' -f1)
  local h2=$(echo "$r2"|md5sum|cut -d' ' -f1)
  local h3=$(echo "$r3"|md5sum|cut -d' ' -f1)
  local s1=${#r1} s2=${#r2} s3=${#r3} s4=${#r4}

  local hash_diff=0
  [[ "$h1" != "$h2" ]] && hash_diff=$(( hash_diff + 1 ))
  [[ "$h2" != "$h3" ]] && hash_diff=$(( hash_diff + 1 ))
  [[ "$h1" != "$h3" ]] && hash_diff=$(( hash_diff + 1 ))

  local size_valid=$(( (s1 + s2 + s3) / 3 ))
  local size_gap=$(( size_valid > s4 ? size_valid - s4 : s4 - size_valid ))

  local strong_idor=false
  [[ "$hash_diff" -ge 2 ]] && strong_idor=true
  [[ "$size_gap" -gt 300 && "$s4" -lt "$size_valid" ]] && strong_idor=true

  $strong_idor && echo "$url"
}

export -f _behavior_check
export TIMEOUT_CURL

if $HAS_PARALLEL; then
  parallel --jobs "$T_CURL" --no-notice _behavior_check {} \
    < "$OUT/engine/diff/dynamic.txt" > "$OUT/engine/behavior/idor.txt"
else
  xargs -P "$T_CURL" -I{} bash -c '_behavior_check "$@"' _ {} \
    < "$OUT/engine/diff/dynamic.txt" > "$OUT/engine/behavior/idor.txt"
fi

sort -u "$OUT/engine/behavior/idor.txt" -o "$OUT/engine/behavior/idor.txt"
log "IDOR candidates: $(count_safe "$OUT/engine/behavior/idor.txt")"

# ── STEP 9: REFLECTION ENGINE (XSS) ──────────────────────────
section "STEP 9 ─ Reflection Engine (XSS Signal)"

CANARY_BASE="pr4recon$(date +%s)"
CANARY_TAG="${CANARY_BASE}tag"
CANARY_ATTR="${CANARY_BASE}attr"

_reflect_check() {
  local url="$1" ctag="$2" cattr="$3"
  local url_tag body_tag ct_tag
  url_tag=$(echo "$url" | sed "s/FUZZ/$ctag/g")
  body_tag=$(curl -sk --max-time "$TIMEOUT_CURL" "$url_tag" 2>/dev/null)
  ct_tag=$(curl -sk -I --max-time 4 "$url_tag" 2>/dev/null \
    | grep -i "^content-type:" | head -1 || echo "")

  echo "$ct_tag" | grep -qiE "text/html" || return
  echo "$ct_tag" | grep -qi "application/json" && return
  echo "$body_tag" | grep -q "$ctag" || return
  echo "$body_tag" | grep -qi "<html\|<!DOCTYPE" || return
  echo "$body_tag" | grep -q "$(echo "$ctag" | sed 's/a/&#97;/g')" && return

  local url_attr body_attr context_type="html"
  url_attr=$(echo "$url" | sed "s/FUZZ/$cattr/g")
  body_attr=$(curl -sk --max-time "$TIMEOUT_CURL" "$url_attr" 2>/dev/null)

  echo "$body_attr" | grep -q "=\"[^\"]*$cattr\|='[^']*$cattr" && context_type="attr"
  echo "$body_tag"  | grep -B5 -A5 "$ctag" | grep -qi "<script\|javascript:" && context_type="script"

  echo "$url [ctx:$context_type]"
}

export -f _reflect_check
export TIMEOUT_CURL CANARY_TAG CANARY_ATTR

if $HAS_PARALLEL; then
  parallel --jobs "$T_CURL" --no-notice \
    _reflect_check {} "$CANARY_TAG" "$CANARY_ATTR" \
    < "$OUT/engine/diff/dynamic.txt" > "$OUT/engine/reflection/xss_candidates.txt"
else
  xargs -P "$T_CURL" -I{} bash -c \
    '_reflect_check "$@"' _ {} "$CANARY_TAG" "$CANARY_ATTR" \
    < "$OUT/engine/diff/dynamic.txt" > "$OUT/engine/reflection/xss_candidates.txt"
fi

sort -u "$OUT/engine/reflection/xss_candidates.txt" -o "$OUT/engine/reflection/xss_candidates.txt"
log "XSS candidates: $(count_safe "$OUT/engine/reflection/xss_candidates.txt")"

# ── STEP 10: OPEN REDIRECT DETECTION ─────────────────────────
section "STEP 10 ─ Open Redirect Detection"

REDIRECT_CANARY="https://recon.interactsh.com"

_redirect_check() {
  local url="$1" canary="$2"
  echo "$url" | grep -qiE '(redirect|return|next|url|goto|dest|target|location|ref|forward|redir|callback)=' || return

  local test_url final_url
  test_url=$(echo "$url" | sed "s|FUZZ|$canary|g")
  final_url=$(curl -sk --max-time "$TIMEOUT_CURL" \
    -o /dev/null -w "%{url_effective}" -L --max-redirs 5 "$test_url" 2>/dev/null) || return

  echo "$final_url" | grep -q "interactsh.com" || return
  echo "$url"
}

export -f _redirect_check
export TIMEOUT_CURL REDIRECT_CANARY

if $HAS_PARALLEL; then
  parallel --jobs "$T_CURL" --no-notice \
    _redirect_check {} "$REDIRECT_CANARY" \
    < "$OUT/engine/diff/dynamic.txt" > "$OUT/engine/behavior/open_redirects.txt"
else
  xargs -P "$T_CURL" -I{} bash -c \
    '_redirect_check "$@"' _ {} "$REDIRECT_CANARY" \
    < "$OUT/engine/diff/dynamic.txt" > "$OUT/engine/behavior/open_redirects.txt"
fi

sort -u "$OUT/engine/behavior/open_redirects.txt" -o "$OUT/engine/behavior/open_redirects.txt"
log "Open redirects: $(count_safe "$OUT/engine/behavior/open_redirects.txt")"

# ── STEP 11: SQLI HEURISTIC ───────────────────────────────────
section "STEP 11 ─ SQLi Error Heuristic"

SQLI_PAYLOADS=("'" "1' OR '1'='1" "1 AND 1=1--" "1\"")
SQLI_ERRORS="(sql syntax|mysql_fetch|ORA-|sqlite_|pg_exec|SQLSTATE|unclosed quotation|syntax error.*query)"

_sqli_check() {
  local url="$1"
  for payload in "'" "1--" "1 AND 1=2--"; do
    local test_url body
    test_url=$(echo "$url" | sed "s/FUZZ/$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")/g")
    body=$(curl -sk --max-time "$TIMEOUT_CURL" "$test_url" 2>/dev/null)
    if echo "$body" | grep -qiE "$SQLI_ERRORS"; then
      echo "$url [payload:$payload]"
      return
    fi
  done
}

export -f _sqli_check SQLI_ERRORS
export TIMEOUT_CURL

mkdir -p "$OUT/engine/reflection"

if $HAS_PARALLEL; then
  parallel --jobs "$T_CURL" --no-notice _sqli_check {} \
    < "$OUT/engine/diff/dynamic.txt" > "$OUT/engine/reflection/sqli_candidates.txt"
else
  xargs -P "$T_CURL" -I{} bash -c '_sqli_check "$@"' _ {} \
    < "$OUT/engine/diff/dynamic.txt" > "$OUT/engine/reflection/sqli_candidates.txt" || true
fi

sort -u "$OUT/engine/reflection/sqli_candidates.txt" -o "$OUT/engine/reflection/sqli_candidates.txt" 2>/dev/null || true
log "SQLi error candidates: $(count_safe "$OUT/engine/reflection/sqli_candidates.txt")"

# ── STEP 12: SSRF CANDIDATE TAGGING ──────────────────────────
section "STEP 12 ─ SSRF Parameter Tagging"

grep -Ei '(url=|uri=|path=|dest=|host=|src=|file=|resource=|image=|data=|load=|fetch=|open=|proxy=|service=|server=|backend=)' \
  "$OUT/engine/valid_params.txt" \
  > "$OUT/engine/reflection/ssrf_candidates.txt" 2>/dev/null || true

log "SSRF-prone param patterns: $(count_safe "$OUT/engine/reflection/ssrf_candidates.txt")"

# ── STEP 13: ELAPSED TIME ─────────────────────────────────────
END_TS=$(date +%s)
ELAPSED=$(( END_TS - START_TS ))
ELAPSED_FMT="$((ELAPSED/60))m $((ELAPSED%60))s"

# ── STEP 14: STATS JSON ───────────────────────────────────────
cat > "$STATS_FILE" << STATS_EOF
{
  "target": "$DOMAIN",
  "date": "$START_DATE",
  "mode": "$(${DEEP_MODE} && echo deep || echo standard)",
  "elapsed": "$ELAPSED_FMT",
  "subs_raw":       $(count_safe "$OUT/subs/raw.txt"),
  "wildcard_ips":   $(count_safe "$OUT/subs/wildcard_ips.txt"),
  "subs_resolved":  $(count_safe "$OUT/subs/resolved.txt"),
  "live_hosts":     $(count_safe "$OUT/http/live.txt"),
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

# ── STEP 15: HTML REPORT ──────────────────────────────────────
if [[ "$SKIP_REPORT" != true ]]; then
  section "STEP 15 ─ Generating HTML Report"
  HTML_REPORT="$OUT/final/report.html"

  # Build findings arrays for injection into HTML
  _file_to_js_array() {
    local file="$1"
    local varname="$2"
    echo -n "const $varname = ["
    if [[ -s "$file" ]]; then
      while IFS= read -r line; do
        line="${line//\\/\\\\}"
        line="${line//\"/\\\"}"
        echo -n "\"$line\","
      done < "$file"
    fi
    echo "];"
  }

  IDOR_JS=$(_file_to_js_array "$OUT/engine/behavior/idor.txt" "IDOR_FINDINGS")
  REDIR_JS=$(_file_to_js_array "$OUT/engine/behavior/open_redirects.txt" "REDIR_FINDINGS")
  XSS_JS=$(_file_to_js_array "$OUT/engine/reflection/xss_candidates.txt" "XSS_FINDINGS")
  SQLI_JS=$(_file_to_js_array "$OUT/engine/reflection/sqli_candidates.txt" "SQLI_FINDINGS")
  SSRF_JS=$(_file_to_js_array "$OUT/engine/reflection/ssrf_candidates.txt" "SSRF_FINDINGS")
  SUBS_JS=$(_file_to_js_array "$OUT/subs/resolved.txt" "SUBS_LIST")
  LIVE_JS=$(_file_to_js_array "$OUT/http/live.txt" "LIVE_LIST")
  DYNAMIC_JS=$(_file_to_js_array "$OUT/engine/diff/dynamic.txt" "DYNAMIC_LIST")

  # Read probe output for hosts table
  PROBE_DATA=$(cat "$OUT/http/probe_full.txt" 2>/dev/null | head -200 | sed "s/\"/'/g" | awk '{printf "\"%s\",", $0}')

  cat > "$HTML_REPORT" << HTML_EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PRECISE RECON v4 — $DOMAIN</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg:      #0a0c0f;
  --bg1:     #111318;
  --bg2:     #181b22;
  --bg3:     #1e2129;
  --border:  #272b35;
  --border2: #2f3440;
  --text:    #e2e4ea;
  --text2:   #8b90a0;
  --text3:   #555b6a;
  --mono:    'Space Mono', monospace;
  --sans:    'DM Sans', sans-serif;
  --red:     #ff4d6a;
  --orange:  #ff8c42;
  --yellow:  #ffd166;
  --green:   #06d6a0;
  --cyan:    #48cae4;
  --blue:    #4361ee;
  --purple:  #9b5de5;
  --red-bg:  rgba(255,77,106,0.08);
  --ora-bg:  rgba(255,140,66,0.08);
  --yel-bg:  rgba(255,209,102,0.08);
  --grn-bg:  rgba(6,214,160,0.08);
  --cyn-bg:  rgba(72,202,228,0.08);
  --radius:  8px;
  --radius2: 12px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
}

/* ── SCROLLBAR ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg1); }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

/* ── LAYOUT ── */
.shell {
  display: grid;
  grid-template-columns: 220px 1fr;
  min-height: 100vh;
}
.sidebar {
  background: var(--bg1);
  border-right: 1px solid var(--border);
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
  padding: 24px 0;
  display: flex;
  flex-direction: column;
}
.main {
  padding: 40px 48px;
  max-width: 1100px;
}

/* ── SIDEBAR ── */
.logo {
  padding: 0 20px 24px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 20px;
}
.logo-title {
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 700;
  color: var(--cyan);
  letter-spacing: 2px;
  text-transform: uppercase;
}
.logo-sub {
  font-size: 11px;
  color: var(--text3);
  margin-top: 4px;
  font-family: var(--mono);
}
.nav-section {
  padding: 0 12px;
  margin-bottom: 8px;
}
.nav-label {
  font-size: 10px;
  font-family: var(--mono);
  color: var(--text3);
  letter-spacing: 1.5px;
  text-transform: uppercase;
  padding: 0 8px;
  margin-bottom: 4px;
}
.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: var(--radius);
  cursor: pointer;
  color: var(--text2);
  font-size: 13px;
  font-weight: 500;
  text-decoration: none;
  transition: all 0.15s;
  border: 1px solid transparent;
}
.nav-item:hover { background: var(--bg3); color: var(--text); }
.nav-item.active {
  background: var(--bg3);
  color: var(--text);
  border-color: var(--border2);
}
.nav-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.dot-red    { background: var(--red); box-shadow: 0 0 6px var(--red); }
.dot-orange { background: var(--orange); box-shadow: 0 0 6px var(--orange); }
.dot-yellow { background: var(--yellow); box-shadow: 0 0 6px var(--yellow); }
.dot-green  { background: var(--green); box-shadow: 0 0 6px var(--green); }
.dot-cyan   { background: var(--cyan); box-shadow: 0 0 6px var(--cyan); }
.dot-blue   { background: var(--blue); }
.dot-purple { background: var(--purple); }
.dot-gray   { background: var(--text3); }
.nav-badge {
  margin-left: auto;
  font-family: var(--mono);
  font-size: 10px;
  padding: 2px 6px;
  border-radius: 4px;
  background: var(--bg2);
  color: var(--text2);
}
.nav-badge.hot {
  background: var(--red-bg);
  color: var(--red);
  border: 1px solid rgba(255,77,106,0.2);
}
.sidebar-footer {
  margin-top: auto;
  padding: 16px 20px 0;
  border-top: 1px solid var(--border);
  font-size: 11px;
  color: var(--text3);
  font-family: var(--mono);
}

/* ── VIEWS ── */
.view { display: none; }
.view.active { display: block; }

/* ── PAGE HEADER ── */
.page-header {
  margin-bottom: 36px;
  padding-bottom: 24px;
  border-bottom: 1px solid var(--border);
}
.page-eyebrow {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--cyan);
  letter-spacing: 2px;
  text-transform: uppercase;
  margin-bottom: 8px;
}
.page-title {
  font-family: var(--mono);
  font-size: 26px;
  font-weight: 700;
  color: var(--text);
  letter-spacing: -0.5px;
  margin-bottom: 8px;
}
.page-title span { color: var(--cyan); }
.page-meta {
  display: flex;
  gap: 20px;
  flex-wrap: wrap;
  margin-top: 12px;
}
.meta-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--text2);
  font-family: var(--mono);
}
.meta-dot { width: 4px; height: 4px; border-radius: 50%; background: var(--text3); }

/* ── STAT CARDS ── */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 36px;
}
.stat-card {
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius2);
  padding: 16px 18px;
  transition: border-color 0.2s;
}
.stat-card:hover { border-color: var(--border2); }
.stat-card.alert { border-color: rgba(255,77,106,0.3); background: var(--red-bg); }
.stat-card.warn  { border-color: rgba(255,140,66,0.3); background: var(--ora-bg); }
.stat-num {
  font-family: var(--mono);
  font-size: 28px;
  font-weight: 700;
  color: var(--text);
  line-height: 1;
  margin-bottom: 6px;
}
.stat-card.alert .stat-num { color: var(--red); }
.stat-card.warn  .stat-num { color: var(--orange); }
.stat-label { font-size: 11px; color: var(--text2); font-weight: 500; }

/* ── SECTION HEADERS ── */
.sec-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
  margin-top: 36px;
}
.sec-title {
  font-family: var(--mono);
  font-size: 13px;
  font-weight: 700;
  color: var(--text);
  letter-spacing: 0.5px;
  text-transform: uppercase;
}
.sec-count {
  font-family: var(--mono);
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 4px;
  background: var(--bg2);
  color: var(--text2);
  border: 1px solid var(--border);
}
.sec-count.hot { background: var(--red-bg); color: var(--red); border-color: rgba(255,77,106,0.3); }
.sec-line { flex: 1; height: 1px; background: var(--border); }

/* ── FINDINGS TABLE ── */
.findings-table {
  width: 100%;
  border-collapse: collapse;
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius2);
  overflow: hidden;
  margin-bottom: 12px;
}
.findings-table th {
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--text3);
  padding: 10px 16px;
  text-align: left;
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
}
.findings-table td {
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text2);
  word-break: break-all;
}
.findings-table tr:last-child td { border-bottom: none; }
.findings-table tr:hover td { background: var(--bg2); }
.findings-table td.url { color: var(--cyan); }
.findings-table td.ctx { color: var(--text3); font-size: 11px; white-space: nowrap; }

/* ── SEVERITY PILLS ── */
.pill {
  display: inline-block;
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 700;
  padding: 3px 8px;
  border-radius: 4px;
  letter-spacing: 0.5px;
}
.pill-crit { background: var(--red-bg); color: var(--red); border: 1px solid rgba(255,77,106,0.3); }
.pill-high { background: var(--ora-bg); color: var(--orange); border: 1px solid rgba(255,140,66,0.3); }
.pill-med  { background: var(--yel-bg); color: var(--yellow); border: 1px solid rgba(255,209,102,0.3); }
.pill-low  { background: var(--grn-bg); color: var(--green); border: 1px solid rgba(6,214,160,0.3); }
.pill-info { background: var(--cyn-bg); color: var(--cyan); border: 1px solid rgba(72,202,228,0.3); }

/* ── EMPTY STATE ── */
.empty {
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius2);
  padding: 32px;
  text-align: center;
  color: var(--text3);
  font-family: var(--mono);
  font-size: 12px;
}

/* ── COPY BUTTON ── */
.copy-btn {
  font-family: var(--mono);
  font-size: 10px;
  padding: 4px 10px;
  border: 1px solid var(--border2);
  border-radius: 4px;
  background: var(--bg2);
  color: var(--text2);
  cursor: pointer;
  transition: all 0.15s;
  margin-left: auto;
}
.copy-btn:hover { background: var(--bg3); color: var(--text); }

/* ── CODE BLOCK ── */
.code-block {
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius2);
  padding: 20px;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text2);
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  line-height: 1.8;
  max-height: 400px;
  overflow-y: auto;
}

/* ── PROGRESS BAR ── */
.progress-track {
  height: 4px;
  background: var(--bg2);
  border-radius: 2px;
  overflow: hidden;
  margin-top: 8px;
}
.progress-fill {
  height: 100%;
  border-radius: 2px;
  background: linear-gradient(90deg, var(--blue), var(--cyan));
  transition: width 1s ease;
}

/* ── TOOLBAR ── */
.toolbar {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.search-input {
  flex: 1;
  min-width: 180px;
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 8px 14px;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text);
  outline: none;
  transition: border-color 0.15s;
}
.search-input:focus { border-color: var(--cyan); }
.search-input::placeholder { color: var(--text3); }
.filter-select {
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 8px 12px;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text2);
  outline: none;
  cursor: pointer;
}

/* ── HOST CARDS ── */
.host-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 10px;
  margin-bottom: 12px;
}
.host-card {
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 14px;
  font-family: var(--mono);
  font-size: 12px;
  transition: border-color 0.15s;
}
.host-card:hover { border-color: var(--border2); }
.host-url { color: var(--cyan); margin-bottom: 4px; word-break: break-all; }
.host-tags { display: flex; gap: 4px; flex-wrap: wrap; }
.host-tag {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 3px;
  background: var(--bg3);
  color: var(--text3);
  border: 1px solid var(--border);
}
.host-tag.code-200 { color: var(--green); border-color: rgba(6,214,160,0.2); }
.host-tag.code-403 { color: var(--orange); border-color: rgba(255,140,66,0.2); }
.host-tag.code-301, .host-tag.code-302, .host-tag.code-307 { color: var(--cyan); }

/* ── ALERT BANNER ── */
.alert-banner {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  padding: 14px 18px;
  border-radius: var(--radius);
  margin-bottom: 16px;
  font-size: 13px;
}
.alert-banner.red   { background: var(--red-bg); border: 1px solid rgba(255,77,106,0.2); }
.alert-banner.orange{ background: var(--ora-bg); border: 1px solid rgba(255,140,66,0.2); }
.alert-icon { font-size: 16px; flex-shrink: 0; margin-top: 1px; }

/* ── OVERVIEW TIMELINE ── */
.timeline {
  position: relative;
  padding-left: 24px;
  margin-bottom: 24px;
}
.timeline::before {
  content: '';
  position: absolute;
  left: 6px; top: 0; bottom: 0;
  width: 1px;
  background: var(--border);
}
.tl-item {
  position: relative;
  margin-bottom: 16px;
}
.tl-dot {
  position: absolute;
  left: -21px;
  top: 4px;
  width: 10px; height: 10px;
  border-radius: 50%;
  background: var(--bg3);
  border: 2px solid var(--border2);
}
.tl-dot.done { background: var(--green); border-color: var(--green); box-shadow: 0 0 6px var(--green); }
.tl-dot.warn { background: var(--orange); border-color: var(--orange); }
.tl-dot.crit { background: var(--red); border-color: var(--red); }
.tl-title { font-family: var(--mono); font-size: 12px; color: var(--text); margin-bottom: 3px; }
.tl-meta  { font-size: 11px; color: var(--text3); }

/* ── PAGINATION ── */
.pagination {
  display: flex;
  gap: 6px;
  align-items: center;
  justify-content: flex-end;
  margin-top: 10px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text2);
}
.page-btn {
  padding: 4px 10px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--bg1);
  color: var(--text2);
  cursor: pointer;
  transition: all 0.15s;
}
.page-btn:hover { background: var(--bg2); color: var(--text); }
.page-btn.active { background: var(--bg3); color: var(--text); border-color: var(--border2); }
.page-btn:disabled { opacity: 0.3; cursor: not-allowed; }

/* ── RESPONSIVE ── */
@media (max-width: 768px) {
  .shell { grid-template-columns: 1fr; }
  .sidebar { position: relative; height: auto; }
  .main { padding: 24px 20px; }
}
</style>
</head>
<body>
<div class="shell">

<!-- ══════════════════ SIDEBAR ══════════════════ -->
<nav class="sidebar">
  <div class="logo">
    <div class="logo-title">// PRECISE RECON</div>
    <div class="logo-sub">v4.0 · $DOMAIN</div>
  </div>

  <div class="nav-section">
    <div class="nav-label">Overview</div>
    <a class="nav-item active" href="#" onclick="showView('overview')">
      <div class="nav-dot dot-blue"></div> Dashboard
    </a>
  </div>

  <div class="nav-section">
    <div class="nav-label">Findings</div>
    <a class="nav-item" href="#" onclick="showView('idor')">
      <div class="nav-dot dot-red"></div> IDOR / Logic
      <span class="nav-badge hot" id="nav-idor-cnt">0</span>
    </a>
    <a class="nav-item" href="#" onclick="showView('xss')">
      <div class="nav-dot dot-orange"></div> XSS Candidates
      <span class="nav-badge" id="nav-xss-cnt">0</span>
    </a>
    <a class="nav-item" href="#" onclick="showView('sqli')">
      <div class="nav-dot dot-yellow"></div> SQLi Heuristic
      <span class="nav-badge" id="nav-sqli-cnt">0</span>
    </a>
    <a class="nav-item" href="#" onclick="showView('redir')">
      <div class="nav-dot dot-cyan"></div> Open Redirect
      <span class="nav-badge" id="nav-redir-cnt">0</span>
    </a>
    <a class="nav-item" href="#" onclick="showView('ssrf')">
      <div class="nav-dot dot-purple"></div> SSRF Patterns
      <span class="nav-badge" id="nav-ssrf-cnt">0</span>
    </a>
  </div>

  <div class="nav-section">
    <div class="nav-label">Recon Data</div>
    <a class="nav-item" href="#" onclick="showView('hosts')">
      <div class="nav-dot dot-green"></div> Live Hosts
      <span class="nav-badge" id="nav-hosts-cnt">0</span>
    </a>
    <a class="nav-item" href="#" onclick="showView('subs')">
      <div class="nav-dot dot-gray"></div> Subdomains
      <span class="nav-badge" id="nav-subs-cnt">0</span>
    </a>
    <a class="nav-item" href="#" onclick="showView('dynamic')">
      <div class="nav-dot dot-gray"></div> Dynamic Params
      <span class="nav-badge" id="nav-dyn-cnt">0</span>
    </a>
  </div>

  <div class="sidebar-footer">
    Generated: $START_DATE<br>
    Runtime: $ELAPSED_FMT
  </div>
</nav>

<!-- ══════════════════ MAIN ══════════════════ -->
<main class="main">

<!-- ── DATA ── -->
<script>
$IDOR_JS
$REDIR_JS
$XSS_JS
$SQLI_JS
$SSRF_JS
$SUBS_JS
$LIVE_JS
$DYNAMIC_JS

const STATS = {
  target: "$DOMAIN",
  date: "$START_DATE",
  mode: "$(${DEEP_MODE} && echo deep || echo standard)",
  elapsed: "$ELAPSED_FMT",
  subs_raw:       $(count_safe "$OUT/subs/raw.txt"),
  wildcard_ips:   $(count_safe "$OUT/subs/wildcard_ips.txt"),
  subs_resolved:  $(count_safe "$OUT/subs/resolved.txt"),
  live_hosts:     $(count_safe "$OUT/http/live.txt"),
  param_urls:     $(count_safe "$OUT/crawl/urls_with_params.txt"),
  param_patterns: $(count_safe "$OUT/crawl/params_normalized.txt"),
  valid_params:   $(count_safe "$OUT/engine/valid_params.txt"),
  dynamic_params: $(count_safe "$OUT/engine/diff/dynamic.txt"),
  idor:           $(count_safe "$OUT/engine/behavior/idor.txt"),
  open_redirects: $(count_safe "$OUT/engine/behavior/open_redirects.txt"),
  xss:            $(count_safe "$OUT/engine/reflection/xss_candidates.txt"),
  sqli:           $(count_safe "$OUT/engine/reflection/sqli_candidates.txt"),
  ssrf:           $(count_safe "$OUT/engine/reflection/ssrf_candidates.txt")
};
</script>

<!-- ── OVERVIEW VIEW ── -->
<div class="view active" id="view-overview">
  <div class="page-header">
    <div class="page-eyebrow">// RECON REPORT</div>
    <div class="page-title">$DOMAIN</div>
    <div class="page-meta">
      <div class="meta-item">📅 $START_DATE</div>
      <div class="meta-dot"></div>
      <div class="meta-item" id="meta-mode"></div>
      <div class="meta-dot"></div>
      <div class="meta-item">⏱ $ELAPSED_FMT</div>
    </div>
  </div>

  <!-- Stat cards -->
  <div class="stats-grid" id="stats-grid"></div>

  <!-- Pipeline timeline -->
  <div class="sec-header">
    <div class="sec-title">Pipeline</div>
    <div class="sec-line"></div>
  </div>
  <div class="timeline" id="pipeline-timeline"></div>

  <!-- Findings summary -->
  <div class="sec-header">
    <div class="sec-title">Findings Summary</div>
    <div class="sec-line"></div>
  </div>
  <div id="findings-summary"></div>
</div>

<!-- ── IDOR VIEW ── -->
<div class="view" id="view-idor">
  <div class="page-header">
    <div class="page-eyebrow">// CRITICAL</div>
    <div class="page-title"><span>IDOR</span> / Logic Flaws</div>
  </div>
  <div id="idor-body"></div>
</div>

<!-- ── XSS VIEW ── -->
<div class="view" id="view-xss">
  <div class="page-header">
    <div class="page-eyebrow">// HIGH</div>
    <div class="page-title"><span>XSS</span> Candidates</div>
  </div>
  <div id="xss-body"></div>
</div>

<!-- ── SQLI VIEW ── -->
<div class="view" id="view-sqli">
  <div class="page-header">
    <div class="page-eyebrow">// HIGH</div>
    <div class="page-title"><span>SQLi</span> Error Heuristic</div>
  </div>
  <div id="sqli-body"></div>
</div>

<!-- ── REDIR VIEW ── -->
<div class="view" id="view-redir">
  <div class="page-header">
    <div class="page-eyebrow">// MEDIUM</div>
    <div class="page-title"><span>Open Redirect</span> Candidates</div>
  </div>
  <div id="redir-body"></div>
</div>

<!-- ── SSRF VIEW ── -->
<div class="view" id="view-ssrf">
  <div class="page-header">
    <div class="page-eyebrow">// MEDIUM</div>
    <div class="page-title"><span>SSRF</span> Parameter Patterns</div>
  </div>
  <div id="ssrf-body"></div>
</div>

<!-- ── HOSTS VIEW ── -->
<div class="view" id="view-hosts">
  <div class="page-header">
    <div class="page-eyebrow">// RECON DATA</div>
    <div class="page-title">Live <span>Hosts</span></div>
  </div>
  <div id="hosts-body"></div>
</div>

<!-- ── SUBS VIEW ── -->
<div class="view" id="view-subs">
  <div class="page-header">
    <div class="page-eyebrow">// RECON DATA</div>
    <div class="page-title">Resolved <span>Subdomains</span></div>
  </div>
  <div id="subs-body"></div>
</div>

<!-- ── DYNAMIC VIEW ── -->
<div class="view" id="view-dynamic">
  <div class="page-header">
    <div class="page-eyebrow">// RECON DATA</div>
    <div class="page-title"><span>Dynamic</span> Parameters</div>
  </div>
  <div id="dynamic-body"></div>
</div>

</main>
</div>

<script>
// ── NAV BADGES ──────────────────────────────────────────────
function setBadge(id, val) {
  const el = document.getElementById(id);
  if (el) { el.textContent = val; if (val > 0 && id.includes('idor')) el.classList.add('hot'); }
}
setBadge('nav-idor-cnt',  IDOR_FINDINGS.length);
setBadge('nav-xss-cnt',   XSS_FINDINGS.length);
setBadge('nav-sqli-cnt',  SQLI_FINDINGS.length);
setBadge('nav-redir-cnt', REDIR_FINDINGS.length);
setBadge('nav-ssrf-cnt',  SSRF_FINDINGS.length);
setBadge('nav-hosts-cnt', LIVE_LIST.length);
setBadge('nav-subs-cnt',  SUBS_LIST.length);
setBadge('nav-dyn-cnt',   DYNAMIC_LIST.length);

// ── VIEW SWITCHER ────────────────────────────────────────────
function showView(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('view-' + id).classList.add('active');
  event && event.currentTarget && event.currentTarget.classList.add('active');
  // Lazy render
  const renderFns = { idor: renderIdor, xss: renderXss, sqli: renderSqli, redir: renderRedir, ssrf: renderSsrf, hosts: renderHosts, subs: renderSubs, dynamic: renderDynamic };
  if (renderFns[id]) renderFns[id]();
}

// ── OVERVIEW ─────────────────────────────────────────────────
(function buildOverview() {
  document.getElementById('meta-mode').textContent = '🔍 Mode: ' + STATS.mode;

  // Stat cards
  const cards = [
    { label: 'Live Hosts',       val: STATS.live_hosts,     cls: '' },
    { label: 'Subdomains',       val: STATS.subs_resolved,  cls: '' },
    { label: 'Parameterized URLs', val: STATS.param_urls,   cls: '' },
    { label: 'Dynamic Params',   val: STATS.dynamic_params, cls: '' },
    { label: 'IDOR Candidates',  val: STATS.idor,           cls: STATS.idor > 0 ? 'alert' : '' },
    { label: 'XSS Candidates',   val: STATS.xss,            cls: STATS.xss > 0 ? 'warn' : '' },
    { label: 'SQLi Heuristic',   val: STATS.sqli,           cls: STATS.sqli > 0 ? 'warn' : '' },
    { label: 'Open Redirects',   val: STATS.open_redirects, cls: '' },
    { label: 'SSRF Patterns',    val: STATS.ssrf,           cls: '' },
    { label: 'Wildcard IPs',     val: STATS.wildcard_ips,   cls: '' },
  ];
  document.getElementById('stats-grid').innerHTML = cards.map(c =>
    \`<div class="stat-card \${c.cls}"><div class="stat-num">\${c.val}</div><div class="stat-label">\${c.label}</div></div>\`
  ).join('');

  // Pipeline
  const steps = [
    { label: 'Subdomain Enumeration', meta: STATS.subs_raw + ' raw → ' + STATS.subs_resolved + ' resolved', cls: 'done' },
    { label: 'Wildcard Pruning', meta: STATS.wildcard_ips + ' wildcard IPs blocked', cls: 'done' },
    { label: 'HTTP Probing', meta: STATS.live_hosts + ' live hosts', cls: 'done' },
    { label: 'URL & Param Collection', meta: STATS.param_urls + ' parameterized URLs', cls: 'done' },
    { label: 'Baseline Validation', meta: STATS.valid_params + ' params passed baseline', cls: 'done' },
    { label: 'Diff Engine', meta: STATS.dynamic_params + ' dynamic parameters confirmed', cls: 'done' },
    { label: 'IDOR Detection', meta: STATS.idor + ' candidates', cls: STATS.idor > 0 ? 'crit' : 'done' },
    { label: 'XSS Reflection', meta: STATS.xss + ' candidates', cls: STATS.xss > 0 ? 'warn' : 'done' },
    { label: 'SQLi Heuristic', meta: STATS.sqli + ' candidates', cls: STATS.sqli > 0 ? 'warn' : 'done' },
    { label: 'Open Redirect', meta: STATS.open_redirects + ' candidates', cls: 'done' },
    { label: 'SSRF Tagging', meta: STATS.ssrf + ' SSRF-prone patterns', cls: 'done' },
  ];
  document.getElementById('pipeline-timeline').innerHTML = steps.map(s =>
    \`<div class="tl-item"><div class="tl-dot \${s.cls}"></div><div class="tl-title">\${s.label}</div><div class="tl-meta">\${s.meta}</div></div>\`
  ).join('');

  // Findings summary
  const findings = [
    { sev: 'CRITICAL', label: 'IDOR / Logic Flaws', count: STATS.idor, pill: 'pill-crit', view: 'idor' },
    { sev: 'HIGH',     label: 'XSS Reflection Candidates', count: STATS.xss, pill: 'pill-high', view: 'xss' },
    { sev: 'HIGH',     label: 'SQLi Error Heuristic', count: STATS.sqli, pill: 'pill-high', view: 'sqli' },
    { sev: 'MEDIUM',   label: 'Open Redirect', count: STATS.open_redirects, pill: 'pill-med', view: 'redir' },
    { sev: 'MEDIUM',   label: 'SSRF-Prone Parameters', count: STATS.ssrf, pill: 'pill-med', view: 'ssrf' },
  ];
  document.getElementById('findings-summary').innerHTML = \`
    <table class="findings-table">
      <thead><tr><th>Severity</th><th>Type</th><th>Count</th><th></th></tr></thead>
      <tbody>\${findings.map(f => \`
        <tr>
          <td><span class="pill \${f.pill}">\${f.sev}</span></td>
          <td>\${f.label}</td>
          <td style="font-family:var(--mono);color:\${f.count>0?'var(--text)':'var(--text3)'}">\${f.count}</td>
          <td><button class="copy-btn" onclick="showView('\${f.view}')">View →</button></td>
        </tr>\`).join('')}
      </tbody>
    </table>\`;
})();

// ── GENERIC FINDING RENDERER ─────────────────────────────────
function renderFindingList(containerId, data, pill, sevLabel, note) {
  const el = document.getElementById(containerId);
  if (!el || el.dataset.rendered) return;
  el.dataset.rendered = '1';

  if (data.length === 0) {
    el.innerHTML = \`<div class="empty">✓ No findings in this category</div>\`;
    return;
  }

  if (note) {
    el.innerHTML = \`<div class="alert-banner orange"><div class="alert-icon">⚠</div><div>\${note}</div></div>\`;
  }

  const PAGE = 50;
  let page = 0;
  function render() {
    const slice = data.slice(page * PAGE, (page + 1) * PAGE);
    const total = Math.ceil(data.length / PAGE);
    const tableId = containerId + '-tbl';
    document.getElementById(tableId) && document.getElementById(tableId).remove();
    document.getElementById(containerId + '-page') && document.getElementById(containerId + '-page').remove();

    const tbl = document.createElement('div');
    tbl.id = tableId;
    tbl.innerHTML = \`
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
        <span class="pill \${pill}">\${sevLabel}</span>
        <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">\${data.length} finding\${data.length!==1?'s':''}</span>
        <button class="copy-btn" onclick="copyAll('\${containerId}')">Copy All</button>
      </div>
      <table class="findings-table">
        <thead><tr><th>#</th><th>URL / Pattern</th><th>Context</th></tr></thead>
        <tbody>\${slice.map((row,i) => {
          const parts = row.split(' [');
          const url = parts[0];
          const ctx = parts[1] ? '[' + parts[1] : '';
          return \`<tr>
            <td style="color:var(--text3);font-size:11px;">\${page*PAGE+i+1}</td>
            <td class="url">\${escHtml(url)}</td>
            <td class="ctx">\${escHtml(ctx)}</td>
          </tr>\`;
        }).join('')}
        </tbody>
      </table>\`;
    el.appendChild(tbl);

    if (total > 1) {
      const pg = document.createElement('div');
      pg.id = containerId + '-page';
      pg.className = 'pagination';
      pg.innerHTML = \`
        <button class="page-btn" \${page===0?'disabled':''} onclick="void(0)" id="\${containerId}-prev">‹ Prev</button>
        <span>Page \${page+1} of \${total}</span>
        <button class="page-btn" \${page>=total-1?'disabled':''} id="\${containerId}-next">Next ›</button>\`;
      el.appendChild(pg);
      document.getElementById(containerId+'-prev').onclick = () => { if(page>0){page--;render();} };
      document.getElementById(containerId+'-next').onclick = () => { if(page<total-1){page++;render();} };
    }
  }
  render();
}

function copyAll(id) {
  const el = document.getElementById(id);
  const urls = el.querySelectorAll('td.url');
  const text = Array.from(urls).map(u => u.textContent).join('\n');
  navigator.clipboard.writeText(text).then(() => {
    const btn = el.querySelector('.copy-btn');
    const orig = btn.textContent; btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── GENERIC LIST RENDERER ────────────────────────────────────
function renderListView(containerId, data, searchable=true) {
  const el = document.getElementById(containerId);
  if (!el || el.dataset.rendered) return;
  el.dataset.rendered = '1';

  if (data.length === 0) {
    el.innerHTML = '<div class="empty">No data in this category</div>';
    return;
  }

  const PAGE = 100;
  let page = 0;
  let filtered = data;

  function render() {
    el.innerHTML = '';
    if (searchable) {
      const tb = document.createElement('div');
      tb.className = 'toolbar';
      tb.innerHTML = \`<input class="search-input" placeholder="Filter..." id="\${containerId}-search">\`;
      el.appendChild(tb);
      document.getElementById(containerId+'-search').addEventListener('input', function() {
        const q = this.value.toLowerCase();
        filtered = data.filter(d => d.toLowerCase().includes(q));
        page = 0; renderPage();
      });
    }
    renderPage();
  }

  function renderPage() {
    document.getElementById(containerId+'-list') && document.getElementById(containerId+'-list').remove();
    document.getElementById(containerId+'-page2') && document.getElementById(containerId+'-page2').remove();
    const slice = filtered.slice(page*PAGE, (page+1)*PAGE);
    const total = Math.ceil(filtered.length/PAGE);
    const div = document.createElement('div');
    div.id = containerId+'-list';
    div.innerHTML = \`<div class="code-block">\${slice.map(escHtml).join('\n')}</div>\`;
    el.appendChild(div);
    if (total > 1) {
      const pg = document.createElement('div');
      pg.id = containerId+'-page2';
      pg.className = 'pagination';
      pg.innerHTML = \`
        <span style="color:var(--text3)">\${filtered.length} items</span>
        <button class="page-btn" \${page===0?'disabled':''} id="\${containerId}-prev2">‹ Prev</button>
        <span>Page \${page+1} of \${total}</span>
        <button class="page-btn" \${page>=total-1?'disabled':''} id="\${containerId}-next2">Next ›</button>\`;
      el.appendChild(pg);
      document.getElementById(containerId+'-prev2').onclick = () => { if(page>0){page--;renderPage();} };
      document.getElementById(containerId+'-next2').onclick = () => { if(page<total-1){page++;renderPage();} };
    }
  }
  render();
}

// ── RENDER FUNCTIONS ─────────────────────────────────────────
function renderIdor()    { renderFindingList('idor-body', IDOR_FINDINGS, 'pill-crit', 'CRITICAL', 'These URLs showed consistent behavioral changes when probed with sequential IDs. Verify manually for real data exposure.'); }
function renderXss()     { renderFindingList('xss-body', XSS_FINDINGS, 'pill-high', 'HIGH', 'Input reflected unencoded in HTML response. Verify canary appears in exploitable context before reporting.'); }
function renderSqli()    { renderFindingList('sqli-body', SQLI_FINDINGS, 'pill-high', 'HIGH', 'DB error strings detected in response body. Confirm with sqlmap or manual payload before reporting.'); }
function renderRedir()   { renderFindingList('redir-body', REDIR_FINDINGS, 'pill-med', 'MEDIUM', null); }
function renderSsrf()    { renderFindingList('ssrf-body', SSRF_FINDINGS, 'pill-med', 'MEDIUM', 'Parameters with URL/host-type names. Test with out-of-band callbacks (interactsh/burp collaborator).'); }
function renderSubs()    { renderListView('subs-body', SUBS_LIST); }
function renderDynamic() { renderListView('dynamic-body', DYNAMIC_LIST); }

function renderHosts() {
  const el = document.getElementById('hosts-body');
  if (!el || el.dataset.rendered) return;
  el.dataset.rendered = '1';
  const grid = document.createElement('div');
  grid.className = 'host-grid';
  LIVE_LIST.forEach(line => {
    const parts = line.split(' ');
    const url = parts[0];
    const tags = parts.slice(1);
    const codeTag = tags.find(t => /^\[[\d]+\]$/.test(t)) || '';
    const code = codeTag.replace(/[\[\]]/g,'');
    const cls = code === '200' ? 'code-200' : code === '403' ? 'code-403' : (['301','302','307'].includes(code) ? 'code-301' : '');
    grid.innerHTML += \`<div class="host-card">
      <div class="host-url">\${escHtml(url)}</div>
      <div class="host-tags">
        \${tags.map(t => \`<span class="host-tag \${t.includes(code)?cls:''}">\${escHtml(t)}</span>\`).join('')}
      </div>
    </div>\`;
  });
  el.appendChild(grid);
}

// ── NAV CLICK FIX ────────────────────────────────────────────
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', function(e) {
    e.preventDefault();
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    this.classList.add('active');
  });
});
</script>
</body>
</html>
HTML_EOF

  log "HTML report generated: $HTML_REPORT"
fi

# ── STEP 16: TEXT REPORT ──────────────────────────────────────
REPORT="$OUT/final/report.txt"
{
printf '%s\n' "╔══════════════════════════════════════════════════════════════╗"
printf '%s\n' "║        PRECISE RECON v4 — BUG BOUNTY RECON REPORT           ║"
printf '%s\n' "╚══════════════════════════════════════════════════════════════╝"
echo "  Target  : $DOMAIN"
echo "  Date    : $START_DATE"
echo "  Mode    : $(${DEEP_MODE} && echo deep || echo standard)"
echo "  Runtime : $ELAPSED_FMT"
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  🔴  CRITICAL — IDOR / Logic Flaws"
echo "══════════════════════════════════════════════════════════════"
[[ -s "$OUT/engine/behavior/idor.txt" ]] && cat "$OUT/engine/behavior/idor.txt" || echo "  (none found)"
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  🟠  HIGH — XSS Candidates"
echo "══════════════════════════════════════════════════════════════"
[[ -s "$OUT/engine/reflection/xss_candidates.txt" ]] && cat "$OUT/engine/reflection/xss_candidates.txt" || echo "  (none found)"
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  🟠  HIGH — SQLi Error Heuristic"
echo "══════════════════════════════════════════════════════════════"
[[ -s "$OUT/engine/reflection/sqli_candidates.txt" ]] && cat "$OUT/engine/reflection/sqli_candidates.txt" || echo "  (none found)"
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  🟡  MEDIUM — Open Redirects"
echo "══════════════════════════════════════════════════════════════"
[[ -s "$OUT/engine/behavior/open_redirects.txt" ]] && cat "$OUT/engine/behavior/open_redirects.txt" || echo "  (none found)"
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  🟡  MEDIUM — SSRF-Prone Parameters"
echo "══════════════════════════════════════════════════════════════"
[[ -s "$OUT/engine/reflection/ssrf_candidates.txt" ]] && cat "$OUT/engine/reflection/ssrf_candidates.txt" || echo "  (none found)"
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  📊  PIPELINE STATS"
echo "══════════════════════════════════════════════════════════════"
echo "  Subdomains (raw)       : $(count_safe "$OUT/subs/raw.txt")"
echo "  Wildcard IPs blocked   : $(count_safe "$OUT/subs/wildcard_ips.txt")"
echo "  Resolved hosts         : $(count_safe "$OUT/subs/resolved.txt")"
echo "  Live HTTP hosts        : $(count_safe "$OUT/http/live.txt")"
echo "  Parameterized URLs     : $(count_safe "$OUT/crawl/urls_with_params.txt")"
echo "  Normalized patterns    : $(count_safe "$OUT/crawl/params_normalized.txt")"
echo "  Valid (baseline pass)  : $(count_safe "$OUT/engine/valid_params.txt")"
echo "  Dynamic params         : $(count_safe "$OUT/engine/diff/dynamic.txt")"
echo "  IDOR findings          : $(count_safe "$OUT/engine/behavior/idor.txt")"
echo "  Open redirects         : $(count_safe "$OUT/engine/behavior/open_redirects.txt")"
echo "  XSS candidates         : $(count_safe "$OUT/engine/reflection/xss_candidates.txt")"
echo "  SQLi candidates        : $(count_safe "$OUT/engine/reflection/sqli_candidates.txt")"
echo "  SSRF patterns          : $(count_safe "$OUT/engine/reflection/ssrf_candidates.txt")"
echo ""
echo "  Full output → $OUT"
[[ "$SKIP_REPORT" != true ]] && echo "  HTML report → $OUT/final/report.html"
echo "══════════════════════════════════════════════════════════════"
} | tee "$REPORT"

echo
echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║  DONE ✓  Runtime: $ELAPSED_FMT       ${RESET}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════╝${RESET}"
echo
[[ "$SKIP_REPORT" != true ]] && echo -e "  ${CYAN}HTML Report:${RESET} ${BOLD}$OUT/final/report.html${RESET}"
echo -e "  ${CYAN}Text Report:${RESET} ${BOLD}$REPORT${RESET}"
echo -e "  ${CYAN}All Data:${RESET}    ${BOLD}$OUT/${RESET}"
