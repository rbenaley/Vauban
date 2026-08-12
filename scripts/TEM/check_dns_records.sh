#!/usr/bin/env bash
#
# check_dns_records.sh
# Robust DNS checks for a domain (SOA, SPF, DKIM, DMARC, MX, A, AAAA, CNAME)
# using dig. Compares answers against expected values for vauban.sh (defaults).
#
# Exit codes:
#   0  all required checks passed (warnings allowed unless --strict)
#   1  one or more required checks failed, or dig/prerequisite error
#   2  invalid usage
#
# Usage:
#   ./check_dns_records.sh [options] [domain]
#
# Options:
#   -h, --help           Show this help
#   -r, --resolver HOST  Query this resolver (e.g. 1.1.1.1); default: system
#   -s, --selector NAME  DKIM selector (default: bundled vauban.sh selector)
#   -t, --timeout SEC    dig per-try timeout (default: 3)
#   -n, --tries N        dig tries (default: 2)
#       --strict         Treat warnings as failures
#       --no-color       Disable ANSI colors
#
# Environment (optional overrides):
#   DKIM_SELECTOR, DIG_TIMEOUT, DIG_TRIES, NO_COLOR=1
#
# Examples:
#   ./check_dns_records.sh
#   ./check_dns_records.sh --resolver 1.1.1.1 vauban.sh
#   ./check_dns_records.sh --strict --selector "$DKIM_SELECTOR" example.com

set -euo pipefail

# ---------- Defaults (vauban.sh) ----------
DOMAIN="vauban.sh"
RESOLVER=""
DKIM_SELECTOR="${DKIM_SELECTOR:-6462b963-9255-4f5f-ae38-a43ff25e7dec}"
DIG_TIMEOUT="${DIG_TIMEOUT:-3}"
DIG_TRIES="${DIG_TRIES:-2}"
STRICT=0
USE_COLOR=1

EXPECTED_SPF="v=spf1 include:_mailcust.gandi.net include:_spf.tem.scaleway.com ?all"
EXPECTED_DKIM_SUBSTR="v=DKIM1; h=sha256; k=rsa"
EXPECTED_DKIM_PSTART="p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0IbqSNoulqIMHLEZ8hNHlb"
EXPECTED_DMARC="v=DMARC1; p=none"
EXPECTED_MX_HOST="blackhole.tem.scaleway.com"
EXPECTED_MX_PRIO="10"
EXPECTED_A="185.176.225.1"
EXPECTED_AAAA="2001:1600:0:aaaa::80:78"
EXPECTED_CNAME_HOST="vcp"
EXPECTED_CNAME_VALUE="ec2-176-34-154-102.eu-west-1.compute.amazonaws.com."
EXPECTED_SOA_NS="ns1.gandi.net."

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

usage() {
  sed -n '3,28p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------- Args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -r|--resolver)
      [[ $# -ge 2 ]] || { echo "error: $1 requires a value" >&2; exit 2; }
      RESOLVER="$2"
      shift 2
      ;;
    -s|--selector)
      [[ $# -ge 2 ]] || { echo "error: $1 requires a value" >&2; exit 2; }
      DKIM_SELECTOR="$2"
      shift 2
      ;;
    -t|--timeout)
      [[ $# -ge 2 ]] || { echo "error: $1 requires a value" >&2; exit 2; }
      DIG_TIMEOUT="$2"
      shift 2
      ;;
    -n|--tries)
      [[ $# -ge 2 ]] || { echo "error: $1 requires a value" >&2; exit 2; }
      DIG_TRIES="$2"
      shift 2
      ;;
    --strict)
      STRICT=1
      shift
      ;;
    --no-color)
      USE_COLOR=0
      shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      echo "Try --help" >&2
      exit 2
      ;;
    *)
      DOMAIN="$1"
      shift
      # Allow optional second positional resolver for backward compatibility.
      if [[ $# -gt 0 && "$1" != -* ]]; then
        RESOLVER="$1"
        shift
      fi
      ;;
  esac
done

# ---------- Validation ----------
if [[ -z "$DOMAIN" || "$DOMAIN" == *[[:space:]]* ]]; then
  echo "error: invalid domain: '${DOMAIN}'" >&2
  exit 2
fi
case "$DIG_TIMEOUT" in
  ''|*[!0-9]*|0) echo "error: --timeout must be a positive integer" >&2; exit 2 ;;
esac
case "$DIG_TRIES" in
  ''|*[!0-9]*|0) echo "error: --tries must be a positive integer" >&2; exit 2 ;;
esac
if [[ -z "$DKIM_SELECTOR" ]]; then
  echo "error: DKIM selector is empty" >&2
  exit 2
fi

if [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; then
  USE_COLOR=0
fi

# ---------- Colors / output ----------
if [[ "$USE_COLOR" -eq 1 ]]; then
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  YELLOW='\033[1;33m'
  BOLD='\033[1m'
  DIM='\033[2m'
  NC='\033[0m'
else
  GREEN='' RED='' YELLOW='' BOLD='' DIM='' NC=''
fi

ok() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '%b[OK]%b %s\n' "$GREEN" "$NC" "$1"
}
warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  printf '%b[WARN]%b %s\n' "$YELLOW" "$NC" "$1"
  if [[ "$STRICT" -eq 1 ]]; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}
fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '%b[FAIL]%b %s\n' "$RED" "$NC" "$1"
}
section() {
  printf '\n%b--- %s ---%b\n' "$BOLD" "$1" "$NC"
}
info() {
  printf '%b%s%b\n' "$DIM" "$1" "$NC"
}

die() {
  printf '%b[FAIL]%b %s\n' "$RED" "$NC" "$1" >&2
  exit 1
}

# ---------- Prerequisites ----------
if ! command -v dig >/dev/null 2>&1; then
  die "dig not found on PATH (install bind-tools / dnsutils)"
fi

# ---------- Helpers ----------

# Lowercase ASCII (portable; sufficient for DNS labels and hex IPv6).
ascii_lower() {
  printf '%s' "$1" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz'
}

# Strip a single trailing dot from an FQDN.
strip_dot() {
  local s="$1"
  s="${s%.}"
  printf '%s' "$s"
}

# Normalize hostname for comparison: lowercase, no trailing dot.
norm_host() {
  ascii_lower "$(strip_dot "$1")"
}

# Join dig +short TXT output into one string per logical record.
# dig may return: "v=DKIM1; " "p=MIIB..."  (quoted chunks on one line)
# or multiple TXT RRs on separate lines.
txt_join_line() {
  # Remove quotes and collapse whitespace inside one dig line.
  printf '%s' "$1" | tr -d '"' | tr -s '[:space:]' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Run dig. Must NOT be used inside $(...) — sets globals in the current shell:
#   DIG_RCODE  NOERROR / NXDOMAIN / SERVFAIL / DIG_ERROR / …
#   DIG_RAW    +short answer body (may be empty)
# Returns 0 only for NOERROR with a non-empty answer.
DIG_RCODE=""
DIG_RAW=""

run_dig() {
  local type="$1" name="$2"
  local status_out answer_out rc_status rc_answer

  DIG_RCODE=""
  DIG_RAW=""

  # Status query (comments only) — distinguishes SERVFAIL/NXDOMAIN from empty.
  set +e
  if [[ -n "$RESOLVER" ]]; then
    status_out=$(dig @"$RESOLVER" +time="$DIG_TIMEOUT" +tries="$DIG_TRIES" \
      +nosearch +noall +comments "$name" "$type" 2>&1)
    rc_status=$?
    answer_out=$(dig @"$RESOLVER" +time="$DIG_TIMEOUT" +tries="$DIG_TRIES" \
      +nosearch +short "$name" "$type" 2>&1)
    rc_answer=$?
  else
    status_out=$(dig +time="$DIG_TIMEOUT" +tries="$DIG_TRIES" \
      +nosearch +noall +comments "$name" "$type" 2>&1)
    rc_status=$?
    answer_out=$(dig +time="$DIG_TIMEOUT" +tries="$DIG_TRIES" \
      +nosearch +short "$name" "$type" 2>&1)
    rc_answer=$?
  fi
  set -e

  if [[ "$rc_status" -ne 0 && "$rc_answer" -ne 0 ]]; then
    DIG_RCODE="DIG_ERROR"
    DIG_RAW="$status_out"
    return 1
  fi

  DIG_RCODE=$(printf '%s\n' "$status_out" | sed -n 's/.*status: \([A-Z0-9]*\).*/\1/p' | head -n1)
  if [[ -z "$DIG_RCODE" ]]; then
    DIG_RCODE="UNKNOWN"
  fi

  DIG_RAW=$(printf '%s\n' "$answer_out" | sed '/^[[:space:]]*$/d')

  if [[ "$DIG_RCODE" != "NOERROR" ]]; then
    return 1
  fi
  if [[ -z "$DIG_RAW" ]]; then
    return 1
  fi
  return 0
}

# Report dig failure with rcode context.
dig_failed() {
  local label="$1"
  if [[ "$DIG_RCODE" == "DIG_ERROR" ]]; then
    fail "$label: dig failed (timeout/network). ${DIG_RAW:-}"
  elif [[ -n "$DIG_RCODE" && "$DIG_RCODE" != "NOERROR" ]]; then
    fail "$label: DNS status $DIG_RCODE (no usable answer)"
  else
    fail "$label: no answer in NOERROR response (or empty)"
  fi
}

# ---------- Header ----------
echo "=================================================="
echo " DNS check for: $DOMAIN"
if [[ -n "$RESOLVER" ]]; then
  echo " Resolver:      @$RESOLVER"
else
  echo " Resolver:      system default"
fi
echo " dig timeout:   ${DIG_TIMEOUT}s  tries: ${DIG_TRIES}"
echo " DKIM selector: $DKIM_SELECTOR"
[[ "$STRICT" -eq 1 ]] && echo " Mode:          strict (warnings count as failures)"
echo "=================================================="

# ---------- SOA ----------
section "SOA ($DOMAIN)"
if run_dig SOA "$DOMAIN"; then
  printf '%s\n' "$DIG_RAW"
  # SOA +short: <mname> <rname> <serial> <refresh> <retry> <expire> <minimum>
  SOA_MNAME=$(printf '%s\n' "$DIG_RAW" | awk '{print $1; exit}')
  if [[ "$(norm_host "$SOA_MNAME")" == "$(norm_host "$EXPECTED_SOA_NS")" ]]; then
    ok "SOA MNAME matches expected NS: $EXPECTED_SOA_NS"
  else
    warn "SOA present but MNAME is '$SOA_MNAME' (expected $EXPECTED_SOA_NS)"
  fi
else
  dig_failed "SOA ($DOMAIN)"
fi

# ---------- SPF ----------
section "SPF (TXT $DOMAIN)"
if run_dig TXT "$DOMAIN"; then
  TXT_RAW="$DIG_RAW"
  SPF_RESULT=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    joined=$(txt_join_line "$line")
    case "$joined" in
      v=spf1*|V=spf1*)
        SPF_RESULT="$joined"
        break
        ;;
    esac
  done <<< "$TXT_RAW"

  if [[ -z "$SPF_RESULT" ]]; then
    fail "TXT answers present but none start with v=spf1"
    info "TXT RRs:"
    printf '%s\n' "$TXT_RAW"
  else
    printf '%s\n' "$SPF_RESULT"
    if [[ "$SPF_RESULT" == "$EXPECTED_SPF" ]]; then
      ok "SPF matches the expected value exactly"
    elif [[ "$SPF_RESULT" == *"_mailcust.gandi.net"* && "$SPF_RESULT" == *"_spf.tem.scaleway.com"* ]]; then
      ok "SPF contains both expected includes (gandi.net + tem.scaleway.com)"
      if [[ "$SPF_RESULT" != "$EXPECTED_SPF" ]]; then
        warn "SPF includes match but full string differs from pinned value"
      fi
    else
      warn "SPF found but differs from the expected value"
      info "expected: $EXPECTED_SPF"
    fi
  fi
else
  dig_failed "SPF (TXT $DOMAIN)"
fi

# ---------- DKIM ----------
DKIM_NAME="${DKIM_SELECTOR}._domainkey.${DOMAIN}"
section "DKIM (TXT $DKIM_NAME)"
if run_dig TXT "$DKIM_NAME"; then
  TXT_RAW="$DIG_RAW"
  # One DKIM RR is usually one dig line with multiple quoted chunks; join all
  # lines in case a resolver splits awkwardly.
  DKIM_RESULT=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    joined=$(txt_join_line "$line")
    DKIM_RESULT="${DKIM_RESULT}${joined}"
  done <<< "$TXT_RAW"
  # Remove spaces that dig inserts between quoted chunks inside the key.
  DKIM_COMPACT=$(printf '%s' "$DKIM_RESULT" | tr -d '[:space:]')

  printf '%s\n' "$DKIM_RESULT"
  if [[ "$DKIM_RESULT" == *"$EXPECTED_DKIM_SUBSTR"* && "$DKIM_COMPACT" == *"$EXPECTED_DKIM_PSTART"* ]]; then
    ok "DKIM matches (header + public key prefix are correct)"
  elif [[ "$DKIM_COMPACT" == *"v=DKIM1"* || "$DKIM_COMPACT" == *"V=DKIM1"* ]]; then
    warn "DKIM TXT present but header/key prefix do not match expected values"
  else
    fail "TXT at $DKIM_NAME does not look like a DKIM key"
  fi
else
  dig_failed "DKIM (TXT $DKIM_NAME)"
fi

# ---------- DMARC ----------
DMARC_NAME="_dmarc.${DOMAIN}"
section "DMARC (TXT $DMARC_NAME)"
if run_dig TXT "$DMARC_NAME"; then
  TXT_RAW="$DIG_RAW"
  DMARC_RESULT=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    joined=$(txt_join_line "$line")
    case "$joined" in
      v=DMARC1*|V=DMARC1*)
        DMARC_RESULT="$joined"
        break
        ;;
    esac
  done <<< "$TXT_RAW"

  if [[ -z "$DMARC_RESULT" ]]; then
    fail "TXT answers present but none start with v=DMARC1"
    printf '%s\n' "$TXT_RAW"
  else
    printf '%s\n' "$DMARC_RESULT"
    # Compare case-insensitively on tags; pin exact string when equal ignoring case.
    if [[ "$(ascii_lower "$DMARC_RESULT")" == "$(ascii_lower "$EXPECTED_DMARC")" ]]; then
      ok "DMARC matches expected: $EXPECTED_DMARC"
    else
      warn "DMARC found but differs from $EXPECTED_DMARC"
      info "got: $DMARC_RESULT"
    fi
  fi
else
  dig_failed "DMARC (TXT $DMARC_NAME)"
fi

# ---------- MX ----------
section "MX ($DOMAIN)"
if run_dig MX "$DOMAIN"; then
  MX_RESULT="$DIG_RAW"
  printf '%s\n' "$MX_RESULT"
  MX_MATCH_PRIO=0
  MX_MATCH_HOST=0
  EXPECTED_MX_HOST_N=$(norm_host "$EXPECTED_MX_HOST")
  while IFS= read -r line || [[ -n "$line" ]]; do
    # +short MX: "<priority> <host>."
    prio=$(printf '%s\n' "$line" | awk '{print $1}')
    host=$(printf '%s\n' "$line" | awk '{print $2}')
    host_n=$(norm_host "$host")
    if [[ "$host_n" == "$EXPECTED_MX_HOST_N" ]]; then
      MX_MATCH_HOST=1
      if [[ "$prio" == "$EXPECTED_MX_PRIO" ]]; then
        MX_MATCH_PRIO=1
      fi
    fi
  done <<< "$MX_RESULT"

  if [[ "$MX_MATCH_HOST" -eq 1 && "$MX_MATCH_PRIO" -eq 1 ]]; then
    ok "MX matches exactly: $EXPECTED_MX_PRIO $EXPECTED_MX_HOST"
  elif [[ "$MX_MATCH_HOST" -eq 1 ]]; then
    warn "MX points to $EXPECTED_MX_HOST but priority differs from $EXPECTED_MX_PRIO"
  else
    fail "MX found but does not point to $EXPECTED_MX_HOST"
  fi
else
  dig_failed "MX ($DOMAIN)"
fi

# ---------- A ----------
section "A ($DOMAIN)"
if run_dig A "$DOMAIN"; then
  A_RESULT="$DIG_RAW"
  printf '%s\n' "$A_RESULT"
  if printf '%s\n' "$A_RESULT" | grep -qxF "$EXPECTED_A"; then
    ok "A matches: $EXPECTED_A"
  elif printf '%s\n' "$A_RESULT" | grep -qF "$EXPECTED_A"; then
    ok "A includes expected address: $EXPECTED_A"
  else
    warn "A found but does not include $EXPECTED_A"
  fi
else
  dig_failed "A ($DOMAIN)"
fi

# ---------- AAAA ----------
section "AAAA ($DOMAIN)"
if run_dig AAAA "$DOMAIN"; then
  AAAA_RESULT="$DIG_RAW"
  printf '%s\n' "$AAAA_RESULT"
  EXPECTED_AAAA_L=$(ascii_lower "$EXPECTED_AAAA")
  AAAA_NORM=$(ascii_lower "$AAAA_RESULT")
  if printf '%s\n' "$AAAA_NORM" | grep -qF "$EXPECTED_AAAA_L"; then
    ok "AAAA matches: $EXPECTED_AAAA"
  else
    # Optional: python ipaddress for compressed/expanded forms when available.
    if command -v python3 >/dev/null 2>&1; then
      if EXPECTED_AAAA="$EXPECTED_AAAA" AAAA_RESULT="$AAAA_RESULT" python3 - <<'PY'
import ipaddress, os, sys
exp = ipaddress.IPv6Address(os.environ["EXPECTED_AAAA"])
for line in os.environ["AAAA_RESULT"].splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        if ipaddress.IPv6Address(line) == exp:
            sys.exit(0)
    except ValueError:
        pass
sys.exit(1)
PY
      then
        ok "AAAA matches (normalized): $EXPECTED_AAAA"
      else
        warn "AAAA found but differs from $EXPECTED_AAAA"
      fi
    else
      warn "AAAA found but differs from $EXPECTED_AAAA (install python3 for IPv6 normalization)"
    fi
  fi
else
  dig_failed "AAAA ($DOMAIN)"
fi

# ---------- CNAME (vcp) ----------
CNAME_NAME="${EXPECTED_CNAME_HOST}.${DOMAIN}"
section "CNAME ($CNAME_NAME)"
if run_dig CNAME "$CNAME_NAME"; then
  CNAME_RESULT="$DIG_RAW"
  printf '%s\n' "$CNAME_RESULT"
  EXPECTED_CNAME_N=$(norm_host "$EXPECTED_CNAME_VALUE")
  CNAME_MATCH=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$(norm_host "$line")" == "$EXPECTED_CNAME_N" ]]; then
      CNAME_MATCH=1
      break
    fi
  done <<< "$CNAME_RESULT"
  if [[ "$CNAME_MATCH" -eq 1 ]]; then
    ok "CNAME matches: $EXPECTED_CNAME_VALUE"
  else
    warn "CNAME found but differs from $EXPECTED_CNAME_VALUE"
  fi
else
  # Some resolvers chase CNAMEs and return empty +short for type CNAME.
  # Retry with +noall +answer and look for a CNAME RR explicitly.
  set +e
  if [[ -n "$RESOLVER" ]]; then
    ANSWER=$(dig @"$RESOLVER" +time="$DIG_TIMEOUT" +tries="$DIG_TRIES" \
      +nosearch +noall +answer "$CNAME_NAME" CNAME 2>&1)
  else
    ANSWER=$(dig +time="$DIG_TIMEOUT" +tries="$DIG_TRIES" \
      +nosearch +noall +answer "$CNAME_NAME" CNAME 2>&1)
  fi
  set -e
  if printf '%s\n' "$ANSWER" | grep -qiE '[[:space:]]CNAME[[:space:]]'; then
    printf '%s\n' "$ANSWER"
    if printf '%s\n' "$ANSWER" | grep -qiF "$(strip_dot "$EXPECTED_CNAME_VALUE")"; then
      ok "CNAME matches (from answer section): $EXPECTED_CNAME_VALUE"
    else
      warn "CNAME RR present but target differs from $EXPECTED_CNAME_VALUE"
    fi
  else
    dig_failed "CNAME ($CNAME_NAME)"
  fi
fi

# ---------- Summary ----------
echo
echo "=================================================="
printf ' Summary: %b%d passed%b, %b%d warnings%b, %b%d failed%b\n' \
  "$GREEN" "$PASS_COUNT" "$NC" \
  "$YELLOW" "$WARN_COUNT" "$NC" \
  "$RED" "$FAIL_COUNT" "$NC"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo " Result:  FAILED"
  echo "=================================================="
  exit 1
fi
if [[ "$WARN_COUNT" -gt 0 ]]; then
  echo " Result:  OK (with warnings)"
else
  echo " Result:  OK"
fi
echo "=================================================="
exit 0
