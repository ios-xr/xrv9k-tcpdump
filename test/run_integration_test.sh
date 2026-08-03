#!/usr/bin/env bash
# Copyright 2026 Cisco Systems Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# run_integration_test.sh
#
# Integration test for xrv9k_pcap_decode.py: decode a real-hardware capture,
# then verify the resulting pcapng with tshark/capinfos.
#
# Usage:
#   ./run_integration_test.sh <capture.pcap> <ifh_map.txt>
#
# Expects xrv9k_pcap_decode.py to live one directory up (the repo root).
# Output files are written alongside the input pcap.

set -uo pipefail

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

PASSED=0; FAILED=0; WARNED=0

pass() { printf "  ${GREEN}PASS${NC}  %-8s %s\n" "$1" "$2"; PASSED=$((PASSED+1)); }
fail() { printf "  ${RED}FAIL${NC}  %-8s %s\n" "$1" "$2"; FAILED=$((FAILED+1)); }
warn() { printf "  ${YELLOW}WARN${NC}  %-8s %s\n" "$1" "$2"; WARNED=$((WARNED+1)); }
header() { printf "\n${BOLD}=== %s ===${NC}\n" "$*"; }

# Count packets matching a tshark display filter; trim any whitespace.
count_packets() {
    tshark -r "$1" -Y "$2" -T fields -e frame.number 2>/dev/null \
        | awk 'END{print NR}'
}

# PASS if count > 0, FAIL otherwise.
check_has() {
    local id=$1 desc=$2 file=$3 filter=$4
    local n; n=$(count_packets "$file" "$filter")
    if [ "$n" -gt 0 ]; then
        pass "$id" "$desc ($n packets)"
    else
        fail "$id" "$desc — 0 packets matched: $filter"
    fi
}

# PASS if count == 0, FAIL otherwise.
check_none() {
    local id=$1 desc=$2 file=$3 filter=$4
    local n; n=$(count_packets "$file" "$filter")
    if [ "$n" -eq 0 ]; then
        pass "$id" "$desc"
    else
        fail "$id" "$desc — expected 0 but got $n packets"
    fi
}

# ── Argument / dependency checks ───────────────────────────────────────────────
header "Preflight"

PCAP=${1:-}
IFHMAP=${2:-}

if [ -z "$PCAP" ] || [ -z "$IFHMAP" ]; then
    printf "Usage: %s <capture.pcap> <ifh_map.txt>\n" "$0" >&2
    exit 1
fi

ERRORS=0
for req in "$PCAP" "$IFHMAP"; do
    if [ ! -f "$req" ]; then
        printf "  ${RED}ERROR${NC}  File not found: %s\n" "$req"
        ERRORS=$((ERRORS+1))
    fi
done

for tool in python3 tshark capinfos; do
    if ! command -v "$tool" &>/dev/null; then
        printf "  ${RED}ERROR${NC}  Required tool not found: %s\n" "$tool"
        ERRORS=$((ERRORS+1))
    fi
done

[ "$ERRORS" -gt 0 ] && exit 1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STRIP="${SCRIPT_DIR}/../xrv9k_pcap_decode.py"

if [ ! -f "$STRIP" ]; then
    printf "  ${RED}ERROR${NC}  xrv9k_pcap_decode.py not found at: %s\n" "$STRIP" >&2
    exit 1
fi

DIR="$(cd "$(dirname "$PCAP")" && pwd)"
STEM="$(basename "$PCAP" .pcap)"
PCAPNG="${DIR}/${STEM}.pcapng"
PCAPNG_NOMAP="${DIR}/${STEM}_nomap.pcapng"
SUMMARY="${DIR}/${STEM}_summary.txt"

printf "  Input pcap    : %s\n" "$PCAP"
printf "  Interface map : %s\n" "$IFHMAP"
printf "  Output (map)  : %s\n" "$PCAPNG"
printf "  Output (nomap): %s\n" "$PCAPNG_NOMAP"

# ── Processing ─────────────────────────────────────────────────────────────────
header "Processing"

# Primary run — with interface map
printf "\n  Running xrv9k_pcap_decode.py with --iface-map …\n"
if python3 "$STRIP" -m "$IFHMAP" "$PCAP" -o "$PCAPNG" 2>"$SUMMARY"; then
    pass "6.1" "xrv9k_pcap_decode.py exited 0 (with --iface-map)"
else
    fail "6.1" "xrv9k_pcap_decode.py exited $? (with --iface-map)"
fi

printf "\n  Summary output:\n"
sed 's/^/    /' "$SUMMARY"

# Alternate run — without interface map
printf "\n  Running xrv9k_pcap_decode.py without --iface-map …\n"
if python3 "$STRIP" "$PCAP" -o "$PCAPNG_NOMAP" 2>/dev/null; then
    pass "6.2" "xrv9k_pcap_decode.py exited 0 (without --iface-map)"
else
    fail "6.2" "xrv9k_pcap_decode.py exited $? (without --iface-map)"
fi

# Abort tshark checks early if the primary output is missing.
if [ ! -f "$PCAPNG" ]; then
    fail "7.x" "Output file missing ($PCAPNG) — cannot continue with verification checks"
    FAILED=$((FAILED+1))
    header "Results"
    printf "  ${GREEN}Passed${NC}: %d\n" "$PASSED"
    [ "$WARNED" -gt 0 ] && printf "  ${YELLOW}Warned${NC}: %d\n" "$WARNED"
    printf "  ${RED}Failed${NC}: %d\n" "$FAILED"
    exit 1
fi

# ── Verification ───────────────────────────────────────────────────────────────
header "IS-IS decode"

check_has "T01" "IS-IS PUNT  (802.3 LLC → sll.pkttype=0)" \
    "$PCAPNG" "isis && sll.pkttype == 0"
check_has "T02" "IS-IS INJECT (LLC prepend → sll.pkttype=4)" \
    "$PCAPNG" "isis && sll.pkttype == 4"
check_has "T02b" "IS-IS Hello PDU (isis.hello)" \
    "$PCAPNG" "isis.hello"

header "IPv4 / BGP decode"

check_has "T03"  "IPv4 PUNT  (BGP received)" \
    "$PCAPNG" "bgp && sll.pkttype == 0"
check_has "T04"  "IPv4 INJECT (BGP sent)" \
    "$PCAPNG" "bgp && sll.pkttype == 4"
check_has "T04b" "IPv4 INJECT (OSPF Hello — subinterfaces)" \
    "$PCAPNG" "ospf && sll.pkttype == 4"

header "IPv6 decode"

check_has "T05"  "IPv6 PUNT" \
    "$PCAPNG" "ipv6 && sll.pkttype == 0"
check_has "T06"  "IPv6 INJECT" \
    "$PCAPNG" "ipv6 && sll.pkttype == 4"
check_has "T06b" "ICMPv6 Echo Request INJECT (ping6)" \
    "$PCAPNG" "icmpv6.type == 128 && sll.pkttype == 4"
check_has "T06c" "ICMPv6 Echo Reply PUNT (ping6)" \
    "$PCAPNG" "icmpv6.type == 129 && sll.pkttype == 0"

header "ARP decode"

check_has "T07" "ARP PUNT  (frame received from wire)" \
    "$PCAPNG" "arp && sll.pkttype == 0"

# T08: ARP — platform note.
# On XRv9K, ARP is largely handled outside this capture path: ARP transmitted
# and ARP requests received are usually absent, while some received ARP
# replies do appear. Treat their absence as expected, not a failure.
n_arp_inject=$(count_packets "$PCAPNG" "arp && sll.pkttype == 4")
if [ "$n_arp_inject" -gt 0 ]; then
    pass "T08" "ARP INJECT present ($n_arp_inject packets — seen in practice)"
else
    warn "T08" "ARP INJECT absent — expected: XRv9K rarely injects ARP into this path"
fi

n_arp_req_punt=$(count_packets "$PCAPNG" "arp && sll.pkttype == 0 && arp.opcode == 1")
if [ "$n_arp_req_punt" -gt 0 ]; then
    pass "T08-ReqPUN" "ARP Request PUNT present ($n_arp_req_punt packets — seen in practice)"
else
    warn "T08-ReqPUN" "ARP Request PUNT absent — expected: XRv9K rarely punts ARP requests"
fi

# ARP Reply PUNT: seen in practice.
check_has "T08-RepPUN" "ARP Reply PUNT (seen in practice)" \
    "$PCAPNG" "arp && sll.pkttype == 0 && arp.opcode == 2"

header "Interface / VLAN IDB separation"

IFACE_LIST=$(tshark -r "$PCAPNG" -T fields -e frame.interface_name 2>/dev/null \
    | sort -u | grep -v '^$')
IFACE_COUNT=$(printf '%s\n' "$IFACE_LIST" | grep -c . || true)

printf "  Interfaces in output:\n"
printf '%s\n' "$IFACE_LIST" | sed 's/^/    /'
printf '\n'

if [ "$IFACE_COUNT" -ge 4 ]; then
    pass "T10" "≥4 distinct IDBs ($IFACE_COUNT found)"
else
    fail "T10" "Expected ≥4 IDBs, got $IFACE_COUNT"
fi

CAPINFO_IFACE=$(capinfos -I "$PCAPNG" 2>/dev/null \
    | awk '/Interface #/{count++} END{print count+0}')
if [ "$CAPINFO_IFACE" -ge 4 ]; then
    pass "T10b" "capinfos reports $CAPINFO_IFACE IDBs"
else
    fail "T10b" "capinfos reports $CAPINFO_IFACE IDBs (expected ≥4)"
fi

for suffix in ".100" ".200"; do
    match=$(printf '%s\n' "$IFACE_LIST" | grep -E "${suffix}$" || true)
    if [ -n "$match" ]; then
        pass "T09${suffix}" "VLAN${suffix} IDB present: $match"
    else
        fail "T09${suffix}" "VLAN${suffix} IDB not found in output"
    fi
done

# The parent trunk (Gi0/0/0/1, no subinterface suffix) must NOT appear.
TRUNK=$(printf '%s\n' "$IFACE_LIST" | grep -E '/0/0/1$' || true)
if [ -z "$TRUNK" ]; then
    pass "T09-trunk" "Parent trunk interface absent from IDBs (correct)"
else
    warn "T09-trunk" "Parent trunk IDB present: $TRUNK (expected absent)"
fi

header "Interface naming"

GE_COUNT=$(printf '%s\n' "$IFACE_LIST" | grep -c "GigabitEthernet" || true)
HEX_COUNT=$(printf '%s\n' "$IFACE_LIST" | grep -c "if-0x" || true)

if [ "$GE_COUNT" -ge 4 ] && [ "$HEX_COUNT" -eq 0 ]; then
    pass "T11" "All IDB names resolved to GigabitEthernet names (no hex fallbacks)"
elif [ "$GE_COUNT" -ge 4 ]; then
    warn "T11" "$GE_COUNT GigabitEthernet names but $HEX_COUNT hex fallback(s) — handle(s) missing from map"
else
    fail "T11" "$GE_COUNT GigabitEthernet IDB names, $HEX_COUNT hex fallback(s) — expected ≥4 named"
fi

if [ -f "$PCAPNG_NOMAP" ]; then
    NOMAP_IFACES=$(tshark -r "$PCAPNG_NOMAP" -T fields -e frame.interface_name 2>/dev/null \
        | sort -u | grep -v '^$')
    NOMAP_HEX=$(printf '%s\n' "$NOMAP_IFACES" | grep -c "if-0x" || true)
    NOMAP_GE=$(printf '%s\n'  "$NOMAP_IFACES" | grep -c "GigabitEthernet" || true)
    if [ "$NOMAP_HEX" -ge 4 ] && [ "$NOMAP_GE" -eq 0 ]; then
        pass "T12" "No-map output: all $NOMAP_HEX IDB names are hex (if-0x…)"
    else
        fail "T12" "No-map output: $NOMAP_HEX hex, $NOMAP_GE GigabitEthernet — expected hex-only"
    fi
else
    warn "T12" "No-map output file missing — T12 skipped"
fi

header "Output format and summary"

FILETYPE=$(capinfos "$PCAPNG" 2>/dev/null | awk -F: '/File type/{gsub(/^[[:space:]]+/,"",$2); print $2}')
if printf '%s' "$FILETYPE" | grep -qi "pcapng\|pcap-ng"; then
    pass "T13" "File type: $FILETYPE"
else
    fail "T13" "Unexpected file type: '$FILETYPE'"
fi

if grep -qE "^xrv9k_pcap_decode: read [0-9]+ packets, wrote [0-9]+ IDBs, [0-9]+ EPBs" "$SUMMARY"; then
    pass "T14a" "Summary totals line present"
else
    fail "T14a" "Summary totals line missing or malformed"
fi

if grep -qE "IDB [0-9]+ .+ punt=[0-9]+ +inject=[0-9]+" "$SUMMARY"; then
    pass "T14b" "Per-IDB summary lines present"
else
    fail "T14b" "Per-IDB lines missing from summary"
fi

BIDIR=$(grep -E "IDB [0-9]+" "$SUMMARY" | awk '
    {
        p=0; inj=0
        for (i=1; i<=NF; i++) {
            if ($i ~ /^punt=/)   { split($i, a, "="); p   = a[2]+0 }
            if ($i ~ /^inject=/) { split($i, a, "="); inj = a[2]+0 }
        }
        if (p > 0 && inj > 0) count++
    }
    END { print count+0 }
')
if [ "$BIDIR" -ge 1 ]; then
    pass "T14c" "≥1 IDB has both PUNT and INJECT traffic ($BIDIR IDB(s))"
else
    fail "T14c" "No IDB has both PUNT and INJECT traffic (ARP/protocol triggers may be missing)"
fi

# ── Exit codes ─────────────────────────────────────────────────────────────────
header "Exit codes"

python3 "$STRIP" /no_such_file_xyz.pcap -o /dev/null 2>/dev/null; rc=$?
if [ "$rc" -eq 1 ]; then
    pass "EC1" "Exit 1 for missing input file"
else
    fail "EC1" "Expected exit 1 for missing file, got $rc"
fi

# ── Results ────────────────────────────────────────────────────────────────────
header "Results"
printf "  ${GREEN}Passed${NC}: %d\n" "$PASSED"
[ "$WARNED" -gt 0 ] && printf "  ${YELLOW}Warned${NC}: %d  (warnings do not affect pass/fail)\n" "$WARNED"
printf "  ${RED}Failed${NC}: %d\n" "$FAILED"
printf '\n'

if [ "$FAILED" -eq 0 ]; then
    printf "  ${GREEN}${BOLD}ALL CHECKS PASSED${NC}\n\n"
    exit 0
else
    printf "  ${RED}${BOLD}%d CHECK(S) FAILED${NC}\n\n" "$FAILED"
    exit 1
fi
