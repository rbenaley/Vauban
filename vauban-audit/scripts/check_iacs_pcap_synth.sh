#!/usr/bin/env bash
# vauban-audit structural lint: every IACS PCAP record on disk MUST
# go through the synthetic L3/L4 layer (`iacs_pcap_synth::build_*`).
#
# Background: pre-v0.7.20 the audit module wrote raw application
# bytes inside libpcap records under LINKTYPE_RAW. Wireshark and
# tcpdump interpret the first nibble as the IP version, so an
# industrial PDU starting with `0x03` (S7) was dissected as IPv0,
# Modbus PDUs starting with `0x00` were dissected as broken IPv0,
# etc. The fix is the synthetic IPv4/IPv6 + TCP wrapper module
# (`vauban-audit/src/iacs_pcap_synth.rs`) -- this lint enforces
# that no caller in `iacs_recording_manager.rs` rewrites bytes by
# hand, bypassing the wrapper.
#
# Returns non-zero if a regression is detected.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)"; then
    cd "$ROOT"
else
    cd "$SCRIPT_DIR/../.."
fi

MGR=vauban-audit/src/iacs_recording_manager.rs
SYNTH=vauban-audit/src/iacs_pcap_synth.rs

if [[ ! -f "$MGR" || ! -f "$SYNTH" ]]; then
    echo "ERROR: missing IACS recording sources ($MGR / $SYNTH)" >&2
    exit 2
fi

fail=0

# 1. The manager MUST import / call the synth module.
if ! grep -q 'iacs_pcap_synth::' "$MGR"; then
    echo "ERROR: $MGR does not call iacs_pcap_synth -- the synthetic" \
         "L3/L4 layer is mandatory for Wireshark / tcpdump dissection" >&2
    fail=1
fi

# 2. The legacy `build_packet_record` raw helper must NOT exist.
if grep -nE '\bfn[[:space:]]+build_packet_record\b' "$MGR" >&2; then
    echo "ERROR: legacy build_packet_record helper found in $MGR" \
         "-- must be replaced by iacs_pcap_synth::build_data_records" >&2
    fail=1
fi

# 3. The synth module exposes the four expected builders.
for fn in build_global_header build_handshake build_data_records build_close; do
    if ! grep -q "pub fn $fn" "$SYNTH"; then
        echo "ERROR: $SYNTH missing required builder pub fn $fn" >&2
        fail=1
    fi
done

# 4. LINKTYPE_RAW (12) constant lives in the synth module, not the
#    manager (single source of truth for the wire format).
if grep -nE 'LINKTYPE_RAW\s*[:=]' "$MGR" >&2 \
   | grep -v 'iacs_pcap_synth::' >/dev/null; then
    echo "ERROR: LINKTYPE_RAW redefinition in $MGR -- only" \
         "iacs_pcap_synth may declare the linktype" >&2
    fail=1
fi

# 5. No raw `0xa1b2c3d4` PCAP magic outside the synth module.
if grep -nE '0xa1b2_?c3d4' "$MGR" >&2; then
    echo "ERROR: PCAP global magic must come from" \
         "iacs_pcap_synth::PCAP_GLOBAL_MAGIC" >&2
    fail=1
fi

# 6. The aggregate BLAKE3 must hash ASCII hex bytes
#    (alignment with vauban-web::aggregate_rdp_blake3).
if ! grep -q 'blake3_hex.as_bytes()' "$MGR"; then
    echo "ERROR: aggregate_channel_blake3 must hash ASCII hex bytes" \
         "(blake3_hex.as_bytes()) to mirror the RDP rule" >&2
    fail=1
fi

if [[ $fail -ne 0 ]]; then
    echo "FAIL: vauban-audit synthetic L3/L4 invariants violated." >&2
    exit 1
fi

echo "OK: vauban-audit IACS PCAP synthetic L3/L4 invariants hold."
