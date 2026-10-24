#!/usr/bin/env bash
#
# LAB-NSE-08: Fragmentation Handling Resilience
#
# Runs three SYN-scan variants of the same port list against the
# authorized lab target -- unfragmented baseline, -f (8-byte
# fragments), -ff (16-byte fragments) -- tagging each with the
# lab-nse-08-fragstate.nse script so results can be compared and
# correlated with pfSense / Snort / Suricata / Zeek logs for the same
# time window.
#
# LAB ONLY. Set TARGET to your isolated lab's Ubuntu victim before
# running. Do not point this at anything outside the authorized lab.

set -euo pipefail

EXPERIMENT_ID="LAB-NSE-08"
TARGET="192.168.56.20"          # <-- set to your Ubuntu victim's IP
PORTS="22,80,443"
SCRIPT="$(dirname "$0")/lab-nse-08-fragstate.nse"
OUTDIR="./results/${EXPERIMENT_ID}"

# The guidelines require every record to carry a "source" field.
# Resolve the Kali scanner's own address automatically; override by
# setting SOURCE yourself if this host has multiple interfaces/IPs.
SOURCE="${SOURCE:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
SOURCE="${SOURCE:-unspecified}"

mkdir -p "$OUTDIR"

echo "[*] ${EXPERIMENT_ID} starting: $(date -u +%FT%TZ)"
echo "[*] Source: ${SOURCE}  Target: ${TARGET}"
echo "[*] NOTE: before trusting results, confirm fragments actually left"
echo "    the wire intact (some OSes defragment outgoing packets in the"
echo "    kernel). Optional tcpdump block is below -- uncomment and set"
echo "    IFACE to capture pcaps for each variant."

# --- Optional packet-capture verification (uncomment to use) --------
# IFACE="eth0"   # <-- set to your Kali scan interface
# sudo tcpdump -i "$IFACE" -w "${OUTDIR}/baseline_capture.pcap" host "$TARGET" &
# TCPDUMP_PID=$!
# ----------------------------------------------------------------------

echo "[*] Running baseline variant (unfragmented)..."
nmap -sS -T4 -p "$PORTS" \
     --script "$SCRIPT" \
     --script-args lab08.variant=baseline,lab08.source="${SOURCE}",lab08.fragsize=0 \
     -oA "${OUTDIR}/baseline_variant" \
     "$TARGET"

echo "[*] Running frag8 variant (-f, 8-byte fragments)..."
nmap -sS -f -T4 -p "$PORTS" \
     --script "$SCRIPT" \
     --script-args lab08.variant=frag8,lab08.source="${SOURCE}",lab08.fragsize=8 \
     -oA "${OUTDIR}/frag8_variant" \
     "$TARGET"

echo "[*] Running frag16 variant (-ff, 16-byte fragments)..."
nmap -sS -ff -T4 -p "$PORTS" \
     --script "$SCRIPT" \
     --script-args lab08.variant=frag16,lab08.source="${SOURCE}",lab08.fragsize=16 \
     -oA "${OUTDIR}/frag16_variant" \
     "$TARGET"

# --- Stop capture if the optional block above was enabled -----------
# sudo kill "$TCPDUMP_PID" 2>/dev/null || true
# ----------------------------------------------------------------------

echo "[*] ${EXPERIMENT_ID} complete: $(date -u +%FT%TZ)"
echo "[*] Now pull the matching pfSense / Snort / Suricata / Zeek logs"
echo "    for this time window and compare against ${OUTDIR}/*.xml"
echo "[*] Fill in the Experiment Results section of README-LAB-NSE-08.md"
