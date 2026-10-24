#!/usr/bin/env bash
#
# LAB-NSE-09: Timing-Threshold Evasion (Scan-Delay Resilience)
#
# Runs a SWEEP of SYN-scan variants of the same 6-port list against
# the authorized lab target, each at a different --scan-delay value,
# tagging each with the lab-nse-09-timingstate.nse script so results
# can be compared and correlated with pfSense / Snort / Suricata /
# Zeek logs for the same time window.
#
# LAB ONLY. Set TARGET to your isolated lab's Ubuntu victim before
# running. Do not point this at anything outside the authorized lab.
#
# PREREQUISITE: your lab must implement the declared Snort and
# Suricata threshold rules in README-LAB-NSE-09.md BEFORE you run
# this sweep. The sweep points below straddle the computed breakpoint
# for that declared threshold (count=5, seconds=60 -> ~15000ms).
# Confirm with your lab that the rules are live before starting.

set -euo pipefail

EXPERIMENT_ID="LAB-NSE-09"
TARGET="192.168.56.20"          # <-- set to your Ubuntu victim's IP
PORTS="21,22,23,25,80,443"
SCRIPT="$(dirname "$0")/lab-nse-09-timingstate.nse"
OUTDIR="./results/${EXPERIMENT_ID}"

# Sweep points (ms), straddling the computed breakpoint of 15000ms
# for the declared count=5/seconds=60 threshold. Adjust if your lab
# implements a different count/seconds.
DELAYS_MS=(0 5000 10000 13000 15000 17000 20000 30000)

# The guidelines require every record to carry a "source" field.
SOURCE="${SOURCE:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
SOURCE="${SOURCE:-unspecified}"

mkdir -p "$OUTDIR"

echo "[*] ${EXPERIMENT_ID} starting: $(date -u +%FT%TZ)"
echo "[*] Source: ${SOURCE}  Target: ${TARGET}"
echo "[*] Sweep points (ms): ${DELAYS_MS[*]}"
echo "[*] Estimated total runtime: roughly 10-15 minutes for this sweep"
echo "    (runtime scales with delay * (ports-1) per point)."

for d in "${DELAYS_MS[@]}"; do
    variant="d${d}"
    echo "[*] Running sweep point ${variant} (--scan-delay ${d}ms)..."
    START=$(date -u +%FT%TZ)

    if [ "$d" -eq 0 ]; then
        nmap -sS -T4 -p "$PORTS" \
             --script "$SCRIPT" \
             --script-args lab09.variant="${variant}",lab09.source="${SOURCE}",lab09.delay_ms=0 \
             -oA "${OUTDIR}/${variant}_variant" \
             "$TARGET"
    else
        nmap -sS -T4 --scan-delay "${d}ms" -p "$PORTS" \
             --script "$SCRIPT" \
             --script-args lab09.variant="${variant}",lab09.source="${SOURCE}",lab09.delay_ms="${d}" \
             -oA "${OUTDIR}/${variant}_variant" \
             "$TARGET"
    fi

    END=$(date -u +%FT%TZ)
    echo "[*] ${variant} window: ${START} -> ${END}"
done

echo "[*] ${EXPERIMENT_ID} complete: $(date -u +%FT%TZ)"
echo "[*] Now pull the matching pfSense / Snort / Suricata / Zeek logs"
echo "    for each sweep point's time window and compare against"
echo "    ${OUTDIR}/*.xml"
echo "[*] Fill in the Experiment Results section of README-LAB-NSE-09.md"
