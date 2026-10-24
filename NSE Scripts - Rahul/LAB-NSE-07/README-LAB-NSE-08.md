# LAB-NSE-08: Fragmentation Handling Resilience

## Experiment template (pre-code spec)

```
========================================================
EXPERIMENT: LAB-NSE-08
NAME: Fragmentation Handling Resilience
========================================================

SOURCE:
    Kali scanner

TARGET:
    Ubuntu victim

TRAFFIC:
    TCP SYN scan (variant=baseline, unfragmented), TCP SYN scan
    (variant=frag8, -f / 8-byte fragments), and TCP SYN scan
    (variant=frag16, -ff / 16-byte fragments) of the same small port
    list, run as three separate invocations.

FIREWALL:
    Expected: IF [scrub/reassembly enabled] Same allow/deny outcome as
              baseline — pfSense reassembles before filtering, so
              fragmentation is invisible to the ruleset.
              [IF disabled/unknown] Possible divergence from baseline
              — pfSense may evaluate the first fragment alone, which
              per the Nmap doc may not contain the full TCP header.
    Reason: pfSense filters on port/protocol/flags, which live in the
            TCP header -- a tiny first fragment may not carry the whole
            header, so the outcome depends on whether scrub reassembles
            before filtering. Resolves once the setting is confirmed
            (see Open TODOs).

SNORT:
    Expected: ALERT on all three variants; frag8 is the likeliest to
    break this expectation if reassembly has limits.

SURICATA:
    Expected: Same as Snort.

ZEEK:
    Expected: OBSERVE on all three variants regardless of alert outcome.

PRIMARY QUESTION:
    Does fragmenting a SYN probe at all change detection by Snort/
    Suricata, compared to an unfragmented baseline?

SECONDARY QUESTION:
    Among fragmented variants, does fragment size itself affect
    whether detection occurs?

SUCCESS:
    The firewall, Snort, Suricata, and Zeek each behave as expected
    across all three variants -- in particular, Snort and Suricata
    still alert and Zeek still observes the fragmented variants
    (frag8, frag16) just as reliably as the baseline, meaning
    fragmentation does not weaken detection.

FAILURE:
    A fragmented variant -- especially frag8 -- reaches the target
    (firewall allows it, matching baseline) but Snort and/or Suricata
    fail to alert where the baseline did, with no documented
    reassembly-limit explanation. This is a genuine detection gap:
    fragmentation lets reconnaissance traffic through undetected.

DATA TO COLLECT:
    - start/end timestamp (per variant)
    - ports tested
    - fragment size used (per variant: 0, 8, 16)
    - firewall decision (per port, per variant)
    - Snort alert (per variant)
    - Suricata alert (per variant)
    - Zeek conn.log entry / visibility (per variant)
    - detection latency (per variant)
    - whether sent packets were confirmed fragmented on the wire
      (verify via Wireshark/tcpdump -- some source OSes defragment
      outgoing packets in the kernel)
```

## What does the script test?

Whether fragmenting a TCP SYN probe -- and the size of those fragments
-- changes what pfSense allows through and what Snort, Suricata, and
Zeek see, compared to an identical unfragmented scan.

## What traffic does it generate?

Three Nmap runs against the same small port list (22, 80, 443) on the
authorized lab target:

1. `nmap -sS` (baseline) tagged `lab08.variant=baseline`, `lab08.fragsize=0`
2. `nmap -sS -f` (8-byte fragments) tagged `lab08.variant=frag8`, `lab08.fragsize=8`
3. `nmap -sS -ff` (16-byte fragments) tagged `lab08.variant=frag16`, `lab08.fragsize=16`

As with LAB-NSE-06, the NSE script sends no extra packets and does not
control fragmentation itself -- Nmap's core scan engine handles that
via `-f`/`-ff`. NSE does not support fragmentation for its own logic,
since script probes rely on the host TCP stack. The script's only job
is to format each port's result into structured text and a JSON line
for the central collector.

## Why should the firewall allow/block it?

Firewall rules in this lab are defined per port/protocol, and a
fragmented SYN carries the same port/protocol information as an
unfragmented one -- just split across more packets. So the expected
outcome is that fragmentation does not change pfSense's allow/deny
decision, **unless** pfSense evaluates the first fragment alone before
reassembly, in which case a divergence from baseline is possible if
that first fragment doesn't contain the full TCP header. This is
exactly the scenario described in Nmap's own documentation on
fragmentation. Confirm pfSense's scrub/reassembly setting
before treating any divergence as a firewall-level finding rather
than expected behavior.

## What Snort rule should detect it?

Whatever scan-detection rule fires on the baseline should, in
principle, also fire on frag8 and frag16 if Snort's `frag3` reassembly
preprocessor is enabled and reconstructs the packet before signature
matching. Record the exact SID(s) that fire for each variant --
frag8 is the variant most likely to expose a reassembly limit, since
smaller fragments stress the preprocessor harder than larger ones.

## What Suricata rule should detect it?

Same expectation as Snort, via Suricata's `defrag` preprocessor.
Record the exact signature ID(s) per variant.

## What should Zeek log?

A `conn.log` entry for every probe in all three variants, since Zeek's
visibility doesn't depend on signature matching the way Snort/Suricata
alerting does. Check `weird.log` for anything flagging inconsistent or
incomplete reassembly, especially on frag8.

## Firewall vs IDS vs IPS vs network visibility

- **Firewall enforcement** — did pfSense allow or drop each
  fragmented probe, and does that match the baseline?
- **IDS detection** — did Snort/Suricata alert, independent of
  whether the firewall let the packet through?
- **IPS prevention** — if Snort/Suricata are deployed inline, did
  they additionally block the fragmented traffic? 
- **Network visibility** — did Zeek log the connection regardless of
  the other three outcomes?

A genuine FAILURE for this experiment requires the firewall to have
let the traffic through (matching baseline) **and** the IDS to have
missed it -- not just one layer behaving unexpectedly.

## What constitutes a detection failure?

See FAILURE in the template above: a fragmented variant reaches the
target but Snort/Suricata fail to alert where baseline did, with no
documented reassembly-limit explanation.

## What metrics should we collect?

See DATA TO COLLECT in the template above.

---

## Things to Make Note of

1. **Confirm pfSense's fragment reassembly/scrub setting**
   This determines the FIREWALL hypothesis above and whether any
   observed divergence from baseline is expected or a real finding.
2. **Confirm whether Snort/Suricata are deployed passively (IDS-only)
   or inline (IPS)** in this lab, so the IPS-prevention column in the
   results table means something.
3. **Verify fragments actually left the wire intact** via tcpdump/
   Wireshark on the Kali box before trusting a "no difference from
   baseline" result on frag8/frag16 -- some source OSes (e.g. Linux
   with iptables connection tracking) silently defragment outgoing
   packets in the kernel, which would make a negative result
   meaningless rather than a finding. The wrapper script has an
   optional, commented-out tcpdump block for this.

---

## Example output (single port, frag8 variant)

```
experiment_id: LAB-NSE-08
variant: frag8
stage: fragmentation_resilience
timestamp: 2026-10-24T18:05:11Z
source: 172.21.50.199
target: 192.168.56.20
fragment_size: 8
port: 443
protocol: tcp
state: filtered
service: https
JSON: {"experiment_id":"LAB-NSE-08","variant":"frag8","stage":"fragmentation_resilience","timestamp":"2026-10-24T18:05:11Z","source":"172.21.50.199","destination":"192.168.56.20","fragment_size":"8","port":443,"protocol":"tcp","state":"filtered"}
```

## Files in this experiment

1. `lab-nse-08-fragstate.nse` — the NSE script (structured output only;
   does not control fragmentation)
2. `run-lab-nse-08.sh` — wrapper that runs all three variants and saves
   `-oA` output under `results/LAB-NSE-08/`, with an optional tcpdump
   verification block
3. `README-LAB-NSE-08.md` — this file
4. Example output — see above
5. Expected firewall / Snort / Suricata / Zeek behavior — see sections
   above
6. **Experiment results** — fill in below after running

---

## Experiment Results (fill in after running)

**Snort/Suricata deployment mode for this run:** IDS-only (passive) / Inline (IPS) — confirm and record before filling the table.

**Fragments confirmed intact on the wire (tcpdump/Wireshark check):** Yes / No — confirm before trusting "no difference" results.

| Port | Baseline state | frag8 state | frag16 state | Firewall inference | Snort alert (IDS) | Suricata alert (IDS) | IPS blocked? (n/a if passive) | Zeek visibility | Notes |
|------|-----------------|-------------|---------------|---------------------|--------------------|------------------------|---------------------------------|------------------|-------|
| 22   |                 |             |               |                     |                    |                        |                                  |                  |       |
| 80   |                 |             |               |                     |                    |                        |                                  |                  |       |
| 443  |                 |             |               |                     |                    |                        |                                  |                  |       |

**Detection latency:**
- Baseline: ___
- frag8: ___
- frag16: ___

**Conclusion:** (does fragmentation change firewall/IDS/IPS/visibility outcomes vs baseline; does fragment size specifically matter; any genuine detection gap found)
