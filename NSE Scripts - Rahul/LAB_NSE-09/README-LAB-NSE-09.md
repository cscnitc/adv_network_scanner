# LAB-NSE-09: Timing-Threshold Evasion (Scan-Delay Resilience)

## Threshold to request from your lead

You are offense; your lead owns Snort/Suricata config. Rather than
guessing or reverse-engineering their defaults, hand them this exact,
identical threshold to implement in both tools before you run
anything. Using the same `count`/`seconds` in both makes the two
sensors directly comparable, and turns the breakpoint into computable
math instead of a guess.

**Declared threshold: 5 matching SYNs from one source within 60
seconds triggers an alert.**

Suricata rule:
```
alert tcp any any -> $HOME_NET any (msg:"LAB-NSE-09 Possible TCP SYN scan"; \
    flags:S; threshold: type threshold, track by_src, count 5, seconds 60; \
    sid:1000009; rev:1; classtype:attempted-recon;)
```

Snort rule (works in both Snort 2 and Snort 3 rule syntax):
```
alert tcp any any -> $HOME_NET any (msg:"LAB-NSE-09 Possible TCP SYN scan"; \
    flags:S; threshold: type threshold, track by_src, count 5, seconds 60; \
    sid:1000109; rev:1; classtype:attempted-recon;)
```

**Breakpoint math:** for `count` matching events to fall inside a
`seconds`-second window, the (count-1) gaps between them must sum to
at most `seconds`. So the maximum safe inter-probe delay is:

```
max_delay_ms = (seconds * 1000) / (count - 1)
             = (60 * 1000) / (5 - 1)
             = 15000 ms
```

Below ~15000ms delay: alert expected. At or above it: no alert
expected, for a 6-probe scan (see TRAFFIC below for why 6 ports).

**Ask your lead two more things** before running:
1. Confirm the rules above are loaded and active (not just syntax-
   checked) in both Snort and Suricata.
2. Whether Snort's built-in `sfPortscan`/`port_scan` preprocessor is
   also enabled alongside the declared rule. If so, it runs its own
   separate threshold and could alert independently -- ask them to
   either disable it for a clean test, or note its config so you can
   record its alerts as a distinct line item rather than conflating
   them with the declared rule's SID 1000109.

---

## Experiment template (pre-code spec)

```
========================================================
EXPERIMENT: LAB-NSE-09
NAME: Timing-Threshold Evasion (Scan-Delay Resilience)
========================================================

SOURCE:
    Kali scanner

TARGET:
    Ubuntu victim

TRAFFIC:
    TCP SYN scan sweep of a 6-port list (21, 22, 23, 25, 80, 443),
    run once per delay value in {0, 5000, 10000, 13000, 15000, 17000,
    20000, 30000} ms via --scan-delay, as separate invocations. Six
    ports are used (rather than 3, as in earlier experiments) so a
    single scan generates enough matching SYNs to potentially cross
    the declared count=5 threshold -- fewer ports could never trigger
    it regardless of delay.

FIREWALL:
    Expected: ALLOW, same outcome at every sweep point.
    Reason: pfSense filters on port/protocol, not inter-probe timing,
            unless an explicit rate-limiting rule is configured
            (confirm with lead).

SNORT:
    Expected: ALERT (SID 1000109) when delay < ~15000ms; no alert at
    or above it, per the declared threshold's breakpoint math.

SURICATA:
    Expected: ALERT (SID 1000009), identical breakpoint to Snort,
    since both run the same declared count/seconds.

ZEEK:
    Expected: OBSERVE at every sweep point regardless of delay or
    alert outcome.

PRIMARY QUESTION:
    Does the measured breakpoint (the delay at which alerts stop)
    match the computed ~15000ms, confirming the declared threshold is
    correctly implemented in both tools?

SECONDARY QUESTION:
    Do Snort and Suricata agree with each other on the breakpoint, or
    does one diverge from the declared threshold despite running the
    "same" rule?

SUCCESS:
    The measured breakpoint matches ~15000ms within one sweep step in
    both Snort and Suricata, confirming the declared threshold is
    implemented and working as specified.

FAILURE:
    Alerts stop firing well below ~15000ms (threshold looser than
    declared, or misconfigured), OR alerts never stop even at the
    longest swept delay (threshold not actually applied) -- while
    Zeek's conn.log still shows every connection regardless. Either
    case is a configuration-verification failure, not a vague
    "detection gap."

DATA TO COLLECT:
    - start/end timestamp (per sweep point)
    - delay used (per sweep point, ms)
    - number of probes (6, fixed)
    - number of alerts generated, Snort and Suricata separately
      (per sweep point)
    - first alert timestamp (per sweep point)
    - last alert timestamp (per sweep point)
    - detection latency (per sweep point)
    - Zeek conn.log entry count (per sweep point)
    - measured breakpoint (the first sweep point, in ascending delay
      order, where alerts stop) for Snort and Suricata separately
```

## What does the script test?

Whether a Snort and Suricata rule carrying an *identical, declared*
timing threshold (5 matching SYNs within 60 seconds) actually produces
the breakpoint that threshold's math predicts (~15000ms), by sweeping
inter-probe delay across values below, at, and above that computed
value.

## What traffic does it generate?

Eight Nmap SYN-scan runs against the same 6-port list on the
authorized lab target, one per delay value: 0, 5000, 10000, 13000,
15000, 17000, 20000, 30000 ms, each tagged `lab09.variant=d<delay>`
and `lab09.delay_ms=<delay>`. As with LAB-NSE-06/08, the NSE script
sends no extra packets and does not control timing itself -- Nmap's
core engine handles pacing via `--scan-delay`. The script's only job
is to format each port's result into structured text and a JSON line,
tagged with the delay used, for the central collector.

## Why should the firewall allow/block it?

Inter-probe timing isn't part of pfSense's per-packet port/protocol
filtering decision in this lab, so the expected outcome is identical
allow/deny behavior at every sweep point -- unless pfSense has an
explicit rate-limiting rule configured, which would need to be
confirmed with your lead before interpreting any divergence.

## What Snort rule should detect it?

The declared rule above (SID 1000109). Expected to alert below
~15000ms delay and stop alerting at or above it. If the built-in
sfPortscan/port_scan preprocessor is also active, record its alerts
(by its own SID/message) as a separate line item rather than merging
them with the declared rule's results.

## What Suricata rule should detect it?

The declared rule above (SID 1000009). Same breakpoint expectation as
Snort, since both run the identical count/seconds.

## What should Zeek log?

A `conn.log` entry for every probe at every sweep point, regardless of
delay or alert outcome, since Zeek's visibility isn't threshold-based
the way the declared Snort/Suricata rule is.

## Firewall vs IDS vs IPS vs network visibility

Same four-way split used in LAB-NSE-06/08, applied here:

- **Firewall enforcement** — did pfSense allow or drop each probe,
  and does that match baseline at every sweep point?
- **IDS detection** — did Snort/Suricata alert via the declared SID,
  and at what delay did that stop happening?
- **IPS prevention** — if Snort/Suricata are deployed inline, did
  they additionally block traffic below the breakpoint? Confirm
  deployment mode with your lead before interpreting results.
- **Network visibility** — did Zeek log the connection regardless of
  delay or alert outcome?

## What constitutes a detection failure?

For this experiment, "failure" is really a configuration-verification
failure rather than a classic detection gap: see FAILURE in the
template above. The declared threshold either triggers too early, too
late, or not at all relative to the computed ~15000ms breakpoint.

## What metrics should we collect?

See DATA TO COLLECT in the template above.

---

## Open TODOs before running

1. **Hand your lead the Suricata and Snort rule text above** and
   confirm both are loaded and active before starting the sweep.
2. **Confirm whether Snort's built-in portscan preprocessor is also
   enabled** alongside the declared rule, and if so, get its
   threshold noted so its alerts can be recorded separately.
3. **Confirm whether Snort/Suricata are deployed passively (IDS-only)
   or inline (IPS)** in this lab, so the IPS-prevention column in the
   results table means something.
4. **Budget real wall-clock time** — the full 8-point sweep takes
   roughly 10-15 minutes total, scaling with delay * (ports - 1) per
   point. The 30000ms point alone takes about 2.5 minutes.

---

## Example output (single port, d15000 sweep point)

```
experiment_id: LAB-NSE-09
variant: d15000
stage: timing_resilience
timestamp: 2026-10-24T19:40:02Z
source: 172.21.50.199
target: 192.168.56.20
delay_ms: 15000
port: 80
protocol: tcp
state: filtered
service: http
JSON: {"experiment_id":"LAB-NSE-09","variant":"d15000","stage":"timing_resilience","timestamp":"2026-10-24T19:40:02Z","source":"172.21.50.199","destination":"192.168.56.20","delay_ms":"15000","port":80,"protocol":"tcp","state":"filtered"}
```

## Files in this experiment

1. `lab-nse-09-timingstate.nse` — the NSE script (structured output
   only; does not control scan timing)
2. `run-lab-nse-09.sh` — wrapper that runs the full 8-point delay
   sweep, saves `-oA` output per point under `results/LAB-NSE-09/`,
   and prints each point's time window for log correlation
3. `README-LAB-NSE-09.md` — this file, including the declared
   threshold rules to hand your lead
4. Example output — see above
5. Expected firewall / Snort / Suricata / Zeek behavior — see sections
   above
6. **Experiment results** — fill in below after running

---

## Experiment Results (fill in after running)

**Snort/Suricata deployment mode for this run:** IDS-only (passive) / Inline (IPS) — confirm and record before filling the table.

**Declared rules confirmed live by lead:** Yes / No — confirm before running.

| Delay (ms) | Firewall inference | Snort alert (SID 1000109)? | Suricata alert (SID 1000009)? | Zeek visibility | Notes |
|------------|---------------------|------------------------------|----------------------------------|------------------|-------|
| 0          |                     |                               |                                   |                  |       |
| 5000       |                     |                               |                                   |                  |       |
| 10000      |                     |                               |                                   |                  |       |
| 13000      |                     |                               |                                   |                  |       |
| 15000      |                     |                               |                                   |                  |       |
| 17000      |                     |                               |                                   |                  |       |
| 20000      |                     |                               |                                   |                  |       |
| 30000      |                     |                               |                                   |                  |       |

**Measured breakpoint:**
- Snort: ___ ms (computed: 15000ms)
- Suricata: ___ ms (computed: 15000ms)

**Conclusion:** (does the declared threshold behave as the math
predicts; do Snort and Suricata agree; any divergence worth flagging
to the lead as a config issue)
