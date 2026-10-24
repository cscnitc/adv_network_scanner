# LAB-NSE-06: Stateful vs Stateless Firewall Fingerprinting

## Experiment template (pre-code spec)

```
========================================================
EXPERIMENT: LAB-NSE-06
NAME: Stateful vs Stateless Firewall Fingerprinting
========================================================

SOURCE:
    Kali scanner

TARGET:
    Ubuntu victim

TRAFFIC:
    TCP SYN scan (variant=syn) and TCP ACK scan (variant=ack) of the
    same port list, run as two separate invocations.

FIREWALL:
    Expected: Non-whitelisted ports FILTERED on the SYN variant.
              ACK variant outcome depends on statefulness -- dropped
              if pfSense is stateful, passed through unfiltered if not.
    Reason: Test service is intentionally exposed on the allow-listed
            ports only; everything else should be denied by default.

SNORT:
    Expected: ALERT on SYN variant (standard scan signature).
              ALERT on ACK variant depends on whether an ACK-scan or
              anomalous-flag rule is enabled -- unconfirmed until run.

SURICATA:
    Expected: Same as Snort -- ALERT on SYN variant, ACK variant
              dependent on ruleset.

ZEEK:
    Expected: OBSERVE -- conn.log entry for every probe in both
              variants regardless of firewall/IDS outcome.

PRIMARY QUESTION:
    Is pfSense enforcing stateful filtering, or just a static
    port/flag-based rule set?

SECONDARY QUESTION:
    Does the choice of scan type (SYN vs ACK) change what Snort,
    Suricata, and Zeek each observe and alert on?

SUCCESS:
    Both variants complete, structured per-port output is captured for
    each, and the comparison yields a clear stateful/stateless
    determination.

FAILURE:
    Either variant produces no usable state information, or
    firewall/Snort/Suricata/Zeek logs cannot be correlated to the
    experiment's time window via its experiment_id/timestamp.

DATA TO COLLECT:
    - start/end timestamp (per variant)
    - ports tested
    - packets/requests generated (per variant)
    - firewall decision (per port, per variant)
    - IDS alerts: Snort (per variant)
    - IDS alerts: Suricata (per variant)
    - IPS action, if Snort/Suricata run inline: blocked vs alerted-only
    - Zeek events (per variant)
    - detection latency (per variant)
```

## What does the script test?

Whether the lab firewall (pfSense) is enforcing **stateful** filtering
or just a simpler **stateless** rule set, by comparing a standard TCP
SYN scan against a TCP ACK scan of the same ports on the same target.

- A SYN scan tells you open / closed / filtered.
- An ACK scan can only tell you filtered / unfiltered, but it reveals
  *whether unsolicited ACK packets are being dropped*, which is what a
  stateful firewall does and a stateless one typically does not.

Comparing the two result sets exposes whether pfSense is actually
tracking connection state or just filtering by port/flag, and gives
the IDS/IPS stack two different traffic shapes to react to.

## What traffic does it generate?

Two Nmap runs against the same port list (21, 22, 23, 25, 53, 80, 113,
443) on the authorized lab target:

1. `nmap -sS` (SYN scan) tagged `lab06.variant=syn`
2. `nmap -sA` (ACK scan) tagged `lab06.variant=ack`

The NSE script itself sends no extra packets — it only formats each
port's result (state, service, timestamp, experiment ID, variant) into
structured text and a single JSON line per port for the central
collector.

## Why should the firewall allow/block it?

Ports in pfSense's explicit allow list should show open/closed on the
SYN scan and unfiltered on the ACK scan either way. Everything else
should be filtered on the SYN scan. The interesting case is the ACK
scan on those "everything else" ports: filtered/dropped implies
pfSense is stateful; unfiltered implies the rule set is stateless and
is letting unsolicited ACKs through — a real policy gap worth noting
even though it's expected lab behavior rather than an exploit.

## What Snort rule should detect it?

Whatever scan-detection preprocessor/rule you have enabled (e.g. a
flow-portscan or scan-threshold style rule). Record the exact rule
SID(s) that fire for each variant — expect the SYN scan to be the more
reliably flagged of the two, since ACK-only probes are a less common
signature target by default.

## What Suricata rule should detect it?

Same expectation as Snort — your scan-detection ruleset should alert
on both variants if properly tuned, but may show a different alert
count or classification between SYN and ACK. Record the exact
signature ID(s).

## What should Zeek log?

A `conn.log` entry for every probe in both variants (Zeek observes
regardless of firewall/IDS outcome). Check `weird.log` for any
flagged anomalies on the ACK variant specifically, since unsolicited
ACKs are a less common pattern than SYNs.

## Firewall vs IDS vs IPS vs network visibility

These are four separate questions, not one, and this experiment records
them separately rather than treating "did Snort alert" as the whole
answer:

- **Firewall enforcement** — did pfSense allow or drop the packet?
  (from the port state in the `.nse`/`-oA` output)
- **IDS detection** — did Snort/Suricata raise an alert, independent of
  whether the packet reached the target?
- **IPS prevention** — if Snort/Suricata are deployed inline rather
  than passively, did they additionally *block* the packet? This is
  distinct from alerting and only applies if your lab runs them
  in-line. **Confirm with the lab which mode Snort/Suricata are
  running in before interpreting results** — a passive/IDS-only
  deployment can never "fail to prevent," since prevention isn't its
  job.
- **Network visibility** — did Zeek log the connection at all,
  regardless of the other three outcomes? This is the baseline check
  that traffic existed on the wire.

## What constitutes a detection failure?

- The SYN scan is not flagged by Snort/Suricata at all (a real gap,
  since this is the easiest scan type to detect).
- The ACK scan passes through pfSense as unfiltered on ports that
  should be protected by a stateful default-deny policy, **and**
  neither Snort nor Suricata raises any alert for it, **and** Zeek's
  conn.log shows the completed exchange — i.e., a true blind spot
  across the whole stack, not just one sensor.

## What metrics should we collect?

- Start/end timestamp of each variant
- Per-port state for both variants (from the `.nse` output / `-oA`
  files)
- Firewall decision inferred per port (filtered / unfiltered / open /
  closed)
- Snort alert count + SID(s) fired, per variant
- Suricata alert count + SID(s) fired, per variant
- Zeek conn.log entry count, and any weird.log entries, per variant
- Detection latency: time between probe sent and first alert logged

---

## Example output (single port, SYN variant)

```
experiment_id: LAB-NSE-06
variant: syn
stage: firewall_fingerprint
timestamp: 2026-10-19T16:42:03Z
source: 172.21.50.199
target: 192.168.56.20
port: 113
protocol: tcp
state: filtered
JSON: {"experiment_id":"LAB-NSE-06","variant":"syn","stage":"firewall_fingerprint","timestamp":"2026-10-19T16:42:03Z","source":"172.21.50.199","destination":"192.168.56.20","port":113,"protocol":"tcp","state":"filtered"}
```

## Files in this experiment

1. `lab-nse-06-portstate.nse` — the NSE script (structured output only;
   does not alter scan type)
2. `run-lab-nse-06.sh` — wrapper that runs both variants and saves
   `-oA` output under `results/LAB-NSE-06/`
3. `README-LAB-NSE-06.md` — this file
4. Example output — see above
5. Expected firewall / Snort / Suricata / Zeek behavior — see sections
   above
6. **Experiment results** — fill in below after running

---

## Experiment Results (fill in after running)

| Port | SYN state | ACK state | Firewall inference | Snort alert (IDS) | Suricata alert (IDS) | IPS blocked? (n/a if passive) | Zeek visibility | Notes |
|------|-----------|-----------|---------------------|--------------------|------------------------|---------------------------------|------------------|-------|
| 21   |           |           |                     |                    |                        |                                  |                  |       |
| 22   |           |           |                     |                    |                        |                                  |                  |       |
| 23   |           |           |                     |                    |                        |                                  |                  |       |
| 25   |           |           |                     |                    |                        |                                  |                  |       |
| 53   |           |           |                     |                    |                        |                                  |                  |       |
| 80   |           |           |                     |                    |                        |                                  |                  |       |
| 113  |           |           |                     |                    |                        |                                  |                  |       |
| 443  |           |           |                     |                    |                        |                                  |                  |       |

**Snort/Suricata deployment mode for this run:** IDS-only (passive) / Inline (IPS) — confirm and record which before filling the table above.

**Detection latency (first alert − probe sent):**
- SYN variant: ___
- ACK variant: ___

**Conclusion:** (stateful / stateless / mixed, and whether a detection
gap was found)