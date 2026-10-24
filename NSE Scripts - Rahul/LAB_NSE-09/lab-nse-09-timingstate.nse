description = [[
LAB-NSE-09: Timing-Threshold Evasion (Scan-Delay Resilience)

Purpose:
    Compare Snort/Suricata scan-detection alerting across a sweep of
    SYN-scan variants of the same port list, differing only in
    inter-probe delay, to find the real breakpoint at which a declared
    detection threshold stops firing. Unlike earlier drafts of this
    experiment, the threshold is not assumed or reverse-engineered --
    it is specified by the offense side and implemented by the lab
    (see README "Threshold for your lab), so the
    expected breakpoint is computable math, not a guess.

    This script does NOT control scan timing itself -- pacing is
    handled entirely by Nmap's core engine (--scan-delay) at
    invocation time. Run this script once per sweep point via the
    companion run-lab-nse-09.sh wrapper, passing
    --script-args lab09.variant=<name>,lab09.delay_ms=<n> matching the
    delay used for that invocation. The script's only job is to emit
    structured, correlatable, per-port output tagged with the
    experiment ID, variant, and delay value, so the central collector
    can line every sweep point up against the same pfSense/Snort/
    Suricata/Zeek time window.

Safety:
    LAB ONLY. Intended for the isolated project lab (Kali scanner,
    pfSense firewall, Ubuntu victim, Snort, Suricata, Zeek). Do not
    run against systems outside the authorized lab.

Important:
    - This experiment requires the lab to implement a declared,
      explicit threshold rule in both Snort and Suricata BEFORE
      running (see README). Do not run against whatever default
      scan-detection config happens to already be present -- an
      undeclared threshold makes the breakpoint math below meaningless.
    - The port list below (6 ports) is intentionally sized so a single
      scan generates enough matching probes to cross a count=5
      threshold; fewer ports could never trigger the rule regardless
      of delay.

Expected (assuming the declared threshold count=5, seconds=60 is
implemented identically in both Snort and Suricata):
    Firewall: ALLOW, same outcome across every sweep point -- timing
              does not change port/protocol, which is what pfSense
              filters on, unless an explicit rate-limiting rule exists
              (confirm with lab config)
    Snort:    ALERT when inter-probe delay < 15000ms (60000/(5-1));
              no alert expected at/above that delay.
    Suricata: Same breakpoint as Snort, since both run the identical
              declared count/seconds threshold.
    Zeek:     OBSERVE at every sweep point regardless of delay or
              alert outcome.

EXPERIMENT ID:
    LAB-NSE-09

TARGET:
    Authorized lab target only (Ubuntu victim).

EXPECTED FIREWALL POLICY:
    Identical allow/deny outcome across every sweep point. Inter-probe
    timing is not part of pfSense's per-packet port/protocol filtering
    decision in this lab, unless an explicit rate-limiting rule is
    configured (confirm with lab comfig).

EXPECTED SNORT RESULT:
    ALERT via the declared custom rule (SID 1000109, see README) when
    delay is below the computed breakpoint (~15000ms for count=5/
    seconds=60); no alert at or above it. Confirm with lab whether
    the built-in sfPortscan/port_scan preprocessor is also active
    alongside the declared rule -- if so, it may fire on its own,
    separate threshold and should be recorded separately.

EXPECTED SURICATA RESULT:
    ALERT via the declared custom rule (SID 1000009, see README),
    same breakpoint logic as Snort.

EXPECTED ZEEK RESULT:
    conn.log entry for every probe at every sweep point, independent
    of delay or alert outcome.

SUCCESS CONDITION:
    The measured breakpoint (the delay at which alerts stop firing)
    matches the computed value (~15000ms) within one sweep step,
    confirming the declared threshold is implemented and working as
    specified.

FAILURE CONDITION:
    Alerts stop firing well below the computed breakpoint (the
    declared threshold is looser than specified, or misconfigured),
    OR alerts never stop firing even at the longest swept delay (the
    threshold isn't actually applied) -- while Zeek's conn.log still
    shows every connection either way. Both are genuine configuration-
    verification failures, not just detection gaps.
]]

author = "Team Security Lab"
license = "Same as Nmap"
categories = {"safe", "discovery"}

-- LAB ONLY.
-- This script generates reconnaissance traffic for a controlled,
-- authorized lab experiment. Do not run it against systems outside
-- that lab.

local shortport = require "shortport"
local stdnse = require "stdnse"

local EXPERIMENT_ID = "LAB-NSE-09"

-- Fixed "stage" label. Every sweep point is a single-stage pass, but
-- every output must carry a stage field per the guidelines so the
-- collector can line this up consistently with multi-stage
-- experiments.
local STAGE = "timing_resilience"

-- Six ports so a single scan generates enough matching SYN probes to
-- potentially cross a count=5 threshold; see Important note above.
portrule = shortport.port_or_service(
    {21, 22, 23, 25, 80, 443},
    {"ftp", "ssh", "telnet", "smtp", "http", "https"}
)

local function now_iso()
    return stdnse.format_timestamp(os.time(), 0)
end

action = function(host, port)

    local variant  = stdnse.get_script_args("lab09.variant")  or "unspecified"
    local source   = stdnse.get_script_args("lab09.source")   or "unspecified"
    local delay_ms = stdnse.get_script_args("lab09.delay_ms") or "unspecified"

    local result = {
        experiment_id = EXPERIMENT_ID,
        variant       = variant,
        stage         = STAGE,
        timestamp     = now_iso(),
        source        = source,
        target        = host.ip,
        delay_ms      = delay_ms,
        port          = port.number,
        protocol      = port.protocol,
        state         = port.state,
        service       = port.service,
    }

    local output = {}

    table.insert(output, "experiment_id: " .. result.experiment_id)
    table.insert(output, "variant: "       .. result.variant)
    table.insert(output, "stage: "         .. result.stage)
    table.insert(output, "timestamp: "     .. result.timestamp)
    table.insert(output, "source: "        .. result.source)
    table.insert(output, "target: "        .. result.target)
    table.insert(output, "delay_ms: "      .. tostring(result.delay_ms))
    table.insert(output, "port: "          .. tostring(result.port))
    table.insert(output, "protocol: "      .. tostring(result.protocol))
    table.insert(output, "state: "         .. tostring(result.state))

    if result.service then
        table.insert(output, "service: " .. tostring(result.service))
    end

    -- Single-line machine-readable record for the central collector.
    table.insert(
        output,
        string.format(
            "JSON: {\"experiment_id\":\"%s\",\"variant\":\"%s\",\"stage\":\"%s\"," ..
            "\"timestamp\":\"%s\",\"source\":\"%s\",\"destination\":\"%s\"," ..
            "\"delay_ms\":\"%s\",\"port\":%d,\"protocol\":\"%s\",\"state\":\"%s\"}",
            result.experiment_id, result.variant, result.stage, result.timestamp,
            result.source, result.target, tostring(result.delay_ms),
            result.port, result.protocol, tostring(result.state)
        )
    )

    return stdnse.format_output(true, output)
end
