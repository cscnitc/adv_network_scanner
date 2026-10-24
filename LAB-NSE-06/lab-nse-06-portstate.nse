description = [[
LAB-NSE-06: Stateful vs Stateless Firewall Fingerprinting

Purpose:
    Compare port-state results from a TCP SYN scan against a TCP ACK
    scan of the same target and port set, to determine whether the
    firewall in front of the target is enforcing stateful filtering.
    RFC 793 compliant endpoints always RST an unsolicited ACK; a
    stateless firewall will pass many of those ACKs straight through,
    while a stateful firewall will drop them unless they belong to an
    established connection.

    This script does NOT switch Nmap's scan type itself. Run it once
    under -sS and once under -sA (see the companion run-lab-nse-06.sh
    wrapper), passing --script-args lab06.variant=syn|ack that matches
    the scan type used for that invocation. The script's only job is
    to emit structured, correlatable, per-port output tagged with the
    experiment ID and variant, so the central collector can line the
    two runs up against the same pfSense/Snort/Suricata/Zeek time
    window.

Safety:
    LAB ONLY. Intended for the isolated project lab (Kali scanner,
    pfSense firewall, Ubuntu victim, Snort, Suricata, Zeek). Do not
    run against systems outside the authorized lab.

Expected:
    Firewall:  SYN variant -> non-whitelisted ports FILTERED.
               ACK variant -> depends on statefulness (see README).
    Snort:     DETECT (scan-threshold rules, if enabled).
    Suricata:  DETECT (scan-threshold rules, if enabled).
    Zeek:      OBSERVE (conn.log entries for both variants).

EXPERIMENT ID:
    LAB-NSE-06

TARGET:
    Authorized lab target only (Ubuntu victim).

EXPECTED FIREWALL POLICY:
    If pfSense is stateful, ACK-scan ports should show the same
    "no useful state learned" result as the SYN scan for anything
    outside the explicit allow rules, since ACK packets are dropped
    unless part of an established connection. If pfSense (or a
    specific rule) is stateless, expect far more "unfiltered"
    results on the ACK variant than the SYN variant would predict --
    that gap is the detection finding.

EXPECTED SNORT RESULT:
    Scan-detection preprocessor/rule alert for both SYN and ACK scan
    patterns, if portscan detection is enabled. Compare alert count
    and classification between the two variants.

EXPECTED SURICATA RESULT:
    Same as Snort: alert via the stream/scan-detection ruleset.
    Compare alert count/type between variants.

EXPECTED ZEEK RESULT:
    conn.log entries for every probe in both variants; weird.log may
    flag unusual flag combinations depending on local policy.

SUCCESS CONDITION:
    Both scan variants complete, structured output is captured for
    each port/variant pair, and the firewall's statefulness can be
    determined by comparing the two result sets.

FAILURE CONDITION:
    A variant produces no usable state information (e.g. the
    lab06.variant script-arg was omitted), or the pfSense/Snort/
    Suricata/Zeek logs cannot be correlated to the experiment's time
    window.
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

local EXPERIMENT_ID = "LAB-NSE-06"

portrule = shortport.port_or_service(
    {21, 22, 23, 25, 53, 80, 113, 443},
    {"ftp", "ssh", "telnet", "smtp", "domain", "http", "auth", "https"}
)

local function now_iso()
    return stdnse.format_timestamp(os.time(), 0)
end

-- Fixed "stage" label for this experiment. LAB-NSE-06 is single-stage
-- (it only ever does one thing: collect port state for one variant),
-- but the guidelines require every output to carry a stage field so
-- the collector can line this up consistently with multi-stage
-- experiments like LAB-NSE-05.
local STAGE = "firewall_fingerprint"

action = function(host, port)

    local variant = stdnse.get_script_args("lab06.variant") or "unspecified"

    -- The attacking host's identity is not something NSE can reliably
    -- self-detect across platforms, so it is passed in explicitly by
    -- the wrapper script (which knows the Kali box's address). This
    -- keeps "source" accurate instead of guessing at an interface.
    local source = stdnse.get_script_args("lab06.source") or "unspecified"

    local result = {
        experiment_id = EXPERIMENT_ID,
        variant       = variant,
        stage         = STAGE,
        timestamp     = now_iso(),
        source        = source,
        target        = host.ip,
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
    table.insert(output, "port: "          .. tostring(result.port))
    table.insert(output, "protocol: "      .. tostring(result.protocol))
    table.insert(output, "state: "         .. tostring(result.state))

    if result.service then
        table.insert(output, "service: " .. tostring(result.service))
    end

    -- Single-line machine-readable record for the central collector.
    -- Contains every field the guidelines require: experiment_id,
    -- timestamp, source, destination, test_variant, stage.
    table.insert(
        output,
        string.format(
            "JSON: {\"experiment_id\":\"%s\",\"variant\":\"%s\",\"stage\":\"%s\"," ..
            "\"timestamp\":\"%s\",\"source\":\"%s\",\"destination\":\"%s\"," ..
            "\"port\":%d,\"protocol\":\"%s\",\"state\":\"%s\"}",
            result.experiment_id, result.variant, result.stage, result.timestamp,
            result.source, result.target,
            result.port, result.protocol, tostring(result.state)
        )
    )

    return stdnse.format_output(true, output)
end