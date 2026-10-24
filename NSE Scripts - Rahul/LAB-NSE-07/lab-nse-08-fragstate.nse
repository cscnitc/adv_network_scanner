description = [[
LAB-NSE-08: Fragmentation Handling Resilience

Purpose:
    Compare firewall and IDS/IPS behavior across three SYN-scan
    variants of the same port list: an unfragmented baseline, an
    8-byte-fragment variant (-f), and a 16-byte-fragment variant
    (-ff). The aim is to determine whether fragmenting reconnaissance
    traffic changes what the firewall allows or what Snort/Suricata/
    Zeek observe, compared to the baseline.

    This script does NOT fragment traffic itself -- fragmentation is
    controlled entirely by Nmap's core scan engine (-f / -ff / --mtu)
    at invocation time, and NSE does not support fragmentation for its
    own logic (it relies on the host TCP stack). Run this script once
    per variant via the companion run-lab-nse-08.sh wrapper, passing
    --script-args lab08.variant=<name>,lab08.fragsize=<n> matching the
    scan flags used for that invocation. The script's only job is to
    emit structured, correlatable, per-port output tagged with the
    experiment ID, variant, and fragment size, so the central
    collector can line all three runs up against the same pfSense/
    Snort/Suricata/Zeek time window.

Safety:
    LAB ONLY. Intended for the isolated project lab (Kali scanner,
    pfSense firewall, Ubuntu victim, Snort, Suricata, Zeek). Do not
    run against systems outside the authorized lab.

Important:
    - Fragmentation is applied by Nmap's core raw-packet scan engine
      (-f/-ff/--mtu), not by this script. NSE itself does not support
      fragmentation.
    - Some source operating systems defragment outgoing packets in the
      kernel before they leave the host (e.g. Linux with iptables
      connection tracking). Verify with a packet capture (tcpdump/
      Wireshark) on the Kali box that fragments actually left the wire
      intact before trusting a "no difference from baseline" result --
      otherwise a silent defragmentation bug could be mistaken for a
      detection finding.

Expected:
    Firewall: ALLOW, same outcome as baseline for each port -- pending
              confirmation of pfSense's fragment reassembly/scrub
              setting (see README). If pfSense does NOT reassemble
              before filtering, a divergence from baseline is possible.
    Snort:    DETECT on all three variants; frag8 is the variant most
              likely to reveal a gap if the reassembly preprocessor has
              limits.
    Suricata: DETECT, same logic as Snort via its defrag preprocessor.
    Zeek:     OBSERVE on all three variants regardless of alert outcome.

EXPERIMENT ID:
    LAB-NSE-08

TARGET:
    Authorized lab target only (Ubuntu victim).

EXPECTED FIREWALL POLICY:
    Fragmentation is a wire-level presentation change; filtering is
    based on port/protocol in this lab, which should be unaffected by
    it unless pfSense evaluates fragments before reassembly. Expected:
    identical allow/deny outcome to baseline, pending confirmation of
    the scrub setting.

EXPECTED SNORT RESULT:
    ALERT on baseline, frag8, and frag16, assuming the frag3 reassembly
    preprocessor is enabled and functioning normally.

EXPECTED SURICATA RESULT:
    ALERT on baseline, frag8, and frag16, assuming the defrag
    preprocessor is enabled and functioning normally.

EXPECTED ZEEK RESULT:
    conn.log entry for every probe in all three variants, independent
    of whether Snort/Suricata alert.

SUCCESS CONDITION:
    The firewall, Snort, Suricata, and Zeek each behave as expected
    across all three variants -- in particular, Snort and Suricata
    still alert and Zeek still observes the fragmented variants just
    as reliably as the baseline, meaning fragmentation does not weaken
    detection.

FAILURE CONDITION:
    A fragmented variant -- especially frag8 -- reaches the target
    (firewall allows it, matching baseline) but Snort and/or Suricata
    fail to alert where the baseline did, with no documented
    reassembly-limit explanation. This is a genuine detection gap:
    fragmentation lets reconnaissance traffic through undetected.
]]

author = "CSC NitC
license = "Same as Nmap"
categories = {"safe", "discovery"}

-- LAB ONLY.
-- This script generates reconnaissance traffic for a controlled,
-- authorized lab experiment. Do not run it against systems outside
-- that lab.

local shortport = require "shortport"
local stdnse = require "stdnse"

local EXPERIMENT_ID = "LAB-NSE-08"

-- Fixed "stage" label. LAB-NSE-08 is single-stage per invocation (one
-- variant collects one pass of port-state data), but every output
-- must carry a stage field per the guidelines so the collector can
-- line this up consistently with multi-stage experiments.
local STAGE = "fragmentation_resilience"

portrule = shortport.port_or_service(
    {22, 80, 443},
    {"ssh", "http", "https"}
)

local function now_iso()
    return stdnse.format_timestamp(os.time(), 0)
end

action = function(host, port)

    local variant  = stdnse.get_script_args("lab08.variant")  or "unspecified"
    local source   = stdnse.get_script_args("lab08.source")   or "unspecified"
    local fragsize = stdnse.get_script_args("lab08.fragsize") or "unspecified"

    local result = {
        experiment_id = EXPERIMENT_ID,
        variant       = variant,
        stage         = STAGE,
        timestamp     = now_iso(),
        source        = source,
        target        = host.ip,
        fragment_size = fragsize,
        port          = port.number,
        protocol      = port.protocol,
        state         = port.state,
        service       = port.service,
    }

    local output = {}

    table.insert(output, "experiment_id: "  .. result.experiment_id)
    table.insert(output, "variant: "        .. result.variant)
    table.insert(output, "stage: "          .. result.stage)
    table.insert(output, "timestamp: "      .. result.timestamp)
    table.insert(output, "source: "         .. result.source)
    table.insert(output, "target: "         .. result.target)
    table.insert(output, "fragment_size: "  .. tostring(result.fragment_size))
    table.insert(output, "port: "           .. tostring(result.port))
    table.insert(output, "protocol: "       .. tostring(result.protocol))
    table.insert(output, "state: "          .. tostring(result.state))

    if result.service then
        table.insert(output, "service: " .. tostring(result.service))
    end

    -- Single-line machine-readable record for the central collector.
    -- Contains every field the guidelines require (experiment_id,
    -- timestamp, source, destination, test_variant, stage) plus
    -- fragment_size, which is specific to this experiment's design.
    table.insert(
        output,
        string.format(
            "JSON: {\"experiment_id\":\"%s\",\"variant\":\"%s\",\"stage\":\"%s\"," ..
            "\"timestamp\":\"%s\",\"source\":\"%s\",\"destination\":\"%s\"," ..
            "\"fragment_size\":\"%s\",\"port\":%d,\"protocol\":\"%s\",\"state\":\"%s\"}",
            result.experiment_id, result.variant, result.stage, result.timestamp,
            result.source, result.target, tostring(result.fragment_size),
            result.port, result.protocol, tostring(result.state)
        )
    )

    return stdnse.format_output(true, output)
end
