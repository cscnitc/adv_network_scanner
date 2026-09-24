
# Network Security Control Evaluation & Benchmarking Framework

A multi-VM security lab and automated framework for evaluating firewall enforcement, IDS/IPS detection, network and endpoint visibility, and security-event correlation under controlled network conditions.

> **Project status:** In development  
> **Environment:** VirtualBox, Linux, pfSense  
> **Primary focus:** Network security testing, detection engineering, telemetry collection and benchmarking

---

## 1. Overview

This project aims to build a controlled, multi-VM security environment to evaluate how different network security controls behave under predefined and reproducible traffic conditions.

The lab integrates:

- pfSense for routing, NAT and firewall enforcement.
- Snort and Suricata for network intrusion detection/prevention.
- Zeek for network protocol analysis and telemetry.
- Wazuh or equivalent endpoint telemetry for host-level visibility.
- Nmap, Scapy and custom scripts for generating controlled test traffic.
- A centralized collection and analysis pipeline for correlating events.

The framework will generate authorized test traffic, collect telemetry from multiple security controls, associate events with experiments, and produce benchmark results.

### Project objectives

1. Evaluate firewall policy enforcement and NAT behaviour.
2. Compare signature-based and behavioural network detection.
3. Measure detection latency, event volume, false positives and telemetry coverage.
4. Identify and document detection, visibility and enforcement gaps under controlled conditions.
5. Develop custom detection rules and evaluate their impact.
6. Automate experiments and generate reproducible reports.
7. Extend the lab to enterprise-style Windows/Linux/Active Directory networks.
8. Evaluate cloud WAF behaviour in a separate web-security experiment.

The project is intended for authorized testing in isolated lab environments and explicitly permitted infrastructure.

---

## 2. Architecture

### 2.1 Current lab topology

```text
                  Kali Linux
              172.21.50.199/22
               Scanner / Tests
                       |
                       | WAN network
                       | 172.21.48.0/22
                       |
                 +-----+------+
                 |   pfSense  |
                 |            |
                 | WAN        | 172.21.50.85
                 | LAN        | 192.168.1.1/24
                 +-----+------+
                       |
                       | Internal LAN
                       | 192.168.1.0/24
                       |
              +--------+---------+
              |                  |
       +------+-------+   +------+-------+
       | Victim VM    |   | Monitor VM   |
       |              |   |              |
       | .100         |   | .101         |
       |192.168.1.100 |   |192.168.1.101 |
       |              |   |              |
       | Web / SSH    |   | Snort        |
       | Test services|   | Suricata     |
       +--------------+   | Zeek         |
                          | Collectors    |
                          +--------------+
```

### 2.2 IP addressing

| Component | Interface / Network | Address |
|---|---|---|
| Kali | eth0 / WAN network | 172.21.50.199/22 |
| pfSense WAN | WAN network | 172.21.50.85 |
| pfSense LAN | Internal LAN | 192.168.1.1/24 |
| Victim | Internal LAN | 192.168.1.100 |
| Monitor | Internal LAN / management | 192.168.1.101 |

WAN subnet: `172.21.48.0/22`

Internal LAN subnet: `192.168.1.0/24`

The addresses above describe the current lab configuration. They may be changed as the lab expands.

### 2.3 Monitor VM network interfaces

The monitor is planned to use three virtual NICs with distinct purposes.

| NIC | Purpose | Attachment |
|---|---|---|
| NIC 1 | Management, SSH, updates and log access | Dedicated management network |
| NIC 2 | Internal/LAN traffic observation | LAN-side capture network |
| NIC 3 | WAN traffic observation | WAN-side capture network |

The capture interfaces are intended for passive monitoring. Promiscuous mode alone does not guarantee visibility of unicast traffic in VirtualBox.

Packet visibility must be validated with tcpdump. Where necessary, use a supported mirroring/TAP arrangement or an inline sensor configuration as a separately documented experiment.

The management interface should remain logically separate from monitored traffic.

---

## 3. Security Components

| Component | Role |
|---|---|
| pfSense | Routing, firewall policy, NAT, connection enforcement and firewall logging |
| Snort | Rule-based network intrusion detection |
| Suricata | Network IDS/IPS, signature detection and EVE JSON event generation |
| Zeek | Network protocol analysis, connection records and behavioural telemetry |
| Wazuh / endpoint agent | Endpoint logs, host activity and security-event collection |
| Nmap / Scapy | Controlled test traffic generation |
| Wireshark / tcpdump | Packet capture and protocol analysis |
| Python scripts | Experiment orchestration, event processing and analysis |

---

## 4. Live Collection Architecture

The primary operating mode is continuous live monitoring.

```text
             Controlled Test Traffic
                       |
                       v
                    pfSense
              Firewall / NAT Logs
                       |
                       v
                  Victim Services
                       |
                       v
                  Monitor VM
             +---------+---------+
             |         |         |
           Snort   Suricata     Zeek
             |         |         |
          Alerts    EVE JSON   Protocol Logs
             |         |         |
             +---------+---------+
                       |
                 Log Collector
                       |
                       v
              Experiment Storage
                       |
                       v
             Normalization / Analysis
                       |
                       v
              Benchmark Reports
```

Snort, Suricata and Zeek will run as managed background services.

The collector will ingest their output, associate events with experiment IDs, preserve raw records and generate a common normalized event format.

### Collection sources

- pfSense firewall logs, exported through syslog or another supported method.
- Snort alert logs.
- Suricata EVE JSON.
- Zeek connection, DNS, HTTP, TLS and notice logs.
- Wazuh or equivalent endpoint telemetry.
- Optional packet captures for selected experiments.

Packet capture is not intended to be retained continuously. PCAPs will be stored selectively for important experiments, detection gaps, false positives and rule-development investigations.

---

## 5. Experiment Management

Every test run receives a unique experiment ID.

Example:

`EXP-0001`

Each experiment records:

- Experiment ID and description.
- Source and destination systems.
- Traffic generator and version.
- Start and end timestamps.
- Sensor versions and configurations.
- Enabled ruleset versions.
- Expected firewall and detection outcomes.
- Observed alerts and telemetry.

Example experiment structure:

```text
experiments/
└── EXP-0001/
    ├── metadata.json
    ├── test-results.json
    ├── firewall/
    ├── snort/
    ├── suricata/
    ├── zeek/
    ├── endpoint/
    ├── normalized/
    │   └── events.jsonl
    └── report/
```

---

## 6. Benchmarking

The benchmark will evaluate security-control behaviour under controlled and documented traffic conditions.

### Planned test categories

| Category | Examples |
|---|---|
| Baseline traffic | Normal HTTP, DNS, SSH and TCP connections |
| TCP reconnaissance | Controlled SYN and targeted port scans |
| UDP reconnaissance | Controlled UDP probing |
| Service discovery | Service/version detection in the lab |
| Firewall enforcement | Allowed/blocked ports, NAT and policy validation |
| Detection configurations | Default rules, additional rules and custom detection |
| Enterprise environment | Windows/Linux hosts, domain services and segmentation |
| Web protection | HTTP workloads against isolated Cloudflare/AWS WAF deployments |

All tests will be performed against lab systems or explicitly authorized targets.

### Metrics

| Metric | Description |
|---|---|
| Enforcement outcome | Whether the firewall allowed or blocked traffic as expected |
| Detection outcome | Whether an IDS/IPS generated an alert or notice |
| Detection latency | Time from the test event to the resulting alert |
| Telemetry coverage | Whether connection/activity records were generated |
| False positives | Alerts produced during defined benign workloads |
| Event volume | Raw event and alert counts |
| Attribution | Availability of source, destination, protocol and port information |
| Correlation | Ability to associate events across different sensors |
| Resource usage | CPU, memory and storage requirements |

Firewall enforcement, IDS alerts, Zeek telemetry and endpoint events will be evaluated as separate outcomes.

A missing IDS alert will not automatically be classified as a firewall bypass or security-control failure. The expected outcome and relevant control policy must be defined for each test.

---

## 7. Custom Detection Engineering

The project will evaluate existing rulesets before introducing custom rules.

Planned work:

1. Establish a baseline using the installed Snort and Suricata rulesets.
2. Record ruleset versions and enabled detection configurations.
3. Evaluate existing scan-related detection and behavioural policies.
4. Develop custom rules for predefined lab traffic patterns.
5. Compare detection coverage, alert volume and false positives before and after changes.
6. Document conditions under which each detector does or does not generate an event.

The goal is to understand detection behaviour and improve detection quality, not to assume that a single rule can identify every scanning tool.

---

## 8. Storage and Event Normalization

Proposed root directory:

```text
/opt/security-lab/
├── config/
├── experiments/
├── rulesets/
├── scripts/
│   ├── experiment-runner/
│   ├── collectors/
│   ├── parsers/
│   └── analysis/
├── normalized/
└── archive/
```

The collector will preserve raw logs and create normalized JSONL events.

A normalized event may contain:

```json
{
  "experiment_id": "EXP-0001",
  "timestamp": "...",
  "sensor": "suricata",
  "event_type": "alert",
  "src_ip": "...",
  "src_port": 0,
  "dest_ip": "...",
  "dest_port": 0,
  "protocol": "TCP",
  "signature": "...",
  "severity": null
}
```

This is a proposed common schema. Sensor-specific fields will be retained in the raw records or an additional metadata field to avoid losing information.

Log rotation, retention limits and disk usage monitoring will be implemented to prevent unbounded storage growth.

---

## 9. Cloud WAF Experiment — Separate Track

A separate, isolated cloud experiment will evaluate web-layer protection.

Proposed architecture:

```text
             Controlled HTTP Workloads
                        |
               +--------+--------+
               |                 |
           Cloudflare          AWS WAF
               |                 |
          Web Application   Web Application
               |                 |
          Security Logs     Security Logs
```

This track will focus on HTTP/API request inspection, rate limiting, managed rules, logging, latency and blocking behaviour.

It will not be treated as equivalent to the local network-level Nmap/firewall benchmark.

Cloud resources will be deployed only after checking current pricing, quotas and available free-tier terms. No assumption of unlimited free AWS WAF usage is made.

---

## 10. Team Responsibilities

| Person | Responsibility |
|---|---|
| 1 | pfSense + Snort + victim: setup, configure rules, run authorized scans and collect firewall/IDS/victim logs |
| 2 | pfSense + Suricata + victim: setup, configure rules, run tests and collect logs/alerts |
| 3 | Zeek + EDR: deploy Zeek, Wazuh or equivalent endpoint telemetry and collect network/host events |
| 4 | Scanning & Analysis: Nmap/Scapy scripts, automated experiments, packet analysis and detection benchmarking |
| 5 | Multi-VM / Corporate Network Lab: Windows + Linux + AD/domain environment, services, OSes and network topology experiments |

All team members are expected to learn the fundamentals of Nmap, TCP/IP, Wireshark, firewalls, IDS/IPS and packet analysis.

The project coordinator will integrate the monitor architecture, live collection pipeline, experiment schema and benchmark reporting.

---

## 11. Roadmap

- [x] Establish initial VirtualBox lab and pfSense routing/NAT.
- [ ] Validate packet visibility on monitor interfaces.
- [ ] Configure Snort as a managed background service.
- [ ] Configure Suricata and validate EVE JSON output.
- [ ] Install and configure Zeek for live monitoring.
- [ ] Establish reliable concurrent sensor operation.
- [ ] Implement central log collection and experiment IDs.
- [ ] Define and execute baseline experiments.
- [ ] Implement normalization and benchmark reports.
- [ ] Evaluate and develop custom detection rules.
- [ ] Integrate endpoint telemetry and enterprise lab.
- [ ] Build isolated cloud WAF experiment.

---

## 12. Scope and Safety

This framework is designed for controlled experiments in isolated lab networks and infrastructure for which explicit authorization has been obtained.

Test cases, generated traffic and automated scans must remain within the defined and authorized scope.

The project focuses on security-control evaluation, detection engineering, telemetry collection and reproducible benchmarking.

---

## License

To be decided.
