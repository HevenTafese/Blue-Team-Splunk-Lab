# SOC Home Lab
### Splunk SIEM · Attack Simulation · Threat Detection

A fully functional Security Operations Centre home lab built to simulate real-world cyberattacks and detect them using Splunk Enterprise. The lab chains an isolated virtual network, a live Windows target, an attacker machine, and a centralised SIEM into a single environment where the full attack-detect-respond lifecycle can be practised hands-on.

---

## Dashboard

**Full Lab Setup** — Kali attacking, Windows forwarding logs, Ubuntu running Splunk, dashboard live

![Full Lab](docs/screenshots/full-lab.png)

**Search & Reporting** — live SPL queries against 5,300+ indexed events

![Search and Reporting](docs/screenshots/search.png)

**SOC Lab Dashboard** — failed logins, brute force detection, login timeline and event count by host

![SOC Dashboard](docs/screenshots/dashboard.png)


---

## Architecture

```
┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
│   KALI LINUX    │        │   WINDOWS 10    │        │ UBUNTU + SPLUNK │
│   10.0.0.30     │──────▶ │   10.0.0.20     │──────▶ │   10.0.0.10     │
│                 │ ATTACK │                 │  LOGS  │                 │
│ • Nmap          │        │ • Event Logs    │ :9997  │ • Splunk 10.2   │
│ • Hydra         │        │ • Sysmon        │        │ • SPL Rules     │
│ • Metasploit    │        │ • UF Forwarder  │        │ • SOC Dashboard │
└─────────────────┘        └─────────────────┘        └─────────────────┘

              NAT Network: SIEMLab · 10.0.0.0/24 · VirtualBox
```

---

## Detection Modules

| Module | Source | Description |
|---|---|---|
| Failed Login Detection | WinEventLog:Security | Detects EventCode 4625 — failed logon attempts grouped by account |
| Brute Force Detection | WinEventLog:Security | Flags accounts with 5+ failures in a time window |
| Port Scan Detection | WinEventLog:Security | High connection count from single IP indicates Nmap scanning |
| Credential Stuffing | WinEventLog:Security | Accounts with multiple failures followed by a successful login |
| Login Timeline | WinEventLog:Security | Timechart of failed vs successful logins over time |
| Event Source Monitor | All indexes | Event count by host — detects silent sources or log gaps |

---

## SPL Detection Rules

### Brute Force Detection
```spl
index=* source="WinEventLog:Security" EventCode=4625
| stats count by Account_Name
| where count > 5
| sort -count
```

### Port Scan Detection
```spl
index=* source="WinEventLog:Security"
| stats count by src_ip
| where count > 100
| sort -count
```

### Credential Stuffing
```spl
index=* source="WinEventLog:Security"
(EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures,
  count(eval(EventCode=4624)) as success by Account_Name
| where failures > 3 AND success > 0
```

### After-Hours Login Alert
```spl
index=* source="WinEventLog:Security" EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 20
| stats count by Account_Name, host
```

---

## Attack Simulations

| Attack | Tool | Target | Event Generated |
|---|---|---|---|
| Port scan / Recon | Nmap | Windows 10 (10.0.0.20) | Network connection events |
| RDP Brute Force | Hydra | Windows 10 RDP :3389 | EventCode 4625 × 14 |
| SMB Brute Force | Hydra | Windows 10 SMB :445 | EventCode 4625 |
| Credential stuffing | Hydra + rockyou.txt | Windows 10 | EventCode 4625 + 4624 |

---

## Results

| Metric | Value |
|---|---|
| Total events indexed | 5,301+ |
| Failed logins detected | 14 (Hydra brute force) |
| Detection rules written | 4 SPL queries |
| Dashboard panels | 4 |
| Log sources | Security, System, Application, Sysmon |
| Lab cost | £0 |

---

## Tools & Technologies

| Category | Tool | Version |
|---|---|---|
| SIEM | Splunk Enterprise | 10.2.2 |
| Hypervisor | VirtualBox | Latest |
| Attacker OS | Kali Linux | 2024.x |
| Target OS | Windows 10 Pro | 22H2 |
| SIEM Host | Ubuntu Server | 22.04 LTS |
| Log Agent | Splunk Universal Forwarder | 10.2 |
| Endpoint Monitor | Sysmon + SwiftOnSecurity config | Latest |
| Brute Force | Hydra | 9.6 |
| Recon | Nmap | 7.98 |

---

## Repository Structure

```
soc-home-lab/
├── README.md
├── splunk/
│   ├── inputs.conf           # Windows log collection config
│   ├── outputs.conf          # Forwarder → Splunk config
│   └── detection-rules.spl   # All SPL detection queries
├── docs/
│   ├── incident-report.pdf   # IR report from Hydra brute force attack
│   └── screenshots/
│       ├── dashboard.png
│       ├── search.png
│       └── full-lab.png
└── config/
    └── sysmon-config.xml     # SwiftOnSecurity Sysmon config
```

---

## Running the Lab

### Prerequisites
- VirtualBox installed
- 16GB RAM minimum
- 100GB free disk space

### Setup Order
```bash
# 1. Create NAT Network in VirtualBox
#    File → Tools → Network Manager → NAT Networks → Create
#    Name: SIEMLab | Subnet: 10.0.0.0/24 | Enable DHCP

# 2. Start Ubuntu VM → install Splunk
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license --run-as-root
sudo /opt/splunk/bin/splunk enable listen 9997 --run-as-root

# 3. Install Universal Forwarder on Windows 10
#    Download MSI from splunk.com
#    Set receiving indexer: 10.0.0.10:9997
#    Enable: Security, System, Application event logs

# 4. Start Kali and run attacks
nmap -sV -A 10.0.0.20
hydra -l username -P /usr/share/wordlists/rockyou.txt rdp://10.0.0.20 -t 4
```

### Access Splunk
```
http://10.0.0.10:8000
Username: admin
```

---

## Key Takeaways

- Deployed and configured a production-grade SIEM from scratch
- Understood the full attack-detect-respond lifecycle hands-on
- Wrote real SPL queries used by SOC analysts daily
- Gained both attacker (red) and defender (blue) perspectives
- Practised incident response against real brute force telemetry

---

## References

- [Splunk Documentation](https://docs.splunk.com)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Splunk Universal Forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html)

---

## About

Built as part of a cybersecurity portfolio. All attacks were performed inside an isolated VirtualBox lab environment with no external network exposure.

**Skills:** `Splunk` `SIEM` `SPL` `Blue Team` `SOC` `Incident Detection` `Log Analysis` `Nmap` `Hydra` `Kali Linux` `Ubuntu Server` `Windows Event Logs` `Sysmon` `VirtualBox` `UFW` `SSH`
