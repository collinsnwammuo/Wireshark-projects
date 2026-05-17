# 🦈 Wireshark Network Analysis Portfolio

> Hands-on packet capture and network traffic analysis projects built in a home lab environment using Kali Linux on VirtualBox.

**Tools:** Wireshark · tcpdump · tshark · Kali Linux  
**Focus:** Network forensics · Protocol analysis · Threat detection · Incident investigation

---

## About This Repository

This portfolio documents my practical Wireshark training as part of my journey toward becoming a SOC analyst. Each project contains a scenario, methodology, key findings, and annotated screenshots of packet captures. All traffic was captured in an isolated VirtualBox lab — no real-world systems were used.

---

## Projects

| # | Project | Protocols | Difficulty | Status |
|---|---------|-----------|------------|--------|
| 01 | [TCP Handshake & Teardown Deep Dive](#01---tcp-handshake--teardown-deep-dive) | TCP | Beginner | ✅ Complete |
| 02 | [DNS Query Analysis & Spoofing Detection](#02---dns-query-analysis--spoofing-detection) | DNS, UDP | Beginner | ✅ Complete |
| 03 | [Cleartext Credential Harvesting (HTTP/FTP)](#03---cleartext-credential-harvesting-httpftp) | HTTP, FTP | Beginner | ✅ Complete |
| 04 | [Nmap Port Scan Detection & Classification](#04---nmap-port-scan-detection--classification) | TCP, ICMP | Intermediate | ✅ Complete |
| 05 | [ARP Poisoning / MITM Attack Detection](#05---arp-poisoning--mitm-attack-detection) | ARP | Intermediate | ✅ Complete |
| 06 | [Malware C2 Beaconing Analysis](#06---malware-c2-beaconing-analysis) | HTTP, TCP | Intermediate | 🔄 In Progress |
| 07 | [Brute Force SSH Attack — Live Capture](#07---brute-force-ssh-attack--live-capture) | SSH, TCP | Intermediate | 🔄 In Progress |
| 08 | [Rogue DHCP Server Detection](#08---rogue-dhcp-server-detection) | DHCP, UDP | Intermediate | ⏳ Planned |
| 09 | [ICMP Tunnel Data Exfiltration](#09---icmp-tunnel-data-exfiltration) | ICMP | Advanced | ⏳ Planned |
| 10 | [Full Attack Chain Analysis (PCAP Forensics)](#10---full-attack-chain-analysis-pcap-forensics) | Multi | Advanced | ⏳ Planned |

---

## Project Details

### 01 - TCP Handshake & Teardown Deep Dive

**Scenario:** Capture and manually trace a complete TCP connection lifecycle — SYN, SYN-ACK, ACK, data transfer, FIN, and RST — to understand normal baseline traffic before analysing anomalies.

**What I did:**
- Ran `curl http://example.com` while capturing on `eth0`
- Used display filter `tcp.stream eq 0` to isolate a single conversation
- Annotated each packet with flags, sequence numbers, and window sizes
- Identified the difference between a clean FIN teardown vs an RST reset

**Key Wireshark skills practised:**
- Display filters (`tcp.flags.syn==1`, `tcp.flags.fin==1`, `tcp.flags.reset==1`)
- Stream following (Right-click → Follow → TCP Stream)
- Packet annotation and export

**Files:** `captures/tcp-handshake.pcap` · `screenshots/` · `notes/tcp-analysis.md`

---

### 02 - DNS Query Analysis & Spoofing Detection

**Scenario:** Analyse DNS traffic to understand normal query/response patterns, then simulate a DNS spoofing scenario and identify the indicators in Wireshark.

**What I did:**
- Captured DNS queries for multiple domains using `nslookup` and `dig`
- Compared UDP vs TCP DNS (for large responses)
- Simulated DNS spoofing using `dnsspoof` on Kali in an isolated LAN
- Identified spoofed responses by: mismatched Transaction IDs, unexpected TTL values, anomalous source IPs

**Key Wireshark skills practised:**
- Filter: `dns`, `dns.flags.response == 1`, `dns.qry.name contains "example"`
- Exporting DNS query list as CSV for IOC extraction
- Identifying duplicate Transaction IDs (spoofing indicator)

**Files:** `captures/dns-normal.pcap` · `captures/dns-spoofed.pcap` · `notes/dns-analysis.md`

---

### 03 - Cleartext Credential Harvesting (HTTP/FTP)

**Scenario:** Demonstrate why cleartext protocols are dangerous by capturing login credentials transmitted over HTTP and FTP — and extract them directly from the packet capture.

**What I did:**
- Set up a simple HTTP login form on an Apache server (isolated VM)
- Logged in via browser while capturing traffic
- Extracted credentials using: Analyse → Follow → HTTP Stream
- Repeated for FTP using `ftp` client against vsftpd
- Compared against HTTPS traffic to show encryption in practice

**Key Wireshark skills practised:**
- Filter: `http.request.method == "POST"`, `ftp.request.command == "PASS"`
- File → Export Objects → HTTP (extract uploaded files)
- Understanding why TLS matters

**Files:** `captures/http-login.pcap` · `captures/ftp-session.pcap` · `notes/cleartext-analysis.md`

---

### 04 - Nmap Port Scan Detection & Classification

**Scenario:** Run several Nmap scan types from Kali against a target VM, capture the traffic, and practise identifying each scan type purely from packet patterns — the way a SOC analyst would see them in logs.

**Scan types covered:**

| Scan | Nmap Flag | Pattern in Wireshark |
|------|-----------|----------------------|
| SYN (Stealth) | `-sS` | SYN only, no ACK completion |
| Connect | `-sT` | Full 3-way handshake per port |
| UDP | `-sU` | UDP to many ports in rapid succession |
| XMAS | `-sX` | FIN+PSH+URG flags set |
| NULL | `-sN` | No flags set |
| Version | `-sV` | Full connection + banner grab |

**Key Wireshark skills practised:**
- Filter by TCP flags: `tcp.flags == 0x002` (SYN only)
- Spotting high-rate connections to sequential ports (scan signature)
- Measuring scan speed via `Statistics → Capture File Properties`
- IO Graph (`Statistics → IO Graph`) to visualise burst traffic

**Files:** `captures/nmap-syn-scan.pcap` · `captures/nmap-udp-scan.pcap` · `notes/scan-detection.md`

---

### 05 - ARP Poisoning / MITM Attack Detection

**Scenario:** Simulate an ARP poisoning attack using `arpspoof` on Kali and detect it in a live Wireshark capture — the same technique attackers use to intercept LAN traffic.

**What I did:**
- Set up 3 VMs: Attacker (Kali), Victim, Gateway — all on Host-Only network
- Ran `arpspoof -i eth0 -t <victim_ip> <gateway_ip>` from Kali
- Captured on the victim VM and identified the attack indicators
- Identified the attack by: duplicate ARP replies, MAC address conflicts, Gratuitous ARPs

**Indicators of Compromise spotted:**
- Two different IPs resolving to the same MAC address
- Unsolicited ARP replies (Gratuitous ARP) from the attacker
- Wireshark Expert Info → Warning: `Duplicate IP address detected`

**Key Wireshark skills practised:**
- Filter: `arp`, `arp.opcode == 2` (ARP replies only)
- Wireshark Expert Info panel for automatic anomaly highlighting
- ARP table reconstruction from captures

**Files:** `captures/arp-poison.pcap` · `screenshots/` · `notes/arp-mitm-analysis.md`

---

### 06 - Malware C2 Beaconing Analysis

**Scenario:** Analyse a real-world malware PCAP sample (from malware-traffic-analysis.net) to identify Command & Control (C2) beaconing — the regular check-in pattern malware uses to communicate with attacker infrastructure.

**What I did:**
- Downloaded a public malware PCAP (Emotet, Trickbot, or similar — sourced from malware-traffic-analysis.net)
- Identified beaconing by looking for regular intervals of outbound connections to the same IP
- Extracted IOCs: C2 IP addresses, domains, User-Agent strings, URI patterns
- Cross-referenced IOCs with VirusTotal and AbuseIPDB
- Documented full findings in an analyst-style report

**Beaconing indicators looked for:**
- Fixed interval connections (e.g. every 300 seconds) — `Statistics → IO Graph`
- Low data volume per beacon (check-in, not data transfer)
- Unusual User-Agent strings in HTTP headers
- Non-standard ports for HTTP/HTTPS traffic

**Files:** `captures/malware-sample.pcap` · `reports/c2-analysis-report.md` · `iocs/extracted-iocs.txt`

---

### 07 - Brute Force SSH Attack — Live Capture

**Scenario:** Launch a brute force SSH attack from Kali against a target VM using `hydra`, capture the traffic live, and identify the attack pattern a SOC analyst would flag for alerting.

**What I did:**
- Configured a vulnerable Ubuntu VM with a weak SSH password
- Ran `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target_ip>`
- Captured simultaneously in Wireshark
- Measured: packets per second, connection attempts per second, RST patterns on failures

**Attack signature identified:**
- High-frequency TCP SYN packets to port 22 from a single source
- Repeated SSH banner exchange followed by RST (failed auth)
- Successful login shows extended session duration vs failed ones

**Files:** `captures/ssh-bruteforce.pcap` · `notes/bruteforce-analysis.md`

---

### 08 - Rogue DHCP Server Detection

**Scenario:** Stand up a rogue DHCP server on the LAN and detect it in Wireshark — a common attack used to redirect victim traffic through an attacker machine.

**What I did:**
- Ran a rogue `dnsmasq` DHCP server on Kali in the isolated LAN
- Had a victim VM request an IP address
- Captured the DHCP Discover → Offer → Request → ACK sequence
- Identified the rogue server: wrong gateway IP, DNS pointing to attacker, earlier response time

**Detection method:**
- Filter: `bootp` (DHCP uses BOOTP ports)
- Compare DHCP Offer source MACs — legitimate vs rogue
- Check offered gateway/DNS IPs against known-good values

**Files:** `captures/rogue-dhcp.pcap` · `notes/rogue-dhcp-analysis.md`

---

### 09 - ICMP Tunnel Data Exfiltration

**Scenario:** Simulate data exfiltration hidden inside ICMP (ping) packets using `icmptunnel` or `ptunnel` — a technique used to bypass firewalls that allow ping but block other traffic.

**What I did:**
- Set up an ICMP tunnel between two VMs using `ptunnel-ng`
- Transferred a file through the tunnel disguised as ping traffic
- Captured and identified the covert channel indicators

**Indicators of covert ICMP use:**
- ICMP payload size abnormally large (normal ping = 32–64 bytes; tunnel = 1000+ bytes)
- ICMP sequence numbers don't increment normally
- Continuous ICMP flood vs occasional pings
- Payload contains readable ASCII / non-random data

**Files:** `captures/icmp-tunnel.pcap` · `notes/icmp-exfil-analysis.md`

---

### 10 - Full Attack Chain Analysis (PCAP Forensics)

**Scenario:** Given a complex, multi-stage PCAP from a simulated attack (recon → exploitation → C2 → exfiltration), reconstruct the full attack timeline using only Wireshark — as a digital forensics exercise.

**What I did:**
- Used a public CTF or forensics challenge PCAP (e.g. from CyberDefenders or PacketTotal)
- Reconstructed the kill chain: initial scan → exploit traffic → malware download → C2 → data out
- Extracted: attacker IP, victim IP, malware hash, stolen data, timestamps
- Wrote a full analyst report mapping findings to MITRE ATT&CK techniques

**Wireshark features used:**
- `Statistics → Conversations` to map all hosts and volumes
- `Statistics → Protocol Hierarchy` to spot anomalous protocol ratios
- File → Export Objects to recover transferred files
- Full timeline reconstruction from packet timestamps

**Files:** `captures/attack-chain.pcap` · `reports/full-forensics-report.md` · `mitre-mapping.md`

---

## Lab Setup

```
VirtualBox Host (Laptop)
├── Kali Linux VM       — Analyst / Attacker workstation
├── Ubuntu Server VM    — Log source, web server, SSH target
├── Metasploitable2 VM  — Vulnerable target
└── Network: Host-Only Adapter (isolated, no internet reach)
```

All captures performed on an isolated Host-Only VirtualBox network. No external systems involved.

---

## Repository Structure

```
wireshark-portfolio/
├── README.md
├── captures/               # .pcap files for each project
├── screenshots/            # Annotated Wireshark screenshots
├── notes/                  # Per-project analysis notes (Markdown)
├── reports/                # Full analyst-style reports
└── iocs/                   # Extracted Indicators of Compromise
```

---

## Skills Demonstrated

- Packet capture (live & offline PCAP analysis)
- TCP/IP, UDP, ICMP, DNS, HTTP, ARP, DHCP protocol analysis
- Attack pattern recognition (scans, brute force, MITM, C2 beaconing)
- IOC extraction from network traffic
- Wireshark display filters, stream following, statistics, export objects
- tshark (CLI Wireshark) for scripted analysis
- Writing analyst-style investigation reports

---

## Resources Used

- [Wireshark Official Documentation](https://www.wireshark.org/docs/)
- [Malware Traffic Analysis (free PCAPs)](https://www.malware-traffic-analysis.net/)
- [CyberDefenders (blue team labs)](https://cyberdefenders.org/)
- [TryHackMe SOC Level 1 Path](https://tryhackme.com/path/outline/soclevel1)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

*Part of my SOC analyst home lab training. Open to feedback from experienced analysts.*
