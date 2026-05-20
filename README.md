
# 🦈 Wireshark Network Analysis Portfolio

> Hands-on packet capture and network traffic analysis projects built in a home lab environment using Wireshark and VirtualBox.

<p align="center">
  <img src="https://img.shields.io/badge/Wireshark-Network_Analysis-1679A7?style=for-the-badge&logo=wireshark&logoColor=white" />
  <img src="https://img.shields.io/badge/SOC-Blue_Team-0A66C2?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Network_Forensics-PCAP_Analysis-8B0000?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Kali_Linux-Lab_Environment-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white" />
</p>

---

## 🛡️ About This Repository

This repository documents my practical Wireshark training as part of my journey toward becoming a SOC analyst and network security professional.

The projects focus on:
- Packet capture and analysis
- Network protocol investigation
- Threat detection techniques
- IOC identification
- Traffic pattern analysis
- Incident investigation workflows

All captures were performed in isolated lab environments using VirtualBox and controlled test systems.

---

# 🧪 Projects

| # | Project | Protocols | Difficulty | Status |
|---|---------|-----------|------------|--------|
| 01 | [TCP Handshake & Session Analysis](https://github.com/collinsnwammuo/Wireshark-projects/tree/main/TCP%20Handshake) | TCP | Beginner | ✅ Complete || TCP | Beginner | ✅ Complete |
| 02 | [DNS Traffic Investigation](https://github.com/collinsnwammuo/Wireshark-projects/tree/main/DNS%20Traffic%20Investigation)| DNS, UDP | Beginner | ✅ Complete |
| 03 | [Cleartext Credential Capture](#03---cleartext-credential-capture) | HTTP, FTP | Beginner | ✅ Complete |
| 04 | [Nmap Scan Detection & Analysis](https://github.com/collinsnwammuo/Wireshark-projects/tree/main/Nmap%20Scan%20Detection%20&%20Analysis) | TCP, ICMP | Intermediate | ✅ Complete |
| 05 | [ARP Spoofing / MITM Detection](#05---arp-spoofing--mitm-detection) | ARP | Intermediate | 🔄 In Progress |
| 06 | [Malware PCAP Investigation](#06---malware-pcap-investigation) | HTTP, TCP | Intermediate | 🔄 In Progress |
| 07 | [SSH Brute Force Detection](#07---ssh-brute-force-detection) | SSH, TCP | Intermediate | 🔄 In Progress |
| 08 | [Rogue DHCP Server Detection](#08---rogue-dhcp-server-detection) | DHCP, UDP | Advanced | ⏳ Planned |
| 09 | [ICMP Tunnel Detection](#09---icmp-tunnel-detection) | ICMP | Advanced | ⏳ Planned |
| 10 | [Full PCAP Forensics Investigation](#10---full-pcap-forensics-investigation) | Multi | Advanced | ⏳ Planned |

---

# 📚 Project Details

---

## 1️⃣ TCP Handshake & Session Analysis 👉 [Open](https://github.com/collinsnwammuo/Wireshark-projects/tree/main/TCP%20Handshake)

### 🎯 Scenario
Capture and analyse a complete TCP connection lifecycle to understand baseline network communication and session behavior.

### 🔍 What I Did
- Captured live TCP traffic using Wireshark
- Analysed:
  - SYN
  - SYN-ACK
  - ACK
  - FIN
  - RST packets
- Followed TCP streams
- Examined sequence and acknowledgement numbers

### 🧠 Skills Practised
- TCP session analysis
- Packet filtering
- Stream following
- Network troubleshooting
<!--
### 🔧 Wireshark Filters
```bash
tcp.flags.syn == 1
````

```bash
tcp.flags.fin == 1
```

```bash
tcp.stream eq 0
```

### 📁 Files

* `captures/tcp-handshake.pcap`
* `notes/tcp-analysis.md`
* `screenshots/`
-->
---

## 02 - DNS Traffic Investigation 👉 [Open](https://github.com/collinsnwammuo/Wireshark-projects/tree/main/DNS%20Traffic%20Investigation)

### 🎯 Scenario

Investigate DNS queries and responses to understand domain resolution and identify suspicious DNS behavior.

### 🔍 What I Did

* Captured DNS traffic generated from:

  * browser activity
  * nslookup
  * dig
* Analysed:

  * query types
  * response codes
  * TTL values
  * source/destination IPs

### 🧠 Skills Practised

* DNS protocol analysis
* IOC identification
* Suspicious domain detection
* Traffic visibility
<!--
### 🔧 Wireshark Filters

```bash
dns
```

```bash
dns.flags.response == 1
```

### 📁 Files

* `captures/dns-analysis.pcap`
* `notes/dns-analysis.md`
-->
---

## 03 - Cleartext Credential Capture 👉 [Open](https://github.com/collinsnwammuo/Wireshark-projects/tree/main/Nmap%20Scan%20Detection%20&%20Analysis)

### 🎯 Scenario

Demonstrate the risks of insecure protocols by capturing credentials transmitted over HTTP and FTP.

### 🔍 What I Did

* Generated HTTP login traffic
* Captured FTP authentication sessions
* Extracted usernames and passwords from packet streams
* Compared plaintext traffic with encrypted HTTPS traffic

### 🧠 Skills Practised

* HTTP analysis
* FTP traffic analysis
* Credential exposure investigation
* Stream reconstruction
<!--
### 🔧 Wireshark Filters

```bash
http.request.method == "POST"
```

```bash
ftp.request.command == "PASS"
```

### 📁 Files

* `captures/http-login.pcap`
* `captures/ftp-session.pcap`
-->
---

## 04 - Nmap Scan Detection & Analysis 👉 [Open](https://github.com/collinsnwammuo/Wireshark-projects/tree/main/Nmap%20Scan%20Detection%20&%20Analysis)
### 🎯 Scenario

Detect and classify various Nmap scan techniques through packet analysis.

### 🔍 What I Did

* Performed:

  * SYN scans
  * UDP scans
  * Connect scans
  * Version detection scans
* Analysed scan signatures in Wireshark
* Identified scan behavior based on packet patterns

### 🧠 Skills Practised

* Threat detection
* Scan classification
* TCP flag analysis
* Network reconnaissance detection
<!--
### 🔧 Wireshark Filters

```bash
tcp.flags == 0x002
```

```bash
icmp
```

### 📁 Files

* `captures/nmap-scan.pcap`
* `notes/scan-analysis.md`
-->
---

## 05 - ARP Spoofing / MITM Detection

### 🎯 Scenario

Simulate ARP poisoning and identify MITM indicators in packet captures.

### 🔍 What I Did

* Simulated ARP spoofing in a lab network
* Analysed duplicate ARP replies
* Identified MAC address inconsistencies
* Investigated unsolicited ARP responses

### 🧠 Skills Practised

* Layer 2 traffic analysis
* MITM detection
* ARP investigation
* IOC identification
<!--
### 🔧 Wireshark Filters

```bash
arp
```

```bash
arp.opcode == 2
```

### 📁 Files

* `captures/arp-spoofing.pcap`
* `notes/arp-analysis.md`
-->
---

## 06 - Malware PCAP Investigation

### 🎯 Scenario

Investigate malware traffic captures to identify command-and-control communication patterns.

### 🔍 What I Did

* Analysed publicly available malware PCAPs
* Identified suspicious outbound traffic
* Extracted:

  * malicious IPs
  * domains
  * user-agent strings
* Investigated beaconing behavior

### 🧠 Skills Practised

* Malware traffic analysis
* IOC extraction
* C2 detection
* Threat hunting fundamentals
<!--
### 📁 Files

* `captures/malware-sample.pcap`
* `reports/malware-analysis.md`
-->
---

## 07 - SSH Brute Force Detection

### 🎯 Scenario

Capture and investigate repeated SSH authentication attempts.

### 🔍 What I Did

* Generated brute force SSH traffic in a lab
* Captured repeated TCP connections to port 22
* Analysed connection frequency and failed attempts

### 🧠 Skills Practised

* Authentication monitoring
* Brute force detection
* Traffic analysis
* Incident investigation
<!--
### 🔧 Wireshark Filters

```bash
tcp.port == 22
```

### 📁 Files

* `captures/ssh-bruteforce.pcap`
* `notes/bruteforce-analysis.md`
-->
---

## 08 - Rogue DHCP Server Detection

### 🎯 Scenario

Detect unauthorized DHCP activity within a LAN environment.

### 🔍 What I Did

* Captured DHCP Discover / Offer traffic
* Compared legitimate vs rogue DHCP responses
* Investigated malicious gateway assignments

### 🧠 Skills Practised

* DHCP analysis
* Rogue device detection
* Infrastructure monitoring
<!--
### 🔧 Wireshark Filters

```bash
bootp
```

### 📁 Files

* `captures/rogue-dhcp.pcap`
-->
---

## 09 - ICMP Tunnel Detection

### 🎯 Scenario

Investigate suspicious ICMP traffic potentially used for covert communication or data exfiltration.

### 🔍 What I Did

* Analysed ICMP packet size anomalies
* Investigated repetitive ICMP payload behavior
* Compared normal vs suspicious ping activity

### 🧠 Skills Practised

* Covert channel detection
* ICMP analysis
* Threat hunting
<!--
### 🔧 Wireshark Filters

```bash
icmp
```

### 📁 Files

* `captures/icmp-tunnel.pcap`
-->
---

## 10 - Full PCAP Forensics Investigation

### 🎯 Scenario

Reconstruct a multi-stage cyber attack using only packet capture analysis.

### 🔍 What I Did

* Analysed:

  * reconnaissance
  * exploitation
  * malware communication
  * data exfiltration
* Built an attack timeline
* Extracted indicators of compromise

### 🧠 Skills Practised

* Network forensics
* Incident reconstruction
* IOC extraction
* Analyst reporting
<!--
### 📁 Files

* `captures/full-attack-chain.pcap`
* `reports/forensics-report.md`
-->
---

# 🖥️ Lab Environment

```text
VirtualBox Host Machine
├── Kali Linux VM
├── Windows Client VM
└── Isolated Host-Only Network
```

---
<!--
# 📂 Repository Structure

```text
wireshark-network-analysis/
├── README.md
├── captures/
├── screenshots/
├── notes/
├── reports/
└── iocs/
```
-->
---

# 🧠 Skills Demonstrated

* Packet capture analysis
* TCP/IP protocol analysis
* DNS investigation
* Network troubleshooting
* IOC extraction
* Malware traffic investigation
* Threat hunting fundamentals
* SOC investigation workflow

---

# 🛠️ Tools Used

* Wireshark
* Kali Linux
* VirtualBox
* tcpdump
* tshark

---
<!--
# 📚 Resources Used

* Wireshark Documentation
* Malware Traffic Analysis
* CyberDefenders
* TryHackMe
* MITRE ATT&CK Framework
-->
---

# 📜 Disclaimer

All captures and investigations were performed in isolated lab environments or using publicly available educational datasets.

---

# 🤝 Connect With Me

<p>
  <a href="https://www.linkedin.com/in/collins-nwammuo-645482248/" target="_blank">
    <img src="https://img.shields.io/badge/LinkedIn-0072b1?style=for-the-badge&logo=linkedin&logoColor=white" />
  </a>

  <a href="https://github.com/collinsnwammuo" target="_blank">
    <img src="https://img.shields.io/badge/GitHub-000000?style=for-the-badge&logo=github&logoColor=white" />
  </a>
</p>
```
