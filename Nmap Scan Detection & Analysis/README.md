# 04 - Nmap Scan Detection & Analysis

**Difficulty:** Intermediate  
**Protocols:** TCP, UDP, ICMP  
**Tools:** Wireshark · Nmap  
**Lab Environment:** Kali Linux (attacker/analyst) · Windows 10 (target) · VirtualBox Host-Only Network

---

## 🎯 Objective

Run six different Nmap scan types from Kali Linux against a Windows 10 target VM and analyse each resulting packet capture in Wireshark — identifying the unique traffic signature of every scan type. A key finding in this project is how Windows 10 responds differently to certain scan types compared to Linux targets, which has direct implications for SOC detection strategies.

---

## ⚠️ Disclaimer

All scanning was performed in a fully isolated VirtualBox Host-Only network. The target is a Windows 10 VM running in a closed lab environment. No external or production systems were involved.

---

## 🧠 Background

Port scanning is almost always the first stage of an attack — the adversary maps which hosts are alive, which ports are open, and what services are running before choosing an exploit. Recognising scan signatures in network traffic is a foundational SOC analyst skill.

```
Attack Kill Chain:
[Reconnaissance] → [Weaponisation] → [Delivery] → [Exploitation] → ...
      ↑
  THIS PROJECT
```

### TCP Scan Logic

```
SYN Scan (-sS):
  Open port:    SYN ──► SYN-ACK ──► RST   (Nmap kills connection — "stealth")
  Closed port:  SYN ──► RST-ACK

Connect Scan (-sT):
  Open port:    SYN ──► SYN-ACK ──► ACK ──► FIN  (full handshake)
  Closed port:  SYN ──► RST-ACK

UDP Scan (-sU):
  Open port:    UDP probe ──► [silence or service reply]
  Closed port:  UDP probe ──► ICMP Port Unreachable (type 3, code 3)

XMAS Scan (-sX):   Sets FIN + PSH + URG flags (illegal TCP combination)
NULL Scan (-sN):   No TCP flags set at all (illegal TCP combination)

Version Scan (-sV -O -A):
  Full connect + banner grab per open port + OS fingerprinting
```

### ⚠️ Windows vs Linux Behaviour

A critical difference observed in this lab: Windows 10 sends **RST for all ports** when receiving XMAS and NULL scan packets — regardless of whether the port is open or closed. Linux follows RFC 793 strictly (no response for open ports). This means XMAS and NULL scans are **unreliable against Windows targets** for determining open ports, but their packets are still clearly identifiable in Wireshark.

---

## 🔬 Methodology

### Lab Setup

```
VirtualBox Host-Only Network: 192.168.56.0/24
├── Kali Linux   192.168.56.102  — attacker + Wireshark analyst
└── Windows 10   192.168.56.101  — target (RDP, SMB, RPC)
```

> Update IP addresses to match your actual lab.

### Services Enabled on Windows 10 Target

| Service | Port | Method |
|---|---|---|
| Remote Desktop (RDP) | 3389 | System Properties → Remote Settings |
| SMB File Sharing | 139, 445 | Network and Sharing Centre |
| Windows RPC | 135 | Default — always on |

### Scan Commands

```bash
sudo nmap -sS 192.168.56.101                     # SYN stealth scan
nmap -sT 192.168.56.101                          # TCP connect scan
sudo nmap -sU --top-ports 20 192.168.56.101     # UDP scan
sudo nmap -sV -O -A 192.168.56.101               # Version + OS detection
sudo nmap -sX 192.168.56.101                     # XMAS scan
sudo nmap -sN 192.168.56.101                    # NULL scan
```

Each scan was captured separately — one `.pcap` file per scan type.

### Key Wireshark Filters Used

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0         # SYN packets only
tcp.flags.syn == 1 && tcp.flags.ack == 1         # SYN-ACK (open port replies)
tcp.flags.reset == 1                              # RST packets
tcp.flags == 0x000                                # NULL packets
icmp.type == 3 && icmp.code == 3                 # ICMP Port Unreachable (UDP scan)
udp                                               # All UDP traffic
```

---

## 📊 Findings

### Open Ports Discovered on Windows 10 Target

| Port | Protocol | Service | Scan That Found It |
|---|---|---|---|
| 135 | TCP | Windows RPC | SYN, Connect, Version |
| 139 | TCP | NetBIOS | SYN, Connect, Version |
| 445 | TCP | SMB | SYN, Connect, Version |
| 3389 | TCP | RDP | SYN, Connect, Version |

### Scan Comparison Table

| Scan | Flag | Open Port Signature | Closed Port Signature | Windows Behaviour | Noise |
|---|---|---|---|---|---|
| SYN Stealth | `-sS` | SYN→SYN-ACK→**RST** | SYN→RST-ACK | Standard | Medium |
| TCP Connect | `-sT` | SYN→SYN-ACK→ACK→FIN | SYN→RST-ACK | Standard | High |
| UDP | `-sU` | Silence / service reply | ICMP Port Unreachable | Rate-limited ICMP | Low |
| Version | `-sV -O` | Full connect + data | SYN→RST-ACK | Standard | Very High |
| NULL | `-sN` | **RST (not silence)** | RST | RSTs all — unreliable | Low |

---

### SYN Scan — Detailed Analysis

**Filter:** `tcp.flags.syn == 1 && tcp.flags.ack == 0`

The SYN scan produced the clearest reconnaissance signature — hundreds of SYN packets sent in rapid succession to sequential destination ports from a single source IP (Kali). The entire scan completed in under 3 seconds, visible as a sharp spike on the IO Graph.

**Open port signature (3 packets):**
```
Kali    → Windows:  [SYN]          seq=0
Windows → Kali:     [SYN-ACK]      seq=0, ack=1   ← port is OPEN
Kali    → Windows:  [RST]                          ← Nmap kills it immediately
```

**Closed port signature (2 packets):**
```
Kali    → Windows:  [SYN]          seq=0
Windows → Kali:     [RST-ACK]                      ← port is CLOSED
```

---

### TCP Connect Scan — Detailed Analysis

**Filter:** `tcp`

Connect scan generated approximately double the packet count of the SYN scan — every open port produced a full 3-way handshake before Nmap closed it with FIN. Unlike SYN scan, every completed connection is recorded in Windows Event Logs (Event ID 5156), making this the most detectable scan type. Closed ports behaved identically to SYN scan.

---

### UDP Scan — Detailed Analysis

**Filter:** `udp` and `icmp.type == 3 && icmp.code == 3`

Windows 10 rate-limits ICMP Port Unreachable responses — not every closed UDP port generated an immediate ICMP reply, which caused Nmap to wait for timeouts and slowed the scan significantly. Open UDP ports produced no response. The ICMP type 3 code 3 replies that did arrive clearly identified closed ports.

---

### Version & OS Detection — Detailed Analysis

**Filter:** `tcp`

The `-A` flag triggered the most traffic of any scan — full connections to all open ports followed by data exchange as Nmap grabbed service banners. Following the TCP stream on port 3389 revealed RDP negotiation data; port 445 showed SMB protocol exchange. Nmap successfully identified the target OS:

```
OS details: Microsoft Windows 10
```

---

## 💡 Key Observations

- **SYN scan is fast but not invisible** — hundreds of SYNs to one target across sequential ports in under 3 seconds is unmistakable in any PCAP or SIEM. "Stealth" only means no completed connections, not no traffic.

- **The RST after SYN-ACK is Nmap's fingerprint** — in normal traffic a client never receives a SYN-ACK then immediately RSTs. Seeing this pattern repeated dozens of times is a definitive scan indicator.

- **Windows rate-limits ICMP** — during UDP scanning, Windows throttles its ICMP Port Unreachable responses. This caused Nmap to time out on many ports, significantly slowing the scan. SOC implication: a burst of ICMP Unreachable messages followed by silence may indicate a target applying rate-limiting.

- **XMAS and NULL scans are OS-dependent** — the RFC 793 behaviour that makes these scans work only applies to Linux/Unix. Windows RSTs everything, making the scan results useless for port discovery — but the packet signatures are still instantly recognisable.

- **Version scan is the richest for intelligence** — following TCP streams from `-sV` reveals real service data: RDP banners, SMB protocol negotiation, HTTP server headers. This is exactly what an attacker uses to choose exploits, and exactly what a defender should monitor.

- **IO Graph reveals scan timing** — a completely flat baseline then a spike to thousands of packets per second is the visual signature of automated scanning. This pattern in a SIEM would trigger an immediate alert.

---

## 🔗 SOC Relevance

| Detection Indicator | Attack Technique | Recommended Response |
|---|---|---|
| Hundreds of SYNs from one IP in seconds | Port scan — active recon | Block source IP, investigate host |
| SYN → SYN-ACK → RST pattern repeated | Nmap SYN stealth scan | Alert, correlate with other indicators |
| ICMP Port Unreachable flood | UDP scan in progress | Alert, check firewall rules |
| FIN+PSH+URG or zero-flag TCP packets | XMAS / NULL scan | Immediate block — no legitimate use |
| Single host touching 100+ ports rapidly | Automated scan tool | Block and investigate |
| Banner grab traffic after port scan | Pre-exploitation recon | Host may be targeted — increase monitoring |
| Nmap OS fingerprint probes | OS detection (-O flag) | Correlate with scan alerts |

---

## 🛠️ Tools Used

- **Wireshark** — packet capture and analysis
- **Nmap** — network scanner (built into Kali Linux)
- **Kali Linux** — attacker and analyst workstation
- **Windows 10** — scan target VM

---

*Project 04 of 10 · [Back to Main Portfolio](../README.md)*
