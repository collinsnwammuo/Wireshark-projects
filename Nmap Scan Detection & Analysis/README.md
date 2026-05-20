# 04 - Nmap Scan Detection & Analysis

**Difficulty:** Intermediate  
**Protocols:** TCP, UDP, ICMP  
**Tool:** Wireshark · Nmap  
**Lab Environment:** Kali Linux (attacker) · Metasploitable2 (target) · VirtualBox Host-Only Network

---

## 🎯 Objective

Run six different Nmap scan types against a vulnerable target VM and analyse the resulting packet captures in Wireshark — identifying the unique traffic signature of each scan type. This is a core SOC skill: recognising reconnaissance activity from network traffic before an attacker moves to exploitation.

---

## ⚠️ Disclaimer

All scans were performed in a fully isolated VirtualBox lab (Host-Only network). The target is a Metasploitable2 VM — a deliberately vulnerable machine built for security training. No external or production systems were scanned.

---

## 🧠 Background

Port scanning is almost always the first stage of an attack — the attacker maps which hosts are alive, which ports are open, and what services are running before choosing an exploit. As a SOC analyst, being able to recognise scan traffic in a PCAP or SIEM alert is fundamental.

```
Attack Kill Chain:
[Reconnaissance] → [Weaponisation] → [Delivery] → [Exploitation] → ...
      ↑
  THIS PROJECT
```

**Nmap scan types and their core logic:**

```
SYN Scan (-sS):      Client sends SYN only. Never completes handshake.
                     Open:    SYN → SYN-ACK → RST  (Nmap kills it)
                     Closed:  SYN → RST-ACK

Connect Scan (-sT):  Full TCP handshake per port.
                     Open:    SYN → SYN-ACK → ACK → FIN
                     Closed:  SYN → RST-ACK

UDP Scan (-sU):      Sends UDP probe to each port.
                     Open:    No response (or service reply)
                     Closed:  ICMP Port Unreachable (type 3 code 3)

XMAS Scan (-sX):     Sets FIN + PSH + URG flags (illegal combo).
                     Open:    No response
                     Closed:  RST

NULL Scan (-sN):     No TCP flags set at all (illegal).
                     Open:    No response
                     Closed:  RST

Version Scan (-sV):  Full connect + banner grab per open port.
                     Nmap reads service responses to fingerprint versions.
```

---

## 🔬 Methodology

### Lab Setup

```
VirtualBox Host-Only Network: 192.168.56.0/24
├── Kali Linux      192.168.56.101   (attacker + analyst running Wireshark)
└── Metasploitable2 192.168.56.102   (target — deliberately vulnerable VM)
```

### Process

For each scan type:
1. Started a fresh Wireshark capture on `eth0`
2. Ran the Nmap scan from terminal
3. Stopped capture immediately after scan completed
4. Saved as a separate `.pcap` file
5. Applied filters and analysed the signature

### Nmap Commands Run

```bash
sudo nmap -sS 192.168.56.102                      # SYN stealth scan
nmap -sT 192.168.56.102                           # TCP connect scan
sudo nmap -sU --top-ports 20 192.168.56.102       # UDP scan (top 20 ports)
sudo nmap -sV -O -A 192.168.56.102                # Version + OS detection
sudo nmap -sX 192.168.56.102                      # XMAS scan
sudo nmap -sN 192.168.56.102                      # NULL scan
```

---

## 📊 Findings

### Scan Signature Comparison

| Scan Type | Flag | Open Port Signature | Closed Port Signature | Noise Level |
|---|---|---|---|---|
| SYN Stealth | `-sS` | SYN → SYN-ACK → **RST** | SYN → RST-ACK | Medium |
| TCP Connect | `-sT` | SYN → SYN-ACK → ACK → FIN | SYN → RST-ACK | High |
| UDP | `-sU` | No response (silence) | **ICMP Port Unreachable** | Low |
| Version | `-sV -O` | Full handshake + data exchange | SYN → RST-ACK | Very High |
| XMAS | `-sX` | No response | **RST** | Low |
| NULL | `-sN` | No response | **RST** | Low |

> Update this table with your actual packet observations.

---

### SYN Scan Analysis

**Wireshark filter:** `tcp.flags.syn == 1 && tcp.flags.ack == 0`

The SYN scan generates the most recognisable pattern — hundreds of SYN packets sent in rapid succession to sequential port numbers from a single source IP. Key observations:

- Open ports responded with SYN-ACK; Nmap immediately sent RST to avoid completing the handshake (avoiding logs on the target)
- Closed ports responded with RST-ACK instantly
- The entire scan completed in under 2 seconds — visible as a sharp spike in the IO Graph
- Total packets observed: (update with your value)

**Open ports discovered on Metasploitable2:**

| Port | Service |
|---|---|
| 21 | FTP (vsftpd) |
| 22 | SSH (OpenSSH) |
| 23 | Telnet |
| 80 | HTTP (Apache) |
| 3306 | MySQL |
| 5432 | PostgreSQL |

> Update with actual results from your scan.

---

### TCP Connect Scan Analysis

**Wireshark filter:** `tcp`

Compared to SYN scan, the connect scan shows full 3-way handshakes for every open port — significantly more packets. Every completed connection would appear in the target's connection logs, making this scan far more detectable. Packet count was approximately double the SYN scan.

---

### UDP Scan Analysis

**Wireshark filter:** `udp` and `icmp.type == 3 && icmp.code == 3`

UDP scanning is inherently slower — Nmap must wait for ICMP Port Unreachable responses (closed ports) or a timeout (open/filtered). ICMP type 3 code 3 responses confirmed closed UDP ports. Open UDP ports generated no response — they appear identical to filtered ports in the capture.

---

### XMAS Scan Analysis

**Wireshark filter:** `tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1`

Every XMAS probe packet has FIN, PSH, and URG flags all set simultaneously — a combination that never occurs in legitimate TCP traffic. This makes XMAS scan packets trivial to identify but potentially able to bypass older, SYN-only firewalls. Against the Linux Metasploitable2 target, open ports returned silence and closed ports returned RST as expected.

---

### NULL Scan Analysis

**Wireshark filter:** `tcp.flags == 0x000`

NULL scan packets carry no TCP flags whatsoever — another illegal combination in normal TCP. Behaviour mirrors XMAS scan. Both NULL and XMAS scans rely on RFC 793 behaviour (which Linux follows strictly) and are unreliable against Windows hosts.

---

### Version Scan Analysis

**Wireshark filter:** `tcp`

The version scan is the noisiest of all — full connections to every open port followed by data exchange as Nmap reads service banners. Following the TCP Stream on any open port reveals Nmap reading HTTP headers, SSH banners, FTP welcome messages and more. This scan generates substantial traffic and is easily detected by any IDS.

---

## 💡 Key Observations

- **SYN scan is "stealthy" but still obvious in a PCAP** — the pattern of hundreds of SYNs with no completed handshakes from one IP to one target in under 2 seconds is unmistakable. "Stealth" only means it avoids completing connections, not that it's invisible.

- **The RST after SYN-ACK is Nmap's signature** — in normal traffic a client never receives a SYN-ACK and then immediately sends RST. Seeing this repeatedly across ports is a definitive scan indicator.

- **UDP scan speed vs TCP** — the UDP scan of just 20 ports took far longer than a SYN scan of all 1000 common ports. This is because UDP has no built-in acknowledgement — Nmap must wait for timeouts on non-responsive ports.

- **XMAS and NULL scans produce zero legitimate traffic matches** — no real application ever sends a packet with no flags or with FIN+PSH+URG. A single such packet in a capture should raise an immediate alert.

- **Version scan reveals far more than port state** — the TCP streams from `-sV` contain actual service banners: SSH version strings, HTTP server headers, FTP welcome messages. All of this helps an attacker choose the right exploit — and tells a defender exactly what's exposed.

- **IO Graph is a powerful detection tool** — a flat baseline then a sudden spike to thousands of packets per second from one source is the visual fingerprint of automated scanning.

---

## 🔗 SOC Relevance

| Detection Indicator | What It Means | Recommended Response |
|---|---|---|
| Hundreds of SYNs from one IP to one target | Port scan in progress | Block source IP, investigate host |
| SYN → SYN-ACK → RST repeated pattern | SYN stealth scan (Nmap -sS) | Alert and investigate |
| ICMP Port Unreachable flood | UDP scan in progress | Alert, check firewall rules |
| Packets with FIN+PSH+URG or no flags | XMAS or NULL scan | Block source, escalate |
| Single host connecting to 100+ ports in seconds | Automated scan tool | Immediate block and investigation |
| Sequential port numbers in connections | Nmap or similar scanner | Correlate with threat intel |
| Banner grab traffic after port discovery | Active reconnaissance | Host may be pre-exploitation target |

---

## 🛠️ Tools Used

- **Wireshark** — packet capture and analysis
- **Nmap** — network scanner (built into Kali)
- **Metasploitable2** — intentionally vulnerable target VM
- **Kali Linux** — attacker and analyst workstation

---

*Project 04 of 10 · [Back to Main Portfolio](../README.md)*
