# 04 - Nmap Scan Detection & Analysis

**Difficulty:** Intermediate  
**Protocols:** TCP, UDP, ICMP  
**Tools:** Wireshark · Nmap  
**Lab Environment:** Kali Linux (attacker/analyst) · Windows 10 (target) · VirtualBox Host-Only Network

---

## 🎯 What I Did

I ran six different Nmap scan types from my Kali Linux VM against a Windows 10 target VM and captured every scan in Wireshark — then analysed each PCAP to identify the unique traffic signature each scan type leaves behind. One of the most interesting things I discovered is that Windows 10 responds differently to certain scan types compared to Linux targets, which has real implications for how a SOC analyst interprets scan traffic depending on what OS is being scanned.

---

## ⚠️ Disclaimer

All scanning was performed in a fully isolated VirtualBox Host-Only network. The target is a Windows 10 VM in my closed home lab. No external or production systems were involved.

---

## 🧠 Background

Port scanning is almost always the first stage of an attack, before choosing an exploit, an attacker needs to know which hosts are alive, which ports are open, and what services are running. As a SOC analyst, being able to recognise scan signatures in a PCAP is foundational. by the time an exploit fires, the scan already happened and may have been your only warning.

```
Attack Kill Chain:
[Reconnaissance] → [Weaponisation] → [Delivery] → [Exploitation] → ...
      ↑
  THIS PROJECT
```

### How Each Scan Type Works

```
SYN Scan (-sS):
  Open port:    SYN ──► SYN-ACK ──► RST   (Nmap kills it — never completes handshake)
  Closed port:  SYN ──► RST-ACK

Connect Scan (-sT):
  Open port:    SYN ──► SYN-ACK ──► ACK ──► FIN  (full handshake — gets logged)
  Closed port:  SYN ──► RST-ACK

UDP Scan (-sU):
  Open port:    UDP probe ──► [silence or service reply]
  Closed port:  UDP probe ──► ICMP Port Unreachable (type 3, code 3)

XMAS Scan (-sX):   Sets FIN + PSH + URG flags simultaneously — illegal combination
NULL Scan (-sN):   No TCP flags set at all — also illegal

Version Scan (-sV -O -A):
  Full connect + reads service banners + fingerprints OS
```

### ⚠️ Windows vs Linux — A Key Finding

One of the most valuable things I learned from this exercise is that Windows 10 **RSTs all ports** when it receives XMAS and NULL scan packets, whether the port is open or closed. Linux follows RFC 793 strictly and stays silent on open ports. This means XMAS and NULL scans are unreliable against Windows for port discovery, but their packet signatures are still clearly identifiable in Wireshark. I've noted this difference throughout my analysis below.

---

## 🔬 How I Set It Up

### Lab Configuration

```
VirtualBox Host-Only Network: 192.168.56.0/24
├── Kali Linux   192.168.56.102  — attacker + Wireshark analyst
└── Windows 10   192.168.56.101  — scan target
```

### Services I Enabled on Windows 10

To make the scan results interesting, I enabled several services on the Windows 10 VM before scanning:

| Service | Port | How I Enabled It |
|---|---|---|
| Remote Desktop (RDP) | 3389 | System Properties → Remote Settings |
| SMB File Sharing | 139, 445 | Network and Sharing Centre |
| Windows RPC | 135 | Default — always running |

### Scan Commands I Ran

I ran each scan separately and saved a separate PCAP for each one:

```bash
sudo nmap -sS 192.168.56.101                    # SYN stealth scan
nmap -sT 192.168.56.101                         # TCP connect scan
sudo nmap -sU --top-ports 20 192.168.56.101     # UDP scan
sudo nmap -sV -O -A 192.168.56.101              # Version + OS detection
sudo nmap -sX 192.168.56.101                    # XMAS scan
sudo nmap -sN 192.168.56.101                    # NULL scan
```

### Wireshark Filters I Used

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0        # SYN packets only
tcp.flags.syn == 1 && tcp.flags.ack == 1        # SYN-ACK replies (open ports)
tcp.flags.reset == 1                             # RST packets
tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1  # XMAS packets
tcp.flags == 0x000                               # NULL packets
icmp.type == 3 && icmp.code == 3                # ICMP Port Unreachable
udp                                              # All UDP traffic
```

---

## 📊 What I Found

### Open Ports on Windows 10

| Port | Protocol | Service | Which Scans Found It |
|---|---|---|---|
| 135 | TCP | Windows RPC | SYN, Connect, Version |
| 139 | TCP | NetBIOS | SYN, Connect, Version |
| 445 | TCP | SMB | SYN, Connect, Version |
| 3389 | TCP | RDP | SYN, Connect, Version |

### Scan Signature Comparison

| Scan | Flag | Open Port Signature | Closed Port Signature | Windows Behaviour | Noise Level |
|---|---|---|---|---|---|
| SYN Stealth | `-sS` | SYN→SYN-ACK→**RST** | SYN→RST-ACK | Standard | Medium |
| TCP Connect | `-sT` | SYN→SYN-ACK→ACK→FIN | SYN→RST-ACK | Standard | High |
| UDP | `-sU` | Silence / service reply | ICMP Port Unreachable | Rate-limited ICMP | Low |
| Version | `-sV -O` | Full connect + data exchange | SYN→RST-ACK | Standard | Very High |
| XMAS | `-sX` | **RST (not silence)** | RST | RSTs everything | Low |
| NULL | `-sN` | **RST (not silence)** | RST | RSTs everything | Low |

---

### SYN Scan — What I Saw

**Filter:** `tcp.flags.syn == 1 && tcp.flags.ack == 0`

This was the clearest reconnaissance signature I observed — hundreds of SYN packets hitting sequential port numbers from my Kali IP in under 3 seconds. The IO Graph showed a completely flat baseline then a sudden spike — exactly the pattern a SIEM would alert on.

For every **open port** I could see exactly 3 packets:
```
Kali    → Windows:  [SYN]          seq=0
Windows → Kali:     [SYN-ACK]      seq=0, ack=1   ← port is OPEN
Kali    → Windows:  [RST]                          ← Nmap kills it immediately
```

For every **closed port** I saw only 2 packets:
```
Kali    → Windows:  [SYN]          seq=0
Windows → Kali:     [RST-ACK]                      ← port is CLOSED
```

---

### TCP Connect Scan — What I Saw

**Filter:** `tcp`

The connect scan generated roughly double the packet count of the SYN scan because every open port completed a full 3-way handshake before Nmap sent a FIN to close it. What I found significant here is that every one of those completed connections is recorded in Windows Event Logs under Event ID 5156 — making this the most detectable scan type. If a Windows host has event logging to a SIEM, a connect scan will leave a clear trail.

---

### UDP Scan — What I Saw

**Filter:** `udp` and `icmp.type == 3 && icmp.code == 3`

This scan was noticeably slower than the TCP scans. I noticed that Windows was rate-limiting its ICMP Port Unreachable responses — not every closed UDP port generated an immediate reply, so Nmap had to wait for timeouts on many ports. The ICMP type 3 code 3 replies that did come back clearly marked those ports as closed. Open UDP ports stayed silent — which from Nmap's perspective looks the same as filtered, making UDP scanning inherently ambiguous.

---

### Version & OS Detection — What I Saw

**Filter:** `tcp`

This was the noisiest scan by far. The `-A` flag triggered full connections to every open port plus data exchange as Nmap read service banners. I followed the TCP stream on port 3389 and could see RDP protocol negotiation, and port 445 showed SMB exchange. Nmap correctly identified the target:

```
OS details: Microsoft Windows 10
```

---

### XMAS & NULL Scans — The Windows Difference

**XMAS filter:** `tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1`  
**NULL filter:** `tcp.flags == 0x000`

Both scan types were immediately visible in Wireshark — the illegal flag combinations have no equivalent in normal traffic so they stand out instantly. However, Windows sent RST responses to every single port regardless of whether it was open or closed. This confirmed what I'd read about Windows not following RFC 793 in the same way Linux does.

The practical takeaway I noted: these scans are useless against Windows for port discovery, but a single XMAS or NULL packet in any production capture is still an immediate red flag — no legitimate software ever generates these flag combinations.

---

## 💡 What I Learned

- **SYN scan is not actually stealthy** — the name is misleading. Yes, it avoids completing connections, but hundreds of SYNs hitting sequential ports in under 3 seconds from one IP is completely unmistakable in Wireshark or any SIEM. I think of it as "less loud" rather than actually hidden.

- **The RST after SYN-ACK is Nmap's fingerprint** — I now know that in legitimate traffic, a client that receives a SYN-ACK will always complete the handshake with an ACK. A client that immediately sends RST after receiving SYN-ACK is running a SYN scan. That pattern, repeated across dozens of ports, is definitive.

- **Windows behaves differently and that matters** — I wasn't expecting the XMAS and NULL scan results to be so different from what tutorials show against Linux targets. Understanding that Windows RSTs everything means a SOC analyst interpreting those scans needs to know the target OS to interpret the results correctly.

- **Windows rate-limits ICMP and it affects scan results** — I could see Nmap slowing down during the UDP scan because Windows wasn't replying fast enough. This is worth knowing because it means a UDP scan against a Windows host will always look slower and more spread out than a TCP scan of the same host.

- **Version scan reveals exactly what an attacker needs** — after following the TCP streams from the `-sV` scan, I could see real service banners — RDP version info, SMB negotiation details. This is exactly the intelligence an attacker uses to pick an exploit. Seeing this from the defender's perspective made me understand why banner grabbing is such a high-priority detection target.

- **IO Graph is one of the most useful tools in Wireshark for detecting scans** — the visual spike from a scan is impossible to miss. I'll use this in every future exercise when I need to identify when a burst of activity occurred.

---

## 🔗 SOC Relevance

| Detection Indicator | Attack Technique | What I Would Do |
|---|---|---|
| Hundreds of SYNs from one IP in seconds | Port scan — active recon | Block source IP, raise alert, investigate |
| SYN → SYN-ACK → RST pattern repeated | Nmap SYN stealth scan | Correlate with threat intel on source IP |
| ICMP Port Unreachable flood | UDP scan in progress | Alert, check firewall rules |
| FIN+PSH+URG or zero-flag TCP packets | XMAS / NULL scan | Immediate block — no legitimate use case |
| Single host touching 100+ ports rapidly | Automated scan tool | Block and investigate host |
| Banner grab traffic following port scan | Pre-exploitation recon | Flag host as active target, increase monitoring |
| OS fingerprint probe patterns | Nmap -O flag | Correlate with other scan indicators |

---

## 🛠️ Tools I Used

- **Wireshark** — packet capture and analysis
- **Nmap** — network scanner (built into Kali Linux)
- **Kali Linux** — my attacker and analyst workstation
- **Windows 10** — scan target VM

---

*Project 04 of 10 · [Back to Main Portfolio](../README.md)*
