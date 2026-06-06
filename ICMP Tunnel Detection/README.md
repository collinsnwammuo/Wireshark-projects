# 09 - ICMP Tunnel Detection

**Difficulty:** Advanced  
**Protocols:** ICMP, TCP, SSH  
**Tools:** Wireshark · ptunnel-ng  
**Lab Environment:** Kali Linux (attacker/analyst) · Windows 10 (target) · VirtualBox NAT + Host-Only

---

## 🎯 What I Did

I created a covert ICMP tunnel between my Kali Linux VM and Windows 10 VM using ptunnel-ng, tunnelled a live SSH session through it so that real TCP traffic was hidden inside ICMP ping packets, and then captured the whole thing in Wireshark. The analysis focused on identifying the specific indicators that separate malicious ICMP tunnelling from normal legitimate ping traffic -- because from a distance they look identical.

This is one of the more advanced evasion techniques in the portfolio. Attackers use ICMP tunnelling specifically to bypass firewalls that allow ping but block other protocols. Understanding what it looks like in a packet capture is something I did not see covered in most beginner SOC resources, which is exactly why I wanted to include it.

---

## ⚠️ Disclaimer

All activity was performed in my isolated VirtualBox lab environment. No external systems or real networks were involved.

---

## 🧠 Background

### Normal ICMP vs ICMP Tunnel

ICMP (Internet Control Message Protocol) is used for network diagnostics. The most common use is ping -- a simple echo request and echo reply to check if a host is reachable.

```
Normal ping:
Kali --> Windows:  [Echo Request]  Type=8  Payload = 48 bytes of padding
Windows --> Kali:  [Echo Reply]    Type=0  Payload = 48 bytes of padding

ICMP Tunnel:
Kali --> Windows:  [Echo Request]  Type=8  Payload = 1400 bytes of SSH data
Windows --> Kali:  [Echo Reply]    Type=0  Payload = 1400 bytes of response
```

From a firewall's perspective both look like ping. From Wireshark's perspective they are completely different -- but only if you know what to look for.

### Why Attackers Use ICMP Tunnelling

Many network environments block outbound TCP and UDP connections to prevent data exfiltration and C2 communication. But they leave ICMP open because blocking ping breaks network diagnostics and makes operations difficult. Attackers exploit this by hiding TCP sessions, shell access, and file transfers inside ICMP echo packets that sail through the firewall unchallenged.

Common uses in real attacks:
- Full shell access through a firewall that blocks all TCP
- Data exfiltration in environments where HTTPS is blocked but ping is allowed
- C2 communication hidden inside what looks like routine network health checks
- Bypassing network monitoring tools that do not inspect ICMP payload content

### Tools Used for This Attack

**ptunnel-ng** is an open source ICMP tunnelling tool that wraps TCP connections inside ICMP echo packets. It runs a server on the destination and a client on the source, creating a transparent TCP-over-ICMP tunnel.

---

## 🔬 How I Set It Up

### Lab Configuration

```
VirtualBox Host-Only Network 192.168.56.0/24:
  Kali Linux   192.168.56.102   (tunnel client + Wireshark analyst)
  Windows 10   192.168.56.101   (tunnel server + SSH target)
```

### The Tunnel Architecture

```
Kali (local port 1234)
        |
        | TCP connection to localhost:1234
        v
ptunnel-ng client on Kali
        |
        | Wraps TCP data inside ICMP Echo Requests
        | Sends ICMP packets to Windows
        v
ptunnel-ng server on Windows
        |
        | Unwraps ICMP, extracts TCP data
        | Forwards to SSH port 22 on Windows
        v
OpenSSH Server on Windows:22
```

From Wireshark's perspective on the network, only ICMP packets are visible. The SSH session is completely invisible at the network layer.

### Commands I Ran

**On Windows 10 -- start ptunnel-ng server:**
```cmd
ptunnel-ng.exe
```

**On Kali -- start tunnel client:**
```bash
sudo ptunnel-ng -p 192.168.56.101 -l 1234 -r 192.168.56.101 -R 22
```

**On Kali -- connect SSH through the tunnel:**
```bash
ssh henry@127.0.0.1 -p 1234
```

- `-p 192.168.56.101` -- ptunnel-ng server address (Windows)
- `-l 1234` -- local port on Kali to listen on
- `-r 192.168.56.101` -- remote destination host
- `-R 22` -- remote port to reach (SSH)

Connecting to `127.0.0.1:1234` on Kali sent the SSH traffic through ptunnel-ng which wrapped it in ICMP packets and sent it to Windows. The SSH session ran normally -- I could run commands -- but all the traffic appeared as ICMP in Wireshark.

### Wireshark Capture Method

- Interface: `eth0`
- Pre-capture filter: `icmp`
- Saved as: `icmp-tunnel.pcap`
- Also captured normal ping separately: `icmp-normal.pcap`

### Filters I Used

```wireshark
icmp                          # All ICMP traffic
icmp.type == 8                # Echo Requests only (outbound data)
icmp.type == 0                # Echo Replies only (inbound responses)
icmp && data.len > 100        # ICMP with large payloads (tunnel indicator)
```

---

## 📊 What I Found

### Normal Ping vs ICMP Tunnel -- Direct Comparison

| Indicator | Normal Ping | ICMP Tunnel |
|---|---|---|
| Total packets (5 pings) | 10 packets | Hundreds of packets |
| Payload size | 48 bytes | 1000+ bytes per packet |
| Payload content | Repeating ASCII pattern | Binary / encrypted data |
| Sequence numbers | Sequential (1, 2, 3...) | Non-standard pattern |
| Duration | Brief burst then silence | Sustained continuous stream |
| Traffic rate | 1 packet per second | Many packets per second |
| Packet size | ~98 bytes total | 1000+ bytes total |

Every single indicator pointed in the same direction. The tunnel was not subtle.

---

### IOC 1 -- Oversized ICMP Payload

The most obvious indicator was payload size. Expanding an ICMP Echo Request from the tunnel capture in the middle pane:

```
Internet Control Message Protocol
  Type: 8 (Echo Request)
  Code: 0
  Sequence number: [non-standard]
  Data (1412 bytes)    <- ICMP tunnel payload
```

Compare this to normal ping:
```
Internet Control Message Protocol
  Type: 8 (Echo Request)
  Code: 0
  Sequence number: 1
  Data (48 bytes)      <- Normal ping payload
```

A 1412-byte ICMP payload is not a ping. It is data. Statistics -> Packet Lengths confirmed the abnormal size distribution -- all normal ping packets clustered around 98 bytes while tunnel packets clustered above 1000 bytes.

---

### IOC 2 -- Payload Content Not ASCII Pattern

In the hex dump pane of Wireshark, normal ping payload looks like this:

```
Normal ping hex dump (right side):
!"#$%&'()*+,-./0123456789:;<=>?@AB...
```

It is a predictable, repeating sequence of printable ASCII characters. The tunnel payload looked completely different -- binary data with no recognisable pattern, confirming that actual TCP session data (SSH packets) was being carried inside the ICMP frames.

---

### IOC 3 -- Volume and Rate

The IO Graph comparison between the two captures told the story immediately. Normal ping: 10 packets over 5 seconds, then silence. ICMP tunnel: sustained stream of hundreds of packets per second for the entire duration of the SSH session. No legitimate ping activity looks like that.

---

### IOC 4 -- Bidirectional Data in Both Request and Reply

In normal ping, the Echo Request carries a small payload and the Echo Reply echoes it back identically. In the tunnel, both the Echo Request (type 8) and the Echo Reply (type 0) carried large, different payloads -- because data was flowing in both directions through the tunnel simultaneously. Filtering separately for type 8 and type 0 and comparing payload sizes confirmed this.

---

## 💡 What I Learned

- **ICMP tunnelling is genuinely effective as an evasion technique.** Running an SSH session through ICMP and watching Wireshark show only ping traffic was a clear demonstration of why this technique gets used in real attacks. If I were only looking at firewall logs showing ICMP allowed, I would see nothing suspicious. The evidence only appears when you inspect the packet payload.

- **Payload size is the fastest detection indicator.** The moment I filtered for `icmp && data.len > 100` everything legitimate disappeared and only the tunnel traffic remained. Normal ICMP payloads are small and predictable. Anything over a few hundred bytes should immediately raise questions.

- **The hex dump reveals what statistics alone cannot.** Looking at the raw hex of both captures made the difference undeniable. The ASCII repeating pattern in normal ping versus the dense binary data in the tunnel is visually obvious. I will use hex dump inspection in future investigations whenever I suspect covert channels.

- **IO Graph volume comparison is the quickest triage tool.** If I received an alert about unusual ICMP traffic and opened the PCAP, the IO Graph would be the first thing I looked at. A sustained high-volume ICMP stream from a single host is not diagnostics activity -- it is a tunnel or a flood.

- **Firewalls that allow all ICMP are overly permissive.** A more secure configuration would rate-limit ICMP, restrict ICMP to specific trusted hosts, or block ICMP types other than the ones needed for diagnostics (types 0, 3, 8, 11). Allowing unrestricted ICMP leaves the door open to exactly this kind of covert channel.

- **Detection requires payload inspection, not just protocol filtering.** A firewall rule that says "allow ICMP" will never catch this. Detection requires either a deep packet inspection tool that checks ICMP payload size and content against a baseline, or an IDS rule that alerts on ICMP packets above a certain payload threshold.

---

## 🔗 SOC Relevance

### Detection Methods

| Method | Tool | What It Catches |
|---|---|---|
| ICMP payload size monitoring | Suricata / Snort IDS | Packets above normal payload threshold |
| ICMP rate limiting | Firewall / IDS | Sustained high-volume ICMP from one host |
| Deep packet inspection | NGFW / IDS | Binary payload content in ICMP frames |
| Baseline deviation | SIEM / NDR | ICMP volume spike from internal host |
| Protocol anomaly detection | Zeek / Suricata | ICMP type 8 with non-standard payload |

### Suricata Rule to Detect This

```
alert icmp any any -> any any (
  msg:"Possible ICMP Tunnel - Large Payload";
  dsize:>200;
  itype:8;
  sid:9000001;
  rev:1;
)
```

This rule fires on any ICMP Echo Request with a payload over 200 bytes -- well above the normal 48-byte ping payload.

### Alert Triggers

| Indicator | Severity | What I Would Do |
|---|---|---|
| ICMP packets over 200 bytes from internal host | High | Inspect payload, identify source host |
| Sustained ICMP stream from one host | High | Check IO Graph, correlate with other alerts |
| ICMP payload contains binary/non-ASCII data | Critical | Likely data exfiltration, isolate host |
| ICMP traffic during off-hours from workstation | Medium | Investigate -- not normal user behaviour |
| Two-way large ICMP between internal and external | Critical | Active tunnel, block and investigate |

### MITRE ATT&CK Mapping

| Technique | ID | How It Appeared |
|---|---|---|
| Protocol Tunnelling | T1572 | TCP/SSH tunnelled inside ICMP |
| Exfiltration Over Alternative Protocol | T1048 | Data carried in ICMP instead of TCP |
| Non-Application Layer Protocol | T1095 | ICMP used as C2 transport layer |

---

## 🛠️ Tools I Used

- **Wireshark** -- packet capture and analysis
- **ptunnel-ng** -- ICMP tunnelling tool
- **OpenSSH** -- tunnelled protocol (running on Windows 10 from Project 07)
- **Kali Linux** -- my attacker and analyst workstation
- **Windows 10** -- tunnel server and SSH target VM

---

*Project 09 of 10 · [Back to Main Portfolio](../README.md)*
