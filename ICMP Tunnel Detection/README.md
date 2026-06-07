# 09 - ICMP Tunnel Detection

**Difficulty:** Advanced  
**Protocols:** ICMP, TCP, SSH  
**Tools:** Wireshark · ptunnel-ng  
**Lab Environment:** Kali Linux only · Loopback interface · VirtualBox

---

## 🎯 What I Did

I set up a complete ICMP tunnel on a single Kali Linux VM -- running both the tunnel server and client on loopback -- and tunnelled a live SSH session through it so that real TCP traffic was hidden inside ICMP ping packets. I captured the entire thing in Wireshark on the loopback interface and then analysed the capture against a normal ping baseline to identify every indicator that distinguishes malicious ICMP tunnelling from legitimate traffic.

I deliberately chose the single-VM loopback approach because it isolates the ICMP tunnel behaviour cleanly without any additional network noise from a second machine. The detection indicators are identical to a real network scenario and the capture is easier to read and analyse.

---

## ⚠️ Disclaimer

All activity was performed entirely within my Kali Linux VM using the loopback interface. No external systems or real networks were involved.

---

## 🧠 Background

### Normal ICMP vs ICMP Tunnel

ICMP (Internet Control Message Protocol) is used for network diagnostics. The most familiar use is ping -- a simple echo request and echo reply to check if a host is reachable.

```
Normal ping on loopback:
Kali --> Kali:  [Echo Request]  Type=8  Data = 48 bytes (ASCII padding)
Kali --> Kali:  [Echo Reply]    Type=0  Data = 48 bytes (same payload echoed)

ICMP Tunnel:
Kali --> Kali:  [Echo Request]  Type=8  Data = 1000+ bytes (SSH session data)
Kali --> Kali:  [Echo Reply]    Type=0  Data = 1000+ bytes (SSH response data)
```

From a firewall perspective both look like ping. From Wireshark they are completely different -- but only if you know exactly what to look for.

### Why Attackers Use This

Many organisations block outbound TCP and UDP connections to prevent data exfiltration and C2 communication but leave ICMP open because blocking ping breaks network diagnostics and is operationally inconvenient. Attackers exploit this gap by hiding TCP connections, remote shell access, and file transfers inside ICMP echo packets that pass through firewalls unchallenged.

Real-world uses include:
- Remote shell access through a firewall that blocks all TCP outbound
- Data exfiltration in environments where HTTPS is monitored but ICMP is ignored
- C2 beaconing disguised as routine network health checks
- Bypassing network monitoring tools that do not inspect ICMP payload content

### How ptunnel-ng Works

```
SSH client connects to localhost:2222
          |
          v
ptunnel-ng CLIENT on Kali
  -- Takes the TCP connection
  -- Wraps the data inside ICMP Echo Request packets
  -- Sends the ICMP packets to the ptunnel-ng server
          |
          | (only ICMP visible on the network)
          v
ptunnel-ng SERVER on Kali (loopback)
  -- Receives ICMP packets
  -- Unwraps the TCP data
  -- Forwards it to SSH port 22
          |
          v
OpenSSH Server on Kali port 22
  -- Receives a normal SSH connection
  -- Has no idea it came through ICMP
```

Wireshark watching the loopback interface sees only ICMP packets. The SSH session is completely invisible at the network layer.

---

## 🔬 How I Set It Up

### Lab Configuration

```
Single Kali Linux VM
  Capture interface: loopback (lo)
  ptunnel-ng server: 127.0.0.1 (listening for ICMP)
  ptunnel-ng client: 127.0.0.1 (wrapping TCP in ICMP)
  SSH server: port 22 (destination for tunnelled traffic)
  Local tunnel port: 2222 (SSH connects here)
```

### Commands I Ran

I used three terminals simultaneously:

**Terminal 1 -- ptunnel-ng server:**
```bash
sudo ptunnel-ng -S
```

**Terminal 2 -- ptunnel-ng client:**
```bash
sudo ptunnel-ng -p 127.0.0.1 -l 2222 -r 127.0.0.1 -R 22
```

**Terminal 3 -- SSH through the tunnel:**
```bash
ssh kali@127.0.0.1 -p 2222
```

Connecting to port `2222` sent the SSH traffic into ptunnel-ng which wrapped it in ICMP and sent it to the server on loopback. The SSH session ran normally -- I ran several commands -- but all the traffic appeared as ICMP ping packets in Wireshark.

### Wireshark Capture Method

- Interface: **Loopback (lo)** -- not eth0
- Pre-capture filter: `icmp`
- Baseline capture: `icmp-normal.pcap` (5 pings to 127.0.0.1 before tunnel)
- Tunnel capture: `icmp-tunnel.pcap` (full SSH session through tunnel)

### Filters I Used

```wireshark
icmp                          # All ICMP traffic
icmp.type == 8                # Echo Requests only -- outbound tunnel data
icmp.type == 0                # Echo Replies only -- inbound tunnel responses
icmp && data.len > 100        # Oversized ICMP -- tunnel detection filter
```

---

## 📊 What I Found

### Normal Ping vs ICMP Tunnel -- Direct Comparison

| Indicator | Normal Ping (5 pings) | ICMP Tunnel (SSH session) |
|---|---|---|
| Total packets | 10 | Hundreds |
| Payload size per packet | 48 bytes | 500 to 1400+ bytes |
| Payload content | Repeating ASCII pattern | Binary / encrypted data |
| Sequence numbers | Sequential 1, 2, 3... | Non-standard |
| Duration | 5 seconds | Length of SSH session |
| Traffic rate | 1 packet per second | Many packets per second |
| `data.len > 100` matches | 0 | All packets |

Every indicator pointed the same way. The tunnel was not subtle once I knew what to look for.

---

### IOC 1 -- Oversized ICMP Payload

The most immediate indicator was payload size. Expanding an Echo Request from the tunnel capture:

```
Internet Control Message Protocol
  Type: 8 (Echo Request)
  Code: 0
  Data (1412 bytes)     <- tunnel payload
```

Versus a normal ping packet:
```
Internet Control Message Protocol
  Type: 8 (Echo Request)
  Code: 0
  Data (48 bytes)       <- normal ping payload
```

A single filter confirmed it:
```wireshark
icmp && data.len > 100
```

Every packet in the tunnel matched. Zero packets from the normal ping matched. That filter alone is sufficient to triage ICMP tunnelling in a live investigation.

---

### IOC 2 -- Binary Payload Content

Looking at the hex dump pane in Wireshark, the difference was immediately visible.

Normal ping hex dump (right side ASCII column):
```
!"#$%&'()*+,-./0123456789:;<=>?   <- predictable repeating characters
```

Tunnel hex dump (right side ASCII column):
```
.R..p\..^J..v...3..}..k...       <- binary data, no recognisable pattern
```

No human-readable content, no repeating pattern. The payload contains the encrypted SSH session data wrapped in ICMP.

---

### IOC 3 -- Sustained High-Volume Traffic

The IO Graph comparison told the clearest visual story. The normal ping produced 10 tiny spikes over 5 seconds then silence. The tunnel produced a continuous stream of packets for the entire duration of my SSH session. No legitimate ping activity looks like a sustained data stream.

---

### IOC 4 -- Large Payloads in Both Directions

In normal ping, the Echo Reply simply echoes back the same 48-byte payload. In the tunnel, both Echo Requests (type 8) and Echo Replies (type 0) carried large different payloads -- because data was flowing bidirectionally through the tunnel simultaneously. Filtering separately for each type and comparing payload sizes confirmed this.

---

## 💡 What I Learned

- **The loopback approach is cleaner for analysis than a two-machine setup.** There is no background network noise, no ARP traffic, no DHCP -- just the ICMP tunnel traffic I generated. This made the indicators much easier to identify and the screenshots easier to annotate clearly.

- **The single most effective detection filter is `icmp && data.len > 100`.** I could triage ICMP tunnelling with that one filter in under 10 seconds. It produces zero false positives against normal ping traffic and catches every tunnel packet. I would add this as a Suricata alert rule on any network I was defending.

- **Hex dump is a detection tool, not just a curiosity.** Before doing this exercise I had not paid much attention to the Wireshark hex pane beyond confirming packet content. Seeing the contrast between the predictable ASCII ping payload and the dense binary tunnel payload made me understand why analysts inspect raw hex during investigations -- it reveals things that protocol field parsing can miss.

- **ICMP tunnelling requires no special privileges on the victim side.** The tunnel server runs as root but the technique itself only requires the ability to send and receive ICMP packets. On most networks any host can do this because ICMP is broadly permitted.

- **Firewalls that allow unrestricted ICMP have a significant blind spot.** A policy that says allow all ICMP will never catch this regardless of how sophisticated the rest of the security stack is. Detection requires either a DPI tool inspecting ICMP payload size and content or a dedicated IDS rule.

- **The IO Graph is the fastest triage tool for this attack.** If I received an alert and opened a PCAP to investigate, the IO Graph would tell me within seconds whether I was looking at ping or a tunnel. A sustained high-volume ICMP stream from a single host is not diagnostics -- it is data exfiltration or a C2 channel.

---

## 🔗 SOC Relevance

### Detection Methods

| Method | Tool | What It Catches |
|---|---|---|
| ICMP payload size threshold | Suricata / Snort | Packets above normal payload size |
| ICMP rate monitoring | Firewall / SIEM | Sustained high-volume ICMP from one host |
| Deep packet inspection | NGFW | Binary content in ICMP payload |
| Volume baseline deviation | NDR / SIEM | ICMP spike from internal workstation |
| Protocol anomaly detection | Zeek | Non-standard ICMP payload patterns |

### Suricata Detection Rule

```
alert icmp any any -> any any (
  msg:"Possible ICMP Tunnel - Oversized Payload";
  dsize:>200;
  itype:8;
  classtype:policy-violation;
  sid:9000001;
  rev:1;
)
```

This rule fires on any ICMP Echo Request with a payload over 200 bytes. Normal ping payloads are 48 bytes on Linux and 32 bytes on Windows. Anything above 200 bytes warrants investigation.

### Alert Triggers

| Indicator | Severity | What I Would Do |
|---|---|---|
| ICMP packets over 200 bytes from internal host | High | Inspect payload, identify source host immediately |
| Sustained ICMP stream from one workstation | High | Check IO Graph, correlate with other alerts |
| Binary non-ASCII content in ICMP payload | Critical | Likely data exfiltration or C2 -- isolate host |
| ICMP traffic during off-hours from workstation | Medium | Investigate -- not normal user behaviour |
| Bidirectional large ICMP between hosts | Critical | Active tunnel -- block and investigate |

### MITRE ATT&CK Mapping

| Technique | ID | How It Appeared |
|---|---|---|
| Protocol Tunnelling | T1572 | TCP/SSH session wrapped inside ICMP |
| Exfiltration Over Alternative Protocol | T1048.003 | Data carried in ICMP instead of TCP |
| Non-Application Layer Protocol | T1095 | ICMP used as C2/exfil transport layer |

---

## 🛠️ Tools I Used

- **Wireshark** -- packet capture and analysis on loopback interface
- **ptunnel-ng** -- ICMP tunnelling tool
- **OpenSSH** -- tunnelled protocol (Kali's built-in SSH server)
- **Kali Linux** -- single VM for both attacker and analyst roles

---

*Project 09 of 10 · [Back to Main Portfolio](../README.md)*
