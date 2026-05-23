# 01 - TCP Handshake & Session Analysis

**Difficulty:** Beginner  
**Protocols:** TCP  
**Tool:** Wireshark  
**Lab Environment:** Kali Linux · VirtualBox

---

## 🎯 What I Did

I captured a live TCP connection from my Kali Linux VM and used Wireshark to analyse every phase of the session — the 3-way handshake, data transfer, and FIN teardown. This was my first hands-on packet analysis exercise and it gave me a solid understanding of what normal TCP traffic looks like, which I now use as a baseline when hunting for anomalies.

---

## 🧠 Background

TCP (Transmission Control Protocol) is a connection-oriented protocol. Before any data is exchanged, a **3-way handshake** must complete between client and server:

```
Client          Server
  |---[SYN]------->|   "I want to connect, my starting seq is X"
  |<--[SYN-ACK]----|   "Okay, my starting seq is Y, I acknowledge X+1"
  |---[ACK]------->|   "Got it, I acknowledge Y+1. Connection open."
  |                |
  |<=== DATA =====>|   (actual communication)
  |                |
  |---[FIN]------->|   "I'm done sending"
  |<--[ACK]--------|   "Acknowledged"
  |<--[FIN]--------|   "I'm done too"
  |---[ACK]------->|   "Acknowledged. Connection closed."
```

Understanding this flow is essential for a SOC analyst — almost every network attack involves manipulating TCP behaviour in some way, whether that's SYN floods, RST injection, or port scanning.

---

## 🔬 How I Did It

### Traffic Generation
I generated a clean HTTP request from Kali to trigger a full TCP session:
```bash
curl http://example.com
```
I chose `curl` over a browser because it produces a single, clean TCP stream with no background noise — much easier to analyse as a first exercise.

### Capture Method
- Interface: `eth0`
- Capture filter: none — I captured everything and filtered inside Wireshark afterwards
- Duration: Single HTTP request + response

### Wireshark Filters I Used

```wireshark
tcp                                          # Show all TCP traffic
tcp.flags.syn == 1 && tcp.flags.ack == 0     # Isolate SYN packets only
tcp.flags.syn == 1 && tcp.flags.ack == 1     # Isolate SYN-ACK packets
tcp.flags.fin == 1                           # Isolate FIN teardown
tcp.flags.reset == 1                         # Isolate RST resets
tcp.stream eq 0                              # Isolate a single TCP conversation
```

---

## 📊 What I Found

### Connection Details

| Field | Value |
|---|---|
| Client IP | `10.0.x.x` (Kali VM) |
| Server IP | `104.20.23.154` (example.com) |
| Destination Port | `80` (HTTP) |
| Client Source Port | `52300` |
| Protocol | TCP over IPv4 |

### 3-Way Handshake — Packet Breakdown

I identified each step of the handshake by filtering on TCP flags:

| Step | Direction | Flags | Seq | Ack |
|---|---|---|---|---|
| SYN | Client → Server | `SYN` | 0 (relative) | — |
| SYN-ACK | Server → Client | `SYN, ACK` | 0 (relative) | 1 |
| ACK | Client → Server | `ACK` | 1 | 1 |

### TCP Options I Observed in the SYN Packet

Expanding the TCP layer in the middle pane of Wireshark, I found the following options negotiated during the handshake:

- **MSS (Maximum Segment Size):** 1460 bytes
- **Window Scale:** Present — indicates large window support is enabled
- **SACK Permitted:** Yes — Selective Acknowledgement is enabled
- **Timestamps:** Present

### Teardown Method
The session ended with a clean **FIN-ACK** teardown — both sides gracefully closed the connection. No RST was observed, which is what I'd expect from a normal, well-behaved HTTP session.

---

## 💡 What I Learned

- **The ISN (Initial Sequence Number) is always randomised** — this is a deliberate security measure to prevent sequence prediction attacks. Wireshark displays relative sequence numbers starting at 0 by default, which makes the handshake much easier to read.

- **FIN vs RST tells a story** — a clean FIN teardown means the session ended normally. An unexpected RST mid-session means something forcibly killed the connection — a firewall rule, an IDS blocking traffic, or an attacker injecting a reset.

- **TCP Window Size grows over time** — I could see the window size increasing across packets as TCP's slow start and congestion control algorithms kicked in. This is completely normal behaviour that I now recognise as a baseline.

- **Expert Information is a useful first check** — I ran Analyse → Expert Information on my capture and it flagged zero issues. I'll use a clean capture like this as a reference point when I see Expert Info warnings in future exercises, so I know what's normal and what isn't.

- **A single `curl` generates surprisingly few packets** — the entire HTTP request and response, including the full TCP lifecycle, completed in just a handful of packets. This made it easy to study each one individually.

---

## 🔗 SOC Relevance

| What I Learned | How It Applies in a SOC |
|---|---|
| SYN without SYN-ACK (no response) | Port is closed or filtered — common in port scans |
| Flood of SYNs from one IP | SYN flood DoS attack — triggers IDS alerts |
| RST after handshake | Connection forcibly killed — firewall block or IDS intervention |
| Many half-open connections | SYN scan (Nmap `-sS`) — stealth reconnaissance in progress |
| Very short sessions (SYN → RST) | Port scan or service refusing connection |

---

## 🛠️ Tools I Used

- **Wireshark** — packet capture and analysis
- **curl** — HTTP client to generate clean TCP traffic
- **Kali Linux** — my lab environment

---

*Project 01 of 10 · [Back to Main Portfolio](../README.md)*
