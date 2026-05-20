# 01 - TCP Handshake & Session Analysis

**Difficulty:** Beginner  
**Protocols:** TCP  
**Tool:** Wireshark  
**Lab Environment:** Kali Linux · VirtualBox

---

## 🎯 Objective

Capture a complete TCP connection lifecycle and identify each phase — SYN, SYN-ACK, ACK (3-way handshake), data transfer, and FIN teardown — by analysing packets in Wireshark. This builds the foundational skill of recognising normal TCP behaviour before hunting for anomalies.

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

Understanding this flow is essential for a SOC analyst as almost every network attack involves manipulating TCP behaviour (SYN floods, RST injection, port scans, etc.).

---

## 🔬 Methodology

### Traffic Generation
Generated a clean HTTP request from Kali Linux to trigger a full TCP session:
```bash
curl http://example.com
```

### Capture Method
- Interface: `eth0`
- Capture filter: none (captured all traffic, filtered in Wireshark post-capture)
- Duration: Single HTTP request + response

### Key Display Filters Used

```wireshark
tcp                                          # Show all TCP traffic
tcp.flags.syn == 1 && tcp.flags.ack == 0     # Isolate SYN packets only
tcp.flags.syn == 1 && tcp.flags.ack == 1     # Isolate SYN-ACK packets
tcp.flags.fin == 1                           # Isolate FIN teardown
tcp.flags.reset == 1                         # Isolate RST resets
tcp.stream eq 0                              # Isolate a single TCP conversation
```

---

## 📊 Findings

### Connection Details

| Field | Value |
|---|---|
| Client IP | `10.0.x.x` (Kali VM) |
| Server IP | `104.20.23.154` (example.com) |
| Destination Port | `80` (HTTP) |
| Client Source Port | `52300`) |
| Protocol | TCP over IPv4 |

### 3-Way Handshake — Packet Breakdown

| Step | Direction | Flags | Seq | Ack |
|---|---|---|---|---|
| SYN | Client → Server | `SYN` | 0 (relative) | — |
| SYN-ACK | Server → Client | `SYN, ACK` | 0 (relative) | 1 |
| ACK | Client → Server | `ACK` | 1 | 1 |

### TCP Options Observed in SYN Packet

- **MSS (Maximum Segment Size):** 1460 bytes
- **Window Scale:** Present (indicates large window support)
- **SACK Permitted:** Yes (Selective Acknowledgement enabled)
- **Timestamps:** Present

### Teardown Method
Clean **FIN-ACK** teardown (not RST) — both sides gracefully closed the connection.

---
<!--
## 📸 Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/01-syn.png` | SYN packet — flags and sequence number visible |
| `screenshots/02-syn-ack.png` | SYN-ACK response from server |
| `screenshots/03-ack.png` | Final ACK completing the handshake |
| `screenshots/04-tcp-stream.png` | Follow TCP Stream — full conversation view |
| `screenshots/05-fin.png` | FIN teardown — clean session close |
| `screenshots/06-full-capture.png` | Full Wireshark capture with TCP filter applied |

---
-->
## 💡 Key Observations

- The **ISN (Initial Sequence Number)** is randomised — a security measure to prevent sequence prediction attacks. Wireshark displays relative sequence numbers (starting at 0) by default for readability.
- A clean teardown uses **FIN** packets. An abrupt termination uses **RST** — RSTs in unexpected contexts are often a sign of scanning, firewall blocking, or connection abuse.
- The **TCP Window Size** grows during the session (TCP slow start / congestion control) — visible if you watch the window field across packets.
- Wireshark's **Expert Info** (`Analyse → Expert Information`) flagged zero issues on this clean capture — useful baseline reference.

---

## 🔗 SOC Relevance

| What I Learned | How It Applies in a SOC |
|---|---|
| SYN without SYN-ACK (no response) | Port is closed or filtered — seen in port scans |
| Flood of SYNs from one IP | SYN flood DoS attack — triggers IDS alerts |
| RST after handshake | Connection forcibly killed — possible firewall or IDS block |
| Many half-open connections | SYN scan (Nmap `-sS`) — stealth reconnaissance |
| Very short sessions (SYN → RST) | Port scan or connection refused |

---
<!--
## 📁 Files in This Folder

```
TCP Handshake/
├── README.md               ← This file
├── tcp-handshake.pcap      ← Full Wireshark capture
└── screenshots/
    ├── 01-syn.png
    ├── 02-syn-ack.png
    ├── 03-ack.png
    ├── 04-tcp-stream.png
    ├── 05-fin.png
    └── 06-full-capture.png
```

---
-->
## 🛠️ Tools Used

- **Wireshark** — packet capture and analysis
- **curl** — HTTP client to generate TCP traffic
- **Kali Linux** — lab environment

---

*Project 01 of 10 · [Back to Main Portfolio](../README.md)*
