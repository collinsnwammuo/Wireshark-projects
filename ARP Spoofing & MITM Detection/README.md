# 05 - ARP Spoofing / MITM Detection

**Difficulty:** Intermediate  
**Protocols:** ARP, HTTP  
**Tools:** Wireshark · arpspoof (dsniff)  
**Lab Environment:** Kali Linux (attacker/analyst) · Windows 10 (victim) · VirtualBox NAT + Host-Only Dual Adapter

---

## 🎯 Objective

Execute a full ARP spoofing / Man-in-the-Middle (MITM) attack from Kali Linux against a Windows 10 victim VM, capture every stage of the attack in Wireshark, and identify all indicators of compromise — from the initial ARP cache poisoning through to live traffic interception. This project demonstrates both the offensive technique and the precise detection signatures a SOC analyst uses to identify ARP-based attacks on a real network.

---

## ⚠️ Disclaimer

All activity was performed in a fully isolated VirtualBox lab environment. No real networks, users, or production systems were involved. ARP spoofing on networks you do not own or have explicit permission to test is illegal.

---

## 🧠 Background

### What is ARP?

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a local network segment. When a device wants to communicate with an IP, it broadcasts an ARP request — *"Who has IP 10.0.3.2? Tell me your MAC."* — and the owner of that IP replies. The requesting device stores this mapping in its **ARP cache** and uses it for all future frames destined for that IP.

**The fundamental weakness: ARP has no authentication.** Any device can send an ARP reply to any other device at any time, claiming any IP address, without verification. The receiver updates its cache and believes the reply unconditionally.

### The Attack

```
BEFORE ATTACK — Normal Traffic Flow:
─────────────────────────────────────────────────────────────────────
Windows 10 (victim)                                  Gateway
192.168.56.101                                      10.0.3.2
MAC: 11:22:33:44:55:66  ────────────────────────►  MAC: aa:bb:cc:dd:ee:ff

Windows ARP cache entry:  10.0.3.2 → aa:bb:cc:dd:ee:ff  ✅ Legitimate


DURING ATTACK — After ARP Poisoning:
─────────────────────────────────────────────────────────────────────
Kali sends to Windows:  "10.0.3.2 is at 08:00:27:8a:35:d2"  ← LIE
Kali sends to Gateway:  "192.168.56.101 is at 08:00:27:8a:35:d2"  ← LIE

             Kali Linux (attacker) 192.168.56.102
Windows  ──────────────► INTERCEPTS & READS ──────────────►  Gateway
(victim)                 ALL TRAFFIC HERE                   (poisoned)

Windows ARP cache entry:  10.0.3.2 → 08:00:27:8a:35:d2  ❌ Poisoned
                                      (Kali's MAC — not the gateway)
```

### Why This is Dangerous

Once the attacker sits between victim and gateway:
- **Credential theft** — HTTP logins, FTP passwords, POP3 email credentials all visible
- **Session hijacking** — authenticated session cookies readable and reusable
- **DNS hijacking** — redirect victim to attacker-controlled sites
- **Traffic inspection** — read any unencrypted communication in real time
- **Traffic modification** — inject content into web pages, redirect downloads to malware

---

## 🔬 Methodology

### Lab Setup

```
┌─────────────────────────────────────────────────────────────────┐
│              VirtualBox Host-Only Network 192.168.56.0/24        │
│                                                                   │
│   Kali Linux                          Windows 10                 │
│   eth0: 192.168.56.102                192.168.56.101             │
│   MAC:  08:00:27:8a:35:d2             MAC: (80:00:27:B7:73:10)          │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│              VirtualBox NAT Network 10.0.3.0/24                  │
│                                                                   │
│   Kali Linux                          Gateway                    │
│   eth1: 10.0.3.15                     10.0.3.2                   │
│                                           │                      │
└───────────────────────────────────────────┼─────────────────────┘
                                            │
                                        Internet
```

### Attack Commands

```bash
# Step 1 — Enable IP forwarding (makes MITM invisible to victim)
sudo sysctl -w net.ipv4.ip_forward=1

# Step 2 — Install arpspoof
sudo apt install dsniff -y

# Terminal 1 — poison Windows ARP cache
# Tells Windows: "gateway 10.0.3.2 is at Kali's MAC"
sudo arpspoof -i eth0 -t 192.168.56.101 10.0.3.2

# Terminal 2 — poison gateway ARP cache
# Tells gateway: "Windows 192.168.56.101 is at Kali's MAC"
sudo arpspoof -i eth1 -t 10.0.3.2 192.168.56.101
```

> Terminal 1 is the primary attack — it poisons Windows' ARP cache and produces all the detectable evidence. Terminal 2 completes the bidirectional MITM. Both run simultaneously.

### Captures Taken

| File | Interface | Filter | Purpose |
|---|---|---|---|
| `arp-spoofing.pcap` | eth0 | `arp` | Capture the ARP poisoning flood |
| `arp-mitm-traffic.pcap` | eth0 | none | Capture intercepted victim traffic |

### Key Wireshark Filters Used

```wireshark
arp                                     # All ARP traffic
arp.opcode == 1                         # ARP requests only
arp.opcode == 2                         # ARP replies — includes all spoofed packets
http                                    # Intercepted HTTP traffic from Windows
ip.src == 192.168.56.101               # Traffic originating from Windows victim
```

---

## 📊 Findings

### ARP Cache State on Windows 10 — Before, During and After

| Timepoint | `10.0.3.2` entry in Windows ARP cache | Status |
|---|---|---|
| Before attack | `10.0.3.2` → `aa:bb:cc:dd:ee:ff` (real gateway MAC) | ✅ Legitimate |
| During attack | `10.0.3.2` → `08:00:27:8a:35:d2` (Kali's MAC) | ❌ Poisoned |
| After attack | `10.0.3.2` → `aa:bb:cc:dd:ee:ff` (real gateway MAC) | ✅ Restored |

> Replace `aa:bb:cc:dd:ee:ff` with the actual gateway MAC from your `arp -n` output.

---

### Indicators of Compromise Identified

#### IOC 1 — Unsolicited ARP Replies (Gratuitous ARP)

**Filter:** `arp.opcode == 2`

Normal ARP follows a strict request → reply pattern. During the attack, Kali sent continuous ARP replies that no device requested — these are called Gratuitous ARPs and are the core attack mechanism. Each packet contained a deliberate falsification:

```
ARP Reply (spoofed) — expanded in Wireshark:
┌──────────────────────────────────────────────────────┐
│ Address Resolution Protocol (reply)                   │
│   Opcode:      reply (2)                              │
│   Sender MAC:  08:00:27:8a:35:d2  ← Kali's real MAC  │
│   Sender IP:   10.0.3.2           ← Gateway IP (LIE) │
│   Target MAC:  11:22:33:44:55:66  ← Windows victim   │
│   Target IP:   192.168.56.101                         │
└──────────────────────────────────────────────────────┘
```

The mismatch between Sender IP (gateway) and Sender MAC (Kali) is the definitive attack signature.

---

#### IOC 2 — Duplicate IP Address Detection (Auto-flagged by Wireshark)

Wireshark detected the attack automatically. When Kali's MAC began claiming the gateway IP `10.0.3.2` — an IP previously associated with a different MAC — Wireshark highlighted the packets and logged:

```
Warning: Duplicate IP address detected for 10.0.3.2
```

Visible without any manual analysis in **Analyse → Expert Information → Warnings**.

---

#### IOC 3 — Unsolicited Reply Flood (No Preceding Requests)

Normal ARP traffic is sparse and always follows request/reply pairs. During the attack:
- Continuous stream of ARP opcode 2 (reply) packets from Kali's MAC
- No corresponding ARP requests preceding them
- Rate: multiple packets per second sustained throughout the attack
- IO Graph showed: flat baseline → sustained spike → flat again after attack stopped

---

#### IOC 4 — One MAC Address Claiming Multiple IPs

Across the capture, Kali's MAC (`08:00:27:8a:35:d2`) appeared as sender in ARP replies claiming to be both `10.0.3.2` (the gateway) and its own legitimate IP. In legitimate traffic, one physical MAC address maps to one IP. Any device claiming multiple IPs via ARP warrants immediate investigation.

---

#### IOC 5 — Victim Traffic on Attacker Interface

**Filter in `arp-mitm-traffic.pcap`:** `http`

With IP forwarding enabled, Windows' outbound traffic routed through Kali before reaching the gateway. HTTP packets with Windows' source IP (`192.168.56.101`) appeared on Kali's `eth0` interface — traffic Kali should never see without actively intercepting it. Following the TCP stream revealed Windows' complete HTTP request in plaintext, fully readable on the attacker's machine.

---

## 💡 Key Observations

- **ARP has no authentication and cannot be patched at the protocol level** — the fix exists at the network infrastructure layer (Dynamic ARP Inspection on managed switches) not in the protocol itself. Every device on every network is vulnerable to this attack without infrastructure-level protection.

- **IP forwarding is what makes the attack invisible** — without `net.ipv4.ip_forward=1`, Kali drops all intercepted packets. Windows loses internet access immediately and the victim is alerted. With forwarding enabled, the victim browses normally while completely compromised.

- **ARP cache is temporary and self-healing** — Windows refreshes ARP entries every few minutes. The attacker must continuously flood fake replies to maintain the poisoning. This sustained flood is precisely what makes the attack detectable — normal ARP traffic is nearly silent.

- **Wireshark caught this with zero manual effort** — the duplicate IP warning in Expert Information fires automatically the moment a second MAC claims an existing IP. In production environments this same detection logic runs in Suricata, Snort, and enterprise NDR platforms.

- **HTTPS limits but does not prevent the attack** — ARP spoofing redirects all traffic regardless of encryption. Against HTTPS the attacker sees destination IPs, timing, and data volumes but not content. Against HTTP everything is fully readable including credentials, session tokens, and page content.

- **The before/after ARP table is forensic proof** — the two screenshots of Windows' ARP cache showing the MAC change and restoration are direct, unambiguous evidence of the attack occurring. This is the kind of artefact a digital forensics analyst would collect during an incident investigation.

---

## 🔗 SOC Relevance

### Detection Methods

| Method | Tool | What It Detects |
|---|---|---|
| Gratuitous ARP monitoring | Wireshark / Suricata | Unsolicited ARP replies from unexpected MACs |
| Duplicate IP detection | Wireshark Expert Info | Two MACs claiming same IP — fires automatically |
| Dynamic ARP Inspection (DAI) | Managed switch | Blocks unauthorised ARP replies at layer 2 |
| ARP cache monitoring | Endpoint agent / SIEM | Alerts when gateway MAC changes unexpectedly |
| Static ARP entries | OS / router | Hardcoded gateway MAC — immune to poisoning |
| ARP traffic baseline | SIEM / NDR | Alerts on ARP volume spike from internal host |

### SOC Alert Triggers

| Indicator | Severity | Response |
|---|---|---|
| Gratuitous ARP flood from internal host | High | Isolate source, investigate device |
| Duplicate IP warning for gateway IP | Critical | Active MITM likely — immediate investigation |
| Gateway MAC changed in endpoint ARP table | Critical | Block source, notify users, reset ARP caches |
| Victim HTTP traffic appearing on unexpected host | Critical | Incident response — data interception confirmed |
| Single MAC claiming multiple IPs | High | Investigate device at that MAC address |

---

## 🛠️ Tools Used

- **Wireshark** — packet capture and analysis
- **arpspoof** (dsniff package) — ARP poisoning tool
- **Kali Linux** — attacker and analyst workstation (eth0: 192.168.56.102, eth1: 10.0.3.15)
- **Windows 10** — victim VM (192.168.56.101)
- **VirtualBox** — NAT + Host-Only dual adapter network

---

*Project 05 of 10 · [Back to Main Portfolio](../README.md)*
