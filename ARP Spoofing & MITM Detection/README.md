# 05 - ARP Spoofing / MITM Detection

**Difficulty:** Intermediate  
**Protocols:** ARP, HTTP  
**Tools:** Wireshark · arpspoof (dsniff)  
**Lab Environment:** Kali Linux (attacker/analyst) · Windows 10 (victim) · VirtualBox Host-Only Network

---

## 🎯 Objective

Execute a full ARP spoofing / Man-in-the-Middle (MITM) attack from Kali Linux against a Windows 10 victim VM, capture the attack traffic in Wireshark, and identify every indicator of compromise — from the initial ARP poisoning to live traffic interception. This project demonstrates both the offensive technique and the defensive detection methods a SOC analyst uses to identify it.

---

## ⚠️ Disclaimer

This attack was performed in a fully isolated VirtualBox Host-Only lab environment. No real networks, users, or systems were involved. ARP spoofing on networks you do not own is illegal.

---

## 🧠 Background

### What is ARP?

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a local network. When a device wants to communicate with an IP address, it broadcasts:
*"Who has IP 192.168.56.1? Tell me your MAC address."*
The device at that IP replies with its MAC, and the requesting device stores this mapping in its **ARP cache**.

ARP has no authentication — any device can reply to any ARP request, or send unrequested replies. This is the fundamental weakness exploited in ARP spoofing.

### The Attack

```
BEFORE ATTACK — Normal Traffic:
─────────────────────────────────────────────────────
Windows 10 (victim)                      Gateway
192.168.56.102                        192.168.56.1
MAC: 11:22:33:44:55:66    ─────────►  MAC: 77:88:99:aa:bb:cc
[ARP cache: .1 = 77:88:99:aa:bb:cc]


DURING ATTACK — ARP Poisoning:
─────────────────────────────────────────────────────
Kali sends to Windows:  "192.168.56.1 is at MY MAC (aa:bb:cc:dd:ee:ff)"
Kali sends to Gateway:  "192.168.56.102 is at MY MAC (aa:bb:cc:dd:ee:ff)"

                        Kali Linux (attacker)
Windows 10  ─────────►  192.168.56.101          ─────────►  Gateway
(poisoned)              READS/MODIFIES TRAFFIC               (also poisoned)
[ARP cache: .1 = aa:bb:cc:dd:ee:ff ← WRONG MAC]

Result: Every packet Windows sends to the internet passes through Kali first.
```

### Why This is Dangerous

Once traffic flows through the attacker's machine:
- **Credential theft** — cleartext HTTP logins, FTP passwords, emails
- **Session hijacking** — steal authenticated session cookies
- **SSL stripping** — downgrade HTTPS to HTTP (with additional tools)
- **DNS spoofing** — redirect victim to fake websites
- **Traffic modification** — alter web pages, inject malware

---

## 🔬 Methodology

### Lab Setup

```
VirtualBox Host-Only Network: 192.168.56.0/24
├── Kali Linux    192.168.56.101   MAC: aa:bb:cc:dd:ee:ff  (attacker/analyst)
├── Windows 10    192.168.56.102   MAC: 11:22:33:44:55:66  (victim)
└── Gateway       192.168.56.1    MAC: 77:88:99:aa:bb:cc  (VirtualBox host)
```

> Update all IPs and MACs with your actual lab values.

### Tools Used for Attack

```bash
sudo apt install dsniff -y          # installs arpspoof

# Enable IP forwarding (makes MITM invisible to victim)
sudo sysctl -w net.ipv4.ip_forward=1

# Terminal 1 — poison Windows' ARP cache
sudo arpspoof -i eth0 -t 192.168.56.102 192.168.56.1

# Terminal 2 — poison Gateway's ARP cache
sudo arpspoof -i eth0 -t 192.168.56.1 192.168.56.102
```

### Capture Method

Two separate captures were taken:
1. **`arp-spoofing.pcap`** — ARP filter only, captures the poisoning phase
2. **`arp-mitm-traffic.pcap`** — No filter, captures full MITM traffic interception

### Key Wireshark Filters Used

```wireshark
arp                                              # All ARP traffic
arp.opcode == 1                                  # ARP requests only
arp.opcode == 2                                  # ARP replies only (includes spoofed)
http                                             # Intercepted HTTP traffic from victim
```

---

## 📊 Findings

### ARP Cache — Before, During, and After Attack

| Timepoint | Gateway entry in Windows ARP cache | Status |
|---|---|---|
| Before attack | `192.168.56.1` → `77:88:99:aa:bb:cc` | ✅ Legitimate |
| During attack | `192.168.56.1` → `aa:bb:cc:dd:ee:ff` | ❌ Poisoned (Kali's MAC) |
| After attack | `192.168.56.1` → `77:88:99:aa:bb:cc` | ✅ Restored (auto-refresh) |

> Update MAC addresses with your actual values from `arp -a`.

---

### Indicators of Compromise Identified in Wireshark

#### IOC 1 — Unsolicited ARP Replies (Gratuitous ARP)

Normal ARP follows a request/reply pattern — a device asks, another answers. During the attack, Kali sent continuous ARP replies **that nobody requested**. These are called **Gratuitous ARPs** and are the core attack packet.

**Filter:** `arp.opcode == 2`

Each spoofed packet contained a deliberate lie:
```
ARP Reply:
  Sender MAC:  aa:bb:cc:dd:ee:ff  ← Kali's real MAC
  Sender IP:   192.168.56.1       ← Gateway's IP (the lie)
  Target MAC:  11:22:33:44:55:66  ← Windows victim
  Target IP:   192.168.56.102
```

The mismatch between Sender IP (gateway) and Sender MAC (Kali) is the attack signature.

---

#### IOC 2 — Duplicate IP Address Warning

Wireshark automatically detected the attack. Packets were highlighted with a warning and the Expert Information panel showed:

```
Warning: Duplicate IP address detected for 192.168.56.1
         (first seen at [legitimate MAC], now at [Kali MAC])
```

This automatic detection appears in **Analyse → Expert Information → Warnings**.

---

#### IOC 3 — Single MAC Claiming Multiple IPs

In the ARP reply flood, Kali's MAC address (`aa:bb:cc:dd:ee:ff`) appeared as the sender in replies claiming to be both the gateway IP and other addresses. One MAC address should never legitimately claim multiple IPs simultaneously.

---

#### IOC 4 — ARP Reply Rate Anomaly

Normal ARP traffic is sparse — a few packets per minute at most.
During the attack: constant stream of ARP replies from one MAC, multiple per second.

IO Graph showed a flat ARP baseline → sudden sustained spike → flat again when attack stopped.

---

#### IOC 5 — Intercepted HTTP Traffic

With IP forwarding enabled, Windows' HTTP traffic routed through Kali and was fully visible in Wireshark. The victim's source IP appeared in HTTP packets destined for external sites — traffic that should not have been visible on Kali's interface at all without an active MITM.

---

## 💡 Key Observations

- **ARP has no authentication by design** — the protocol was built in an era where network security was not a concern. There is no mechanism to verify that an ARP reply is legitimate. This has never been fixed at the protocol level.

- **Wireshark detects this automatically** — the duplicate IP warning in Expert Information fires without any manual analysis needed. In a real SOC environment, this same detection logic is built into IDS tools like Suricata and Snort.

- **IP forwarding is what makes the attack invisible** — without `net.ipv4.ip_forward=1`, Kali would intercept and DROP all Windows traffic, breaking the victim's connection and immediately alerting the user. With forwarding enabled, the victim experiences no interruption while being completely compromised.

- **ARP cache is temporary** — Windows automatically refreshes its ARP cache every few minutes. This means the attacker must continuously send spoofed ARP replies to maintain the poisoning, which is exactly why the attack generates a sustained flood rather than a single packet.

- **HTTPS severely limits the damage** — while ARP spoofing redirects traffic through the attacker, HTTPS encryption means the attacker can read metadata (destination, timing, volume) but not the content. HTTP traffic is fully readable. This reinforces why HTTPS everywhere matters.

- **The before/after ARP table comparison is forensic proof** — if you captured a Windows ARP table showing an unexpected MAC for a known IP, that is direct evidence of an ARP poisoning attack.

---

## 🔗 SOC Relevance

| Detection Method | Tool | What to Look For |
|---|---|---|
| ARP monitoring | Wireshark / IDS | Gratuitous ARPs, duplicate IP warnings |
| Dynamic ARP Inspection (DAI) | Managed switch | Block unauthorised ARP replies at switch level |
| ARP cache monitoring | Endpoint agent | Gateway MAC changed unexpectedly |
| Network behaviour analysis | SIEM | Sudden ARP flood from internal host |
| Static ARP entries | OS / router | Hardcode gateway MAC — immune to poisoning |
| 802.1X port authentication | Network | Authenticate devices before they can send ARP |

| Attack Indicator | Severity | SOC Response |
|---|---|---|
| Gratuitous ARP flood from internal IP | High | Isolate source host, investigate |
| Duplicate IP warning for gateway | Critical | Immediate investigation — active MITM possible |
| Gateway MAC changed in ARP table | Critical | Block source, notify users, reset ARP caches |
| Internal HTTP credential traffic on unexpected host | Critical | Incident response — credentials likely compromised |

---

## 🛠️ Tools Used

- **Wireshark** — packet capture and analysis
- **arpspoof** (dsniff package) — ARP poisoning tool
- **Kali Linux** — attacker and analyst workstation
- **Windows 10** — victim VM

---

*Project 05 of 10 · [Back to Main Portfolio](../README.md)*
