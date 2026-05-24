# 05 - ARP Spoofing / MITM Detection

**Difficulty:** Intermediate  
**Protocols:** ARP, HTTP  
**Tools:** Wireshark · arpspoof (dsniff)  
**Lab Environment:** Kali Linux (attacker/analyst) · Windows 10 (victim) · VirtualBox NAT + Host-Only Dual Adapter

---

## 🎯 What I Did

I executed a full ARP spoofing / Man-in-the-Middle (MITM) attack from my Kali VM against my Windows 10 VM, captured every stage of it in Wireshark, and then analysed the capture to identify all the indicators of compromise. This was the most technically involved project so far because I had to troubleshoot the network setup before the attack would work properly. I ended up using a dual-adapter configuration (Host-Only + NAT) to get a real gateway to spoof through, which made the lab more realistic than a simple Host-Only setup.

---

## ⚠️ Disclaimer

All activity was performed in a fully isolated VirtualBox lab environment. No real networks, users, or production systems were involved. ARP spoofing on networks you do not own or have explicit permission to test is illegal.

---

## 🧠 Background

### What is ARP?

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a local network. When a device wants to communicate with an IP address it does not have a MAC for, it broadcasts an ARP request asking who owns that IP. The owner replies with its MAC address, and the requesting device stores that mapping in its ARP cache for future use.

The critical weakness is that ARP has no authentication at all. Any device can send an ARP reply to any other device at any time, claiming any IP address, and the receiver will update its cache and believe it unconditionally. This is what makes ARP spoofing possible.

### How the Attack Works

```
BEFORE ATTACK -- Normal Traffic Flow:
Windows 10 (victim)                                  Gateway
192.168.56.101                                      10.0.3.2
MAC: 80:00:27:B7:73:10  ---------------------> MAC: aa:bb:cc:dd:ee:ff

Windows ARP cache:  10.0.3.2 -> aa:bb:cc:dd:ee:ff  (correct)


DURING ATTACK -- After ARP Poisoning:
Kali tells Windows:  "10.0.3.2 is at 08:00:27:8a:35:d2"  <- LIE
Kali tells Gateway:  "192.168.56.101 is at 08:00:27:8a:35:d2"  <- LIE

Windows --> Kali (intercepts and reads everything) --> Gateway

Windows ARP cache:  10.0.3.2 -> 08:00:27:8a:35:d2  (Kali's MAC, not gateway)
```

### What an Attacker Can Do Once in the Middle

Once traffic flows through my machine I can:
- Read HTTP credentials, FTP passwords, and session cookies in plaintext
- Hijack authenticated sessions using captured cookies without needing the password
- Redirect DNS responses to send the victim to attacker-controlled sites
- Read any unencrypted communication in real time
- Inject content into unencrypted web pages

---

## 🔬 How I Set It Up

### Lab Configuration

```
Host-Only Network 192.168.56.0/24:
  Kali Linux   eth0: 192.168.56.102   MAC: 08:00:27:8a:35:d2
  Windows 10        192.168.56.101    MAC: 80:00:27:B7:73:10

NAT Network 10.0.3.0/24:
  Kali Linux   eth1: 10.0.3.15
  Gateway           10.0.3.2
```

I ran into an issue initially where arpspoof could not reach the gateway because the gateway (`10.0.3.2`) lives on the NAT interface (`eth1`) while Windows lives on the Host-Only interface (`eth0`). I solved this by running Terminal 1 on `eth0` to poison Windows and Terminal 2 on `eth1` to poison the gateway. Terminal 1 is the critical one that produces all the detectable evidence in Wireshark.

### Commands I Ran

```bash
# Enable IP forwarding first -- without this Windows loses internet and notices
sudo sysctl -w net.ipv4.ip_forward=1

# Install arpspoof
sudo apt install dsniff -y

# Terminal 1 -- poison Windows ARP cache (primary attack)
sudo arpspoof -i eth0 -t 192.168.56.101 10.0.3.2

# Terminal 2 -- poison gateway ARP cache
sudo arpspoof -i eth1 -t 10.0.3.2 192.168.56.101
```

### Captures I Took

| File | Interface | Filter | Purpose |
|---|---|---|---|
| `arp-spoofing.pcap` | eth0 | `arp` | Capture the ARP poisoning flood |
| `arp-mitm-traffic.pcap` | eth0 | none | Capture intercepted victim traffic |

### Wireshark Filters I Used

```wireshark
arp                                     # All ARP traffic
arp.opcode == 1                         # ARP requests only
arp.opcode == 2                         # ARP replies including all spoofed packets
http                                    # Intercepted HTTP traffic from Windows
ip.src == 192.168.56.101               # Traffic originating from Windows victim
```

---

## 📊 What I Found

### ARP Cache State on Windows 10

| Timepoint | Entry for 10.0.3.2 in Windows ARP cache | Status |
|---|---|---|
| Before attack | `10.0.3.2 -> aa:bb:cc:dd:ee:ff` (real gateway MAC) | Legitimate |
| During attack | `10.0.3.2 -> 08:00:27:8a:35:d2` (Kali's MAC) | Poisoned |
| After attack stopped | `10.0.3.2 -> aa:bb:cc:dd:ee:ff` (real gateway MAC) | Restored |

Watching the MAC address change on Windows in real time while arpspoof was running was the clearest confirmation the attack was working. I ran `arp -a` on Windows before starting, then again mid-attack, and the gateway entry had changed to Kali's MAC.

---

### IOC 1 -- Unsolicited ARP Replies (Gratuitous ARP)

**Filter:** `arp.opcode == 2`

Normal ARP always follows a request then reply pattern. During my attack, Kali was sending continuous ARP replies that nobody asked for. These are called Gratuitous ARPs and are the core mechanism of the attack. When I expanded one in the middle pane I could see the lie clearly:

```
Address Resolution Protocol (reply)
  Opcode:      reply (2)
  Sender MAC:  08:00:27:8a:35:d2  <- Kali's real MAC
  Sender IP:   10.0.3.2           <- Gateway IP (the lie)
  Target MAC:  80:00:27:B7:73:10  <- Windows victim
  Target IP:   192.168.56.101
```

The mismatch between Sender IP (the gateway) and Sender MAC (Kali) is the attack signature.

---

### IOC 2 -- Duplicate IP Warning (Caught Automatically by Wireshark)

I did not need to manually spot this one. The moment Kali's MAC started claiming the gateway IP `10.0.3.2`, Wireshark highlighted those packets automatically and logged the following in Expert Information:

```
Warning: Duplicate IP address detected for 10.0.3.2
```

I found this in Analyse -> Expert Information -> Warnings. The fact that Wireshark caught this with no manual work from me shows why this detection logic is built into production IDS tools.

---

### IOC 3 -- ARP Flood With No Preceding Requests

When I applied the `arp` filter and looked at the traffic pattern, the attack was obvious immediately. Normal ARP is sparse and always paired (request then reply). What I saw during the attack was a continuous stream of opcode 2 (reply) packets with no opcode 1 (request) packets preceding them, coming from Kali's MAC at multiple packets per second. The IO Graph showed a completely flat baseline, then a sustained spike for the entire attack duration, then flat again when I stopped arpspoof.

---

### IOC 4 -- One MAC Claiming Multiple IPs

Looking across the ARP replies in the capture, Kali's MAC (`08:00:27:8a:35:d2`) appeared as the sender in replies claiming to be both the gateway IP and other addresses. A single MAC claiming multiple IPs is not something that happens in legitimate traffic and would immediately flag in any ARP monitoring tool.

---

### IOC 5 -- Victim Traffic Visible on Attacker Interface

**Filter in `arp-mitm-traffic.pcap`:** `http`

With IP forwarding enabled, Windows' traffic routed through Kali before reaching the gateway. When I applied the `http` filter I could see HTTP packets with Windows' IP (`192.168.56.101`) as the source appearing on my Kali interface. That traffic should never be visible on Kali without active interception. I followed the TCP stream on one of those packets and could read Windows' full HTTP request in plaintext.

---

## 💡 What I Learned

- **IP forwarding is the difference between a MITM and a DoS.** The first time I ran arpspoof without enabling IP forwarding, Windows immediately lost internet access because Kali was dropping the intercepted packets instead of forwarding them. The victim noticed instantly. Enabling `net.ipv4.ip_forward=1` first is what makes the attack invisible.

- **The before and after ARP table screenshots are the strongest evidence.** Seeing the gateway MAC change from the real value to Kali's MAC in `arp -a` is direct, unambiguous proof the poisoning worked. This is exactly the kind of artefact a forensics analyst would collect during an incident investigation.

- **Wireshark's Expert Information caught this automatically.** I expected to have to hunt for the duplicate IP indicator manually. Wireshark flagged it without any input from me the moment the attack started. Understanding that this same logic runs in Suricata and enterprise NDR platforms helped me understand how these attacks get caught in production environments.

- **ARP cache is self-correcting but slow.** When I stopped arpspoof, Windows did not immediately restore the correct MAC. It took a minute or two before the real gateway MAC reappeared in `arp -a`. During that window an attacker could still intercept traffic even after stopping the tool. This is worth knowing for incident response timing.

- **The dual adapter setup was necessary and worth the extra effort.** A simple Host-Only network has no real gateway so there is nothing to spoof through. Adding a NAT adapter gave me a real gateway at `10.0.3.2` and made the lab much more realistic. The troubleshooting I had to do to get `arpspoof` working across two interfaces taught me more than if it had just worked immediately.

- **HTTPS protects content but not metadata.** When I visited an HTTPS site on Windows during the attack, I could see in Wireshark that traffic was flowing through Kali, but the payload was unreadable encrypted data. I could still see the destination IP, timing, and data volume. Against HTTP sites everything was fully readable. The lesson is that HTTPS is essential but it does not make a MITM attack invisible.

---

## 🔗 SOC Relevance

### Detection Methods

| Method | Tool | What It Catches |
|---|---|---|
| Gratuitous ARP monitoring | Wireshark / Suricata | Unsolicited ARP replies from unexpected MACs |
| Duplicate IP detection | Wireshark Expert Info | Two MACs claiming the same IP |
| Dynamic ARP Inspection (DAI) | Managed switch | Blocks unauthorised ARP replies at layer 2 |
| ARP cache monitoring | Endpoint agent / SIEM | Alerts when gateway MAC changes |
| Static ARP entries | OS / router config | Hardcoded gateway MAC, immune to poisoning |
| ARP volume baseline | SIEM / NDR | Spike in ARP traffic from one internal host |

### Alert Priorities

| Indicator | Severity | What I Would Do |
|---|---|---|
| Gratuitous ARP flood from internal host | High | Isolate the source host, investigate |
| Duplicate IP warning for gateway | Critical | Active MITM likely, investigate immediately |
| Gateway MAC changed in endpoint ARP table | Critical | Block source, notify users, flush ARP caches |
| Victim HTTP traffic on unexpected interface | Critical | Data interception confirmed, escalate to IR |
| Single MAC claiming multiple IPs | High | Investigate the device at that MAC address |

---

## 🛠️ Tools I Used

- **Wireshark** -- packet capture and analysis
- **arpspoof** (dsniff package) -- ARP poisoning tool
- **Kali Linux** -- my attacker and analyst workstation (eth0: 192.168.56.102, eth1: 10.0.3.15)
- **Windows 10** -- victim VM (192.168.56.101)
- **VirtualBox** -- NAT + Host-Only dual adapter network

---

*Project 05 of 10 · [Back to Main Portfolio](../README.md)*
