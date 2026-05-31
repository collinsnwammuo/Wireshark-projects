# 08 - Rogue DHCP Server Detection

**Difficulty:** Intermediate  
**Protocols:** DHCP, UDP, DNS  
**Tools:** Wireshark · dnsmasq  
**Lab Environment:** Kali Linux (attacker/analyst) · Windows 10 (victim) · VirtualBox NAT + Host-Only

---

## 🎯 What I Did

I ran a rogue DHCP server from Kali Linux using dnsmasq, forced my Windows 10 VM to request a new IP lease, and captured the moment Windows accepted my fake network configuration -- pointing its gateway and DNS to Kali instead of the real network infrastructure. I then analysed the capture in Wireshark to identify every indicator that reveals a rogue DHCP server is operating on a network.

What makes this attack interesting from a SOC perspective is that it requires no exploitation, no credentials, and no special privileges on the victim machine. DHCP has no authentication -- any device that responds faster than the legitimate server wins.

---

## ⚠️ Disclaimer

This attack was performed entirely within my isolated VirtualBox lab environment. No real networks or production systems were involved.

---

## 🧠 Background

### How DHCP Works

When a device joins a network it has no IP address yet. It broadcasts a DHCP Discover message asking if any server can give it one. The first server to respond with a DHCP Offer wins -- the client accepts that offer and configures itself based entirely on what the server tells it.

This is the DORA process:

```
Client                    DHCP Server
  |                            |
  |-----[DISCOVER]------------>|   "Anyone there? I need an IP"
  |<----[OFFER]----------------|   "I have 192.168.56.50 for you"
  |-----[REQUEST]------------->|   "I will take that IP please"
  |<----[ACK]------------------|   "Confirmed, lease is 24 hours"
  |                            |
Client now has:
  IP address:   192.168.56.50
  Gateway:      from DHCP option 3
  DNS:          from DHCP option 6
```

DHCP has no authentication mechanism at all. The client cannot verify whether the server it is talking to is legitimate. Whoever responds first wins.

### Why This is Dangerous

By running a rogue DHCP server I can tell any device that joins the network:
- Your gateway is my IP -- so all your internet traffic flows through me
- Your DNS is my IP -- so I control every domain you resolve
- Your IP is whatever I choose to give you

This gives me full MITM capability over any victim that accepts my lease -- without any ARP spoofing or active injection. The victim configures itself to route traffic through me voluntarily.

---

## 🔬 How I Set It Up

### Lab Configuration

```
VirtualBox Host-Only Network 192.168.56.0/24:
  Kali Linux   192.168.56.102   (rogue DHCP server + analyst)
  Windows 10   192.168.56.101   (victim -- forced DHCP renewal)
```

### Rogue DHCP Server Configuration

I installed dnsmasq on Kali and created a custom config file that hands out IPs with Kali set as the gateway and DNS:

```bash
sudo apt install dnsmasq -y
sudo nano /etc/dnsmasq-rogue.conf
```

Config I used:
```
interface=eth0
dhcp-range=192.168.56.200,192.168.56.220,255.255.255.0,12h
dhcp-option=3,192.168.56.102
dhcp-option=6,192.168.56.102
log-dhcp
```

- `dhcp-range` -- the IPs my rogue server hands out
- `dhcp-option=3` -- sets the gateway to Kali (192.168.56.102)
- `dhcp-option=6` -- sets DNS to Kali (192.168.56.102)

### Starting the Attack

```bash
# Start rogue DHCP server
sudo dnsmasq -C /etc/dnsmasq-rogue.conf --no-daemon

# On Windows 10 -- forced DHCP renewal
ipconfig /release
ipconfig /renew
```

### Wireshark Capture Method

- Interface: `eth0`
- Pre-capture filter: `bootp` (DHCP uses BOOTP ports)
- Saved as: `rogue-dhcp.pcap`

### Filters I Used

```wireshark
bootp                          # All DHCP traffic
bootp.option.dhcp == 1         # DHCP Discover -- client broadcasting
bootp.option.dhcp == 2         # DHCP Offer -- server responding
bootp.option.dhcp == 3         # DHCP Request -- client accepting
bootp.option.dhcp == 5         # DHCP ACK -- server confirming lease
```

---

## 📊 What I Found

### Windows 10 Network Config -- Before and After

| Field | Before Attack | After Attack |
|---|---|---|
| IP Address | 192.168.56.101 (legitimate) | 192.168.56.20x (from rogue server) |
| Default Gateway | Real gateway | 192.168.56.102 (Kali) |
| DNS Server | Real DNS | 192.168.56.102 (Kali) |
| DHCP Server | Legitimate server | 192.168.56.102 (Kali) |

Watching `ipconfig /all` on Windows change to show Kali's IP as both the gateway and DNS server confirmed the attack worked. From that point, every DNS query Windows made and every packet it sent to the internet was routed through my machine.

---

### The DORA Sequence in Wireshark

I identified all four DHCP packets in the capture:

**DHCP Discover (bootp.option.dhcp == 1)**

Windows broadcasted to `255.255.255.255` (everyone on the network) asking for an IP. The client MAC address was visible in the Bootstrap Protocol layer:
```
Client MAC address: 80:00:27:B7:73:10  <- Windows 10 VM
```

**DHCP Offer (bootp.option.dhcp == 2)**

My rogue dnsmasq server responded before any legitimate server. Expanding this packet in the detail pane revealed the malicious configuration being offered:
```
Bootstrap Protocol (Offer)
  Your (client) IP: 192.168.56.20x
  Options:
    Option 53: DHCP Offer
    Option 3:  Router -- 192.168.56.102   <- ROGUE GATEWAY (Kali)
    Option 6:  DNS    -- 192.168.56.102   <- ROGUE DNS (Kali)
    Option 54: DHCP Server ID -- 192.168.56.102  <- Identifies rogue server
```

Option 3 and Option 6 both pointing to Kali's IP are the definitive indicators of a rogue DHCP server.

**DHCP Request (bootp.option.dhcp == 3)**

Windows broadcast its acceptance of the offer -- at this point it had not yet applied the config but was committing to it.

**DHCP ACK (bootp.option.dhcp == 5)**

My rogue server confirmed the lease. As soon as Windows received this packet it applied the rogue configuration and all its traffic began routing through Kali.

---

### The Rogue Server Identifier -- Option 54

The single most useful indicator in the capture is **DHCP Option 54 (Server Identifier)** in the Offer and ACK packets. This field contains the IP of the DHCP server that issued the lease. In a legitimate network this should always be your known DHCP server IP. Seeing an unexpected IP in this field is the definitive rogue server detection indicator.

In my capture, Option 54 showed `192.168.56.102` -- an IP that should never be acting as a DHCP server on this network.

---

## 💡 What I Learned

- **DHCP has no authentication and that is a serious problem.** There is nothing in the protocol that lets a client verify whether the server responding to it is legitimate. It is entirely first-come-first-served. Any device on the local segment that runs a DHCP server will compete with the real one, and if it responds faster it wins.

- **This attack requires zero interaction from the victim.** Unlike phishing which requires the user to click something, or ARP spoofing which requires continuous packet flooding, a rogue DHCP attack only needs to respond to a DHCP Discover before the real server does. Once the lease is issued the configuration persists until it expires -- even if the attacker stops the rogue server.

- **Option 54 is the most reliable detection indicator.** In a real investigation I would look for DHCP Offer and ACK packets where Option 54 contains an IP that is not the known legitimate DHCP server. This single field immediately identifies rogue DHCP activity.

- **DHCP logs on the legitimate server tell you what got poisoned.** In a production environment the legitimate DHCP server logs every lease it issues. If a device appears in network logs with an IP that was never issued by the legitimate server, that device got its config from somewhere else -- a rogue DHCP server being the most likely explanation.

- **The attack is most dangerous at the moment a device first joins a network.** Existing devices have valid leases and will not renew immediately. But any new device that connects -- a laptop joining a meeting room WiFi, a phone connecting to the corporate network -- will broadcast DHCP Discover and is immediately at risk. This is why hotel networks, coffee shop WiFi, and open corporate networks are particularly dangerous environments.

- **dnsmasq is a powerful tool that exists on many real systems.** It is commonly installed on Linux routers, Raspberry Pi setups, and development environments for legitimate purposes. Seeing dnsmasq running on a host that should not be acting as a DHCP server is a detection indicator in itself.

---

## 🔗 SOC Relevance

### Detection Methods

| Detection Method | Tool | What It Catches |
|---|---|---|
| DHCP server monitoring | SIEM / DHCP logs | Unexpected DHCP server IP in Option 54 |
| DHCP snooping | Managed switch | Blocks DHCP offers from unauthorised ports |
| Network baseline monitoring | NDR / SIEM | New DHCP server IP appearing on network |
| Endpoint config monitoring | MDM / endpoint agent | Gateway or DNS change on managed device |
| Wireshark / packet capture | Manual analysis | Rogue DHCP offer visible in bootp filter |

### Alert Triggers

| Indicator | Severity | What I Would Do |
|---|---|---|
| DHCP Offer from unexpected IP | Critical | Identify source host immediately, isolate |
| Option 54 showing unknown DHCP server | Critical | Active rogue DHCP -- investigate source |
| Endpoint gateway changed to internal IP | High | Check if DHCP poisoning is the cause |
| New device received IP not in legitimate DHCP range | High | Cross-reference with DHCP server logs |
| Multiple devices with rogue gateway config | Critical | Network-wide incident, isolate segment |

### MITRE ATT&CK Mapping

| Technique | ID | How It Appeared |
|---|---|---|
| Network Sniffing | T1040 | Traffic intercepted after rogue DHCP success |
| Adversary-in-the-Middle | T1557 | All victim traffic routed through Kali |
| DHCP Spoofing | T1557.003 | Core attack technique |

---

## 🛠️ Tools I Used

- **Wireshark** -- packet capture and analysis
- **dnsmasq** -- rogue DHCP server
- **Kali Linux** -- my attacker and analyst workstation
- **Windows 10** -- victim VM

---

*Project 08 of 10 · [Back to Main Portfolio](../README.md)*
