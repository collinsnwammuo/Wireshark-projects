# 02 - DNS Traffic Investigation

**Protocols:** DNS, UDP, TCP  
**Tool:** Wireshark  
**Lab Environment:** Kali Linux · VirtualBox

---

## 🎯 Objective

Capture and analyse DNS (Domain Name System) traffic to understand how name resolution works at the packet level — including query/response pairs, different record types, TTL values, Transaction IDs, and anomalous responses like NXDOMAIN. DNS is one of the most abused protocols in real-world attacks, making it a critical protocol for any SOC analyst to understand deeply.

---

## 🧠 Background

DNS translates human-readable domain names into IP addresses. Every time a device visits a website, sends an email, or connects to any service, DNS queries happen first — often invisibly.

```
Client                    DNS Resolver              Authoritative NS
  |                            |                          |
  |---[Query: google.com?]---->|                          |
  |                            |---[Query: google.com?]-->|
  |                            |<--[Answer: 142.250.x.x]--|
  |<--[Answer: 142.250.x.x]----|                          |
  |                            |                          |
```

**Why DNS matters to a SOC analyst:**
- Malware uses DNS to find C2 servers (Domain Generation Algorithms)
- DNS tunnelling can exfiltrate data hidden inside DNS queries
- A flood of NXDOMAIN responses can indicate malware trying to reach sinkholed/dead C2 infrastructure
- DNS spoofing/poisoning redirects victims to attacker-controlled servers
- Unusual record types (TXT, NULL) queried in high volumes signal tunnelling

---

## 🔬 Methodology

### Traffic Generation
Generated multiple DNS query types from Kali Linux using `nslookup` and `dig`:

```bash
nslookup google.com                    # A record (IPv4)
nslookup -type=AAAA google.com         # AAAA record (IPv6)
nslookup -type=MX gmail.com            # MX record (mail server)
nslookup -type=NS google.com           # NS record (nameservers)
nslookup 8.8.8.8                       # PTR record (reverse lookup)
nslookup thisisafakedomain12345xyz.com # NXDOMAIN simulation
dig google.com
dig google.com MX
```

### Capture Method
- Interface: `eth0`
- Display filter applied post-capture: `dns`
- File saved as: `dns-investigation.pcap`

### Key Display Filters Used

```wireshark
dns                          # All DNS traffic
dns.flags.response == 0      # Queries only
dns.flags.response == 1      # Responses only
dns.qry.type == 1            # A records (IPv4)
dns.qry.type == 28           # AAAA records (IPv6)
dns.qry.type == 15           # MX records (mail)
dns.qry.type == 2            # NS records (nameservers)
dns.qry.type == 12           # PTR records (reverse DNS)
dns.flags.rcode == 3         # NXDOMAIN responses
tcp.port == 53               # DNS over TCP (large responses)
```

---

## 📊 Findings

### Protocol Behaviour

| Observation | Detail |
|---|---|
| Transport protocol | UDP port 53 (all queries fit within UDP) |
| TCP DNS observed | No — no responses exceeded UDP limit |
| Average query size | ~60–80 bytes |
| Average response size | ~80–150 bytes (varies by record type) |

### DNS Record Types Captured

| Record Type | Query | Answer | TTL |
|---|---|---|---|
| A | google.com | 142.250.x.x | 300s |
| AAAA | google.com | 2a00:1450:xxxx | 300s |
| MX | gmail.com | smtp.google.com (priority 10) | 3600s |
| NS | google.com | ns1.google.com | 21600s |
| PTR | 8.in-addr.arpa | dns.google | 21463s |

> **Note:** Update the above table with actual values from your capture.

### Transaction ID Matching

Every DNS query carries a **Transaction ID** (e.g. `0x3fa2`). The DNS server echoes the same ID back in its response so the client can match answers to questions. Observed in capture: all Transaction IDs matched correctly between query and response — indicating normal, non-spoofed DNS traffic.

### NXDOMAIN Observation

Querying `thisisafakedomain12345xyz.com` returned **RCODE 3 (NXDOMAIN)** — Non-Existent Domain. The response contained no answer section, only the question section and the error code in the flags field.

---

## 📸 Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/01-dns-filter.png` | Full Wireshark capture with `dns` filter applied |
| `screenshots/02-dns-query.png` | Single DNS query packet with details expanded |
| `screenshots/03-dns-response.png` | Matching DNS response with answer section expanded |
| `screenshots/04-record-types.png` | Multiple record types (A, MX, NS) visible in capture |
| `screenshots/05-transaction-id.png` | Query and response showing matching Transaction IDs |
| `screenshots/06-nxdomain.png` | NXDOMAIN response packet — RCODE 3 visible in flags |
| `screenshots/07-dns-statistics.png` | Statistics → DNS summary table |

---

## 💡 Key Observations

- **TTL values vary significantly by record type** — A records have short TTLs (300s) because IPs change more often; NS records have long TTLs (21600s+) because nameservers rarely change. Attackers using fast-flux DNS set very low TTLs (0–60s) to rapidly rotate IPs.

- **DNS uses UDP by default** — quick, stateless, no handshake. This makes it easy to spoof (no connection state to verify). TCP is only used when the response payload exceeds 512 bytes (or 4096 bytes with EDNS).

- **Transaction IDs are only 16 bits** — meaning only 65,536 possible values. DNS cache poisoning attacks (Kaminsky attack) exploit this by flooding forged responses and guessing the Transaction ID.

- **NXDOMAIN flood = SOC red flag** — a single host generating hundreds of NXDOMAIN responses per minute typically indicates malware using a Domain Generation Algorithm (DGA) trying to reach its C2 infrastructure.

---

## 🔗 SOC Relevance

| Pattern | What It Means in a SOC |
|---|---|
| Abnormally long domain names in queries | Possible DNS tunnelling (data exfiltration) |
| High volume of NXDOMAIN responses | DGA malware looking for active C2 domain |
| DNS queries to unusual/external resolvers | Bypassing internal DNS — policy violation or malware |
| TXT record queries in high volume | DNS tunnelling tool (e.g. iodine, dnscat2) |
| Very low TTL values (0–60s) | Fast-flux DNS — bulletproof hosting / botnet |
| Duplicate Transaction IDs from different IPs | DNS spoofing attempt |
| DNS over non-standard ports | Evasion technique — DNS on port 5353, 4444 etc. |

---

## 📁 Files in This Folder

```
DNS Traffic Investigation/
├── README.md                    ← This file
├── dns-investigation.pcap       ← Full Wireshark capture
└── screenshots/
    ├── 01-dns-filter.png
    ├── 02-dns-query.png
    ├── 03-dns-response.png
    ├── 04-record-types.png
    ├── 05-transaction-id.png
    ├── 06-nxdomain.png
    └── 07-dns-statistics.png
```

---

## 🛠️ Tools Used

- **Wireshark** — packet capture and analysis
- **nslookup** — DNS query tool (built into Kali)
- **dig** — detailed DNS query tool (built into Kali)
- **Kali Linux** — lab environment

---

*Project 02 of 10 · [Back to Main Portfolio](../README.md)*
