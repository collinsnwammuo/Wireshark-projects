# 02 - DNS Traffic Investigation

**Protocols:** DNS, UDP, TCP  
**Tool:** Wireshark  
**Lab Environment:** Kali Linux · VirtualBox

---

## 🎯 What I Did

I generated several different types of DNS traffic from my Kali VM and captured them in Wireshark, then worked through the capture analysing query/response pairs, different record types, TTL values, Transaction IDs, and what an NXDOMAIN response looks like at the packet level. DNS is one of the most abused protocols in real-world attacks, so I treated this exercise as building the baseline knowledge I need before I can spot malicious DNS activity in a real investigation.

---

## 🧠 Background

DNS translates human-readable domain names into IP addresses. Every time a device visits a website, sends an email, or connects to any service, DNS queries happen first — often invisibly in the background.

```
Client                    DNS Resolver              Authoritative NS
  |                              |                          |
  |---[Query: google.com?]-----> |                          |
  |                              |---[Query: google.com?]-->|
  |                              |<--[Ans: 142.251.142.142]-|
  |<--[Answer: 142.251.142.142]--|                          |
  |                              |                          |
```

**Why I think DNS matters for SOC work:**
- Malware uses DNS to locate C2 servers — Domain Generation Algorithms produce hundreds of random domains per day looking for an active one
- DNS tunnelling hides data exfiltration inside DNS queries — a technique that bypasses many firewalls
- A flood of NXDOMAIN responses often means malware is cycling through dead C2 domains
- DNS spoofing and poisoning redirect victims to attacker-controlled servers without them knowing
- Unusual record types like TXT queried at high volume are a tunnelling indicator

---

## 🔬 How I Did It

### Traffic I Generated

I deliberately generated several different DNS record types so I could study each one individually in Wireshark:

```bash
nslookup google.com                    # A record — standard IPv4 lookup
nslookup -type=AAAA google.com         # AAAA record — IPv6 address
nslookup -type=MX gmail.com            # MX record — mail server
nslookup -type=NS google.com           # NS record — nameservers
nslookup 8.8.8.8                       # PTR record — reverse DNS lookup
nslookup thisisafakedomain12345xyz.com # Simulated NXDOMAIN
dig google.com
dig google.com MX
```

I also deliberately queried a domain I made up to generate an NXDOMAIN response — this is the same response malware gets when it tries to reach a dead C2 domain, so I wanted to see exactly what it looks like in a capture.

### Capture Method
- Interface: `eth0`
- Display filter post-capture: `dns`
- Saved as: `dns-investigation.pcap`

### Wireshark Filters I Used

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
tcp.port == 53               # DNS over TCP
```

---

## 📊 What I Found

### Protocol Behaviour

| Observation | What I Saw |
|---|---|
| Transport protocol | UDP port 53 — all my queries fit within UDP |
| TCP DNS observed | No — no responses were large enough to trigger TCP fallback |
| Average query size | ~60–80 bytes |
| Average response size | ~80–150 bytes depending on record type |

### DNS Record Types I Captured

| Record Type | Query I Made | Answer Received | TTL |
|---|---|---|---|
| A | google.com | 142.251.142.142 | 64s |
| AAAA | google.com | 2a00:1450:4003:805::200e | 64s |
| MX | gmail.com | smtp.google.com (priority 17) | 64s |
| NS | google.com | ns1.google.com | 64s |
| PTR | 8.8.8.8 | dns.google | 64s |

### Transaction ID Matching

I expanded the DNS layer on several query/response pairs and confirmed that the Transaction ID (`0x8ef1` in one example) was identical between the query and its matching response. This is how the client matches answers to the right question when multiple queries are in flight at once. All Transaction IDs in my capture matched correctly — no spoofing indicators.

### NXDOMAIN — What I Saw

When I queried `thisisafakedomain12345xyz.com`, the response came back with **RCODE 3 (NXDOMAIN)**. The response packet had no answer section at all. just the question echoed back and the error code in the flags field. This is exactly what a malware sample sees hundreds of times per minute when its DGA domains haven't been registered yet.

---

## 📸 Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/01-dns-filter.png` | Wireshark with `dns` filter — full capture view |
| `screenshots/02-dns-query.png` | Single DNS query expanded in detail pane |
| `screenshots/03-dns-response.png` | Matching DNS response with answer section expanded |
| `screenshots/04-record-types.png` | A, MX and NS records visible in the same capture |
| `screenshots/05-transaction-id.png` | Query and response side by side — matching Transaction IDs |
| `screenshots/06-nxdomain.png` | NXDOMAIN response — RCODE 3 visible in flags |
| `screenshots/07-dns-statistics.png` | Statistics → DNS summary table |

---

## 💡 What I Learned

- **TTL values tell you about the infrastructure** — I noticed all my responses came back with short TTLs around 64 seconds, which is Google's current setting. I now know that legitimate CDN infrastructure often has short TTLs, and that attackers using fast-flux DNS deliberately set TTLs near zero to rapidly rotate IPs and make takedowns harder.

- **DNS over UDP has no authentication** — because there's no connection state, anyone can send an ARP reply claiming any IP. The only verification mechanism is the Transaction ID, which is only 16 bits — just 65,536 possible values. The Kaminsky attack exploited exactly this by flooding forged responses and racing to guess the right ID before the real response arrived.

- **NXDOMAIN looks completely ordinary at the packet level** — the response is almost identical to a successful response except the answer section is empty and the RCODE field reads 3 instead of 0. A single NXDOMAIN is nothing. Hundreds per minute from one host is a DGA alarm.

- **I didn't see any TCP DNS in my capture** — all my queries fit within UDP. I know TCP kicks in when a response exceeds 512 bytes (or 4096 with EDNS), so in future exercises I want to generate a query that forces TCP fallback — probably a large DNSSEC or TXT response — so I can see what that looks like.

- **DNS is the first thing to check when investigating malware** — before malware can connect to anything it has to resolve a domain. That DNS query is often the earliest visible indicator of compromise in a PCAP, appearing before any actual C2 traffic.

---

## 🔗 SOC Relevance

| Pattern I'd Look For | What It Means |
|---|---|
| Abnormally long or random-looking domain names | Possible DNS tunnelling — data being exfiltrated in queries |
| High volume of NXDOMAIN responses from one host | DGA malware cycling through dead C2 domains |
| DNS queries going to non-corporate resolvers | Malware bypassing internal DNS — common evasion technique |
| High volume of TXT record queries | DNS tunnelling tool in use (e.g. iodine, dnscat2) |
| Very low TTLs (0–60s) on external domains | Fast-flux DNS — bulletproof hosting or botnet infrastructure |
| Same Transaction ID in replies from different IPs | DNS spoofing attempt in progress |
| DNS traffic on non-standard ports | Evasion technique — hiding DNS on ports like 4444 or 5353 |

---

## 🛠️ Tools I Used

- **Wireshark** — packet capture and analysis
- **nslookup** — DNS query tool (built into Kali)
- **dig** — more detailed DNS query tool (built into Kali)
- **Kali Linux** — my lab environment

---

*Project 02 of 10 · [Back to Main Portfolio](../README.md)*
