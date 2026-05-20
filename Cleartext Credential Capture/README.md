# 03 - Cleartext Credential Capture

**Protocols:** HTTP, FTP, TLS  
**Tool:** Wireshark  
**Lab Environment:** Kali Linux · VirtualBox · DVWA · vsftpd

---

## 🎯 Objective

Demonstrate how credentials transmitted over unencrypted protocols (HTTP and FTP) can be captured and read directly from network traffic using Wireshark — and contrast this with HTTPS to show why encryption is non-negotiable. This is one of the most fundamental concepts in network security and a daily reality in SOC analyst work.

---

## ⚠️ Disclaimer

All traffic captured in this project was generated in a fully isolated VirtualBox lab environment. No real credentials, external systems, or production networks were involved. This project is purely for educational purposes.

---

## 🧠 Background

Many legacy protocols transmit data — including usernames and passwords — in **plaintext**, meaning anyone on the same network with a packet capture tool can read them directly.

```
HTTP Login (CLEARTEXT):
Client → Server:
  POST /login HTTP/1.1
  Host: 192.168.1.x
  Content: username=admin&password=hunter2    ← VISIBLE TO ANYONE

FTP Login (CLEARTEXT):
Client → Server:  USER ftpuser               ← VISIBLE
Server → Client:  331 Password required
Client → Server:  PASS ftppass123            ← VISIBLE
Server → Client:  230 Login successful

HTTPS Login (ENCRYPTED):
Client → Server:  [TLS Application Data - encrypted gibberish]
                  ← NO readable content, credentials protected
```

**Protocols that send credentials in cleartext:**

| Protocol | Port | Risk |
|---|---|---|
| HTTP | 80 | Login forms, cookies, session tokens |
| FTP | 21 | Username and password fully visible |
| Telnet | 23 | Entire session including commands |
| SMTP (no TLS) | 25 | Email credentials and content |
| POP3 (no TLS) | 110 | Email credentials |
| SNMP v1/v2 | 161 | Community strings (passwords) |

---

## 🔬 Methodology

### Lab Setup

```
Kali Linux VM
├── DVWA (Damn Vulnerable Web App) — HTTP login target
├── vsftpd — FTP server running locally
└── Wireshark — capturing on loopback (lo) and eth0
```

### Part A — HTTP Credential Capture

Deployed DVWA on Kali and submitted a login form over HTTP while Wireshark captured on the loopback interface.

```bash
# DVWA setup
sudo apt install dvwa -y && sudo dvwa-start
# Accessed at http://127.0.0.1:42001
# Submitted login: username=testuser, password=hunter2
```

**Wireshark filters used:**
```wireshark
http.request.method == "POST"          # Find login POST request
http                                   # All HTTP traffic
```

### Part B — FTP Credential Capture

Installed and configured vsftpd on Kali, connected via FTP client, and captured the full authentication sequence.

```bash
# FTP server setup
sudo apt install vsftpd -y
sudo systemctl start vsftpd
sudo useradd -m ftpuser && sudo passwd ftpuser

# FTP client connection
ftp 127.0.0.1
```

**Wireshark filters used:**
```wireshark
ftp                                    # All FTP control channel traffic
ftp.request.command == "USER"          # Username packet only
ftp.request.command == "PASS"          # Password packet only
ftp.response.code == 230               # Successful login response
ftp-data                               # FTP data channel (file transfers)
```

### Part C — HTTPS Comparison

Captured HTTPS traffic to the same type of site for direct comparison — showing what encrypted traffic looks like versus cleartext.

```wireshark
tls                                    # TLS/HTTPS traffic
ssl.record.content_type == 23          # Application Data (encrypted payload)
```

---

## 📊 Findings

### Part A — HTTP Results

| Field | Value |
|---|---|
| Protocol | HTTP/1.1 |
| Method | POST |
| Target URL | `http://127.0.0.1:42001/login.php` |
| Credentials exposed | Username and password visible in packet payload |
| Capture interface | Loopback (lo) |

**Credentials found in packet:**
```
username=testuser&password=hunter2
```
> Fully readable with zero effort — no decryption, no tools beyond Wireshark.

### Part B — FTP Results

| Packet | Content Visible |
|---|---|
| USER command | `USER ftpuser` — username in plaintext |
| PASS command | `PASS ftppass123` — password in plaintext |
| Server response | `230 Login successful` |
| Session | All commands (ls, pwd, quit) fully readable |

### Part C — HTTPS Comparison

| Field | HTTP | HTTPS |
|---|---|---|
| Credentials visible | ✅ Yes — plaintext | ❌ No — encrypted |
| Content readable | ✅ Yes | ❌ No |
| Attack difficulty | Trivial | Requires key/cert compromise |
| Wireshark payload | Username & password | `Application Data` (ciphertext) |

---

## 📸 Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/01-http-post-filter.png` | Wireshark with POST filter — login packet visible in list |
| `screenshots/02-http-credentials-exposed.png` | Middle pane expanded — username and password in plaintext |
| `screenshots/03-http-stream.png` | Follow HTTP Stream — full POST request with credentials |
| `screenshots/04-ftp-filter.png` | Wireshark with `ftp` filter — USER and PASS packets visible |
| `screenshots/05-ftp-user-packet.png` | FTP USER packet — username visible in packet details |
| `screenshots/06-ftp-pass-packet.png` | FTP PASS packet — password visible in packet details |
| `screenshots/07-ftp-stream.png` | Follow TCP Stream on FTP — full session with credentials |
| `screenshots/08-https-encrypted.png` | TLS traffic — Application Data, nothing readable |

---

## 💡 Key Observations

- **HTTP POST parameters are fully visible** in the packet payload — no special tool needed, just Wireshark and a filter. Any attacker on the same LAN (or running a MITM attack) can harvest credentials instantly.

- **FTP is even more dangerous than HTTP** — not only are credentials sent in cleartext, but the entire session (every command typed, every file listed or transferred) is readable. FTP should never be used on any modern network.

- **Follow TCP/HTTP Stream is the most powerful feature here** — it reconstructs the entire conversation in human-readable format, exactly as the attacker would see it. One right-click to compromise a session.

- **HTTPS makes this attack impossible** without the private key or a TLS interception proxy. The payload in a TLS capture is completely unreadable — all you see is metadata (IP, port, timing) but no content.

- **Cookies and session tokens** transmitted over HTTP are just as dangerous as passwords — an attacker can use a captured session cookie to hijack an authenticated session without ever knowing the password (session hijacking).

---

## 🔗 SOC Relevance

| Scenario | SOC Action |
|---|---|
| HTTP login detected on corporate network | Alert — credentials may be compromised. Enforce HTTPS |
| FTP traffic detected from internal host | Alert — legacy protocol in use. Identify system and remediate |
| Cleartext auth to internal application | Raise finding — application needs TLS enforcement |
| MITM attack in progress on LAN | ARP spoofing + HTTP credential harvesting = full account compromise |
| Telnet traffic detected | Critical — entire session including commands is exposed |
| Unencrypted SMTP on port 25 | Email credentials and content at risk — enforce STARTTLS |

---

## 🛠️ Tools Used

- **Wireshark** — packet capture and analysis
- **DVWA** (Damn Vulnerable Web Application) — HTTP login target
- **vsftpd** — FTP server
- **ftp** — FTP client (built into Kali)
- **Firefox** — browser for HTTP/HTTPS traffic generation
- **Kali Linux** — lab environment

---

*Project 03 of 10 · [Back to Main Portfolio](../README.md)*
