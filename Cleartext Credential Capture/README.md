# 03 - Cleartext Credential Capture

**Protocols:** HTTP, FTP, TLS  
**Tool:** Wireshark  
**Lab Environment:** Kali Linux · VirtualBox · DVWA · vsftpd

---

## 🎯 What I Did

I set up DVWA and an FTP server on my Kali VM, submitted real login credentials over both HTTP and FTP while Wireshark was capturing, and then pulled those credentials straight out of the packets. I also captured HTTPS traffic side by side to show the difference encryption makes. This was one of the most eye-opening exercises so far because seeing your own password sitting in plain text inside a packet makes the risk feel very real.

---

## ⚠️ Disclaimer

All traffic in this project was generated in a fully isolated VirtualBox lab environment. No real credentials, external systems, or production networks were involved. This is purely for educational purposes.

---

## 🧠 Background

Many legacy protocols transmit usernames and passwords in **plaintext**, meaning anyone on the same network with a packet capture tool can read them directly.

```
HTTP Login (CLEARTEXT):
Client → Server:
  POST /login HTTP/1.1
  Host: 127.0.0.1
  Content: username=testuser&password=hunter2    <- VISIBLE TO ANYONE

FTP Login (CLEARTEXT):
Client → Server:  USER ftpuser               <- VISIBLE
Server → Client:  331 Password required
Client → Server:  PASS ftpkali               <- VISIBLE
Server → Client:  230 Login successful

HTTPS Login (ENCRYPTED):
Client → Server:  [TLS Application Data]
                  <- Nothing readable, credentials fully protected
```

**Protocols that expose credentials in cleartext:**

| Protocol | Port | What Gets Exposed |
|---|---|---|
| HTTP | 80 | Login forms, cookies, session tokens |
| FTP | 21 | Username and password fully visible |
| Telnet | 23 | Entire session including every command typed |
| SMTP (no TLS) | 25 | Email credentials and message content |
| POP3 (no TLS) | 110 | Email credentials |
| SNMP v1/v2 | 161 | Community strings used as passwords |

---

## 🔬 How I Did It

### Lab Setup

```
Kali Linux VM
├── DVWA (Damn Vulnerable Web App) -- HTTP login target
├── vsftpd -- FTP server running locally
└── Wireshark -- capturing on loopback (lo)
```

I captured everything on the **loopback interface (lo)** because both DVWA and vsftpd were running locally on Kali. Traffic to 127.0.0.1 goes through loopback, not eth0, so selecting the wrong interface would have given me an empty capture.

### Part A -- HTTP Credential Capture

I installed DVWA, started it, and submitted a login form while Wireshark was running:

```bash
sudo apt install dvwa -y && sudo dvwa-start
# Accessed at http://127.0.0.1:42001
# Login submitted: username=testuser, password=hunter2
```

**Filters I used:**
```wireshark
http.request.method == "POST"          # Find the login POST request
http                                   # All HTTP traffic
```

### Part B -- FTP Credential Capture

I set up a local FTP server and connected to it with the FTP client while capturing:

```bash
sudo apt install vsftpd -y
sudo systemctl start vsftpd
sudo useradd -m ftpuser && sudo passwd ftpuser

ftp 127.0.0.1
```

**Filters I used:**
```wireshark
ftp                                    # All FTP control traffic
ftp.request.command == "USER"          # Just the username packet
ftp.request.command == "PASS"          # Just the password packet
ftp.response.code == 230               # Successful login confirmation
ftp-data                               # FTP data channel
```

### Part C -- HTTPS Comparison

I visited an HTTPS site and captured the traffic to compare it directly against the HTTP and FTP captures:

```wireshark
tls                                    # TLS/HTTPS traffic
ssl.record.content_type == 23          # Application Data (encrypted payload)
```

---

## 📊 What I Found

### Part A -- HTTP Results

| Field | Value |
|---|---|
| Protocol | HTTP/1.1 |
| Method | POST |
| Target URL | `http://127.0.0.1:42001/login.php` |
| Credentials exposed | Username and password fully visible in packet payload |
| Capture interface | Loopback (lo) |

**Exact credentials I pulled from the packet:**
```
username=testuser&password=hunter2
```
No decryption needed. No special tools. Just Wireshark and a filter.

### Part B -- FTP Results

| Packet | What I Could Read |
|---|---|
| USER command | `USER ftpuser` in plaintext |
| PASS command | `PASS ftpkali` in plaintext |
| Server response | `230 Login successful` |
| Full session | Every command I typed (ls, pwd, quit) was readable |

### Part C -- HTTPS Comparison

| Field | HTTP | HTTPS |
|---|---|---|
| Credentials visible | Yes, plaintext | No, encrypted |
| Content readable | Yes | No |
| Wireshark payload | Username and password in full | `Application Data` (unreadable ciphertext) |

---

## 💡 What I Learned

- **Seeing your own password in a packet is genuinely unsettling.** I typed `hunter2` into DVWA, opened the POST packet in Wireshark, and there it was sitting in the payload in plain text. No effort required. This exercise made the risk of cleartext protocols feel concrete rather than theoretical.

- **FTP exposes more than just the password.** After logging in I ran a few commands and could read every single one of them in the TCP stream. Every file I listed, every directory I changed to, all of it visible. FTP is not just a credential risk, it is a full session exposure risk.

- **Follow TCP/HTTP Stream is the feature that makes this real.** Right-clicking a packet and following the stream reconstructs the entire conversation in a readable format. It takes about two seconds to go from a raw capture to seeing someone's login details laid out clearly. This is what an attacker with MITM access sees.

- **HTTPS makes the content completely unreadable.** When I applied the `tls` filter to the HTTPS capture, all I could see in the payload was `Application Data`. No usernames, no passwords, no page content. The only metadata visible was the destination IP, port, and packet timing. This is the difference encryption actually makes.

- **Session cookies are just as valuable as passwords.** I noted that HTTP responses include Set-Cookie headers which are also fully visible in the capture. An attacker who grabs a session cookie can impersonate an authenticated user without ever needing the password. This is session hijacking and it works on any site that does not use HTTPS.

- **The loopback interface catches localhost traffic.** I learned this the hard way when I started capturing on eth0 and got nothing. Traffic to 127.0.0.1 does not go through eth0 at all. Switching to lo fixed it immediately. I will remember this for any future exercise involving locally hosted services.

---

## 🔗 SOC Relevance

| Scenario | What I Would Do |
|---|---|
| HTTP login traffic detected on corporate network | Raise alert, credentials may be compromised, enforce HTTPS |
| FTP traffic from internal host | Alert, identify the system, begin remediation |
| Cleartext authentication to internal app | Raise finding, application needs TLS |
| MITM attack combined with HTTP traffic | ARP spoofing plus credential harvesting equals full compromise |
| Telnet traffic detected | Treat as critical, entire session is exposed |
| SMTP on port 25 with no TLS | Email credentials and content at risk, enforce STARTTLS |

---

## 🛠️ Tools I Used

- **Wireshark** -- packet capture and analysis
- **DVWA** (Damn Vulnerable Web Application) -- HTTP login target
- **vsftpd** -- FTP server
- **ftp** -- FTP client built into Kali
- **Firefox** -- browser for HTTPS comparison traffic
- **Kali Linux** -- my lab environment

---

*Project 03 of 10 · [Back to Main Portfolio](../README.md)*
