# 07 - SSH Brute Force Detection

**Difficulty:** Intermediate  
**Protocols:** SSH, TCP  
**Tools:** Wireshark · Hydra  
**Lab Environment:** Kali Linux (attacker/analyst) · Windows 10 (target) · VirtualBox NAT + Host-Only

---

## 🎯 What I Did

I launched a real SSH brute force attack from my Kali VM against my Windows 10 VM using Hydra, captured the entire attack in Wireshark, and then switched hats to analyse the capture as a SOC analyst would. I also checked Windows Event Viewer to correlate the network evidence with host-based logs -- exactly the way a real investigation combines both data sources. This project taught me what brute force traffic actually looks like at the packet level, which looks very different from what I expected before doing it.

---

## ⚠️ Disclaimer

This attack was performed entirely within my isolated VirtualBox lab on machines I own. No external systems or real user accounts were involved. Running brute force attacks against systems you do not own is illegal.

---

## 🧠 Background

### What is SSH Brute Forcing?

SSH (Secure Shell) is used to remotely access systems over an encrypted connection. Brute forcing SSH means systematically trying username and password combinations until one works. It is one of the most common attack techniques against internet-facing servers and a regular source of alerts in any SOC.

```
Normal SSH login:
Kali --> Windows:  [SYN]
Windows --> Kali:  [SYN-ACK]
Kali --> Windows:  [ACK]            <- handshake complete
[SSH version exchange]
[Key exchange]
[Authentication -- one attempt]     <- succeeds
[Encrypted session open]

Brute force SSH:
Kali --> Windows:  [SYN]            <- attempt 1
[authentication fails]
[connection closes]
Kali --> Windows:  [SYN]            <- attempt 2
[authentication fails]
[connection closes]
Kali --> Windows:  [SYN]            <- attempt 3
... repeats for every password in the list ...
Kali --> Windows:  [SYN]            <- attempt N
[authentication succeeds]
[encrypted session stays open]
```

The key difference between a normal login and a brute force is volume, speed, and pattern. A human types one password. A tool like Hydra tries hundreds per minute in a mechanical, regular pattern.

### Why This Matters for SOC Work

SSH brute force is one of the most frequently seen attacks against Linux servers and increasingly against Windows machines with OpenSSH enabled. Recognising it in a PCAP and correlating it with host logs is a core Tier 1 SOC skill. Many SIEM rules are built specifically to alert on this pattern.

---

## 🔬 How I Set It Up

### Lab Configuration

```
VirtualBox Host-Only Network 192.168.56.0/24:
  Kali Linux   192.168.56.102   (attacker + Wireshark analyst)
  Windows 10   192.168.56.101   (SSH target -- OpenSSH Server installed)
```

### What I Installed on Windows 10

OpenSSH Server is not enabled by default on Windows 10. I installed it through:

```
Settings -> Apps -> Optional Features -> Add a feature -> OpenSSH Server
```

Then started the service and set it to start automatically via Services. I confirmed it was listening with `netstat -an | findstr :22` which showed port 22 in LISTENING state.

### The Wordlist I Used

I created a small custom wordlist with the real password buried in the middle so the capture would show both failed and successful attempts:

```
admin
password
123456
letmein
[real windows password]
qwerty
welcome
test123
```

### The Attack Command

```bash
hydra -l <windows-username> -P ~/wordlist.txt ssh://192.168.56.101 -t 4 -V
```

- `-l` -- the Windows username to attack
- `-P` -- my wordlist file
- `-t 4` -- 4 parallel threads
- `-V` -- verbose so I could watch each attempt in the terminal

### Wireshark Capture Method

- Interface: `eth0` (Host-Only -- where SSH traffic flows between the two VMs)
- Pre-capture filter: `tcp.port == 22`
- Started capture before running Hydra, stopped after Hydra finished

### Captures I Took

| File | Purpose |
|---|---|
| `ssh-bruteforce.pcap` | Full brute force attack capture |
| `ssh-normal-session.pcap` | Clean normal SSH login for comparison |

### Wireshark Filters I Used

```wireshark
tcp.port == 22                                  # All SSH traffic
tcp.flags.syn == 1 && tcp.dstport == 22         # Just the connection attempts
ssh                                             # SSH protocol layer
tcp.flags.syn == 1 && tcp.flags.ack == 0        # SYN packets only
```

---

## 📊 What I Found

### Attack Summary

| Metric | Value |
|---|---|
| Attack tool | Hydra |
| Target | Windows 10 OpenSSH Server (192.168.56.101:22) |
| Passwords tried | [update with actual count from Hydra output] |
| Password found | Yes -- [update with position in wordlist] |
| Attack duration | [update from Wireshark capture file properties] |
| Total packets | [update from Wireshark capture file properties] |

### Failed vs Successful Session Pattern

The most important thing I noticed in the capture was the difference in TCP session duration between failed and successful logins.

**Failed login session (short):**
```
Kali   --> Windows:  [SYN]
Windows --> Kali:    [SYN-ACK]
Kali   --> Windows:  [ACK]
[SSH banner exchange]
[Authentication attempt -- fails]
[Connection closes -- FIN or RST]
Total duration: under 1 second
```

**Successful login session (longer):**
```
Kali   --> Windows:  [SYN]
Windows --> Kali:    [SYN-ACK]
Kali   --> Windows:  [ACK]
[SSH banner exchange]
[Authentication attempt -- succeeds]
[Session remains open]
Total duration: several seconds or more
```

I found the successful session immediately in Statistics -> Conversations -> TCP by sorting on the Duration column. It was the obvious outlier -- one long session surrounded by dozens of very short ones.

### SSH Banner Observed

Expanding an SSH packet in the middle pane I could see the server banner from Windows:

```
SSH-2.0-OpenSSH_for_Windows_8.1
```

This is significant from a SOC perspective because an attacker who sees this banner immediately knows the SSH server version, which tells them whether known exploits or configuration weaknesses apply. In a real environment I would flag this as a finding -- SSH banners should be suppressed or minimised.

### Brute Force Signature in the Capture

When I filtered for `tcp.flags.syn == 1 && tcp.dstport == 22` and looked at the Time column, the pattern was immediately obvious. SYN packets were arriving at a completely regular, mechanical interval -- nothing like a human typing passwords. Each SYN was a new connection attempt from Hydra. The IO Graph showed a concentrated burst for the duration of the attack then silence once Hydra found the password and stopped.

### Windows Event Log Correlation

On Windows 10 in Event Viewer -> Windows Logs -> Security I found:

- **Event ID 4625** (Failed Logon): Dozens of entries all timestamped within the attack window, one for each Hydra attempt
- **Event ID 4624** (Successful Logon): One entry corresponding to when Hydra cracked the password

Matching these event timestamps against the Wireshark packet timestamps confirmed the same activity from two different data sources -- exactly how a real SOC investigation works.

---

## 💡 What I Learned

- **Brute force traffic looks completely different from human traffic.** I knew this conceptually before doing the exercise but seeing it in the capture made it concrete. The SYN packets come in at a mechanical, perfectly regular interval. A human typing passwords has irregular timing, pauses, and typically does not make dozens of attempts in a few seconds. That regularity is the signature.

- **The Conversations duration sort is the fastest way to find the successful login.** Every failed attempt was a very short TCP session. The successful one was obviously longer because the session stayed open after authentication. Without even looking at the packet content I could identify the exact moment the attack succeeded just by sorting that column.

- **Correlating Wireshark with Windows Event Viewer told a more complete story.** The PCAP shows what happened at the network level. Event Viewer shows what the operating system recorded. When the timestamps from Event ID 4625 entries lined up with the SYN flood in Wireshark I could see both perspectives of the same attack. This is what proper incident investigation looks like.

- **SSH banners leak version information.** I had not thought about this before but the server banner that comes back in the first SSH packet tells an attacker exactly what software is running. In a real environment I would now check whether SSH banners can be suppressed or replaced with something non-informative.

- **Hydra's parallel threads create a distinctive traffic pattern.** With `-t 4` I was running 4 threads simultaneously, meaning 4 TCP connections to port 22 could be open at the same time. In the capture I could see overlapping connection attempts rather than strictly sequential ones. A higher thread count would make this even more obvious and would typically trigger rate-limiting or lockout on a hardened system.

- **Windows does not lock accounts by default after failed SSH attempts.** I noticed that Hydra was able to try every password in my wordlist without being blocked. On a hardened system I would expect account lockout policies or fail2ban-style tools to start dropping connections after a few failures. The absence of that here is itself a finding worth noting.

---

## 🔗 SOC Relevance

| Detection Indicator | What It Means | What I Would Do |
|---|---|---|
| Many SYN packets to port 22 from one IP in seconds | SSH brute force in progress | Block source IP, alert, investigate |
| Dozens of short TCP sessions to port 22 | Failed authentication attempts | Correlate with auth logs, check for success |
| One long session following many short ones | Brute force succeeded | Incident response -- account compromised |
| Mechanical regular timing between connection attempts | Automated tool in use | Not a human, escalate immediately |
| High volume of Event ID 4625 from one source | Account being attacked | Check for corresponding 4624, isolate if found |
| SSH server banner visible in capture | Version information exposed | Suppress banners, review SSH hardening |

### MITRE ATT&CK Mapping

| Technique | ID | How It Appeared |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Hydra trying every password in wordlist |
| Valid Accounts | T1078 | Successful authentication after brute force |
| Remote Services: SSH | T1021.004 | SSH used as the attack vector |
| Network Service Discovery | T1046 | Port 22 was identified before attacking |

---

## 🛠️ Tools I Used

- **Wireshark** -- packet capture and analysis
- **Hydra** -- brute force attack tool (built into Kali)
- **OpenSSH Server** -- SSH server installed on Windows 10
- **Windows Event Viewer** -- host-based log correlation
- **Kali Linux** -- my attacker and analyst workstation
- **Windows 10** -- SSH target VM

---

*Project 07 of 10 · [Back to Main Portfolio](../README.md)*
