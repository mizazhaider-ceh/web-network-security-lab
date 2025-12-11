# Web Application & Network Security Assessment Lab

**Combined penetration testing lab covering SQL Injection exploitation and network traffic analysis**

## 🎓 Academic Context

**Institution:** Howest University of Applied Sciences  
**Course:** Cyber Security Essentials (CSE)  
**Instructor:** Kurt Schoenmaekers  
**Lab Type:** Black-box penetration testing  
**Date:** December 2025  
**Student:** Muhammad Izaz Haider

---

## 📋 Lab Overview

This comprehensive lab combines two critical penetration testing domains:

1. **Web Application Security** - SQL Injection exploitation against CSPbook login system
2. **Network Security** - Traffic analysis and credential interception using Wireshark + Shodan reconnaissance

Both exercises demonstrate how attackers exploit common vulnerabilities in web applications and network protocols.

---

## 🎯 Objectives

**Web Application Testing:**
- Bypass authentication using SQL injection
- Escalate privileges through filter evasion
- Extract database contents via UNION queries
- Demonstrate impact of unsanitized input

**Network Traffic Analysis:**
- Identify exposed internet-facing devices via Shodan
- Analyze packet captures for cleartext credentials
- Demonstrate insecurity of legacy protocols (HTTP, FTP)
- Extract authentication data from network traffic

---

# PART 1: SQL INJECTION WEB APPLICATION PENTEST

## 🧭 Methodology

### What is a Penetration Test?

A penetration test (pentest) is a simulated cyberattack performed on a system to evaluate its security.

**Goal:** Identify vulnerabilities before attackers do.

**Approach:** Ethical hackers use the same techniques as malicious actors but report findings responsibly.

**Types:**
- **Blackbox** (no prior knowledge) ← *This lab*
- **Whitebox** (full knowledge)
- **Greybox** (partial knowledge)

In this lab, I performed a blackbox pentest starting with only the login page, probing for weaknesses using SQL injection.

---

## 🔍 Step-by-Step Exploitation

### Step 1: Initial Login Bypass (Level 1)

**Target:** CSPbook login page

**Injection Point:** Email and password fields

**Payload:**

> error' OR '1'='1


**Injection into both fields:**
- Email: `error' OR '1'='1`
- Password: `error' OR '1'='1`

**SQL Query Logic:**

SELECT * FROM users WHERE email='error' OR '1'='1' AND password='error' OR '1'='1'


**Result:** ✅ Login bypassed → **Level 1 access granted**

**Explanation:** The `OR '1'='1'` condition is always TRUE, causing the query to return all users and bypassing authentication.

---

### Step 2: URL Clue Recognition (Level 2)

**Observation:** After successful login, URL parameter appeared:

> ?user=admin


**Adjusted Attack:**
- Email: `admin`
- Password: `error' OR '1'='1`

**Result:** ✅ Login succeeded → **Level 2 access granted**

**Lesson:** URL parameters often reveal backend logic and can guide payload crafting.

---

### Step 3: Filter Evasion (Level 3)

**Challenge:** Keywords `TRUE` and `1=1` were blocked by input filters

**Evasion Techniques Tested:**

**Payload 1: Boolean TRUE**

> ' OR TRUE #


**Payload 2: String-based Truth Injection**

> ' OR 'howest'='howest' #


**Result:** ✅ Both payloads bypassed filters → **Level 3 access granted**

**Explanation:**
- `#` is MySQL comment character, ignoring everything after
- String comparison creates alternative truth condition
- Demonstrates weak filter implementation (blacklist-based)

---

### Step 4: UNION-Based Data Extraction (Critical)

**Target Field:** "Look for users" search functionality

**UNION SELECT** allows combining results from different queries to extract arbitrary data.

#### Extraction 1: Database Version

**Payload:**

> ' UNION SELECT @@version #


**Result:**

> 10.5.26-MariaDB-0+deb11u2


**Impact:** Reveals database type and version, enabling version-specific attacks.

---

#### Extraction 2: Server Hostname

**Payload:**

> ' UNION SELECT @@hostname #


**Result:**

> PinkPantherLinux


**Impact:** Discloses internal hostname, providing infrastructure intelligence.

---

#### Extraction 3: User Password Extraction

**Payload:**

> ' UNION SELECT password FROM users WHERE username='steve' #

**Result:**

 lorinda

 
**Impact:** 🔴 **CRITICAL** - Direct password disclosure from database.

---

### Step 5: Secret Admin Page Discovery

**Final Discovery:** Codeword revealed through database enumeration

**Result:**

> FacebookFTW!


**Impact:** Access to hidden administrative functionality.

---

## 📊 SQL Injection Types Used

### 1. Authentication Bypass (Boolean-based)

**Example Payloads:**

- OR '1'='1
- ' OR 'a'='a
- admin' OR '1'='1' --


**Mechanism:** Manipulates WHERE clause to always return TRUE.

---

### 2. Comment Truncation

**Example:**

> ' OR '1'='1' #


**Mechanism:** `#` comments out remaining query, bypassing password checks.

---

### 3. String-based Truth Injection

**Example:**

> ' OR 'howest'='howest' #


**Mechanism:** Creates always-true condition using string comparison instead of blocked keywords.

---

### 4. UNION-based Injection

**Example:**

> ' UNION SELECT password FROM users WHERE username='steve' #


**Mechanism:** Combines malicious query with original query to extract data from different tables/columns.

---

## 🔴 Risk Assessment

| Finding | Risk Level | Reason |
|---------|-----------|---------|
| **Login bypass** | 🔴 High | Unauthorized access to user accounts |
| **Filter evasion** | 🔴 High | Weak input validation easily bypassed |
| **UNION extraction** | 🔴 **CRITICAL** | Direct database disclosure |
| **Exposed credentials** | 🔴 **CRITICAL** | Full compromise of user accounts |

---

## 🛡️ Remediation Recommendations

### 1. Use Prepared Statements / Parameterized Queries

**BAD (Vulnerable):**

- $query = "SELECT * FROM users WHERE email='$email' AND password='$password'";


**GOOD (Secure):**
 
- $stmt = $pdo->prepare("SELECT * FROM users WHERE email=? AND password=?");
$stmt->execute([$email, $password]);


**Benefit:** Separates code from data, preventing injection.

---

### 2. Input Validation & Escaping

- **Whitelist approach** (allow only expected characters)
- Reject suspicious characters: `'`, `"`, `-`, `#`, `;`
- Implement length limits
- Use database-specific escaping functions

---

### 3. Error Handling

**Current (Vulnerable):**
- Detailed SQL error messages exposed to users
- Reveals database structure

**Recommended:**
- Generic error messages to users
- Detailed logs only to administrators
- Never expose stack traces or queries

---

### 4. Least Privilege

- Application database accounts should **NOT** have admin rights
- Use separate read-only accounts where possible
- Restrict access to sensitive tables

---

### 5. Monitoring & Logging

- Detect repeated failed login attempts
- Alert on suspicious queries (multiple single quotes, SQL keywords)
- Implement intrusion detection systems (IDS)
- Regular security audits and penetration testing

--- 



# PART 2: NETWORK TRAFFIC ANALYSIS & RECONNAISSANCE

## 🌐 Shodan Reconnaissance

### Objective

Identify internet-facing SonicWall firewall devices in Belgium using Shodan search engine.

### Methodology

**Tool:** Shodan.io (Internet-wide scanning platform)

**Search Query:**

> sonicwall country:"BE"

**Result:**

> 1,526 exposed SonicWall devices in Belgium


### Analysis

**Attack Surface Assessment:**

| Metric | Value | Security Implication |
|--------|-------|---------------------|
| **Total Devices** | 1,526 | Massive attack surface |
| **Visibility** | Public internet | Exposed to global threat actors |
| **Device Type** | Firewalls | Critical security infrastructure |
| **Location** | Belgium | Geographic targeting possible |

**Impact:**
- 🔴 1,526 potential entry points into Belgian networks
- ⚠️ Public exposure of perimeter security devices
- ⚠️ Attackers can identify vulnerable firmware versions
- ⚠️ Enables targeted attacks on Belgian infrastructure

---

### WHOIS Intelligence Gathering

**Target IP:** `193.191.179.94`

**Tool:** DomainTools WHOIS Lookup

**Extracted Information:**

```text
IP Location: Belgium, Kortrijk
Organization: Hogeschool West-Vlaanderen (Howest University)
ASN: AS2611 BELNET, BE
Network Range: 193.191.179.64 - 193.191.179.127
Network Name: HOWEST

Technical Contact:
Person: Bart Strubbe
Organization: Hogeschool West-Vlaanderen
Address: Marksesteenweg 58, B-8500 Kortrijk, Belgium
Phone: +32 56 241290
Fax: +32 56 241292

Admin Contact:
Person: Koen Vanbelle
Same address and contact details
```


**Intelligence Value:**
- ✅ Confirmed organizational ownership
- ✅ Identified technical contacts for social engineering
- ✅ Mapped IP address ranges for network reconnaissance
- ✅ Physical location confirmed (Kortrijk, Belgium)

---

## 📡 Wireshark Packet Capture Analysis

### Part A: HTTP Credential Interception

**Target File:** `Test_HTTP_LOGIN2.pcapng`

**Tool:** Wireshark 

**Protocol:** HTTP (Hypertext Transfer Protocol) - **Cleartext**

---

#### Analysis Steps

**Step 1: Open Packet Capture**

> File → Open → Test_HTTP_LOGIN.pcapng


**Step 2: Apply Display Filter**

- Display Filter: http

Result: Only HTTP packets visible

**Step 3: Locate Login Packet**
- Look for packet with "login" in Info column
- Identified: Packet #1361 - `POST /login.php HTTP/1.1`

**Step 4: Examine Packet Details**
Expand: `Hypertext Transfer Protocol → HTML Form URL Encoded`

---

#### Extracted Credentials

**Form Data:**

```text
Form item: "CSRFToken" = "b8941aa77175758896b2169f7005db1111595604"
Form item: "luser" = "MerlijnDeGrote Tovenaar"
Form item: "lpasswd" = "AcracadabraHocus PocusPats"
```


**Captured Credentials:**
- **Username:** `MerlijnDeGrote Tovenaar`
- **Password:** `AcracadabraHocus PocusPats`

**Packet Details:**

```text
ource IP: 192.168.1.19
Destination IP: 193.191.179.114
Protocol: HTTP (Port 80)
Method: POST /login.php
```

---

#### Security Analysis

**Vulnerability:** Cleartext HTTP authentication

**Impact:**
- 🔴 **CRITICAL** - Credentials transmitted unencrypted
- ⚠️ Any attacker on network path can intercept
- ⚠️ Man-in-the-middle (MITM) attacks trivial
- ⚠️ WiFi sniffing on public networks exposes credentials

**Attack Scenario:**

```text
User → Coffee Shop WiFi → Attacker (Wireshark) → Internet
↑
Credentials captured in cleartext
```


---

### Part B: FTP Credential Interception

**Target File:** `Test_FTP_LOGIN1.pcapng`

**Protocol:** FTP (File Transfer Protocol) - **Cleartext**

---

#### Analysis Steps

**Step 1: Apply Display Filter**

- Display Filter: ftp


**Step 2: Analyze FTP Request Packets**

**Observed Packets:**

```text
Request: USER anonymous ← Ignored (anonymous login)
Request: USER Donald Duck ← Valid user!
Request: PASS chrome@example.com ← Anonymous password (ignored)
Request: PASS Disney ← Valid password!
Request: QUIT
```


**Step 3: Extract Valid Credentials**

---

#### Extracted Credentials

**FTP Authentication:**
- **Username:** `Donald Duck`
- **Password:** `Disney`

**Server Details:**

```text
Server Response: 220 Microsoft FTP Service
Source IP: 192.168.1.19
Destination IP: 193.191.136.195
Protocol: FTP (Port 21)
```

---

#### Security Analysis

**Vulnerability:** Unencrypted FTP protocol

**Impact:**
- 🔴 **CRITICAL** - Credentials and all file transfers visible in cleartext
- ⚠️ Username and password transmitted without encryption
- ⚠️ All commands and responses interceptable
- ⚠️ File contents transferred in cleartext

**FTP Security Issues:**
1. No encryption of authentication
2. No encryption of command channel
3. No encryption of data transfer
4. Legacy protocol from 1971 (pre-dates modern security)

---

## 📊 Combined Findings Summary

### Shodan Reconnaissance

| Finding | Value | Impact |
|---------|-------|--------|
| Exposed devices (Belgium) | 1,526 SonicWall firewalls | Massive attack surface |
| WHOIS Intelligence | Technical contacts, IP ranges | Social engineering targets |

### HTTP Traffic Analysis

| Finding | Value | Risk Level |
|---------|-------|-----------|
| Username | MerlijnDeGrote Tovenaar | 🔴 Critical |
| Password | AcracadabraHocus PocusPats | 🔴 Critical |
| Protocol | HTTP (cleartext) | 🔴 Critical |

### FTP Traffic Analysis

| Finding | Value | Risk Level |
|---------|-------|-----------|
| Username | Donald Duck | 🔴 Critical |
| Password | Disney | 🔴 Critical |
| Protocol | FTP (cleartext) | 🔴 Critical |

---

## 🛡️ Comprehensive Remediation

### SQL Injection Mitigation

1. **Implement Prepared Statements**
2. **Input validation (whitelist approach)**
3. **Error handling (hide database details)**
4. **Least privilege database accounts**
5. **Web Application Firewall (WAF)**

### Network Security Improvements

1. **Migrate HTTP → HTTPS**
   - Implement TLS 1.3
   - Force HTTPS redirects
   - Use HSTS headers

2. **Migrate FTP → FTPS/SFTP**
   - FTP over TLS (FTPS)
   - SSH File Transfer Protocol (SFTP)
   - Disable legacy FTP entirely

3. **Network Segmentation**
   - Isolate sensitive systems
   - Implement VLANs
   - Restrict internet exposure

4. **Perimeter Security**
   - Reduce Shodan visibility (unnecessary port exposure)
   - Implement firewall access controls
   - Regular vulnerability scanning

---

## 🎓 Skills Demonstrated

**Web Application Security:**
- SQL injection exploitation (authentication bypass, UNION queries)
- Filter evasion techniques
- Database enumeration
- Payload crafting and iteration

**Network Security:**
- Wireshark packet capture analysis
- Display filter usage (http, ftp)
- TCP stream reconstruction
- Cleartext credential extraction

**Reconnaissance:**
- Shodan internet-wide scanning
- WHOIS intelligence gathering
- Attack surface mapping
- Infrastructure enumeration

---

## 🛠️ Tools & Technologies

| Category | Tool | Purpose |
|----------|------|---------|
| **Web Exploitation** | Browser + Manual SQL payloads | SQL injection testing |
| **Network Analysis** | Wireshark | Packet capture analysis |
| **Reconnaissance** | Shodan.io | Internet-facing device discovery |
| **Intelligence** | WHOIS / DomainTools | IP address and contact intelligence |

---

## ⚖️ Ethical & Legal Notice

All testing conducted:

✅ In **authorized academic lab environment** at Howest University  
✅ On **synthetic targets** designed for educational purposes  
✅ Under supervision of **faculty instructor** (Kurt Schoenmaekers)  
✅ Following **ethical hacking principles** and Belgian legal guidelines

**No real production systems were accessed. All credentials and systems were fictional and created specifically for this training exercise.**

⚠️ **Warning:** These techniques must NEVER be applied to real systems without explicit written authorization. Unauthorized access to computer systems is illegal under Belgian Computer Crime Act and international cybercrime laws.

---

## 🧠 Key Lessons Learned

### SQL Injection

1. **Unsanitized input = full database compromise**
2. **Blacklist filters are easily bypassed** (use whitelist instead)
3. **Error messages reveal sensitive information** (hide in production)
4. **Multiple injection vectors** (email, password, search fields)
5. **UNION queries extract arbitrary data** (critical vulnerability)

### Network Security

1. **Cleartext protocols expose ALL data in transit**
2. **WiFi sniffing requires no sophisticated tools** (Wireshark sufficient)
3. **Legacy protocols (HTTP, FTP) have no place in modern networks**
4. **Encryption is mandatory for authentication** (HTTPS, FTPS, SFTP)
5. **Public exposure (Shodan) creates massive attack surface**

### Career Application

As a cybersecurity professional, I now understand:
- How attackers chain multiple attack vectors (SQL + network sniffing)
- The importance of defense-in-depth (application + network security)
- Why legacy protocol migration is critical
- How to conduct security assessments using industry-standard tools

---

## 👤 Author

**Muhammad Izaz Haider**  
Cybersecurity Student @ Howest University of Applied Sciences  
Junior DevSecOps & Ai Secuirty Engineer 
Focus: Penetration Testing · OSINT · DevSecOps



- 📧 Contact: mizazhaiderceh@gmail.com 
- 💼 LinkedIn: https://www.linkedin.com/in/muhammad-izaz-haider-091639314
- 🐙 GitHub: github.com/mizazhaider-ceh


---

## 📚 References

- OWASP Top 10 (A03:2021 – Injection)
- OWASP SQL Injection Prevention Cheat Sheet
- Wireshark Documentation
- Shodan.io Search Queries
- MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
- NIST SP 800-115: Technical Guide to Information Security Testing

---

**Last Updated:** December 11, 2025  
**Lab Status:** ✅ Completed

---

<p align="center">
  <i>"Starting from a simple login page, I escalated access using multiple attack vectors."</i><br>
  <i>"Cleartext protocols expose everything - encryption is not optional."</i>
</p>


































 
