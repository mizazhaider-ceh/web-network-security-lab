# Web Application & Network Security Assessment Lab

Combined web application penetration testing (SQL Injection) and network traffic analysis (Wireshark) lab from Howest University's Cyber Security Essentials course.

## Part 1: SQL Injection Web Application Pentest

### Objective
Test authentication bypass and database extraction on vulnerable web login portal.

### Methodology
- Boolean-based SQL injection testing
- Authentication bypass attempts
- Database enumeration via UNION queries
- Filter and WAF evasion techniques

### Key Findings
**Vulnerability:** SQL Injection in login form  
**Payload Used:** `' OR 1=1 --`  
**Result:** Authentication bypass successful  
**Impact:** Complete unauthorized access to backend database

### Exploitation Process
1. Identified unvalidated user input in login form
2. Injected SQL payload to manipulate query logic
3. Bypassed authentication without valid credentials
4. Enumerated database structure
5. Extracted sensitive user data

### Impact
- Full database access without credentials
- User credential exposure
- Potential privilege escalation
- Proof of concept for data exfiltration

## Part 2: Network Traffic Analysis (Wireshark)

### Objective
Intercept and analyze network traffic to extract credentials and map infrastructure.

### Tools Used
- Wireshark (packet capture analysis)
- Shodan (internet-wide reconnaissance)
- WHOIS (domain intelligence)

### Methodology

#### Shodan Reconnaissance
- **Target:** SonicWall firewalls in Belgium
- **Query:** `sonicwall country:BE`
- **Result:** 1,526 exposed devices identified
- **Impact:** Massive attack surface mapped

#### HTTP Credential Interception
- **File Analyzed:** `HTTP_LOGIN.pcapng`
- **Filter Applied:** `http.request.method == "POST"`
- **Credentials Extracted:**
  - Username: `MerlijnDeGrote Tovenaar`
  - Password: `AcracadabraHocus PocusPats`
- **Vulnerability:** Cleartext HTTP authentication

#### FTP Credential Interception
- **File Analyzed:** `FTP_LOGIN.pcapng`
- **Filter Applied:** `ftp`
- **Credentials Extracted:**
  - Username: `Donald Duck`
  - Password: `Disney`
- **Vulnerability:** Unencrypted FTP protocol

### Key Findings

| Protocol | Status | Credentials Exposed | Risk Level |
|----------|--------|-------------------|-----------|
| HTTP | Cleartext | ✅ Yes | 🔴 Critical |
| FTP | Cleartext | ✅ Yes | 🔴 Critical |
| Shodan | Public | 1,526 devices | 🟠 High |

### Impact Summary
- Complete credential exposure in network traffic
- Massive attack surface (1,526+ devices)
- Legacy protocols (HTTP, FTP) create critical vulnerabilities
- Man-in-the-middle attacks trivial to execute

## Skills Demonstrated

**Web Security:**
- SQL Injection exploitation
- Authentication bypass techniques
- Database enumeration
- Web application security testing

**Network Security:**
- Wireshark packet analysis
- TCP stream reconstruction
- Protocol security assessment
- Shodan reconnaissance
- Cleartext credential extraction

## Recommendations

**Web Application:**
- Implement parameterized queries (prepared statements)
- Input validation and sanitization
- Web Application Firewall (WAF)
- Security code review

**Network Security:**
- Migrate HTTP → HTTPS
- Migrate FTP → FTPS/SFTP
- Network segmentation
- Reduce internet-facing exposure

## Ethical Notice

All testing conducted in authorized academic lab environment at Howest University. Lab data only - no production systems accessed.

## Author

**Muhammad Izaz Haider**  
Cybersecurity Student @ Howest University  
Course: Cyber Security Essentials (CSE)  
Date: December 2025
