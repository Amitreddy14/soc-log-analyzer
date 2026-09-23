# Incident Report: INC-C302E86F5D6A

**Severity:** CRITICAL  
**Generated:** 2026-09-23 06:37:50  
**Generator:** template  

---

## Brute Force Attack from 91.240.118.172 targeting 5 hosts (multi-stage: initial_access → impact → unknown)

### Executive Summary

A critical-severity incident was detected involving repeated authentication attempts using common or dictionary-based credentials to gain unauthorized access. The activity originated from 7 source IPs and targeted 5 internal hosts over a period of 31 hours and 19 minutes. A total of 3282 related events were correlated into this incident. The attack follows a multi-stage pattern (Initial Access → Impact → Unknown → Reconnaissance → Execution → Persistence → Lateral Movement), indicating a coordinated and potentially advanced threat.

### Timeline

**2026-09-22T03:09:26** — SSH login failed for ftpuser detected from 91.240.118.172 to None:None (category: brute_force)

**2026-09-22T03:12:00** — DoS Hulk detected from 91.240.118.172 to 10.0.0.5:22 (category: dos)

**2026-09-22T03:12:04** — Firewall event detected from 91.240.118.172 to 192.168.1.10:8080 (category: unknown)

**2026-09-22T03:42:00** — PortScan detected from 91.240.118.172 to 10.0.0.5:3306 (category: port_scan)

**2026-09-22T03:47:00** — SSH login failed for deploy detected from 91.240.118.172 to None:None (category: brute_force)


The incident spanned 31 hours and 19 minutes with an average rate of 1.8 events per minute.

### Impact Assessment

Potential unauthorized access to user accounts and sensitive data. If any attempts succeeded, the attacker may have access to internal systems.

Service availability may be degraded or disrupted for legitimate users. Business operations depending on targeted services could be affected.

Potential database compromise. If successful, the attacker may have extracted, modified, or deleted database records, including sensitive customer or business data.

Potential session hijacking and credential theft from web application users. Stored XSS could affect all users who visit the compromised page.

Evidence of unauthorized internal network access. Affected systems may have been used for data exfiltration, lateral movement, or establishing persistence.

One or more internal hosts may be compromised and under external control. These systems could be used for DDoS attacks, spam, cryptocurrency mining, or as pivot points for further network compromise.

Network reconnaissance indicates an adversary is mapping the attack surface. This is typically a precursor to targeted exploitation attempts.


**Affected assets:** 10.0.0.5, 192.168.1.10, 192.168.1.25, 10.0.0.12, 192.168.1.50

**Target ports:** 22, 8080, 3306, 80, 21, 445, 443, 23, 1433, 3389

### Technical Details

**Attack vectors observed:** Brute Force, Dos, Unknown, Port Scan, Web Attack Xss, Web Attack Bruteforce, Botnet, Ddos, Web Attack Sql, Infiltration, Benign

**Kill chain progression:** Initial Access → Impact → Unknown → Reconnaissance → Execution → Persistence → Lateral Movement
The multi-stage nature of this attack suggests a deliberate, coordinated operation rather than opportunistic scanning.

**Source distribution:** 7 distinct source IPs observed, indicating a distributed attack or the use of proxies/VPN.

### Indicators of Compromise (IoCs)

| Type | Value | Context | Action |
|------|-------|---------|--------|
| ip | `91.240.118.172` | Source of attack traffic | block |
| ip | `23.129.64.100` | Source of attack traffic | block |
| ip | `185.156.73.54` | Source of attack traffic | block |
| ip | `198.51.100.22` | Source of attack traffic | block |
| ip | `203.0.113.45` | Source of attack traffic | block |
| ip | `45.33.32.156` | Source of attack traffic | block |
| ip | `185.220.101.1` | Source of attack traffic | block |
| port | `22` | Targeted service port | investigate |
| port | `8080` | Targeted service port | investigate |
| port | `3306` | Targeted service port | investigate |
| port | `80` | Targeted service port | investigate |
| port | `21` | Targeted service port | investigate |
| port | `445` | Targeted service port | investigate |
| port | `443` | Targeted service port | investigate |
| port | `23` | Targeted service port | investigate |
| port | `1433` | Targeted service port | investigate |
| port | `3389` | Targeted service port | investigate |
| port | `53` | Targeted service port | investigate |
| signature | `ALERT-BRUTE_FORCE` | Attack pattern: brute force | monitor |
| signature | `ALERT-DOS` | Attack pattern: dos | monitor |
| signature | `ALERT-PORT_SCAN` | Attack pattern: port scan | monitor |
| signature | `ALERT-WEB_ATTACK_XSS` | Attack pattern: web attack xss | monitor |
| signature | `ALERT-WEB_ATTACK_BRUTEFORCE` | Attack pattern: web attack bruteforce | monitor |
| signature | `ALERT-BOTNET` | Attack pattern: botnet | monitor |
| signature | `ALERT-DDOS` | Attack pattern: ddos | monitor |
| signature | `ALERT-WEB_ATTACK_SQL` | Attack pattern: web attack sql | monitor |
| signature | `ALERT-INFILTRATION` | Attack pattern: infiltration | monitor |

### Recommended Response Actions

- **[!] IMMEDIATE:** Immediately isolate affected hosts from the network
  - *Prevent lateral movement and data exfiltration while investigation proceeds*
- **[!] IMMEDIATE:** Block source IPs at the perimeter firewall
  - *Cut off attacker's active communication channel*
- **[!] IMMEDIATE:** Escalate to Incident Response team and CISO
  - *Critical severity incidents require leadership awareness and IR team engagement*
- **[*] URGENT:** Capture forensic images of affected systems before remediation
  - *Preserve evidence for root cause analysis and potential legal proceedings*
- **[*] URGENT:** Rotate credentials for all accounts that accessed affected systems
  - *Compromised credentials may have been harvested during the incident*

### MITRE ATT&CK Mapping

`T1110 - Brute Force`, `T1110.001 - Password Guessing`, `T1499 - Endpoint Denial of Service`, `T1046 - Network Service Discovery`, `T1059.007 - JavaScript`, `T1189 - Drive-by Compromise`, `T1190 - Exploit Public-Facing Application`, `T1583.005 - Botnet`, `T1071 - Application Layer Protocol`, `T1498 - Network Denial of Service`, `T1498.001 - Direct Network Flood`, `T1505.003 - Web Shell`, `T1078 - Valid Accounts`, `T1021 - Remote Services`

---

*Report generated by SOC Log Analyzer | 3282 events analyzed | Duration: 31h 19m*