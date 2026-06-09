# CrimsonWeb Scan Report — scanme.nmap.org

- **Scan time (UTC):** 2026-06-04 18:49:39 UTC
- **Target:** `scanme.nmap.org` (`45.33.32.156`)
- **RoE reference:** `BLD`
- **Scan mode:** syn-stealth
- **Egress mode:** direct
- **Tool:** CrimsonWeb v2.1.0

## Executive Summary

Scan identified **4** open service(s), **10** potential CVE match(es), **0** sensitive path exposure(s), **0** API endpoint indicator(s), **5** total web hardening finding(s). Overall risk: **High**.

**Recommendation:** Immediate remediation required for findings flagged Critical/High. 
See Findings section. Patch within 72 hours.

## Methodology

Authorized scan executed against the in-scope hosts under the referenced RoE. 
Techniques applied:

- Port discovery (async-connect / SYN as configured)
- Service fingerprinting via banner grabbing and protocol probes
- Passive WAF/header analysis
- HTTP security header, cookie flag, CORS and API path checks
- TLS certificate metadata collection when safe for the configured egress
- Sensitive path enumeration (limited list)
- NVD CVE correlation by detected version
- Multi-egress traffic with ban-aware backoff and adaptive pacing

Excluded by RoE: active exploitation, DoS, exfiltration, social engineering.

## Findings

### Port 22/tcp — ssh

- **Version:** `SSH-2.0-OpenSSH_6.6.1p1`
- **MITRE ATT&CK mapping:**
    - `T1046` Network Service Discovery: Open service exposed during authorized discovery
    - `T1021.004` SSH: SSH remote access service exposed
- **Potential CVEs:**
    - `CVE-2015-5352` (UNKNOWN): The x11_open_helper function in channels.c in ssh in OpenSSH before 6.9, when ForwardX11Trusted mode is not used, lacks a check of the refusal deadline for X connections, which makes it easier for ...
    - `CVE-2015-5600` (HIGH): The kbdint_next_device function in auth2-chall.c in sshd in OpenSSH through 6.9 does not properly restrict the processing of keyboard-interactive devices within a single connection, which makes it ...
    - `CVE-2015-6563` (MEDIUM): The monitor component in sshd in OpenSSH before 7.0 on non-OpenBSD platforms accepts extraneous username data in MONITOR_REQ_PAM_INIT_CTX requests, which allows local users to conduct impersonation...
    - `CVE-2015-6564` (HIGH): Use-after-free vulnerability in the mm_answer_pam_free_ctx function in monitor.c in sshd in OpenSSH before 7.0 on non-OpenBSD platforms might allow local users to gain privileges by leveraging cont...
    - `CVE-2016-3115` (MEDIUM): Multiple CRLF injection vulnerabilities in session.c in sshd in OpenSSH before 7.2p2 allow remote authenticated users to bypass intended shell-command restrictions via crafted X11 forwarding data, ...

**Remediation:** Upgrade to a patched release, restrict exposure where possible, 
monitor logs for exploitation attempts. Verify with vendor advisories.

### Port 80/tcp — http

- **Version:** `Apache/2.4.7 (Ubuntu)`
- **Title:** Go ahead and ScanMe!
- **Security header findings:**
    - `content-security-policy`: content-security-policy header not present
    - `x-frame-options`: x-frame-options header not present
    - `x-content-type-options`: x-content-type-options header not present
    - `referrer-policy`: referrer-policy header not present
    - `permissions-policy`: permissions-policy header not present
- **MITRE ATT&CK mapping:**
    - `T1046` Network Service Discovery: Open service exposed during authorized discovery
    - `T1190` Exploit Public-Facing Application: Public-facing web weakness or vulnerable component indicator
- **Potential CVEs:**
    - `CVE-2013-6438` (UNKNOWN): The dav_xml_get_cdata function in main/util.c in the mod_dav module in the Apache HTTP Server before 2.4.8 does not properly remove whitespace characters from CDATA sections, which allows remote at...
    - `CVE-2014-0098` (UNKNOWN): The log_cookie function in mod_log_config.c in the mod_log_config module in the Apache HTTP Server before 2.4.8 allows remote attackers to cause a denial of service (segmentation fault and daemon c...
    - `CVE-2013-5704` (UNKNOWN): The mod_headers module in the Apache HTTP Server 2.2.22 allows remote attackers to bypass "RequestHeader unset" directives by placing a header in the trailer portion of data sent with chunked trans...
    - `CVE-2014-0117` (UNKNOWN): The mod_proxy module in the Apache HTTP Server 2.4.x before 2.4.10, when a reverse proxy is enabled, allows remote attackers to cause a denial of service (child-process crash) via a crafted HTTP Co...
    - `CVE-2014-0118` (UNKNOWN): The deflate_in_filter function in mod_deflate.c in the mod_deflate module in the Apache HTTP Server before 2.4.10, when request body decompression is enabled, allows remote attackers to cause a den...

**Remediation:** Upgrade to a patched release, restrict exposure where possible, 
monitor logs for exploitation attempts. Verify with vendor advisories.

## MITRE ATT&CK Summary

- `T1046` **Network Service Discovery**: Open service exposed during authorized discovery
- `T1021.004` **SSH**: SSH remote access service exposed
- `T1190` **Exploit Public-Facing Application**: Public-facing web weakness or vulnerable component indicator

## Egress & Behavioral Log Summary

- **Egress mode:** direct
- **Total egress nodes:** 1
- **Total requests:** 51 (failures: 2)
- **Block events:** 0

## Appendix

- **Raw JSON report:** `reports\crimsonweb_45.33.32.156_20260604_184939Z.json`
- **Audit log (text):** `crimsonweb_audit.log`
- **Audit log (JSONL):** `crimsonweb_audit.jsonl`
