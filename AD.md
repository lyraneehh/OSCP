### Check if domain joined
```
systeminfo | findstr /B /C:"Domain"
# If it returns a domain name, the machine is domain-joined.
# If it returns WORKGROUP, it's not part of a domain.
```


### Powerview
# Users
Get-NetUser | select samaccountname

# DC IP
Get-NetDomainController -Domain domain.com

# Who is domain admin
Get-DomainGroupMember "Domain Admins" -Recurse

# You can use CME to get hostname <-> IP 

