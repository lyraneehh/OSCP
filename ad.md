### Check if domain joined
```
systeminfo | findstr /B /C:"Domain"
# If it returns a domain name, the machine is domain-joined.
# If it returns WORKGROUP, it's not part of a domain.
```
