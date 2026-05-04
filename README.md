# Arista Management Port Web Interface

## Deploy

Copy the on-box WebUI to the switch:

```powershell
scp .\onbox\arista7050_web.py admin@SWITCH_IP:/mnt/flash/arista7050_web.py
ssh admin@SWITCH_IP
```

Run it on EOS:

```text
enable
bash
python3 /mnt/flash/arista7050_web.py --host 0.0.0.0 --port 2480 --daemon
```

Allow access to TCP/2480 through the EOS control-plane ACL:

```text
configure terminal
ip access-list codex-web-2480-cp
   5 permit tcp any any eq 2480
system control-plane
   ip access-group codex-web-2480-cp in
write memory
```

Open the WebUI:

```text
http://SWITCH_IP:2480/
```
