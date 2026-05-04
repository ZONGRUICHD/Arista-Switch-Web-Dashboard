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

## TODO

### Completed

- [x] On-box single-file WebUI that runs directly on Arista EOS with Python.
- [x] HTTP service on TCP/2480.
- [x] Dashboard page with hostname, EOS version, CPU, memory, temperature, fan, PSU, alerts, events, and integration status.
- [x] Dedicated ports page at `/ports`.
- [x] Port up/down/media/error color states.
- [x] Per-port detail modal with status, VLAN, duplex, negotiated speed, media type, RX/TX Mbps, Kpps, errors, and raw EOS lines.
- [x] Per-port RX/TX line chart in the port detail modal.
- [x] Global traffic chart for aggregate interface throughput.
- [x] Dark mode toggle with browser-local persistence.
- [x] VLAN table collection with `show vlan brief`.
- [x] ARP table collection with `show arp`.
- [x] FDB/MAC table collection with `show mac address-table`.
- [x] LLDP neighbor collection with `show lldp neighbors`.
- [x] OSPF, OSPFv3, and BGP summary collection.
- [x] Basic alert generation for environment faults, fan/PSU issues, high temperature, interface errors, media-present/down links, and collection failures.
- [x] Syslog, sFlow, and NetFlow/IPFIX configuration detection.
- [x] Read-only command console with write/destructive command blocking.
- [x] Controlled configuration API requiring `confirm: "APPLY"`.
- [x] Dry-run preview for configuration templates.
- [x] Configuration templates for interface enable/disable, interface description, VLAN creation, access VLAN, routed interface, OSPF network, and BGP neighbor.

### Partially Done / Needs More Validation

- [ ] Validate all read parsers across more EOS versions and switch models.
- [ ] Validate LLDP parsing when system names, chassis IDs, or port IDs contain spaces.
- [ ] Improve OSPF/OSPFv3/BGP parsing beyond simple summary rows.
- [ ] Improve VLAN/ARP/FDB pagination and large-table rendering.
- [ ] Persist traffic history server-side instead of browser-only in-memory charts.
- [ ] Add authentication for the WebUI before production use.
- [ ] Add role-based access control for read-only users vs operators.
- [ ] Add complete audit logging for every configuration action.
- [ ] Add rollback helpers for configuration actions.
- [ ] Add startup persistence through EOS event-handler or a supported init mechanism.
- [ ] Test controlled write operations in a lab before production use.

### Not Done Yet

- [ ] PoE status and PoE control.
- [ ] Optical transceiver detail page using `show interfaces transceiver`.
- [ ] Optical power, DOM temperature, serial number, vendor, and threshold alarms.
- [ ] Interface counters history storage and longer time-range charts.
- [ ] Custom dashboard builder with draggable widgets.
- [ ] Multi-device automatic discovery.
- [ ] Multi-device topology map.
- [ ] Syslog receiver integration.
- [ ] NetFlow/sFlow/IPFIX collector integration.
- [ ] Alert notification channels.
- [ ] User login/session management.
- [ ] HTTPS/TLS support.
- [ ] Config diff before/after each write operation.
- [ ] Save configuration button with explicit confirmation.
- [ ] VLAN trunk configuration templates.
- [ ] SVI creation and gateway validation workflows.
- [ ] OSPF area/interface workflow.
- [ ] BGP address-family and route-policy workflows.
- [ ] Unit tests with captured EOS command fixtures.
- [ ] Browser UI regression tests.
- [ ] Packaging/release artifacts.

Production note: many features have only been tested in a limited environment. Validate commands, parsing, and write workflows in a lab before using this on production switches.
