#!/usr/bin/env python3
import argparse
import base64
import csv
import difflib
import io
import ipaddress
import json
import os
import re
import signal
import ssl
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import urllib.error
import urllib.request

MODEL = "Arista DCS-7050QX-32S-F"
DATA_DIR = os.environ.get("WEB_DATA_DIR", "/mnt/flash")
HISTORY_FILE = os.environ.get("WEB_HISTORY_FILE", os.path.join(DATA_DIR, "arista7050_web_history.json"))
AUDIT_FILE = os.environ.get("WEB_AUDIT_FILE", os.path.join(DATA_DIR, "arista7050_web_audit.jsonl"))
EAPI_URL = os.environ.get("WEB_EAPI_URL", "http://localhost:8080/command-api")
EAPI_ENABLED = os.environ.get("WEB_USE_EAPI", "1").lower() not in ("0", "false", "no")
READ_ONLY = re.compile(r"^(show|ping|traceroute|traceroute6|dir|more)\b", re.I)
BLOCKED = re.compile(r"^(configure|conf|enable|reload|reboot|write|copy|delete|erase|bash|sudo|install)\b", re.I)


def now_ms():
    return int(time.time() * 1000)


def read_json_file(path, fallback):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return fallback


def write_json_file(path, payload):
    try:
        directory = os.path.dirname(path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        tmp = "%s.tmp" % path
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, path)
    except Exception:
        pass


def append_audit(entry):
    record = dict(entry)
    record["time"] = now_ms()
    try:
        directory = os.path.dirname(AUDIT_FILE)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        with open(AUDIT_FILE, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    except Exception:
        pass


def is_safe_command(command):
    command = command.strip()
    return bool(command) and not BLOCKED.search(command) and bool(READ_ONLY.search(command))


def auth_credentials():
    user = os.environ.get("WEB_USERNAME", "").strip()
    password = os.environ.get("WEB_PASSWORD", "")
    return user, password


def run_cli(command, timeout=22):
    if not is_safe_command(command):
        raise ValueError("Only read-only commands are allowed: show / ping / traceroute / dir / more.")

    candidates = [
        ["FastCli", "-p", "15", "-c", command],
        ["/usr/bin/FastCli", "-p", "15", "-c", command],
        ["Cli", "-c", command],
        ["/usr/bin/Cli", "-c", command],
    ]

    last_error = None
    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            output = (result.stdout or "").strip()
            error = (result.stderr or "").strip()
            if result.returncode == 0 and output:
                return output
            last_error = error or output or "command returned %s" % result.returncode
        except FileNotFoundError as exc:
            last_error = str(exc)
        except subprocess.TimeoutExpired:
            raise TimeoutError("Command timed out.")

    raise RuntimeError(last_error or "No EOS CLI runner found.")


def run_eapi(commands, fmt="json", timeout=12):
    if not EAPI_ENABLED:
        raise RuntimeError("eAPI disabled by WEB_USE_EAPI.")
    if isinstance(commands, str):
        commands = [commands]
    commands = [str(command).strip() for command in commands if str(command).strip()]
    for command in commands:
        if not is_safe_command(command):
            raise ValueError("Only read-only commands are allowed: show / ping / traceroute / dir / more.")
    payload = {
        "jsonrpc": "2.0",
        "method": "runCmds",
        "params": {"version": 1, "cmds": commands, "format": fmt},
        "id": "arista-webui-%s" % now_ms(),
    }
    request = urllib.request.Request(
        EAPI_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        raise RuntimeError("eAPI unavailable: %s" % exc)
    try:
        data = json.loads(body)
    except ValueError:
        raise RuntimeError("eAPI returned non-JSON response.")
    if data.get("error"):
        error = data.get("error") or {}
        details = error.get("data") or error.get("message") or error
        raise RuntimeError("eAPI command failed: %s" % details)
    result = data.get("result")
    if not isinstance(result, list):
        raise RuntimeError("eAPI returned unexpected result.")
    return result


def eapi_text_value(item):
    if isinstance(item, dict):
        return str(item.get("output", "")).strip()
    return str(item or "").strip()


def run_eapi_text(command, timeout=12):
    result = run_eapi([command], fmt="text", timeout=timeout)
    return eapi_text_value(result[0]) if result else ""


def run_read_command(command, timeout=22):
    try:
        return run_eapi_text(command, timeout=min(timeout, 12))
    except Exception:
        return run_cli(command, timeout=timeout)


def run_eapi_json_map(commands, timeout=12):
    mapping = {}
    try:
        results = run_eapi(commands, fmt="json", timeout=timeout)
        for command, result in zip(commands, results):
            mapping[command] = result if isinstance(result, dict) else {}
        return mapping
    except Exception:
        pass
    for command in commands:
        try:
            result = run_eapi([command], fmt="json", timeout=timeout)
            mapping[command] = result[0] if result and isinstance(result[0], dict) else {}
        except Exception:
            mapping[command] = {}
    return mapping


def run_eos_script(script, timeout=25):
    runners = [["/usr/bin/Cli", "-c", script], ["Cli", "-c", script], ["/usr/bin/FastCli", "-p", "15", "-c", script]]
    last_error = None
    for cmd in runners:
        try:
            result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
            output = ((result.stdout or "") + (result.stderr or "")).strip()
            if result.returncode == 0:
                return output or "OK"
            last_error = output or "command returned %s" % result.returncode
        except FileNotFoundError as exc:
            last_error = str(exc)
    raise RuntimeError(last_error or "No EOS CLI runner found.")


def normalize_interface(token):
    match = re.match(r"^(?:Et|Ethernet)([\d/]+)$", str(token), re.I)
    if match:
        return "Ethernet%s" % match.group(1)
    return str(token)


def parse_hostname(output):
    match = re.search(r"^Hostname:\s*(.+)$", output, re.I | re.M)
    if match:
        return match.group(1).strip()
    fqdn = re.search(r"^FQDN:\s*(.+)$", output, re.I | re.M)
    if fqdn:
        return fqdn.group(1).strip()
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-1] if lines else "arista-7050qx"


def parse_version(output):
    version = "-"
    serial = "-"
    version_match = re.search(r"Software image version:\s*([^\r\n]+)", output, re.I)
    if not version_match:
        version_match = re.search(r"EOS version:\s*([^\r\n]+)", output, re.I)
    serial_match = re.search(r"Serial number:\s*(\S+)", output, re.I)
    if version_match:
        version = version_match.group(1).strip()
    if serial_match:
        serial = serial_match.group(1).strip()
    return version, serial


def parse_version_json(data):
    data = data or {}
    return str(data.get("version") or "-"), str(data.get("serialNumber") or "-")


def interface_sort_key(name):
    text = str(name or "")
    prefix = re.sub(r"[\d/].*$", "", text)
    numbers = [int(part) for part in re.findall(r"\d+", text)]
    return (prefix, numbers, text)


def format_bandwidth(bps):
    try:
        value = float(bps)
    except (TypeError, ValueError):
        return "-"
    if value <= 0:
        return "-"
    units = [(1000000000000.0, "T"), (1000000000.0, "G"), (1000000.0, "M"), (1000.0, "K")]
    for factor, suffix in units:
        if value >= factor:
            number = value / factor
            return ("%g%s" % (number, suffix)).upper()
    return "%gbps" % value


def format_duration(seconds):
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return "-"
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    if days:
        return "%dd %02dh %02dm" % (days, hours, minutes)
    if hours:
        return "%dh %02dm %02ds" % (hours, minutes, seconds)
    return "%dm %02ds" % (minutes, seconds)


def normalize_duplex(value):
    lower = str(value or "").lower()
    if "full" in lower:
        return "full"
    if "half" in lower:
        return "half"
    return clean_optic_value(value)


def parse_interfaces_json(data):
    statuses = (data or {}).get("interfaceStatuses") or {}
    ports = []
    for name, item in sorted(statuses.items(), key=lambda pair: interface_sort_key(pair[0])):
        normalized = normalize_interface(name)
        if not re.match(r"^Ethernet\d", normalized, re.I):
            continue
        vlan_info = item.get("vlanInformation") or {}
        vlan = vlan_info.get("vlanId")
        if vlan is None:
            vlan = vlan_info.get("interfaceMode") or vlan_info.get("interfaceForwardingModel") or "-"
        link = str(item.get("linkStatus") or item.get("lineProtocolStatus") or "").lower()
        media = clean_optic_value(item.get("interfaceType"))
        status = "up" if link in ("connected", "up") else "down"
        port = {
            "name": normalized,
            "label": short_interface_name(normalized),
            "media": media,
            "speed": format_bandwidth(item.get("bandwidth")),
            "duplex": normalize_duplex(item.get("duplex")),
            "status": status,
            "vlan": str(vlan),
            "description": str(item.get("description") or ""),
            "rxMbps": 0.0,
            "txMbps": 0.0,
            "rxKpps": 0.0,
            "txKpps": 0.0,
            "errors": 0,
            "statusLine": "%s %s vlan=%s speed=%s media=%s" % (short_interface_name(normalized), link or "-", vlan, format_bandwidth(item.get("bandwidth")), media),
        }
        port["hasMedia"] = bool(media and media.lower() not in ("-", "not present"))
        ports.append(port)
    return ports


def parse_interface_rates_json(data):
    rates = {}
    for name, item in ((data or {}).get("interfaces") or {}).items():
        key = normalize_interface(name).lower()
        in_bps = float(item.get("inBpsRate") or 0)
        out_bps = float(item.get("outBpsRate") or 0)
        in_pps = float(item.get("inPpsRate") or item.get("inPktsRate") or 0)
        out_pps = float(item.get("outPpsRate") or item.get("outPktsRate") or 0)
        rates[key] = {
            "rxMbps": round(in_bps / 1000000.0, 4),
            "txMbps": round(out_bps / 1000000.0, 4),
            "rxKpps": round(in_pps / 1000.0, 4),
            "txKpps": round(out_pps / 1000.0, 4),
        }
    return rates


def parse_interface_errors_json(data):
    errors = {}
    for name, item in ((data or {}).get("interfaceErrorCounters") or {}).items():
        total = 0
        for value in item.values():
            if isinstance(value, (int, float)):
                total += int(value)
        errors[normalize_interface(name).lower()] = {"errors": total}
    return errors


def parse_system_health_json(top_data, environment_output, version_data):
    health = parse_environment(environment_output)
    cpu_info = (top_data or {}).get("cpuInfo") or {}
    cpu_values = cpu_info.get("%Cpu(s)") or next((value for value in cpu_info.values() if isinstance(value, dict)), {})
    idle = float(cpu_values.get("idle") or 0) if isinstance(cpu_values, dict) else 0
    cpu = max(0, min(100, round(100 - idle))) if idle else 0

    physical = ((top_data or {}).get("memInfo") or {}).get("physicalMem") or {}
    total_kib = float(physical.get("memTotal") or (version_data or {}).get("memTotal") or 0)
    used_kib = float(physical.get("memUsed") or 0)
    free_kib = float(physical.get("memFree") or (version_data or {}).get("memFree") or 0)
    buffer_kib = float(physical.get("memBuffer") or 0)
    available_kib = free_kib + buffer_kib if buffer_kib else free_kib
    if not used_kib and total_kib:
        used_kib = max(0.0, total_kib - available_kib)
    memory = round((used_kib / total_kib) * 100) if total_kib else 0
    health.update(
        {
            "cpu": cpu,
            "memory": memory,
            "memoryTotalMiB": round(total_kib / 1024.0, 1) if total_kib else 0,
            "memoryUsedMiB": round(used_kib / 1024.0, 1) if used_kib else 0,
            "memoryAvailableMiB": round(available_kib / 1024.0, 1) if available_kib else 0,
        }
    )
    return health


def parse_lldp_json(data):
    rows = []
    neighbors = (data or {}).get("lldpNeighbors") or {}
    if isinstance(neighbors, list):
        iterable = [(item.get("port") or item.get("interface") or "-", {"lldpNeighborInfo": [item]}) for item in neighbors if isinstance(item, dict)]
    else:
        iterable = neighbors.items()
    for port, entry in iterable:
        infos = []
        if isinstance(entry, dict):
            infos = entry.get("lldpNeighborInfo") or entry.get("neighbors") or []
        elif isinstance(entry, list):
            infos = entry
        for info in infos:
            if not isinstance(info, dict):
                continue
            iface = normalize_interface(port)
            neighbor_iface = info.get("neighborInterfaceInfo") or {}
            management = info.get("managementAddresses") or []
            management_address = "-"
            if management and isinstance(management[0], dict):
                management_address = clean_lldp_value(management[0].get("address"))
            neighbor_port = clean_lldp_value(neighbor_iface.get("interfaceId_v2") or neighbor_iface.get("interfaceId") or info.get("neighborPort"))
            row = {
                "port": iface,
                "label": short_interface_name(iface),
                "neighbor": clean_lldp_value(info.get("systemName") or info.get("neighborDevice") or info.get("chassisId")),
                "neighborPort": neighbor_port,
                "ttl": str(info.get("ttl") or "-"),
                "chassisId": clean_lldp_value(info.get("chassisId")),
                "managementAddress": management_address,
                "raw": json.dumps(info, ensure_ascii=True, separators=(",", ":"))[:1200],
            }
            rows.append(row)
    return rows


def parse_vlans_json(data):
    rows = []
    for vlan_id, item in sorted(((data or {}).get("vlans") or {}).items(), key=lambda pair: int(pair[0]) if str(pair[0]).isdigit() else 0):
        interfaces = item.get("interfaces") or {}
        rows.append(
            {
                "id": str(vlan_id),
                "name": str(item.get("name") or "-"),
                "status": str(item.get("status") or "-"),
                "ports": ", ".join(short_interface_name(name) for name in sorted(interfaces, key=interface_sort_key)),
            }
        )
    return rows


def parse_arp_json(data):
    rows = []
    for item in (data or {}).get("ipV4Neighbors") or []:
        rows.append(
            {
                "address": str(item.get("address") or "-"),
                "mac": normalize_mac_display(item.get("hwAddress")),
                "interface": str(item.get("interface") or "-"),
                "raw": json.dumps(item, ensure_ascii=True, separators=(",", ":")),
            }
        )
    return rows


def normalize_mac_display(value):
    text = str(value or "-").strip().lower()
    compact = re.sub(r"[^0-9a-f]", "", text)
    if len(compact) == 12:
        return "%s.%s.%s" % (compact[:4], compact[4:8], compact[8:])
    return text or "-"


def parse_fdb_json(data):
    rows = []
    tables = []
    for table_name in ("unicastTable", "multicastTable"):
        table = ((data or {}).get(table_name) or {}).get("tableEntries") or []
        tables.extend(table)
    for item in tables:
        rows.append(
            {
                "vlan": str(item.get("vlanId") or "-"),
                "mac": normalize_mac_display(item.get("macAddress")),
                "type": str(item.get("entryType") or "-"),
                "port": short_interface_name(item.get("interface") or "-"),
                "raw": json.dumps(item, ensure_ascii=True, separators=(",", ":")),
            }
        )
    return rows


def metric_value(value, unit):
    if value is None:
        return "-"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return clean_optic_value(value)
    return ("%g %s" % (number, unit)).strip()


def parse_transceivers_json(summary_data, detail_data=None, properties_data=None, inventory_data=None):
    modules = {}
    interfaces = (summary_data or {}).get("interfaces") or {}
    detail_interfaces = (detail_data or {}).get("interfaces") or {}
    property_interfaces = (properties_data or {}).get("interfaces") or {}
    for name in sorted(set(list(interfaces.keys()) + list(detail_interfaces.keys()) + list(property_interfaces.keys())), key=interface_sort_key):
        normalized = normalize_interface(name)
        if not re.match(r"^Ethernet\d", normalized, re.I):
            continue
        item = modules.setdefault(normalized.lower(), blank_transceiver(normalized))
        summary = interfaces.get(name) or {}
        detail = detail_interfaces.get(name) or {}
        props = property_interfaces.get(name) or {}
        item["type"] = clean_optic_value(summary.get("mediaType") or detail.get("mediaType") or props.get("mediaType"))
        item["serial"] = clean_optic_value(summary.get("vendorSn") or detail.get("vendorSn") or item.get("serial"))
        item["temperature"] = metric_value(summary.get("temperature", detail.get("temperature")), "C")
        item["txPower"] = metric_value(summary.get("txPower", detail.get("txPower")), "dBm")
        item["rxPower"] = metric_value(summary.get("rxPower", detail.get("rxPower")), "dBm")
        item["voltage"] = metric_value(summary.get("voltage", detail.get("voltage")), "V")
        item["current"] = metric_value(summary.get("txBias", detail.get("txBias")), "mA")
        if summary.get("updateTime") or detail.get("updateTime"):
            item["lastUpdate"] = format_duration(time.time() - float(summary.get("updateTime") or detail.get("updateTime")))
        thresholds = (detail.get("details") or {})
        for metric, label, unit in (
            ("temperature", "Temperature", "C"),
            ("voltage", "Voltage", "V"),
            ("txBias", "Current", "mA"),
            ("txPower", "TX power", "dBm"),
            ("rxPower", "RX power", "dBm"),
        ):
            threshold = thresholds.get(metric) or {}
            value = detail.get(metric, summary.get(metric))
            add_threshold_alert(item, label, value, threshold.get("highAlarm"), threshold.get("highWarn"), threshold.get("lowAlarm"), threshold.get("lowWarn"), unit)
        item["present"] = transceiver_present(item)

    for slot, inv in ((inventory_data or {}).get("xcvrSlots") or {}).items():
        normalized = normalize_interface("Ethernet%s" % slot)
        key = normalized.lower()
        item = modules.setdefault(key, blank_transceiver(normalized))
        vendor = clean_optic_value(inv.get("mfgName"))
        model = clean_optic_value(inv.get("modelName"))
        serial = clean_optic_value(inv.get("serialNum"))
        if vendor.lower() == "not present":
            if not transceiver_present(item):
                item["present"] = False
            continue
        if vendor != "-":
            item["vendor"] = vendor
        if model != "-":
            item["model"] = model
        if serial != "-":
            item["serial"] = serial
        item["present"] = transceiver_present(item)

    for item in modules.values():
        item["present"] = transceiver_present(item)
    return modules


def parse_protocols_json(ospf_data=None, ospfv3_data=None, bgp_data=None):
    def bgp_rows(data):
        rows = []
        for vrf_name, vrf in ((data or {}).get("vrfs") or {}).items():
            peers = vrf.get("peers") or {}
            for peer, item in peers.items():
                rows.append(
                    {
                        "peer": str(peer),
                        "asn": str(item.get("asn") or item.get("peerAsn") or item.get("remoteAs") or "-"),
                        "state": str(item.get("peerState") or item.get("state") or item.get("established") or "-"),
                        "vrf": str(vrf_name),
                        "raw": json.dumps(item, ensure_ascii=True, separators=(",", ":")),
                    }
                )
        return rows

    def ospf_rows(data):
        rows = []

        def walk(value):
            if isinstance(value, dict):
                if any(key in value for key in ("neighborId", "routerId", "neighborAddress")) and any(key in value for key in ("adjacencyState", "state", "interfaceName")):
                    rows.append(
                        {
                            "neighbor": str(value.get("neighborId") or value.get("routerId") or value.get("neighborAddress") or "-"),
                            "state": str(value.get("adjacencyState") or value.get("state") or "-"),
                            "interface": str(value.get("interfaceName") or value.get("interface") or "-"),
                            "raw": json.dumps(value, ensure_ascii=True, separators=(",", ":")),
                        }
                    )
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk((data or {}).get("vrfs") or {})
        return rows

    return {"ospf": ospf_rows(ospf_data), "ospfv3": ospf_rows(ospfv3_data), "bgp": bgp_rows(bgp_data)}


def parse_interfaces(output):
    ports = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or not re.match(r"^(Et|Ethernet)\d+(?:/\d+)?\b", stripped, re.I):
            continue

        tokens = stripped.split()
        port = {
            "name": normalize_interface(tokens[0]),
            "label": tokens[0],
            "media": "-",
            "speed": "-",
            "duplex": "-",
            "status": "down",
            "vlan": "-",
            "description": "",
            "rxMbps": 0.0,
            "txMbps": 0.0,
            "rxKpps": 0.0,
            "txKpps": 0.0,
            "errors": 0,
            "statusLine": stripped,
        }

        status_index = -1
        for idx, token in enumerate(tokens):
            if token.lower() in ("connected", "notconnect", "disabled", "errdisabled", "inactive"):
                status_index = idx
                break

        if status_index >= 0:
            port["status"] = "up" if tokens[status_index].lower() == "connected" else "down"
            if status_index + 1 < len(tokens):
                port["vlan"] = tokens[status_index + 1]
            if status_index + 2 < len(tokens):
                port["duplex"] = tokens[status_index + 2]
            if status_index + 3 < len(tokens):
                port["speed"] = tokens[status_index + 3].upper()
            if status_index + 4 < len(tokens):
                port["media"] = " ".join(tokens[status_index + 4:])
        if status_index > 1:
            port["description"] = " ".join(tokens[1:status_index])
        port["hasMedia"] = bool(port["media"] and port["media"].lower() not in ("-", "not present"))
        ports.append(port)

    return ports


def parse_interface_rates(output):
    rates = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or not re.match(r"^(Et|Ethernet|Ma)\S+", stripped, re.I):
            continue
        tokens = stripped.split()
        interval_index = -1
        for idx, token in enumerate(tokens):
            if re.match(r"^\d+:\d+$", token):
                interval_index = idx
                break
        if interval_index < 0 or len(tokens) <= interval_index + 6:
            continue

        def to_float(value):
            try:
                return float(str(value).replace("%", ""))
            except ValueError:
                return 0.0

        rates[normalize_interface(tokens[0]).lower()] = {
            "rxMbps": to_float(tokens[interval_index + 1]),
            "rxPercent": to_float(tokens[interval_index + 2]),
            "rxKpps": to_float(tokens[interval_index + 3]),
            "txMbps": to_float(tokens[interval_index + 4]),
            "txPercent": to_float(tokens[interval_index + 5]),
            "txKpps": to_float(tokens[interval_index + 6]),
            "rateLine": stripped,
        }
    return rates


def parse_interface_errors(output):
    errors = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or not re.match(r"^(Et|Ethernet|Ma)\S+", stripped, re.I):
            continue
        tokens = stripped.split()
        total = 0
        for token in tokens[1:]:
            if re.match(r"^\d+$", token):
                total += int(token)
        errors[normalize_interface(tokens[0]).lower()] = {"errors": total, "errorLine": stripped}
    return errors


def enrich_ports(ports, rates, errors, transceivers=None):
    transceivers = transceivers or {}
    enriched = []
    for port in ports:
        key = port["name"].lower()
        item = dict(port)
        item.update(rates.get(key, {}))
        item.update(errors.get(key, {}))
        item["transceiver"] = transceivers.get(key, {})
        item["errors"] = int(item.get("errors") or 0)
        enriched.append(item)
    return enriched


def parse_environment(output):
    text = output.lower()
    temperatures = []
    ambient = re.search(r"Ambient temperature:\s*(-?\d+(?:\.\d+)?)\s*C", output, re.I)
    if ambient:
        temperatures.append(float(ambient.group(1)))
    for line in output.splitlines():
        match = re.match(r"^\s*\d+\s+.+?\s+(-?\d+(?:\.\d+)?)\s+(?:\(|N/A|[-\d])", line)
        if match:
            value = float(match.group(1))
            if value > 0:
                temperatures.append(value)
    temperature = round(max(temperatures)) if temperatures else 40

    temp_status = re.search(r"System temperature status is:\s*([A-Za-z]+)", output, re.I)
    cooling_status = re.search(r"System cooling status is:\s*([A-Za-z]+)", output, re.I)
    fan_status = "OK"
    if cooling_status and cooling_status.group(1).lower() != "ok":
        fan_status = "CHECK"
    elif not cooling_status and re.search(r"^\s*(?:\d+/\d+|PowerSupply\d+/\d+)\s+(?!Ok\b)\S+", output, re.I | re.M):
        fan_status = "CHECK"

    psu_statuses = []
    for line in output.splitlines():
        tokens = line.split()
        if len(tokens) >= 7 and tokens[0].isdigit() and re.match(r"^PWR|^PSU", tokens[1], re.I):
            status = " ".join(tokens[6:])
            status = re.sub(r"\s+\d+:\d+:\d+$", "", status).strip().lower()
            if status and not re.search(r"\b(not present|not inserted|absent|empty)\b", status):
                psu_statuses.append(status if status == "ok" else "PSU%s %s" % (tokens[0], status))
    psu_ok = any(status == "ok" for status in psu_statuses)
    psu_fault = any(re.search(r"\b(fail|fault|bad|error|overheat|power loss|offline)\b", status) for status in psu_statuses)
    psu_redundancy_lost = len(psu_statuses) > 1 and any(status != "ok" for status in psu_statuses)
    psu_status = "CHECK" if psu_fault or psu_redundancy_lost or (psu_statuses and not psu_ok) else "OK"

    if temp_status and temp_status.group(1).lower() != "ok":
        fan_status = "CHECK"
    return {
        "temperature": temperature,
        "fanStatus": fan_status,
        "psuStatus": psu_status,
        "psuDetails": psu_statuses,
    }


def parse_system_health(top_output, environment_output, version_output):
    health = parse_environment(environment_output)
    cpu = 0
    idle_match = re.search(r"([\d.]+)\s*id", top_output)
    if idle_match:
        cpu = max(0, min(100, round(100 - float(idle_match.group(1)))))

    mem_total = mem_used = mem_free = mem_avail = 0.0
    mem_match = re.search(
        r"MiB Mem\s*:\s*([\d.]+)\s+total,\s*([\d.]+)\s+free,\s*([\d.]+)\s+used,\s*([\d.]+)\s+buff/cache",
        top_output,
        re.I,
    )
    avail_match = re.search(r"([\d.]+)\s+avail Mem", top_output, re.I)
    if mem_match:
        mem_total = float(mem_match.group(1))
        mem_free = float(mem_match.group(2))
        mem_used = float(mem_match.group(3))
        mem_avail = float(avail_match.group(1)) if avail_match else mem_free
    else:
        total_match = re.search(r"Total memory:\s*(\d+)\s*kB", version_output, re.I)
        free_match = re.search(r"Free memory:\s*(\d+)\s*kB", version_output, re.I)
        if total_match:
            mem_total = int(total_match.group(1)) / 1024.0
        if free_match:
            mem_free = int(free_match.group(1)) / 1024.0
        mem_avail = mem_free
        mem_used = max(0.0, mem_total - mem_free)

    memory = round(((mem_total - mem_avail) / mem_total) * 100) if mem_total else 0
    health.update(
        {
            "cpu": cpu,
            "memory": memory,
            "memoryTotalMiB": round(mem_total, 1),
            "memoryUsedMiB": round(mem_used, 1),
            "memoryAvailableMiB": round(mem_avail, 1),
        }
    )
    return health


def format_rate(mbps):
    if mbps >= 1000000:
        return "%.2f Tbps" % (mbps / 1000000.0)
    if mbps >= 1000:
        return "%.2f Gbps" % (mbps / 1000.0)
    return "%.2f Mbps" % mbps


def format_packets(kpps):
    if kpps >= 1000000:
        return "%.2f Bpps" % (kpps / 1000000.0)
    if kpps >= 1000:
        return "%.2f Mpps" % (kpps / 1000.0)
    return "%.2f Kpps" % kpps


def traffic_summary(ports):
    rx_mbps = sum(float(port.get("rxMbps") or 0) for port in ports)
    tx_mbps = sum(float(port.get("txMbps") or 0) for port in ports)
    rx_kpps = sum(float(port.get("rxKpps") or 0) for port in ports)
    tx_kpps = sum(float(port.get("txKpps") or 0) for port in ports)
    total_mbps = rx_mbps + tx_mbps
    total_kpps = rx_kpps + tx_kpps
    return {
        "rxMbps": round(rx_mbps, 2),
        "txMbps": round(tx_mbps, 2),
        "totalMbps": round(total_mbps, 2),
        "rxKpps": round(rx_kpps, 2),
        "txKpps": round(tx_kpps, 2),
        "totalKpps": round(total_kpps, 2),
        "throughputLabel": format_rate(total_mbps),
        "packetRateLabel": format_packets(total_kpps),
        "capacityUtilization": round((total_mbps / 2560000.0) * 100, 4),
    }


def update_history(ports, traffic):
    history = read_json_file(HISTORY_FILE, {"traffic": [], "ports": {}})
    if not isinstance(history, dict):
        history = {"traffic": [], "ports": {}}
    history.setdefault("traffic", [])
    history.setdefault("ports", {})

    point = {"time": now_ms(), "rxMbps": traffic.get("rxMbps", 0), "txMbps": traffic.get("txMbps", 0), "totalMbps": traffic.get("totalMbps", 0)}
    history["traffic"].append(point)
    history["traffic"] = history["traffic"][-2880:]

    for port in ports:
        name = port.get("name")
        if not name:
            continue
        series = history["ports"].setdefault(name, [])
        series.append({"time": point["time"], "rxMbps": port.get("rxMbps", 0), "txMbps": port.get("txMbps", 0), "errors": port.get("errors", 0)})
        history["ports"][name] = series[-2880:]

    write_json_file(HISTORY_FILE, history)
    return history


def compact_history(history, limit=80, include_ports=True):
    if not isinstance(history, dict):
        return {"traffic": [], "ports": {}}
    ports = history.get("ports") if isinstance(history.get("ports"), dict) else {}
    return {
        "traffic": list(history.get("traffic") or [])[-limit:],
        "ports": {name: list(series or [])[-limit:] for name, series in ports.items()} if include_ports else {},
    }


def clean_lldp_value(value):
    return str(value or "").strip().strip('"') or "-"


def short_interface_name(name):
    normalized = normalize_interface(name)
    match = re.match(r"^Ethernet(.+)$", normalized, re.I)
    if match:
        return "Et%s" % match.group(1)
    if re.match(r"^Management(\d+)$", normalized, re.I):
        return re.sub(r"^Management", "Ma", normalized, flags=re.I)
    return normalized


def parse_lldp_detail(output):
    neighbors = []
    current_port = None
    current = None

    def finish():
        if not current:
            return
        if current.get("neighbor") == "-" and current.get("chassisId") != "-":
            current["neighbor"] = current["chassisId"]
        current["raw"] = "\n".join(current.pop("_raw", []))
        neighbors.append(current)

    for line in output.splitlines():
        stripped = line.strip()
        interface = re.match(r"^Interface\s+(\S+)\s+detected\s+\d+\s+LLDP neighbors", stripped, re.I)
        if interface:
            finish()
            current = None
            current_port = normalize_interface(interface.group(1))
            continue
        if not current_port:
            continue
        neighbor = re.match(r"^Neighbor\s+(.+?),\s+age\s+(.+)$", stripped, re.I)
        if neighbor:
            finish()
            current = {
                "port": current_port,
                "label": short_interface_name(current_port),
                "neighbor": "-",
                "neighborPort": "-",
                "ttl": "-",
                "chassisId": "-",
                "managementAddress": "-",
                "_raw": [stripped],
            }
            descriptor = clean_lldp_value(neighbor.group(1))
            if descriptor != "-":
                current["neighbor"] = descriptor
            continue
        if not current:
            continue
        current["_raw"].append(stripped)
        fields = {
            "chassisId": r"^-?\s*Chassis ID\s*:\s*(.+)$",
            "neighborPort": r"^-?\s*Port ID\s*:\s*(.+)$",
            "neighbor": r"^-?\s*System Name:\s*(.+)$",
            "managementAddress": r"^-?\s*Management Address\s*:\s*(.+)$",
        }
        for key, pattern in fields.items():
            match = re.match(pattern, stripped, re.I)
            if match:
                current[key] = clean_lldp_value(match.group(1))
        ttl = re.match(r"^-?\s*Time To Live:\s*(\d+)", stripped, re.I)
        if ttl:
            current["ttl"] = ttl.group(1)
    finish()
    return neighbors


def parse_lldp_neighbors(output, detail_output=""):
    detail_neighbors = parse_lldp_detail(detail_output)
    if detail_neighbors:
        return detail_neighbors

    neighbors = []
    neighbor_start = None
    neighbor_port_start = None
    ttl_start = None
    for line in output.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("port") and "neighbor device id" in lower:
            neighbor_start = line.lower().find("neighbor device id")
            neighbor_port_start = line.lower().find("neighbor port id")
            ttl_start = line.lower().find("ttl")
            continue
        if not stripped or lower.startswith(("last table", "number of", "port", "----")):
            continue
        if not re.match(r"^(Et|Ethernet|Ma|Management)\S+", stripped, re.I):
            continue
        if neighbor_start is not None and neighbor_port_start is not None and ttl_start is not None:
            port = line[:neighbor_start].strip()
            neighbor = line[neighbor_start:neighbor_port_start].strip()
            neighbor_port = line[neighbor_port_start:ttl_start].strip()
            ttl = line[ttl_start:].strip().split()[0] if line[ttl_start:].strip() else "-"
        else:
            tokens = stripped.split()
            if len(tokens) < 2:
                continue
            port = tokens[0]
            ttl = tokens[-1] if tokens[-1].isdigit() else "-"
            neighbor_port = tokens[-2] if len(tokens) > 3 else "-"
            neighbor = " ".join(tokens[1:-2]) if len(tokens) > 3 else tokens[1]
        neighbors.append(
            {
                "port": normalize_interface(port),
                "label": port,
                "neighbor": clean_lldp_value(neighbor),
                "neighborPort": clean_lldp_value(neighbor_port),
                "ttl": ttl,
                "raw": stripped,
            }
        )
    return neighbors


def parse_vlans(output):
    vlans = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or not re.match(r"^\d+\s+", stripped):
            continue
        parts = stripped.split(None, 3)
        vlan = {"id": parts[0], "name": parts[1] if len(parts) > 1 else "-", "status": parts[2] if len(parts) > 2 else "-", "ports": parts[3] if len(parts) > 3 else ""}
        vlans.append(vlan)
    return vlans


def parse_arp(output):
    rows = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("address", "protocol")):
            continue
        if not re.search(r"\d+\.\d+\.\d+\.\d+", stripped):
            continue
        tokens = stripped.split()
        rows.append(
            {
                "address": next((token for token in tokens if re.match(r"\d+\.\d+\.\d+\.\d+", token)), "-"),
                "mac": next((token for token in tokens if re.match(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", token, re.I)), "-"),
                "interface": tokens[-1] if tokens else "-",
                "raw": stripped,
            }
        )
    return rows


def parse_fdb(output):
    rows = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("vlan", "mac address", "---")):
            continue
        mac = re.search(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", stripped, re.I)
        if not mac:
            continue
        tokens = stripped.split()
        mac_index = next((i for i, token in enumerate(tokens) if re.match(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", token, re.I)), -1)
        entry_type = tokens[mac_index + 1] if mac_index >= 0 and len(tokens) > mac_index + 1 else "-"
        port = tokens[mac_index + 2] if mac_index >= 0 and len(tokens) > mac_index + 2 else "-"
        rows.append(
            {
                "vlan": tokens[mac_index - 1] if mac_index > 0 else (tokens[0] if tokens else "-"),
                "mac": mac.group(0),
                "type": entry_type if entry_type.lower() in ("dynamic", "static", "learned", "multicast", "cpu") else next((token for token in tokens if token.lower() in ("dynamic", "static", "learned")), "-"),
                "port": port,
                "raw": stripped,
            }
        )
    return rows


def clean_optic_value(value):
    value = str(value or "").replace("\x00", "").strip().strip('"')
    if not value or value.upper() in ("N/A", "NA", "NONE", "NOT PRESENT"):
        return "-"
    return value


def optic_value_with_unit(value, unit):
    value = clean_optic_value(value)
    if value == "-":
        return "-"
    if re.search(r"[A-Za-z%]", value):
        return value
    return "%s %s" % (value, unit)


def optic_number(value):
    value = clean_optic_value(value)
    if value == "-":
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", value)
    return float(match.group(0)) if match else None


def blank_transceiver(name):
    return {
        "interface": name,
        "present": False,
        "type": "-",
        "vendor": "-",
        "model": "-",
        "serial": "-",
        "temperature": "-",
        "txPower": "-",
        "rxPower": "-",
        "alerts": [],
        "raw": "",
    }


def transceiver_present(item):
    return any(clean_optic_value(item.get(key)) != "-" for key in ("type", "vendor", "model", "serial", "temperature", "txPower", "rxPower"))


def parse_transceiver_csv(output, modules):
    try:
        reader = csv.DictReader(io.StringIO(output))
    except Exception:
        return
    for row in reader:
        port = row.get("Port (Interface Name)") or row.get("Port") or row.get("Interface")
        if not port:
            continue
        name = normalize_interface(port.strip())
        key = name.lower()
        item = modules.setdefault(key, blank_transceiver(name))
        media = clean_optic_value(row.get("Media type"))
        serial = clean_optic_value(row.get("Xcvr Serial Number"))
        if media != "-":
            item["type"] = media
        if serial != "-":
            item["serial"] = serial
        item["temperature"] = optic_value_with_unit(row.get("Temperature (Celsius)"), "C")
        item["txPower"] = optic_value_with_unit(row.get("Tx Power (dBm)"), "dBm")
        item["rxPower"] = optic_value_with_unit(row.get("Rx Power (dBm)"), "dBm")
        voltage = optic_value_with_unit(row.get("Voltage (Volts)"), "V")
        current = optic_value_with_unit(row.get("Current (mA)"), "mA")
        if voltage != "-":
            item["voltage"] = voltage
        if current != "-":
            item["current"] = current
        last_update = clean_optic_value(row.get("Last Update"))
        if last_update != "-":
            item["lastUpdate"] = last_update
        item["present"] = transceiver_present(item)


def parse_transceiver_properties(output, modules):
    current = None
    for line in output.splitlines():
        stripped = line.strip()
        match = re.match(r"^Name:\s*(\S+)", stripped, re.I)
        if match:
            name = normalize_interface(match.group(1))
            if not re.match(r"^Ethernet\d", name, re.I):
                current = None
                continue
            current = name.lower()
            modules.setdefault(current, blank_transceiver(name))
            continue
        if not current or current not in modules:
            continue
        media = re.match(r"^Media type:\s*(.+)$", stripped, re.I)
        if media:
            value = clean_optic_value(media.group(1))
            if value == "-":
                modules[current]["present"] = False
            else:
                modules[current]["type"] = value
                modules[current]["present"] = True


def parse_transceiver_inventory(output, modules):
    in_slots = False
    for line in output.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if re.match(r"^system has \d+ switched transceiver slots", lower):
            in_slots = True
            continue
        if in_slots and (not stripped or lower.startswith("system has ")):
            in_slots = False
        if not in_slots or not re.match(r"^\d+\s+", stripped):
            continue
        tokens = stripped.split()
        port = tokens[0]
        name = normalize_interface("Et%s" % port)
        key = name.lower()
        item = modules.setdefault(key, blank_transceiver(name))
        if "not present" in lower:
            item["present"] = False
            continue
        if len(tokens) >= 4:
            item["vendor"] = clean_optic_value(tokens[1])
            item["model"] = clean_optic_value(tokens[2])
            item["serial"] = clean_optic_value(tokens[3])
            item["present"] = True


def add_threshold_alert(item, label, value, high_alarm, high_warn, low_alarm, low_warn, unit):
    reading = optic_number(value)
    if reading is None:
        return
    thresholds = {
        "high alarm": optic_number(high_alarm),
        "high warning": optic_number(high_warn),
        "low alarm": optic_number(low_alarm),
        "low warning": optic_number(low_warn),
    }
    alert = None
    if thresholds["high alarm"] is not None and reading >= thresholds["high alarm"]:
        alert = "%s high alarm: %s %s >= %s %s" % (label, reading, unit, thresholds["high alarm"], unit)
    elif thresholds["high warning"] is not None and reading >= thresholds["high warning"]:
        alert = "%s high warning: %s %s >= %s %s" % (label, reading, unit, thresholds["high warning"], unit)
    elif thresholds["low alarm"] is not None and reading <= thresholds["low alarm"]:
        alert = "%s low alarm: %s %s <= %s %s" % (label, reading, unit, thresholds["low alarm"], unit)
    elif thresholds["low warning"] is not None and reading <= thresholds["low warning"]:
        alert = "%s low warning: %s %s <= %s %s" % (label, reading, unit, thresholds["low warning"], unit)
    if alert and alert not in item["alerts"]:
        item["alerts"].append(alert)


def parse_transceivers(summary_output, detail_output="", csv_output="", properties_output="", inventory_output=""):
    modules = {}
    for line in summary_output.splitlines():
        stripped = line.strip()
        if not stripped or not re.match(r"^(Et|Ethernet)\d+(?:/\d+)?\b", stripped, re.I):
            continue
        tokens = stripped.split()
        name = normalize_interface(tokens[0])
        raw_tail = " ".join(tokens[1:])
        item = modules.setdefault(name.lower(), blank_transceiver(name))
        item["raw"] = stripped
        lower_tail = raw_tail.lower()
        dom_row = len(tokens) >= 6 and all(re.match(r"^(?:N/A|NA|-?\d+(?:\.\d+)?)$", token, re.I) for token in tokens[1:6])
        if "not present" in lower_tail or "not-present" in lower_tail:
            item["present"] = False
        elif dom_row:
            item["temperature"] = optic_value_with_unit(tokens[1], "C")
            item["txPower"] = optic_value_with_unit(tokens[4], "dBm")
            item["rxPower"] = optic_value_with_unit(tokens[5], "dBm")
            item["present"] = transceiver_present(item)
        elif raw_tail:
            item["type"] = clean_optic_value(raw_tail)
            item["present"] = transceiver_present(item)

    parse_transceiver_csv(csv_output, modules)
    parse_transceiver_properties(properties_output, modules)
    parse_transceiver_inventory(inventory_output, modules)

    current = None
    detail_metric = None
    detail_label = None
    detail_unit = ""
    for line in detail_output.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if "temperature" in lower and "threshold" in lower:
            detail_metric, detail_label, detail_unit = "temperature", "Temperature", "C"
            continue
        if "voltage" in lower and "threshold" in lower:
            detail_metric, detail_label, detail_unit = "voltage", "Voltage", "V"
            continue
        if "current" in lower and "threshold" in lower:
            detail_metric, detail_label, detail_unit = "current", "Current", "mA"
            continue
        if "tx power" in lower and "threshold" in lower:
            detail_metric, detail_label, detail_unit = "txPower", "TX power", "dBm"
            continue
        if "rx power" in lower and "threshold" in lower:
            detail_metric, detail_label, detail_unit = "rxPower", "RX power", "dBm"
            continue
        if not stripped or stripped.startswith("---") or stripped.lower().startswith(("port ", "high alarm")):
            continue
        header = re.match(r"^(Et|Ethernet)\d+(?:/\d+)?\b", stripped, re.I)
        if header:
            current = normalize_interface(header.group(0)).lower()
            item = modules.setdefault(current, blank_transceiver(normalize_interface(header.group(0))))
            row_tokens = stripped.split()
            if detail_metric and len(row_tokens) >= 6:
                item[detail_metric] = optic_value_with_unit(row_tokens[1], detail_unit)
                item["present"] = transceiver_present(item)
                add_threshold_alert(item, detail_label, row_tokens[1], row_tokens[2], row_tokens[3], row_tokens[4], row_tokens[5], detail_unit)
                continue
        if not current or current not in modules:
            continue
        item = modules[current]
        if "not present" in lower:
            item["present"] = False
        for key, patterns in {
            "type": [r"type\s+(?:is\s+)?(.+)$", r"media type\s*:\s*(.+)$"],
            "vendor": [r"vendor(?: name)?\s+(?:is\s+)?(.+)$", r"vendor(?: name)?\s*:\s*(.+)$"],
            "model": [r"(?:part|model)(?: number)?\s+(?:is\s+)?(.+)$", r"(?:part|model)(?: number)?\s*:\s*(.+)$"],
            "serial": [r"serial(?: number)?\s+(?:is\s+)?(.+)$", r"serial(?: number)?\s*:\s*(.+)$"],
            "temperature": [r"temperature\s*[:=]?\s*([-\d.]+\s*C?)"],
            "txPower": [r"tx\s+power\s*[:=]?\s*([-\d.]+\s*\w*)", r"transmit\s+power\s*[:=]?\s*([-\d.]+\s*\w*)"],
            "rxPower": [r"rx\s+power\s*[:=]?\s*([-\d.]+\s*\w*)", r"receive\s+power\s*[:=]?\s*([-\d.]+\s*\w*)"],
        }.items():
            for pattern in patterns:
                match = re.search(pattern, stripped, re.I)
                if match:
                    item[key] = clean_optic_value(match.group(1))
                    break
        if any(word in lower for word in ("alarm", "warning", "fault")) and "threshold" not in lower:
            item["alerts"].append(stripped)

    for item in modules.values():
        item["present"] = transceiver_present(item)
        if item["present"] is False:
            item["type"] = clean_optic_value(item.get("type"))
    return modules


def parse_poe(output):
    rows = []
    unsupported = not output.strip()
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "invalid input" in stripped.lower() or "not supported" in stripped.lower():
            unsupported = True
            continue
        if not re.match(r"^(Et|Ethernet)\d+(?:/\d+)?\b", stripped, re.I):
            continue
        tokens = stripped.split()
        rows.append(
            {
                "interface": normalize_interface(tokens[0]),
                "admin": next((token for token in tokens if token.lower() in ("auto", "on", "off", "never")), "-"),
                "state": next((token for token in tokens if token.lower() in ("delivering", "searching", "disabled", "fault", "denied")), "-"),
                "watts": next((token for token in tokens if re.match(r"^\d+(?:\.\d+)?W?$", token, re.I)), "-"),
                "raw": stripped,
            }
        )
    return {"supported": bool(rows) and not unsupported, "ports": rows, "raw": output}


def parse_protocol_rows(output, kind):
    rows = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("%") or stripped.lower().startswith(("neighbor", "vrf", "bgp summary")):
            continue
        if kind == "bgp" and re.match(r"^\d+\.\d+\.\d+\.\d+", stripped):
            tokens = stripped.split()
            rows.append({"peer": tokens[0], "asn": tokens[2] if len(tokens) > 2 else "-", "state": tokens[-1], "raw": stripped})
        elif kind != "bgp" and re.match(r"^\d+\.\d+\.\d+\.\d+", stripped):
            tokens = stripped.split()
            rows.append({"neighbor": tokens[0], "state": tokens[2] if len(tokens) > 2 else "-", "interface": tokens[-1], "raw": stripped})
    return rows


def parse_integrations(config_output):
    text = config_output.lower()
    return {
        "syslog": "logging host" in text,
        "sflow": "sflow" in text,
        "netflow": "netflow" in text or "ip flow" in text or "flow exporter" in text,
        "raw": config_output,
    }


def build_alerts(ports, health, env_output, command_errors):
    alerts = []
    if command_errors:
        alerts.append({"severity": "critical", "title": "采集异常", "message": "; ".join(command_errors[:3])})
    if health.get("fanStatus") != "OK":
        alerts.append({"severity": "critical", "title": "风扇状态异常", "message": "请检查 show environment all。"})
    if health.get("psuStatus") != "OK":
        details = [str(item) for item in health.get("psuDetails") or [] if str(item) != "ok"]
        message = "；".join(details) if details else "请检查 PSU 状态。"
        alerts.append({"severity": "critical", "title": "电源状态异常", "message": message})
    if int(health.get("temperature") or 0) >= 55:
        alerts.append({"severity": "warning", "title": "温度偏高", "message": "%sC" % health.get("temperature")})
    for port in ports:
        if port.get("hasMedia") and port.get("status") != "up":
            alerts.append({"severity": "warning", "title": "介质存在但链路未 Up", "message": "%s / %s" % (port.get("label"), port.get("media"))})
        if int(port.get("errors") or 0) > 0:
            alerts.append({"severity": "warning", "title": "接口错误计数", "message": "%s errors=%s" % (port.get("label"), port.get("errors"))})
        optic = port.get("transceiver") or {}
        if optic.get("alerts"):
            alerts.append({"severity": "warning", "title": "光模块告警", "message": "%s / %s" % (port.get("label"), "; ".join(optic.get("alerts")[:2]))})
    if "fail" in env_output.lower() or "fault" in env_output.lower():
        alerts.append({"severity": "critical", "title": "环境告警", "message": "show environment all 中包含 fail/fault。"})
    return alerts[:100]


def safe_text(value, pattern=r"^[\w .:/@+-]{0,80}$"):
    value = str(value or "").strip()
    if not re.match(pattern, value):
        raise ValueError("Invalid input: %s" % value)
    return value


def safe_interface(value):
    value = str(value or "").strip()
    if not re.match(r"^(Ethernet|Et)\d+(?:/\d+)?$", value, re.I):
        raise ValueError("Invalid interface.")
    return normalize_interface(value)


def safe_vlan(value):
    number = int(value)
    if number < 1 or number > 4094:
        raise ValueError("VLAN must be 1-4094.")
    return str(number)


def safe_vlan_list(value):
    text = str(value or "").strip()
    if not re.match(r"^[\d,\- ]+$", text):
        raise ValueError("Expected VLAN list like 10,20,30-40.")
    for part in re.split(r"[, ]+", text):
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            if int(start) > int(end):
                raise ValueError("Invalid VLAN range.")
            safe_vlan(start)
            safe_vlan(end)
        else:
            safe_vlan(part)
    return text.replace(" ", "")


def safe_ipv4(value):
    value = str(value or "").strip()
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", value):
        raise ValueError("Expected IPv4 address.")
    return value


def safe_ip_prefix(value):
    value = str(value or "").strip()
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$", value):
        raise ValueError("Expected IPv4 prefix like 192.168.1.1/24.")
    try:
        ipaddress.ip_interface(value)
    except ValueError:
        raise ValueError("Expected valid IPv4 prefix like 192.168.1.1/24.")
    return value


def safe_svi_ip_prefix(value):
    value = safe_ip_prefix(value)
    interface = ipaddress.ip_interface(value)
    network = interface.network
    if network.version != 4:
        raise ValueError("Expected IPv4 prefix.")
    if network.prefixlen < 31 and interface.ip in (network.network_address, network.broadcast_address):
        raise ValueError("SVI address cannot be the network or broadcast address.")
    return value


def build_config_action(action, params):
    params = params or {}
    if action == "interface_admin":
        iface = safe_interface(params.get("interface"))
        state = str(params.get("state") or "").lower()
        if state not in ("enable", "disable"):
            raise ValueError("state must be enable or disable.")
        return ["interface %s" % iface, "no shutdown" if state == "enable" else "shutdown"]
    if action == "poe_control":
        iface = safe_interface(params.get("interface"))
        state = str(params.get("state") or "").lower()
        if state not in ("enable", "disable"):
            raise ValueError("state must be enable or disable.")
        return ["interface %s" % iface, "poe enable" if state == "enable" else "poe disable"]
    if action == "description":
        return ["interface %s" % safe_interface(params.get("interface")), "description %s" % safe_text(params.get("description"))]
    if action == "access_vlan":
        return ["interface %s" % safe_interface(params.get("interface")), "switchport mode access", "switchport access vlan %s" % safe_vlan(params.get("vlan"))]
    if action == "trunk_vlan":
        commands = ["interface %s" % safe_interface(params.get("interface")), "switchport mode trunk", "switchport trunk allowed vlan %s" % safe_vlan_list(params.get("vlan"))]
        native_vlan = str(params.get("nativeVlan") or "").strip()
        if native_vlan:
            commands.append("switchport trunk native vlan %s" % safe_vlan(native_vlan))
        return commands
    if action == "create_vlan":
        commands = ["vlan %s" % safe_vlan(params.get("vlan"))]
        name = str(params.get("name") or "").strip()
        if name:
            commands.append("name %s" % safe_text(name))
        return commands
    if action == "svi_interface":
        commands = ["interface Vlan%s" % safe_vlan(params.get("vlan")), "ip address %s" % safe_svi_ip_prefix(params.get("address"))]
        name = str(params.get("description") or "").strip()
        if name:
            commands.append("description %s" % safe_text(name))
        return commands
    if action == "l3_interface":
        return ["interface %s" % safe_interface(params.get("interface")), "no switchport", "ip address %s" % safe_ip_prefix(params.get("address"))]
    if action == "ospf_network":
        process = safe_text(params.get("process") or "1", r"^\d{1,5}$")
        network = safe_ip_prefix(params.get("network"))
        area = safe_text(params.get("area") or "0", r"^[\d.]{1,15}$")
        return ["router ospf %s" % process, "network %s area %s" % (network, area)]
    if action == "ospf_interface":
        area = safe_text(params.get("area") or "0", r"^[\d.]{1,15}$")
        return ["interface %s" % safe_interface(params.get("interface")), "ip ospf area %s" % area]
    if action == "bgp_neighbor":
        asn = safe_text(params.get("asn"), r"^\d{1,10}$")
        peer = safe_ipv4(params.get("neighbor"))
        remote_as = safe_text(params.get("remoteAs"), r"^\d{1,10}$")
        return ["router bgp %s" % asn, "neighbor %s remote-as %s" % (peer, remote_as)]
    if action == "bgp_address_family":
        asn = safe_text(params.get("asn"), r"^\d{1,10}$")
        peer = safe_ipv4(params.get("neighbor"))
        family = safe_text(params.get("addressFamily") or "ipv4", r"^(ipv4|ipv6)$")
        mode = safe_text(params.get("mode") or "activate", r"^(activate|deactivate)$")
        command = "neighbor %s activate" % peer if mode == "activate" else "no neighbor %s activate" % peer
        return ["router bgp %s" % asn, "address-family %s" % family, command]
    if action == "save_config":
        return ["write memory"]
    raise ValueError("Unsupported config action.")


def run_config_commands(commands):
    if commands == ["write memory"]:
        return run_eos_script("write memory", timeout=45)
    script = "configure terminal\n%s\nend" % "\n".join(commands)
    return run_eos_script(script, timeout=25) or "Configuration applied."


def config_diff(before, after):
    if before == after:
        return ""
    return "\n".join(
        difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile="before-running-config",
            tofile="after-running-config",
            lineterm="",
        )
    )


def merge_state(base, update):
    if not base:
        merged = dict(update)
    else:
        merged = dict(base)
        for key, value in update.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                child = dict(merged[key])
                child.update(value)
                merged[key] = child
            else:
                merged[key] = value
    if merged.get("ports") and merged.get("transceivers"):
        optics = {str(item.get("interface") or "").lower(): item for item in merged.get("transceivers", [])}
        merged["ports"] = [dict(port, transceiver=optics.get(str(port.get("name") or "").lower(), port.get("transceiver") or {})) for port in merged.get("ports", [])]
    return merged


def collect_state_cli_legacy(scope="full"):
    errors = []

    def get(command):
        try:
            return run_cli(command)
        except Exception as exc:
            errors.append("%s: %s" % (command, exc))
            return ""

    def get_optional(command):
        try:
            return run_cli(command)
        except Exception:
            return ""

    scope = str(scope or "full").lower()
    if scope == "core":
        version_output = get("show version")
        hostname_output = get("show hostname")
        uptime_output = get("show uptime")
        interface_output = get("show interfaces status")
        rates_output = get("show interfaces counters rates")
        errors_output = get("show interfaces counters errors")
        top_output = get("show processes top once")
        env_output = get_optional("show system environment all") or get_optional("show environment all")
        lldp_output = get_optional("show lldp neighbors")

        eos_version, serial = parse_version(version_output)
        ports = enrich_ports(parse_interfaces(interface_output), parse_interface_rates(rates_output), parse_interface_errors(errors_output), {})
        traffic = traffic_summary(ports)
        history = update_history(ports, traffic)
        health = parse_system_health(top_output, env_output, version_output)
        alerts = build_alerts(ports, health, env_output, errors)
        return {
            "device": {
                "model": MODEL,
                "hostname": parse_hostname(hostname_output),
                "serial": serial,
                "eosVersion": eos_version,
                "uptime": uptime_output.strip() or "-",
                "switchingCapacity": traffic["throughputLabel"],
                "forwardingRate": traffic["packetRateLabel"],
                "airflow": "Front-to-back",
                "lastRefresh": now_ms(),
                "source": "on-box",
            },
            "health": health,
            "traffic": traffic,
            "history": compact_history(history, limit=40, include_ports=False),
            "ports": ports,
            "lldp": parse_lldp_neighbors(lldp_output),
            "alerts": alerts,
            "events": [{"time": now_ms(), "level": "error" if errors else "info", "message": "; ".join(errors[:4]) if errors else "核心状态已刷新"}],
            "loading": {"core": "done", "tables": "pending", "optics": "pending", "protocols": "pending", "extras": "pending"},
        }

    if scope == "tables":
        vlan_output = get("show vlan brief")
        arp_output = get("show arp")
        fdb_output = get("show mac address-table")
        return {"vlans": parse_vlans(vlan_output), "arp": parse_arp(arp_output), "fdb": parse_fdb(fdb_output), "loading": {"tables": "done"}}

    if scope == "optics":
        transceiver_output = get("show interfaces transceiver")
        transceiver_detail_output = get("show interfaces transceiver detail")
        transceiver_csv_output = get_optional("show interfaces transceiver csv")
        transceiver_properties_output = get_optional("show interfaces transceiver properties")
        inventory_output = get_optional("show inventory")
        transceivers = parse_transceivers(transceiver_output, transceiver_detail_output, transceiver_csv_output, transceiver_properties_output, inventory_output)
        return {"transceivers": list(transceivers.values()), "loading": {"optics": "done"}}

    if scope == "protocols":
        ospf_output = get_optional("show ip ospf neighbor")
        ospfv3_output = get_optional("show ipv6 ospf neighbor")
        bgp_output = get_optional("show ip bgp summary")
        return {
            "protocols": {
                "ospf": parse_protocol_rows(ospf_output, "ospf"),
                "ospfv3": parse_protocol_rows(ospfv3_output, "ospfv3"),
                "bgp": parse_protocol_rows(bgp_output, "bgp"),
            },
            "loading": {"protocols": "done"},
        }

    if scope == "extras":
        poe_output = get_optional("show poe interface")
        integration_output = get_optional("show running-config | include logging host|sflow|netflow|ip flow|flow exporter|flow monitor")
        return {"poe": parse_poe(poe_output), "integrations": parse_integrations(integration_output), "loading": {"extras": "done"}}

    version_output = get("show version")
    hostname_output = get("show hostname")
    uptime_output = get("show uptime")
    interface_output = get("show interfaces status")
    rates_output = get("show interfaces counters rates")
    errors_output = get("show interfaces counters errors")
    transceiver_output = get("show interfaces transceiver")
    transceiver_detail_output = get("show interfaces transceiver detail")
    transceiver_csv_output = get_optional("show interfaces transceiver csv")
    transceiver_properties_output = get_optional("show interfaces transceiver properties")
    inventory_output = get_optional("show inventory")
    poe_output = get_optional("show poe interface")
    top_output = get("show processes top once")
    env_output = get_optional("show system environment all") or get_optional("show environment all")
    lldp_output = get("show lldp neighbors")
    lldp_detail_output = get_optional("show lldp neighbors detail")
    vlan_output = get("show vlan brief")
    arp_output = get("show arp")
    fdb_output = get("show mac address-table")
    ospf_output = get("show ip ospf neighbor")
    ospfv3_output = get("show ipv6 ospf neighbor")
    bgp_output = get("show ip bgp summary")
    integration_output = get("show running-config | include logging host|sflow|netflow|ip flow|flow exporter|flow monitor")

    eos_version, serial = parse_version(version_output)
    transceivers = parse_transceivers(transceiver_output, transceiver_detail_output, transceiver_csv_output, transceiver_properties_output, inventory_output)
    ports = enrich_ports(parse_interfaces(interface_output), parse_interface_rates(rates_output), parse_interface_errors(errors_output), transceivers)
    traffic = traffic_summary(ports)
    history = update_history(ports, traffic)
    health = parse_system_health(top_output, env_output, version_output)
    alerts = build_alerts(ports, health, env_output, errors)
    return {
        "device": {
            "model": MODEL,
            "hostname": parse_hostname(hostname_output),
            "serial": serial,
            "eosVersion": eos_version,
            "uptime": uptime_output.strip() or "-",
            "switchingCapacity": traffic["throughputLabel"],
            "forwardingRate": traffic["packetRateLabel"],
            "airflow": "Front-to-back",
            "lastRefresh": now_ms(),
            "source": "on-box",
        },
        "health": health,
        "traffic": traffic,
        "history": compact_history(history),
        "ports": ports,
        "transceivers": list(transceivers.values()),
        "poe": parse_poe(poe_output),
        "lldp": parse_lldp_neighbors(lldp_output, lldp_detail_output),
        "vlans": parse_vlans(vlan_output),
        "arp": parse_arp(arp_output),
        "fdb": parse_fdb(fdb_output),
        "protocols": {
            "ospf": parse_protocol_rows(ospf_output, "ospf"),
            "ospfv3": parse_protocol_rows(ospfv3_output, "ospfv3"),
            "bgp": parse_protocol_rows(bgp_output, "bgp"),
        },
        "integrations": parse_integrations(integration_output),
        "alerts": alerts,
        "events": [
            {
                "time": now_ms(),
                "level": "error" if errors else ("warning" if alerts else "success"),
                "message": "; ".join(errors) if errors else ("Active alerts: %s" % len(alerts) if alerts else "Refreshed from local EOS CLI."),
            }
        ],
        "loading": {"core": "done", "tables": "done", "optics": "done", "protocols": "done", "extras": "done"},
    }


def collect_state(scope="full"):
    errors = []

    def get(command, optional=False, timeout=22):
        try:
            return run_read_command(command, timeout=timeout)
        except Exception as exc:
            if not optional:
                errors.append("%s: %s" % (command, exc))
            return ""

    def get_optional(command):
        return get(command, optional=True)

    def jsons(commands):
        return run_eapi_json_map(commands)

    def has_data(data):
        return isinstance(data, dict) and bool(data)

    scope = str(scope or "full").lower()
    if scope == "core":
        commands = [
            "show version",
            "show hostname",
            "show uptime",
            "show interfaces status",
        ]
        data = jsons(commands)
        version_data = data.get("show version") or {}
        hostname_data = data.get("show hostname") or {}
        uptime_data = data.get("show uptime") or {}
        interface_data = data.get("show interfaces status") or {}

        version_output = "" if has_data(version_data) else get("show version")
        hostname_output = "" if has_data(hostname_data) else get("show hostname")
        uptime_output = "" if has_data(uptime_data) else get("show uptime")
        interface_output = "" if has_data(interface_data) else get("show interfaces status")
        env_output = ""

        eos_version, serial = parse_version_json(version_data) if has_data(version_data) else parse_version(version_output)
        ports = enrich_ports(
            parse_interfaces_json(interface_data) if has_data(interface_data) else parse_interfaces(interface_output),
            {},
            {},
            {},
        )
        traffic = traffic_summary(ports)
        history = read_json_file(HISTORY_FILE, {"traffic": [], "ports": {}})
        health = parse_system_health("", env_output, version_output)
        alerts = build_alerts(ports, health, env_output, errors)
        uptime = format_duration(uptime_data.get("upTime") or version_data.get("uptime")) if has_data(uptime_data) or has_data(version_data) else (uptime_output.strip() or "-")
        hostname = (hostname_data.get("hostname") or hostname_data.get("fqdn")) if has_data(hostname_data) else parse_hostname(hostname_output)
        return {
            "device": {
                "model": version_data.get("modelName") or MODEL,
                "hostname": hostname,
                "serial": serial,
                "eosVersion": eos_version,
                "uptime": uptime,
                "switchingCapacity": traffic["throughputLabel"],
                "forwardingRate": traffic["packetRateLabel"],
                "airflow": "Front-to-back",
                "lastRefresh": now_ms(),
                "source": "eAPI + CLI fallback",
            },
            "health": health,
            "traffic": traffic,
            "history": compact_history(history, limit=40, include_ports=False),
            "ports": ports,
            "lldp": [],
            "alerts": alerts,
            "events": [{"time": now_ms(), "level": "error" if errors else "info", "message": "; ".join(errors[:4]) if errors else "Core state refreshed via eAPI."}],
            "loading": {"core": "done", "metrics": "pending", "health": "pending", "tables": "pending", "discovery": "pending", "optics": "pending", "protocols": "pending", "extras": "pending"},
        }

    if scope == "metrics":
        commands = ["show interfaces status", "show interfaces counters rates", "show interfaces counters errors", "show processes top once", "show version"]
        data = jsons(commands)
        interface_data = data.get("show interfaces status") or {}
        rates_data = data.get("show interfaces counters rates") or {}
        errors_data = data.get("show interfaces counters errors") or {}
        top_data = data.get("show processes top once") or {}
        version_data = data.get("show version") or {}
        interface_output = "" if has_data(interface_data) else get("show interfaces status")
        rates_output = "" if has_data(rates_data) else get("show interfaces counters rates")
        errors_output = "" if has_data(errors_data) else get("show interfaces counters errors")
        top_output = "" if has_data(top_data) else get("show processes top once")
        version_output = "" if has_data(version_data) else get("show version")
        ports = enrich_ports(
            parse_interfaces_json(interface_data) if has_data(interface_data) else parse_interfaces(interface_output),
            parse_interface_rates_json(rates_data) if has_data(rates_data) else parse_interface_rates(rates_output),
            parse_interface_errors_json(errors_data) if has_data(errors_data) else parse_interface_errors(errors_output),
            {},
        )
        traffic = traffic_summary(ports)
        history = update_history(ports, traffic)
        health = parse_system_health_json(top_data, "", version_data) if has_data(top_data) else parse_system_health(top_output, "", version_output)
        return {
            "health": health,
            "traffic": traffic,
            "history": compact_history(history, limit=40, include_ports=False),
            "ports": ports,
            "loading": {"metrics": "done"},
        }

    if scope == "health":
        data = jsons(["show version", "show processes top once"])
        version_data = data.get("show version") or {}
        top_data = data.get("show processes top once") or {}
        top_output = "" if has_data(top_data) else get("show processes top once")
        version_output = "" if has_data(version_data) else get("show version")
        env_output = get_optional("show system environment all") or get_optional("show environment all")
        health = parse_system_health_json(top_data, env_output, version_data) if has_data(top_data) else parse_system_health(top_output, env_output, version_output)
        return {
            "health": health,
            "alerts": build_alerts([], health, env_output, errors),
            "loading": {"health": "done"},
        }

    if scope == "discovery":
        data = jsons(["show lldp neighbors detail"])
        lldp_data = data.get("show lldp neighbors detail") or {}
        lldp_output = "" if has_data(lldp_data) else get_optional("show lldp neighbors")
        return {
            "lldp": parse_lldp_json(lldp_data) if has_data(lldp_data) else parse_lldp_neighbors(lldp_output),
            "loading": {"discovery": "done"},
        }

    if scope == "tables":
        commands = ["show vlan brief", "show arp", "show mac address-table"]
        data = jsons(commands)
        vlan_data = data.get("show vlan brief") or {}
        arp_data = data.get("show arp") or {}
        fdb_data = data.get("show mac address-table") or {}
        return {
            "vlans": parse_vlans_json(vlan_data) if has_data(vlan_data) else parse_vlans(get("show vlan brief")),
            "arp": parse_arp_json(arp_data) if has_data(arp_data) else parse_arp(get("show arp")),
            "fdb": parse_fdb_json(fdb_data) if has_data(fdb_data) else parse_fdb(get("show mac address-table")),
            "loading": {"tables": "done"},
        }

    if scope == "optics":
        commands = ["show interfaces transceiver", "show interfaces transceiver detail", "show interfaces transceiver properties", "show inventory"]
        data = jsons(commands)
        if any(has_data(data.get(command)) for command in commands):
            transceivers = parse_transceivers_json(
                data.get("show interfaces transceiver") or {},
                data.get("show interfaces transceiver detail") or {},
                data.get("show interfaces transceiver properties") or {},
                data.get("show inventory") or {},
            )
        else:
            transceiver_output = get("show interfaces transceiver")
            transceiver_detail_output = get("show interfaces transceiver detail")
            transceiver_csv_output = get_optional("show interfaces transceiver csv")
            transceiver_properties_output = get_optional("show interfaces transceiver properties")
            inventory_output = get_optional("show inventory")
            transceivers = parse_transceivers(transceiver_output, transceiver_detail_output, transceiver_csv_output, transceiver_properties_output, inventory_output)
        return {"transceivers": list(transceivers.values()), "loading": {"optics": "done"}}

    if scope == "protocols":
        commands = ["show ip ospf neighbor", "show ipv6 ospf neighbor", "show ip bgp summary"]
        data = jsons(commands)
        if any(has_data(data.get(command)) for command in commands):
            protocols = parse_protocols_json(data.get("show ip ospf neighbor"), data.get("show ipv6 ospf neighbor"), data.get("show ip bgp summary"))
        else:
            ospf_output = get_optional("show ip ospf neighbor")
            ospfv3_output = get_optional("show ipv6 ospf neighbor")
            bgp_output = get_optional("show ip bgp summary")
            protocols = {
                "ospf": parse_protocol_rows(ospf_output, "ospf"),
                "ospfv3": parse_protocol_rows(ospfv3_output, "ospfv3"),
                "bgp": parse_protocol_rows(bgp_output, "bgp"),
            }
        return {"protocols": protocols, "loading": {"protocols": "done"}}

    if scope == "extras":
        poe_data = (jsons(["show poe interface"]).get("show poe interface") or {})
        poe_output = "" if has_data(poe_data) else get_optional("show poe interface")
        integration_output = get_optional("show running-config | include logging host|sflow|netflow|ip flow|flow exporter|flow monitor")
        return {"poe": parse_poe(poe_output), "integrations": parse_integrations(integration_output), "loading": {"extras": "done"}}

    state = collect_state("core")
    for child_scope in ("metrics", "health", "tables", "discovery", "extras", "optics", "protocols"):
        state = merge_state(state, collect_state(child_scope))
    state["history"] = compact_history(read_json_file(HISTORY_FILE, {"traffic": [], "ports": {}}))
    state["loading"] = {"core": "done", "metrics": "done", "health": "done", "tables": "done", "discovery": "done", "optics": "done", "protocols": "done", "extras": "done"}
    if state.get("alerts"):
        state["events"] = [{"time": now_ms(), "level": "warning", "message": "Active alerts: %s" % len(state.get("alerts", []))}]
    else:
        state["events"] = [{"time": now_ms(), "level": "success", "message": "Refreshed via eAPI with CLI fallback."}]
    return state


INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Arista 7050QX 后台</title>
  <style>
    :root{--bg:#f6f7f9;--surface:#fff;--subtle:#fbfcfd;--ink:#18202a;--muted:#697586;--line:#dde3ea;--accent:#0f766e;--green:#168a45;--red:#c2410c;--amber:#b7791f;--blue:#2563eb;--purple:#7c3aed;--shadow:0 14px 35px rgba(24,32,42,.08)}
    body[data-theme=dark]{--bg:#0f1720;--surface:#17212d;--subtle:#111a24;--ink:#edf3fa;--muted:#9aa8b8;--line:#2b3a4a;--shadow:0 14px 35px rgba(0,0,0,.28)}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}button,input{font:inherit}
    .topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:22px clamp(16px,4vw,44px);border-bottom:1px solid var(--line);background:var(--surface)}.eyebrow{margin:0 0 4px;color:var(--accent);font-size:12px;font-weight:800;letter-spacing:.12em}h1,h2,p{margin:0}h1{font-size:clamp(22px,3vw,34px);line-height:1.1}h2{font-size:16px}.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-end}.badge{display:inline-flex;align-items:center;min-height:34px;padding:0 12px;border:1px solid #86d8c8;border-radius:999px;background:rgba(15,118,110,.12);color:var(--accent);font-size:13px;font-weight:800;white-space:nowrap}.primary{min-height:38px;border:1px solid var(--accent);border-radius:8px;padding:0 14px;background:var(--accent);color:#fff;font-weight:750;cursor:pointer}.ghost{min-height:34px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--ink);cursor:pointer}.nav{display:flex;gap:8px;margin-top:12px}.nav button.active{border-color:var(--accent);color:#fff;background:var(--accent)}
    .layout{width:min(1480px,100%);margin:0 auto;padding:22px clamp(14px,3vw,34px) 34px}.dashboard-section.hidden{display:none!important}.ports-page{display:none}.ports-page.active{display:block}.overview{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:16px}.metric,.panel{border:1px solid var(--line);border-radius:8px;background:var(--surface);box-shadow:var(--shadow)}.metric{min-height:92px;padding:15px}.metric span,.muted{color:var(--muted);font-size:12px}.metric strong{display:block;margin-top:8px;overflow-wrap:anywhere;font-size:20px;line-height:1.15}.metric small{display:block;margin-top:6px;color:var(--muted);font-size:11px}.main-grid{display:grid;grid-template-columns:minmax(0,1fr) 370px;gap:16px;align-items:start}.bottom-grid{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(320px,.85fr);gap:16px;margin-top:16px}.panel{padding:16px}.panel-title{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:14px}
    .legend{display:flex;gap:12px;flex-wrap:wrap;justify-content:flex-end;color:var(--muted);font-size:12px}.legend span{display:inline-flex;align-items:center;gap:6px}.dot{display:inline-block;width:9px;height:9px;border-radius:50%}.up{background:var(--green)}.down{background:var(--muted)}.media{background:var(--purple)}.warn{background:var(--amber)}
    .port-grid{display:grid;grid-template-columns:repeat(8,minmax(82px,1fr));gap:8px}.port{position:relative;min-height:104px;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--subtle);overflow:hidden;text-align:left;cursor:pointer;color:var(--ink)}.port:hover{border-color:#9fb0c2;background:var(--surface)}.port:before{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--muted)}.port[data-media=true]:before{background:var(--purple)}.port[data-status=up]:before{background:var(--green)}.port[data-errors=true]:before{background:var(--amber)}.port[data-breakout=true]{min-height:128px;background:linear-gradient(180deg,var(--surface),var(--subtle))}.port-name{display:flex;align-items:center;justify-content:space-between;gap:6px;font-size:12px;font-weight:800}.port-speed{color:var(--blue);font-size:11px;font-weight:800}.port-detail{margin-top:8px;color:var(--muted);font-size:11px;line-height:1.35;overflow-wrap:anywhere}.port-traffic{display:grid;grid-template-columns:1fr 1fr;gap:4px;margin-top:8px;font-size:11px}.port-traffic b{display:block;color:var(--ink);font-size:12px}.lane-dots{display:grid;grid-template-columns:repeat(4,1fr);gap:4px;margin-top:9px}.lane-dots i{height:7px;border-radius:999px;background:var(--muted)}.lane-dots i[data-status=up]{background:var(--green)}.lane-dots i[data-media=true]{background:var(--purple)}.lane-dots i[data-errors=true]{background:var(--amber)}.lane-table{width:100%;margin-top:12px;border-collapse:collapse;font-size:12px}.lane-table th,.lane-table td{padding:8px;border-bottom:1px solid var(--line);text-align:left}.lane-btn{min-height:28px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--ink);cursor:pointer}
    .side-stack{display:grid;gap:16px}.gauge-list{display:grid;gap:12px}.gauge-row{display:grid;grid-template-columns:56px minmax(120px,1fr) 60px;align-items:center;gap:10px;color:var(--muted);font-size:13px}meter{width:100%;height:12px}.mini-status{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:15px}.mini-status span{min-height:44px;padding:10px;border:1px solid var(--line);border-radius:8px;color:var(--muted);background:var(--subtle)}.mini-status b{display:block;margin-top:2px;color:var(--ink)}.command-form{display:grid;grid-template-columns:minmax(0,1fr) 92px;gap:10px}input,select{width:100%;min-height:38px;border:1px solid var(--line);border-radius:8px;padding:0 10px;color:var(--ink);background:var(--surface)}.refresh-select{width:auto;min-width:96px;height:38px;font-weight:700}pre{min-height:210px;max-height:360px;margin:12px 0 0;overflow:auto;border:1px solid #1e293b;border-radius:8px;padding:14px;color:#d7e2ef;background:#111827;font:13px/1.55 "Cascadia Mono",Consolas,monospace;white-space:pre-wrap}
    .event-list{display:grid;gap:8px;max-height:320px;margin:0;padding:0;overflow:auto;list-style:none}.event-list li{display:grid;gap:3px;min-height:54px;border-left:4px solid var(--line);border-radius:8px;padding:9px 10px;background:var(--subtle)}.event-list li[data-level=success]{border-left-color:var(--green)}.event-list li[data-level=error]{border-left-color:var(--red)}.event-time{color:var(--muted);font-size:11px}.event-message{font-size:13px}.toast{position:fixed;right:18px;bottom:18px;max-width:min(420px,calc(100vw - 36px));padding:12px 14px;border:1px solid var(--line);border-radius:8px;background:var(--surface);box-shadow:var(--shadow);transform:translateY(90px);opacity:0;transition:.18s ease}.toast.show{transform:translateY(0);opacity:1}
    .modal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;padding:18px;background:rgba(15,23,42,.58);z-index:30}.modal.show{display:flex}.dialog{width:min(820px,100%);max-height:88vh;overflow:auto;border-radius:8px;border:1px solid var(--line);background:var(--surface);box-shadow:0 24px 80px rgba(0,0,0,.24)}.dialog-head{display:flex;align-items:center;justify-content:space-between;padding:16px;border-bottom:1px solid var(--line)}.dialog-body{padding:16px}.detail-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.detail-item{border:1px solid var(--line);border-radius:8px;padding:10px;background:var(--subtle)}.detail-item span{display:block;color:var(--muted);font-size:11px}.detail-item b{display:block;margin-top:5px;font-size:15px;overflow-wrap:anywhere}.port-chart{width:100%;height:180px;margin-top:12px;border:1px solid var(--line);border-radius:8px;background:var(--subtle)}
    .wide-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:16px}.table-wrap{max-height:280px;overflow:auto;border:1px solid var(--line);border-radius:8px}.data-table{width:100%;border-collapse:collapse;font-size:12px}.data-table th,.data-table td{padding:8px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.data-table th{position:sticky;top:0;background:var(--subtle);color:var(--muted);font-size:11px}.alert-list,.topology-list{display:grid;gap:8px;margin:0;padding:0;list-style:none}.alert-list li,.topology-list li{border-left:4px solid var(--line);border-radius:8px;padding:9px 10px;background:var(--subtle);font-size:13px}.alert-list li[data-severity=critical]{border-left-color:var(--red)}.alert-list li[data-severity=warning]{border-left-color:var(--amber)}.alert-list b{display:block}.ops-form{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.ops-form label{display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700}.ops-form select,.ops-form input{min-height:36px;border:1px solid var(--line);border-radius:8px;padding:0 9px;background:var(--surface);color:var(--ink)}.ops-form button{align-self:end}.full{grid-column:1/-1}.chart{width:100%;height:120px;border:1px solid var(--line);border-radius:8px;background:var(--subtle)}
    @media(max-width:1080px){.overview{grid-template-columns:repeat(2,minmax(0,1fr))}.main-grid,.bottom-grid,.wide-grid{grid-template-columns:1fr}.port-grid{grid-template-columns:repeat(6,minmax(72px,1fr))}}@media(max-width:720px){.topbar{align-items:flex-start;flex-direction:column}.actions{width:100%;justify-content:space-between}.overview,.mini-status,.detail-grid,.ops-form{grid-template-columns:1fr}.port-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.command-form{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <header class="topbar"><div><p class="eyebrow">ON-BOX CONSOLE</p><h1>Arista DCS-7050QX-32S-F</h1><nav class="nav"><button id="dashboardNav" class="ghost active" type="button">仪表盘</button><button id="portsNav" class="ghost" type="button">端口视图</button></nav></div><div class="actions"><span class="badge">EOS 本机运行</span><select id="refreshInterval" class="refresh-select" title="自动刷新间隔"><option value="0">手动</option><option value="5000">5 秒</option><option value="10000">10 秒</option><option value="15000" selected>15 秒</option><option value="30000">30 秒</option><option value="60000">60 秒</option></select><button id="themeBtn" class="ghost" type="button">深色</button><button id="refreshBtn" class="primary">刷新</button></div></header>
  <main class="layout">
    <section class="overview dashboard-section"><article class="metric"><span>主机名</span><strong id="hostname">-</strong></article><article class="metric"><span>EOS</span><strong id="eosVersion">-</strong></article><article class="metric"><span>实时转发</span><strong id="forwardingLive">-</strong><small id="trafficSubline">-</small></article><article class="metric"><span>实时交换</span><strong id="switchingLive">-</strong><small id="capacitySubline">-</small></article></section>
    <section class="main-grid dashboard-section"><div class="panel"><div class="panel-title"><div><h2>端口概览</h2><p id="portSummary" class="muted">-</p></div><button id="openPortsBtn" class="ghost" type="button">打开端口视图</button></div><canvas id="trafficChart" class="chart" width="700" height="120"></canvas></div>
      <aside class="side-stack"><div class="panel"><div class="panel-title"><h2>设备健康</h2><span id="lastRefresh" class="muted">-</span></div><div class="gauge-list"><div class="gauge-row"><span>CPU</span><meter id="cpuMeter" min="0" max="100" value="0"></meter><strong id="cpuValue">-</strong></div><div class="gauge-row"><span>内存</span><meter id="memoryMeter" min="0" max="100" value="0"></meter><strong id="memoryValue">-</strong></div><div class="gauge-row"><span>温度</span><meter id="temperatureMeter" min="0" max="90" value="0"></meter><strong id="temperatureValue">-</strong></div></div><div class="mini-status"><span>风扇 <b id="fanStatus">-</b></span><span>电源 <b id="psuStatus">-</b></span></div></div>
      <div class="panel"><div class="panel-title"><h2>运行位置</h2><span class="muted">0.0.0.0:2480</span></div><p class="muted">此页面直接运行在交换机 EOS bash 环境中，通过本机 CLI 读取实时状态。</p></div></aside></section>
    <section class="bottom-grid dashboard-section"><div class="panel"><div class="panel-title"><h2>命令控制台</h2><span class="muted">只读命令</span></div><form id="commandForm" class="command-form"><input id="commandInput" value="show interfaces status" /><button class="primary" type="submit">运行</button></form><pre id="commandOutput">等待命令...</pre></div><div class="panel"><div class="panel-title"><h2>事件</h2><span class="muted">最近状态</span></div><ul id="eventList" class="event-list"></ul></div></section>
    <section class="wide-grid dashboard-section"><div class="panel"><div class="panel-title"><h2>设备告警</h2><span class="muted">自动发现</span></div><ul id="alertList" class="alert-list"></ul></div><div class="panel"><div class="panel-title"><h2>基础拓扑 / LLDP</h2><span class="muted">邻居</span></div><ul id="lldpList" class="topology-list"></ul></div></section>
    <section class="wide-grid dashboard-section"><div class="panel"><div class="panel-title"><h2>协议状态</h2><span class="muted">OSPF / OSPFv3 / BGP</span></div><div class="table-wrap"><table id="protocolTable" class="data-table"></table></div></div><div class="panel"><div class="panel-title"><h2>VLAN / ARP / FDB</h2><span class="muted">采集表</span></div><div class="table-wrap"><table id="tablesView" class="data-table"></table></div></div></section>
    <section class="wide-grid dashboard-section"><div class="panel"><div class="panel-title"><h2>Syslog / Flow 集成</h2><span class="muted">配置探测</span></div><div id="integrationView" class="mini-status"></div></div><div class="panel"><div class="panel-title"><h2>流量图</h2><span id="chartLabel" class="muted">实时汇总</span></div><canvas id="trafficChart2" class="chart" width="700" height="120"></canvas></div></section>
    <section class="panel dashboard-section" style="margin-top:16px"><div class="panel-title"><h2>光模块</h2><span class="muted">Transceiver / DOM</span></div><div class="table-wrap"><table id="transceiverTable" class="data-table"></table></div></section>
    <section class="panel dashboard-section" style="margin-top:16px"><div class="panel-title"><h2>PoE</h2><span class="muted">支持机型自动显示</span></div><div class="table-wrap"><table id="poeTable" class="data-table"></table></div></section>
    <section class="panel dashboard-section" style="margin-top:16px"><div class="panel-title"><h2>受控配置</h2><span class="muted">需要输入 APPLY</span></div><form id="opsForm" class="ops-form"><label><span>动作</span><select id="opsAction"><option value="interface_admin">端口启停</option><option value="poe_control">PoE 启停</option><option value="description">改接口描述</option><option value="create_vlan">创建 VLAN</option><option value="access_vlan">接口加入 VLAN</option><option value="trunk_vlan">VLAN trunk</option><option value="svi_interface">创建 SVI</option><option value="l3_interface">配置三层接口</option><option value="ospf_network">OSPF network</option><option value="ospf_interface">OSPF interface</option><option value="bgp_neighbor">BGP neighbor</option><option value="bgp_address_family">BGP address-family</option><option value="save_config">保存配置</option></select></label><label><span>接口</span><input id="opsInterface" placeholder="Ethernet3" /></label><label><span>状态</span><select id="opsState"><option value="enable">enable</option><option value="disable">disable</option><option value="activate">activate</option><option value="deactivate">deactivate</option></select></label><label><span>VLAN</span><input id="opsVlan" placeholder="10 或 10,20,30-40" /></label><label><span>描述 / 名称 / 原生 VLAN</span><input id="opsText" placeholder="server-uplink" /></label><label><span>IP/前缀</span><input id="opsAddress" placeholder="192.168.10.1/24" /></label><label><span>进程/本端 AS</span><input id="opsProcess" placeholder="1 或 65000" /></label><label><span>Area / 邻居 AS</span><input id="opsArea" placeholder="0 或 65001" /></label><label><span>BGP 邻居</span><input id="opsNeighbor" placeholder="192.168.10.2" /></label><label><span>确认</span><input id="opsConfirm" placeholder="APPLY" /></label><button id="opsPreview" class="ghost" type="button">预览</button><button class="primary" type="submit">执行</button><pre id="opsOutput" class="full">等待操作...</pre></form></section>
    <section id="portsPage" class="ports-page"><div class="panel"><div class="panel-title"><div><h2>端口视图</h2><p id="portsPageSummary" class="muted">-</p></div><div class="legend"><span><i class="dot up"></i>Up</span><span><i class="dot down"></i>Down</span><span><i class="dot media"></i>Media</span><span><i class="dot warn"></i>Error</span></div></div><div id="portGrid" class="port-grid"></div></div></section>
  </main>
  <div id="portModal" class="modal"><div class="dialog"><div class="dialog-head"><h2 id="modalTitle">端口详情</h2><button id="modalClose" class="ghost">关闭</button></div><div id="modalBody" class="dialog-body"></div></div></div>
  <div id="toast" class="toast"></div>
  <script>
    const $=s=>document.querySelector(s),el={refreshBtn:$("#refreshBtn"),refreshInterval:$("#refreshInterval"),themeBtn:$("#themeBtn"),dashboardNav:$("#dashboardNav"),portsNav:$("#portsNav"),openPortsBtn:$("#openPortsBtn"),hostname:$("#hostname"),eosVersion:$("#eosVersion"),forwardingLive:$("#forwardingLive"),switchingLive:$("#switchingLive"),trafficSubline:$("#trafficSubline"),capacitySubline:$("#capacitySubline"),portSummary:$("#portSummary"),portsPageSummary:$("#portsPageSummary"),portsPage:$("#portsPage"),lastRefresh:$("#lastRefresh"),cpuMeter:$("#cpuMeter"),cpuValue:$("#cpuValue"),memoryMeter:$("#memoryMeter"),memoryValue:$("#memoryValue"),temperatureMeter:$("#temperatureMeter"),temperatureValue:$("#temperatureValue"),fanStatus:$("#fanStatus"),psuStatus:$("#psuStatus"),portGrid:$("#portGrid"),commandForm:$("#commandForm"),commandInput:$("#commandInput"),commandOutput:$("#commandOutput"),eventList:$("#eventList"),alertList:$("#alertList"),lldpList:$("#lldpList"),protocolTable:$("#protocolTable"),tablesView:$("#tablesView"),transceiverTable:$("#transceiverTable"),poeTable:$("#poeTable"),integrationView:$("#integrationView"),trafficChart:$("#trafficChart"),trafficChart2:$("#trafficChart2"),chartLabel:$("#chartLabel"),opsForm:$("#opsForm"),opsAction:$("#opsAction"),opsInterface:$("#opsInterface"),opsState:$("#opsState"),opsVlan:$("#opsVlan"),opsText:$("#opsText"),opsAddress:$("#opsAddress"),opsProcess:$("#opsProcess"),opsArea:$("#opsArea"),opsNeighbor:$("#opsNeighbor"),opsConfirm:$("#opsConfirm"),opsPreview:$("#opsPreview"),opsOutput:$("#opsOutput"),toast:$("#toast"),portModal:$("#portModal"),modalTitle:$("#modalTitle"),modalBody:$("#modalBody"),modalClose:$("#modalClose")};
    let toastTimer=null,currentPorts=[],currentPortCards=[],activePortName=null;const portHistory={};function esc(v){return String(v??"-").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]))}function toast(m){el.toast.textContent=m;el.toast.classList.add("show");clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.toast.classList.remove("show"),2600)}function fmt(v){return v?new Intl.DateTimeFormat("zh-CN",{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"}).format(new Date(v)):"-"}async function req(u,o={}){const r=await fetch(u,{headers:{"Content-Type":"application/json"},...o});const p=await r.json();if(!r.ok||p.ok===false)throw new Error(p.error||`HTTP ${r.status}`);return p}function pct(v){return Number.isFinite(Number(v))?`${Number(v).toFixed(0)}%`:"-"}function mbps(v){return `${Number(v||0).toFixed(2)}M`}
    function setTheme(theme){document.body.dataset.theme=theme;localStorage.setItem("theme",theme);el.themeBtn.textContent=theme==="dark"?"浅色":"深色"}setTheme(localStorage.getItem("theme")||"light");function showPage(page){const ports=page==="ports";document.querySelectorAll(".dashboard-section").forEach(x=>x.classList.toggle("hidden",ports));el.portsPage.classList.toggle("active",ports);el.dashboardNav.classList.toggle("active",!ports);el.portsNav.classList.toggle("active",ports);history.replaceState(null,"",ports?"/ports":"/")} 
    function detail(label,value){return `<div class="detail-item"><span>${label}</span><b>${esc(value)}</b></div>`}function uniq(values){return [...new Set(values.filter(v=>v&&v!=="-"))]}function diagLines(...values){return values.flatMap(v=>String(v||"").split("\n")).map(v=>v.trim()).filter(v=>v&&v!=="eAPI rates"&&v!=="eAPI errors").join("\n")}function portBase(name){const m=String(name||"").match(/^Ethernet(\d+)\/(\d+)$/i);return m?{base:`Ethernet${m[1]}`,lane:Number(m[2])}:null}function groupPorts(ports){const out=[],groups={};ports.forEach(p=>{const b=portBase(p.name);if(!b){out.push({...p,kind:"port"});return}if(!groups[b.base]){groups[b.base]={kind:"breakout",name:b.base,label:b.base,lanes:[]};out.push(groups[b.base])}groups[b.base].lanes.push({...p,lane:b.lane,kind:"lane"})});return out.map(item=>item.kind==="breakout"?summarizeGroup(item):item)}function summarizeGroup(g){const lanes=g.lanes.sort((a,b)=>(a.lane||0)-(b.lane||0)),up=lanes.filter(p=>p.status==="up").length,media=lanes.filter(p=>p.hasMedia&&p.status!=="up").length,errors=lanes.reduce((n,p)=>n+Number(p.errors||0),0),rx=lanes.reduce((n,p)=>n+Number(p.rxMbps||0),0),tx=lanes.reduce((n,p)=>n+Number(p.txMbps||0),0),speeds=uniq(lanes.map(p=>p.speed)),vlans=uniq(lanes.map(p=>p.vlan)),medias=uniq(lanes.map(p=>p.media));return {...g,lanes,status:up?"up":"down",hasMedia:media>0,errors,rxMbps:rx,txMbps:tx,speed:`${lanes.length}x${speeds[0]||"lane"}`,vlan:vlans.length<=2?vlans.join(", ")||"-":"Mixed",media:medias.length<=2?medias.join(", ")||"-":"Mixed",description:`${up}/${lanes.length} lanes up`}}function showPortDetail(p){if(!p)return;const o=p.transceiver||{},diag=diagLines(p.statusLine,p.rateLine,p.errorLine,o.raw,(o.alerts||[]).join("\n"));activePortName=p.name;el.modalTitle.textContent=`${p.label||p.name} 端口详情`;el.modalBody.innerHTML=`<div class="detail-grid">${detail("状态",p.status)}${detail("VLAN",p.vlan)}${detail("双工",p.duplex)}${detail("协商/网速",p.speed)}${detail("介质",p.media)}${detail("RX Mbps",Number(p.rxMbps||0).toFixed(2))}${detail("TX Mbps",Number(p.txMbps||0).toFixed(2))}${detail("RX Kpps",Number(p.rxKpps||0).toFixed(2))}${detail("TX Kpps",Number(p.txKpps||0).toFixed(2))}${detail("错误计数",p.errors||0)}${detail("描述",p.description||"-")}${detail("光模块",o.present===false?"Not Present":(o.type||"-"))}${detail("厂商",o.vendor||"-")}${detail("序列号",o.serial||"-")}${detail("DOM 温度",o.temperature||"-")}${detail("TX/RX 光功率",`${o.txPower||"-"} / ${o.rxPower||"-"}`)}</div><canvas id="portLineChart" class="port-chart" width="760" height="180"></canvas>${diag?`<pre>${esc(diag)}</pre>`:""}`;el.portModal.classList.add("show");setTimeout(()=>drawPortChart(p.name),0)}function showPortGroup(g){activePortName=null;el.modalTitle.textContent=`${g.label} QSFP breakout`;el.modalBody.innerHTML=`<div class="detail-grid">${detail("汇总状态",g.description)}${detail("Lane 数量",g.lanes.length)}${detail("VLAN",g.vlan)}${detail("介质",g.media)}${detail("RX Mbps",Number(g.rxMbps||0).toFixed(2))}${detail("TX Mbps",Number(g.txMbps||0).toFixed(2))}${detail("错误计数",g.errors||0)}</div><table class="lane-table"><thead><tr><th>Lane</th><th>状态</th><th>VLAN</th><th>速率</th><th>RX/TX</th><th>错误</th><th></th></tr></thead><tbody>${g.lanes.map(p=>`<tr><td>${esc(p.label||p.name)}</td><td>${esc(p.status)}</td><td>${esc(p.vlan)}</td><td>${esc(p.speed)}</td><td>${mbps(p.rxMbps)} / ${mbps(p.txMbps)}</td><td>${esc(p.errors||0)}</td><td><button class="lane-btn" data-port="${esc(p.name)}">查看</button></td></tr>`).join("")}</tbody></table>`;el.portModal.classList.add("show")}function showPort(i){const p=currentPortCards[i];if(!p)return;p.kind==="breakout"?showPortGroup(p):showPortDetail(p)}
    const historyData=[];function drawSingleChart(c,values,color){if(!c)return;const ctx=c.getContext("2d"),w=c.width,h=c.height,max=Math.max(1,...values);ctx.clearRect(0,0,w,h);ctx.strokeStyle=getComputedStyle(document.body).getPropertyValue("--line").trim();ctx.beginPath();for(let y=20;y<h;y+=25){ctx.moveTo(0,y);ctx.lineTo(w,y)}ctx.stroke();ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();values.forEach((v,i)=>{const x=i*(w/Math.max(1,values.length-1)),y=h-12-(v/max)*(h-24);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke()}function drawChart(t){historyData.push(Number(t.totalMbps||0));while(historyData.length>40)historyData.shift();drawSingleChart(el.trafficChart,historyData,"#0f766e");drawSingleChart(el.trafficChart2,historyData,"#0f766e");el.chartLabel.textContent=`${Number(t.totalMbps||0).toFixed(2)} Mbps / ${Number(t.totalKpps||0).toFixed(2)} Kpps`}function drawPortChart(name){const c=$("#portLineChart"),h=portHistory[name]||[];if(!c||!h.length)return;const rx=h.map(x=>x.rx),tx=h.map(x=>x.tx),ctx=c.getContext("2d"),w=c.width,ht=c.height,max=Math.max(1,...rx,...tx);ctx.clearRect(0,0,w,ht);ctx.strokeStyle=getComputedStyle(document.body).getPropertyValue("--line").trim();ctx.beginPath();for(let y=24;y<ht;y+=34){ctx.moveTo(0,y);ctx.lineTo(w,y)}ctx.stroke();function line(vals,color){ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();vals.forEach((v,i)=>{const x=i*(w/Math.max(1,vals.length-1)),y=ht-18-(v/max)*(ht-36);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke()}line(rx,"#2563eb");line(tx,"#0f766e");ctx.fillStyle=getComputedStyle(document.body).getPropertyValue("--muted").trim();ctx.fillText("RX blue / TX green",10,14)}
    function rows(headers,items,map){return `<thead><tr>${headers.map(h=>`<th>${h}</th>`).join("")}</tr></thead><tbody>${items.map(item=>`<tr>${map(item).map(v=>`<td>${esc(v)}</td>`).join("")}</tr>`).join("")}</tbody>`}function renderExtra(state){const alerts=state.alerts||[];el.alertList.innerHTML=alerts.length?alerts.map(a=>`<li data-severity="${esc(a.severity)}"><b>${esc(a.title)}</b>${esc(a.message)}</li>`).join(""):"<li>暂无告警</li>";el.lldpList.innerHTML=(state.lldp||[]).length?(state.lldp||[]).map(n=>`<li><b>${esc(n.label)}</b> → ${esc(n.neighbor)} / ${esc(n.neighborPort)}</li>`).join(""):"<li>未发现 LLDP 邻居</li>";const proto=[...(state.protocols?.ospf||[]).map(x=>({type:"OSPF",a:x.neighbor,b:x.state,c:x.interface})),...(state.protocols?.ospfv3||[]).map(x=>({type:"OSPFv3",a:x.neighbor,b:x.state,c:x.interface})),...(state.protocols?.bgp||[]).map(x=>({type:"BGP",a:x.peer,b:x.state,c:x.asn}))];el.protocolTable.innerHTML=rows(["协议","对象","状态","接口/AS"],proto,x=>[x.type,x.a,x.b,x.c]);const tableItems=[...(state.vlans||[]).slice(0,40).map(x=>({type:"VLAN",a:x.id,b:x.name,c:x.status,d:x.ports})),...(state.arp||[]).slice(0,40).map(x=>({type:"ARP",a:x.address,b:x.mac,c:x.interface,d:""})),...(state.fdb||[]).slice(0,40).map(x=>({type:"FDB",a:x.vlan,b:x.mac,c:x.type,d:x.port}))];el.tablesView.innerHTML=rows(["类型","键","值","状态","端口"],tableItems,x=>[x.type,x.a,x.b,x.c,x.d]);const optics=(state.transceivers||[]).filter(x=>x.present!==false).slice(0,96);el.transceiverTable.innerHTML=optics.length?rows(["接口","类型","厂商","型号","序列号","温度","TX/RX","告警"],optics,x=>[x.interface,x.type,x.vendor,x.model,x.serial,x.temperature,`${x.txPower||"-"} / ${x.rxPower||"-"}`,(x.alerts||[]).join("; ")]):rows(["接口","类型","厂商","型号","序列号","温度","TX/RX","告警"],[],x=>[]);const poe=state.poe||{},poeRows=poe.ports||[];el.poeTable.innerHTML=poeRows.length?rows(["接口","Admin","状态","功率","原始行"],poeRows,x=>[x.interface,x.admin,x.state,x.watts,x.raw]):rows(["接口","Admin","状态","功率","原始行"],[{interface:"-",admin:"-",state:poe.supported===false?"当前机型/系统未返回 PoE 数据":"暂无 PoE 数据",watts:"-",raw:""}],x=>[x.interface,x.admin,x.state,x.watts,x.raw]);const i=state.integrations||{};el.integrationView.innerHTML=`<span>Syslog <b>${i.syslog?"ON":"OFF"}</b></span><span>sFlow <b>${i.sflow?"ON":"OFF"}</b></span><span>NetFlow/IPFIX <b>${i.netflow?"ON":"OFF"}</b></span><span>采集 <b>${(state.vlans||[]).length} VLAN / ${(state.arp||[]).length} ARP / ${(state.fdb||[]).length} FDB</b></span>`;if(state.history?.traffic?.length)historyData.splice(0,historyData.length,...state.history.traffic.slice(-80).map(x=>Number(x.totalMbps||0)));drawChart(state.traffic||{})}
    function render(state){const d=state.device||{},h=state.health||{},t=state.traffic||{},ports=state.ports||[],up=ports.filter(p=>p.status==="up").length,media=ports.filter(p=>p.hasMedia&&p.status!=="up").length,err=ports.filter(p=>Number(p.errors||0)>0).length;currentPorts=ports;currentPortCards=groupPorts(ports);ports.forEach(p=>{const k=p.name;const saved=(state.history?.ports?.[k]||[]).slice(-80).map(x=>({rx:Number(x.rxMbps||0),tx:Number(x.txMbps||0)}));portHistory[k]=saved.length?saved:(portHistory[k]||[]);if(!saved.length)portHistory[k].push({rx:Number(p.rxMbps||0),tx:Number(p.txMbps||0)});while(portHistory[k].length>80)portHistory[k].shift()});el.hostname.textContent=d.hostname||"-";el.eosVersion.textContent=d.eosVersion||"-";el.forwardingLive.textContent=d.forwardingRate||t.packetRateLabel||"-";el.switchingLive.textContent=d.switchingCapacity||t.throughputLabel||"-";el.trafficSubline.textContent=`RX ${mbps(t.rxMbps)} / TX ${mbps(t.txMbps)}`;el.capacitySubline.textContent=`占用 ${Number(t.capacityUtilization||0).toFixed(4)}% of 2.56Tbps`;const summary=`${up}/${ports.length} logical up, ${currentPortCards.length} cards, ${media} media, ${err} error`;el.portSummary.textContent=summary;el.portsPageSummary.textContent=summary;el.lastRefresh.textContent=fmt(d.lastRefresh);el.cpuMeter.value=Number(h.cpu||0);el.cpuValue.textContent=pct(h.cpu);el.memoryMeter.value=Number(h.memory||0);el.memoryValue.textContent=pct(h.memory);el.temperatureMeter.value=Number(h.temperature||0);el.temperatureValue.textContent=Number.isFinite(Number(h.temperature))?`${h.temperature}C`:"-";el.fanStatus.textContent=h.fanStatus||"-";el.psuStatus.textContent=h.psuStatus||"-";el.portGrid.innerHTML=currentPortCards.map((p,i)=>`<button class="port" data-index="${i}" data-breakout="${p.kind==="breakout"}" data-status="${p.status}" data-media="${Boolean(p.hasMedia)}" data-errors="${Number(p.errors||0)>0}"><div class="port-name"><span>${esc(p.label||p.name)}</span><span class="port-speed">${esc(p.speed)}</span></div><div class="port-detail">${esc(p.media)} / VLAN ${esc(p.vlan)}<br>${esc(p.description||p.status)}</div>${p.kind==="breakout"?`<div class="lane-dots">${p.lanes.map(x=>`<i title="${esc(x.label||x.name)}" data-status="${esc(x.status)}" data-media="${Boolean(x.hasMedia&&x.status!=="up")}" data-errors="${Number(x.errors||0)>0}"></i>`).join("")}</div>`:""}<div class="port-traffic"><span>RX <b>${mbps(p.rxMbps)}</b></span><span>TX <b>${mbps(p.txMbps)}</b></span></div></button>`).join("");if(activePortName&&el.portModal.classList.contains("show"))drawPortChart(activePortName);el.eventList.innerHTML=(state.events||[]).map(e=>`<li data-level="${e.level||"info"}"><span class="event-time">${fmt(e.time)} / ${esc(e.level||"info")}</span><span class="event-message">${esc(e.message)}</span></li>`).join("");renderExtra(state)}
    let refreshRun=0,refreshTimer=null,autoRefreshBusy=false;const progressiveScopes=["metrics","health","tables","discovery","extras","optics","protocols"];async function load(scope="state"){const p=scope==="state"?await req("/api/state"):await req("/api/refresh",{method:"POST",body:JSON.stringify({scope})});render(p.state);return p.state}async function loadProgressive(){const run=++refreshRun;for(const scope of progressiveScopes){if(run!==refreshRun)return;try{await load(scope)}catch(e){toast(`${scope}: ${e.message}`)}}}async function boot(){el.refreshBtn.disabled=true;el.refreshBtn.textContent="加载中";try{await load("core");loadProgressive()}catch(e){toast(e.message);await load().catch(()=>{})}finally{el.refreshBtn.disabled=false;el.refreshBtn.textContent="刷新"}}async function refresh(silent=false){el.refreshBtn.disabled=true;el.refreshBtn.textContent="刷新中";try{await load("core");if(!silent)toast("核心状态已刷新，其余数据继续加载");loadProgressive()}catch(e){if(!silent)toast(e.message)}finally{el.refreshBtn.disabled=false;el.refreshBtn.textContent="刷新"}}function setAutoRefresh(){if(refreshTimer)clearInterval(refreshTimer);const ms=Number(el.refreshInterval?.value||0);localStorage.setItem("refreshInterval",String(ms));if(ms>0)refreshTimer=setInterval(async()=>{if(document.hidden||autoRefreshBusy)return;autoRefreshBusy=true;try{await refresh(true)}finally{autoRefreshBusy=false}},ms)}
    function opsPayload(dryRun){return{action:el.opsAction.value,confirm:el.opsConfirm.value,dryRun,params:{interface:el.opsInterface.value,state:el.opsState.value,mode:el.opsState.value,vlan:el.opsVlan.value,nativeVlan:el.opsText.value,description:el.opsText.value,name:el.opsText.value,address:el.opsAddress.value,network:el.opsAddress.value,addressFamily:el.opsAddress.value||"ipv4",process:el.opsProcess.value,asn:el.opsProcess.value,area:el.opsArea.value,remoteAs:el.opsArea.value,neighbor:el.opsNeighbor.value}}}async function runOps(dryRun){el.opsOutput.textContent=dryRun?"生成配置中...":"执行配置中...";try{const p=await req("/api/config",{method:"POST",body:JSON.stringify(opsPayload(dryRun))});el.opsOutput.textContent=(p.commands||[]).join("\n")+(p.diff?`\n\nDIFF:\n${p.diff}`:"")+(p.output?`\n\n${p.output}`:"");if(!dryRun){toast("配置已提交");refresh()}}catch(err){el.opsOutput.textContent=`ERROR: ${err.message}`}}
    el.refreshBtn.addEventListener("click",()=>refresh(false));el.refreshInterval.addEventListener("change",setAutoRefresh);el.themeBtn.addEventListener("click",()=>setTheme(document.body.dataset.theme==="dark"?"light":"dark"));el.dashboardNav.addEventListener("click",()=>showPage("dashboard"));el.portsNav.addEventListener("click",()=>showPage("ports"));el.openPortsBtn.addEventListener("click",()=>showPage("ports"));el.portGrid.addEventListener("click",e=>{const card=e.target.closest(".port");if(card)showPort(Number(card.dataset.index))});el.modalBody.addEventListener("click",e=>{const btn=e.target.closest(".lane-btn");if(btn){const p=currentPorts.find(x=>x.name===btn.dataset.port);showPortDetail(p)}});el.modalClose.addEventListener("click",()=>el.portModal.classList.remove("show"));el.portModal.addEventListener("click",e=>{if(e.target===el.portModal)el.portModal.classList.remove("show")});el.opsPreview.addEventListener("click",()=>runOps(true));el.opsForm.addEventListener("submit",e=>{e.preventDefault();runOps(false)});el.commandForm.addEventListener("submit",async e=>{e.preventDefault();const command=el.commandInput.value.trim();if(!command)return;el.commandOutput.textContent=`> ${command}\n运行中...`;try{const p=await req("/api/command",{method:"POST",body:JSON.stringify({command})});el.commandOutput.textContent=`> ${p.command}\n${p.output}`}catch(err){el.commandOutput.textContent=`> ${command}\nERROR: ${err.message}`}});document.addEventListener("visibilitychange",()=>{if(!document.hidden)refresh(true)});showPage(location.pathname==="/ports"?"ports":"dashboard");const savedRefresh=localStorage.getItem("refreshInterval");if(savedRefresh!==null&&el.refreshInterval.querySelector(`option[value="${savedRefresh}"]`))el.refreshInterval.value=savedRefresh;boot();setAutoRefresh();
  </script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    cached_state = None
    cached_at = 0

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0") or "0")
        if size > 1024 * 1024:
            raise ValueError("Request body too large.")
        raw = self.rfile.read(size).decode("utf-8") if size else "{}"
        return json.loads(raw or "{}")

    def check_auth(self):
        user, password = auth_credentials()
        if not user and not password:
            return True
        header = self.headers.get("Authorization", "")
        if not header.lower().startswith("basic "):
            self.send_auth_required()
            return False
        try:
            decoded = base64.b64decode(header.split(None, 1)[1]).decode("utf-8")
            supplied_user, supplied_password = decoded.split(":", 1)
        except Exception:
            self.send_auth_required()
            return False
        if supplied_user == user and supplied_password == password:
            return True
        self.send_auth_required()
        return False

    def send_auth_required(self):
        body = b'{"ok":false,"error":"Authentication required"}'
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Arista WebUI"')
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.check_auth():
            return
        path = urlparse(self.path).path
        if path in ("/", "/ports"):
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        if path == "/api/state":
            if not Handler.cached_state:
                Handler.cached_state = collect_state("core")
                Handler.cached_at = time.time()
            elif time.time() - Handler.cached_at > 60:
                Handler.cached_state = merge_state(Handler.cached_state, collect_state("core"))
                Handler.cached_at = time.time()
            self.send_json(200, {"ok": True, "state": Handler.cached_state})
            return

        self.send_json(404, {"ok": False, "error": "Not found"})

    def do_POST(self):
        if not self.check_auth():
            return
        path = urlparse(self.path).path
        try:
            if path == "/api/refresh":
                payload = self.read_json()
                scope = str(payload.get("scope") or "full").lower()
                if scope not in ("core", "metrics", "health", "tables", "discovery", "optics", "protocols", "extras", "full"):
                    raise ValueError("Unknown refresh scope.")
                state = collect_state(scope)
                Handler.cached_state = state if scope == "full" else merge_state(Handler.cached_state, state)
                Handler.cached_at = time.time()
                self.send_json(200, {"ok": True, "state": Handler.cached_state})
                return

            if path == "/api/command":
                payload = self.read_json()
                command = str(payload.get("command", "")).strip()
                output = run_read_command(command)
                self.send_json(200, {"ok": True, "command": command, "output": output})
                return

            if path == "/api/config":
                payload = self.read_json()
                if payload.get("confirm") != "APPLY":
                    raise ValueError("Type APPLY to confirm configuration changes.")
                action = str(payload.get("action") or "")
                commands = build_config_action(action, payload.get("params") or {})
                if payload.get("dryRun"):
                    self.send_json(200, {"ok": True, "dryRun": True, "commands": commands})
                    return
                before = ""
                if commands != ["write memory"]:
                    try:
                        before = run_cli("show running-config")
                    except Exception:
                        before = ""
                output = run_config_commands(commands)
                after = ""
                diff = ""
                if commands != ["write memory"]:
                    try:
                        after = run_cli("show running-config")
                        diff = config_diff(before, after) if before else ""
                    except Exception:
                        diff = ""
                append_audit({"client": self.client_address[0], "action": action, "commands": commands, "diff": diff})
                Handler.cached_state = None
                self.send_json(200, {"ok": True, "action": action, "commands": commands, "diff": diff, "output": output})
                return

            self.send_json(404, {"ok": False, "error": "Not found"})
        except Exception as exc:
            self.send_json(400, {"ok": False, "error": str(exc)})


def main():
    parser = argparse.ArgumentParser(description="On-box web console for Arista DCS-7050QX-32S-F.")
    parser.add_argument("--host", default=os.environ.get("WEB_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("WEB_PORT", "2480")))
    parser.add_argument("--daemon", action="store_true", help="Run in the background on EOS.")
    parser.add_argument("--log", default="/mnt/flash/arista7050_web.log")
    parser.add_argument("--tls-cert", default=os.environ.get("WEB_TLS_CERT", ""))
    parser.add_argument("--tls-key", default=os.environ.get("WEB_TLS_KEY", ""))
    args = parser.parse_args()

    if args.daemon:
        if os.fork() > 0:
            print("Arista 7050QX web console started in background.")
            return
        os.setsid()
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        if os.fork() > 0:
            os._exit(0)
        os.chdir("/")
        sys.stdin.close()
        log = open(args.log, "a", buffering=1)
        os.dup2(log.fileno(), sys.stdout.fileno())
        os.dup2(log.fileno(), sys.stderr.fileno())

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    scheme = "http"
    if args.tls_cert and args.tls_key:
        context = ssl.SSLContext(getattr(ssl, "PROTOCOL_TLS_SERVER", ssl.PROTOCOL_SSLv23))
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    print("Arista 7050QX on-box web console listening on %s://%s:%s" % (scheme, args.host, args.port))
    print("Open %s://<switch-management-ip>:%s/" % (scheme, args.port))
    server.serve_forever()


if __name__ == "__main__":
    main()
