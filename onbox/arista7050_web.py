#!/usr/bin/env python3
import argparse
import base64
import difflib
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

MODEL = "Arista DCS-7050QX-32S-F"
DATA_DIR = os.environ.get("WEB_DATA_DIR", "/mnt/flash")
HISTORY_FILE = os.environ.get("WEB_HISTORY_FILE", os.path.join(DATA_DIR, "arista7050_web_history.json"))
AUDIT_FILE = os.environ.get("WEB_AUDIT_FILE", os.path.join(DATA_DIR, "arista7050_web_audit.jsonl"))
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
    has_fault = any(word in text for word in ("fail", "fault", "bad", "overheat"))
    temp_match = re.search(r"(\d+)\s*(?:c|degrees)", output, re.I)
    temperature = int(temp_match.group(1)) if temp_match else (58 if has_fault else 40)
    return {
        "temperature": temperature,
        "fanStatus": "CHECK" if has_fault else "OK",
        "psuStatus": "CHECK" if has_fault else "OK",
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


def parse_lldp_neighbors(output):
    neighbors = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("port", "----")):
            continue
        if not re.match(r"^(Et|Ethernet|Ma)\S+", stripped, re.I):
            continue
        tokens = stripped.split()
        if len(tokens) < 2:
            continue
        port = tokens[0]
        neighbor = tokens[1]
        ttl = tokens[-1] if tokens[-1].isdigit() else "-"
        neighbor_port = tokens[-2] if len(tokens) > 3 else "-"
        neighbors.append(
            {
                "port": normalize_interface(port),
                "label": port,
                "neighbor": neighbor,
                "neighborPort": neighbor_port,
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
        rows.append(
            {
                "vlan": tokens[0] if tokens else "-",
                "mac": mac.group(0),
                "type": next((token for token in tokens if token.lower() in ("dynamic", "static", "learned")), "-"),
                "port": tokens[-1] if tokens else "-",
                "raw": stripped,
            }
        )
    return rows


def parse_transceivers(summary_output, detail_output=""):
    modules = {}
    for line in summary_output.splitlines():
        stripped = line.strip()
        if not stripped or not re.match(r"^(Et|Ethernet)\d+(?:/\d+)?\b", stripped, re.I):
            continue
        tokens = stripped.split()
        name = normalize_interface(tokens[0])
        raw_tail = " ".join(tokens[1:])
        present = "not present" not in raw_tail.lower() and "not-present" not in raw_tail.lower()
        modules[name.lower()] = {
            "interface": name,
            "present": present,
            "type": raw_tail or "-",
            "vendor": "-",
            "model": "-",
            "serial": "-",
            "temperature": "-",
            "txPower": "-",
            "rxPower": "-",
            "alerts": [],
            "raw": stripped,
        }

    current = None
    for line in detail_output.splitlines():
        stripped = line.strip()
        header = re.match(r"^(Et|Ethernet)\d+(?:/\d+)?\b", stripped, re.I)
        if header:
            current = normalize_interface(header.group(0)).lower()
            modules.setdefault(
                current,
                {
                    "interface": normalize_interface(header.group(0)),
                    "present": True,
                    "type": "-",
                    "vendor": "-",
                    "model": "-",
                    "serial": "-",
                    "temperature": "-",
                    "txPower": "-",
                    "rxPower": "-",
                    "alerts": [],
                    "raw": stripped,
                },
            )
        if not current or current not in modules:
            continue
        item = modules[current]
        lower = stripped.lower()
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
                    item[key] = match.group(1).strip()
                    break
        if any(word in lower for word in ("alarm", "warning", "fault", "high", "low")):
            item["alerts"].append(stripped)

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
        alerts.append({"severity": "critical", "title": "电源状态异常", "message": "请检查 PSU 状态。"})
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
        commands = ["interface Vlan%s" % safe_vlan(params.get("vlan")), "ip address %s" % safe_ip_prefix(params.get("address"))]
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


def collect_state():
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

    version_output = get("show version")
    hostname_output = get("show hostname")
    uptime_output = get("show uptime")
    interface_output = get("show interfaces status")
    rates_output = get("show interfaces counters rates")
    errors_output = get("show interfaces counters errors")
    transceiver_output = get("show interfaces transceiver")
    transceiver_detail_output = get("show interfaces transceiver detail")
    poe_output = get_optional("show poe interface")
    top_output = get("show processes top once")
    env_output = get("show environment all")
    lldp_output = get("show lldp neighbors")
    vlan_output = get("show vlan brief")
    arp_output = get("show arp")
    fdb_output = get("show mac address-table")
    ospf_output = get("show ip ospf neighbor")
    ospfv3_output = get("show ipv6 ospf neighbor")
    bgp_output = get("show ip bgp summary")
    integration_output = get("show running-config | include logging host|sflow|netflow|ip flow|flow exporter|flow monitor")

    eos_version, serial = parse_version(version_output)
    transceivers = parse_transceivers(transceiver_output, transceiver_detail_output)
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
        "history": history,
        "ports": ports,
        "transceivers": list(transceivers.values()),
        "poe": parse_poe(poe_output),
        "lldp": parse_lldp_neighbors(lldp_output),
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
    }


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
    .port-grid{display:grid;grid-template-columns:repeat(8,minmax(82px,1fr));gap:8px}.port{position:relative;min-height:104px;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--subtle);overflow:hidden;text-align:left;cursor:pointer;color:var(--ink)}.port:hover{border-color:#9fb0c2;background:var(--surface)}.port:before{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--muted)}.port[data-media=true]:before{background:var(--purple)}.port[data-status=up]:before{background:var(--green)}.port[data-errors=true]:before{background:var(--amber)}.port-name{display:flex;align-items:center;justify-content:space-between;gap:6px;font-size:12px;font-weight:800}.port-speed{color:var(--blue);font-size:11px;font-weight:800}.port-detail{margin-top:8px;color:var(--muted);font-size:11px;line-height:1.35;overflow-wrap:anywhere}.port-traffic{display:grid;grid-template-columns:1fr 1fr;gap:4px;margin-top:8px;font-size:11px}.port-traffic b{display:block;color:var(--ink);font-size:12px}
    .side-stack{display:grid;gap:16px}.gauge-list{display:grid;gap:12px}.gauge-row{display:grid;grid-template-columns:56px minmax(120px,1fr) 60px;align-items:center;gap:10px;color:var(--muted);font-size:13px}meter{width:100%;height:12px}.mini-status{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:15px}.mini-status span{min-height:44px;padding:10px;border:1px solid var(--line);border-radius:8px;color:var(--muted);background:var(--subtle)}.mini-status b{display:block;margin-top:2px;color:var(--ink)}.command-form{display:grid;grid-template-columns:minmax(0,1fr) 92px;gap:10px}input{width:100%;min-height:38px;border:1px solid var(--line);border-radius:8px;padding:0 10px;color:var(--ink);background:var(--surface)}pre{min-height:210px;max-height:360px;margin:12px 0 0;overflow:auto;border:1px solid #1e293b;border-radius:8px;padding:14px;color:#d7e2ef;background:#111827;font:13px/1.55 "Cascadia Mono",Consolas,monospace;white-space:pre-wrap}
    .event-list{display:grid;gap:8px;max-height:320px;margin:0;padding:0;overflow:auto;list-style:none}.event-list li{display:grid;gap:3px;min-height:54px;border-left:4px solid var(--line);border-radius:8px;padding:9px 10px;background:var(--subtle)}.event-list li[data-level=success]{border-left-color:var(--green)}.event-list li[data-level=error]{border-left-color:var(--red)}.event-time{color:var(--muted);font-size:11px}.event-message{font-size:13px}.toast{position:fixed;right:18px;bottom:18px;max-width:min(420px,calc(100vw - 36px));padding:12px 14px;border:1px solid var(--line);border-radius:8px;background:var(--surface);box-shadow:var(--shadow);transform:translateY(90px);opacity:0;transition:.18s ease}.toast.show{transform:translateY(0);opacity:1}
    .modal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;padding:18px;background:rgba(15,23,42,.58);z-index:30}.modal.show{display:flex}.dialog{width:min(820px,100%);max-height:88vh;overflow:auto;border-radius:8px;border:1px solid var(--line);background:var(--surface);box-shadow:0 24px 80px rgba(0,0,0,.24)}.dialog-head{display:flex;align-items:center;justify-content:space-between;padding:16px;border-bottom:1px solid var(--line)}.dialog-body{padding:16px}.detail-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.detail-item{border:1px solid var(--line);border-radius:8px;padding:10px;background:var(--subtle)}.detail-item span{display:block;color:var(--muted);font-size:11px}.detail-item b{display:block;margin-top:5px;font-size:15px;overflow-wrap:anywhere}.port-chart{width:100%;height:180px;margin-top:12px;border:1px solid var(--line);border-radius:8px;background:var(--subtle)}
    .wide-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:16px}.table-wrap{max-height:280px;overflow:auto;border:1px solid var(--line);border-radius:8px}.data-table{width:100%;border-collapse:collapse;font-size:12px}.data-table th,.data-table td{padding:8px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.data-table th{position:sticky;top:0;background:var(--subtle);color:var(--muted);font-size:11px}.alert-list,.topology-list{display:grid;gap:8px;margin:0;padding:0;list-style:none}.alert-list li,.topology-list li{border-left:4px solid var(--line);border-radius:8px;padding:9px 10px;background:var(--subtle);font-size:13px}.alert-list li[data-severity=critical]{border-left-color:var(--red)}.alert-list li[data-severity=warning]{border-left-color:var(--amber)}.alert-list b{display:block}.ops-form{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.ops-form label{display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700}.ops-form select,.ops-form input{min-height:36px;border:1px solid var(--line);border-radius:8px;padding:0 9px;background:var(--surface);color:var(--ink)}.ops-form button{align-self:end}.full{grid-column:1/-1}.chart{width:100%;height:120px;border:1px solid var(--line);border-radius:8px;background:var(--subtle)}
    @media(max-width:1080px){.overview{grid-template-columns:repeat(2,minmax(0,1fr))}.main-grid,.bottom-grid,.wide-grid{grid-template-columns:1fr}.port-grid{grid-template-columns:repeat(6,minmax(72px,1fr))}}@media(max-width:720px){.topbar{align-items:flex-start;flex-direction:column}.actions{width:100%;justify-content:space-between}.overview,.mini-status,.detail-grid,.ops-form{grid-template-columns:1fr}.port-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.command-form{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <header class="topbar"><div><p class="eyebrow">ON-BOX CONSOLE</p><h1>Arista DCS-7050QX-32S-F</h1><nav class="nav"><button id="dashboardNav" class="ghost active" type="button">仪表盘</button><button id="portsNav" class="ghost" type="button">端口视图</button></nav></div><div class="actions"><span class="badge">EOS 本机运行</span><button id="themeBtn" class="ghost" type="button">深色</button><button id="refreshBtn" class="primary">刷新</button></div></header>
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
    const $=s=>document.querySelector(s),el={refreshBtn:$("#refreshBtn"),themeBtn:$("#themeBtn"),dashboardNav:$("#dashboardNav"),portsNav:$("#portsNav"),openPortsBtn:$("#openPortsBtn"),hostname:$("#hostname"),eosVersion:$("#eosVersion"),forwardingLive:$("#forwardingLive"),switchingLive:$("#switchingLive"),trafficSubline:$("#trafficSubline"),capacitySubline:$("#capacitySubline"),portSummary:$("#portSummary"),portsPageSummary:$("#portsPageSummary"),portsPage:$("#portsPage"),lastRefresh:$("#lastRefresh"),cpuMeter:$("#cpuMeter"),cpuValue:$("#cpuValue"),memoryMeter:$("#memoryMeter"),memoryValue:$("#memoryValue"),temperatureMeter:$("#temperatureMeter"),temperatureValue:$("#temperatureValue"),fanStatus:$("#fanStatus"),psuStatus:$("#psuStatus"),portGrid:$("#portGrid"),commandForm:$("#commandForm"),commandInput:$("#commandInput"),commandOutput:$("#commandOutput"),eventList:$("#eventList"),alertList:$("#alertList"),lldpList:$("#lldpList"),protocolTable:$("#protocolTable"),tablesView:$("#tablesView"),transceiverTable:$("#transceiverTable"),poeTable:$("#poeTable"),integrationView:$("#integrationView"),trafficChart:$("#trafficChart"),trafficChart2:$("#trafficChart2"),chartLabel:$("#chartLabel"),opsForm:$("#opsForm"),opsAction:$("#opsAction"),opsInterface:$("#opsInterface"),opsState:$("#opsState"),opsVlan:$("#opsVlan"),opsText:$("#opsText"),opsAddress:$("#opsAddress"),opsProcess:$("#opsProcess"),opsArea:$("#opsArea"),opsNeighbor:$("#opsNeighbor"),opsConfirm:$("#opsConfirm"),opsPreview:$("#opsPreview"),opsOutput:$("#opsOutput"),toast:$("#toast"),portModal:$("#portModal"),modalTitle:$("#modalTitle"),modalBody:$("#modalBody"),modalClose:$("#modalClose")};
    let toastTimer=null,currentPorts=[],activePortIndex=null;const portHistory={};function esc(v){return String(v??"-").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]))}function toast(m){el.toast.textContent=m;el.toast.classList.add("show");clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.toast.classList.remove("show"),2600)}function fmt(v){return v?new Intl.DateTimeFormat("zh-CN",{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"}).format(new Date(v)):"-"}async function req(u,o={}){const r=await fetch(u,{headers:{"Content-Type":"application/json"},...o});const p=await r.json();if(!r.ok||p.ok===false)throw new Error(p.error||`HTTP ${r.status}`);return p}function pct(v){return Number.isFinite(Number(v))?`${Number(v).toFixed(0)}%`:"-"}function mbps(v){return `${Number(v||0).toFixed(2)}M`}
    function setTheme(theme){document.body.dataset.theme=theme;localStorage.setItem("theme",theme);el.themeBtn.textContent=theme==="dark"?"浅色":"深色"}setTheme(localStorage.getItem("theme")||"light");function showPage(page){const ports=page==="ports";document.querySelectorAll(".dashboard-section").forEach(x=>x.classList.toggle("hidden",ports));el.portsPage.classList.toggle("active",ports);el.dashboardNav.classList.toggle("active",!ports);el.portsNav.classList.toggle("active",ports);history.replaceState(null,"",ports?"/ports":"/")} 
    function detail(label,value){return `<div class="detail-item"><span>${label}</span><b>${esc(value)}</b></div>`}function showPort(i){const p=currentPorts[i];if(!p)return;const o=p.transceiver||{};activePortIndex=i;el.modalTitle.textContent=`${p.label||p.name} 端口详情`;el.modalBody.innerHTML=`<div class="detail-grid">${detail("状态",p.status)}${detail("VLAN",p.vlan)}${detail("双工",p.duplex)}${detail("协商/网速",p.speed)}${detail("介质",p.media)}${detail("RX Mbps",Number(p.rxMbps||0).toFixed(2))}${detail("TX Mbps",Number(p.txMbps||0).toFixed(2))}${detail("RX Kpps",Number(p.rxKpps||0).toFixed(2))}${detail("TX Kpps",Number(p.txKpps||0).toFixed(2))}${detail("错误计数",p.errors||0)}${detail("描述",p.description||"-")}${detail("光模块",o.present===false?"Not Present":(o.type||"-"))}${detail("厂商",o.vendor||"-")}${detail("序列号",o.serial||"-")}${detail("DOM 温度",o.temperature||"-")}${detail("TX/RX 光功率",`${o.txPower||"-"} / ${o.rxPower||"-"}`)}</div><canvas id="portLineChart" class="port-chart" width="760" height="180"></canvas><pre>${esc([p.statusLine,p.rateLine,p.errorLine,o.raw,(o.alerts||[]).join("\n")].filter(Boolean).join("\n"))}</pre>`;el.portModal.classList.add("show");setTimeout(()=>drawPortChart(p.name),0)}
    const historyData=[];function drawSingleChart(c,values,color){if(!c)return;const ctx=c.getContext("2d"),w=c.width,h=c.height,max=Math.max(1,...values);ctx.clearRect(0,0,w,h);ctx.strokeStyle=getComputedStyle(document.body).getPropertyValue("--line").trim();ctx.beginPath();for(let y=20;y<h;y+=25){ctx.moveTo(0,y);ctx.lineTo(w,y)}ctx.stroke();ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();values.forEach((v,i)=>{const x=i*(w/Math.max(1,values.length-1)),y=h-12-(v/max)*(h-24);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke()}function drawChart(t){historyData.push(Number(t.totalMbps||0));while(historyData.length>40)historyData.shift();drawSingleChart(el.trafficChart,historyData,"#0f766e");drawSingleChart(el.trafficChart2,historyData,"#0f766e");el.chartLabel.textContent=`${Number(t.totalMbps||0).toFixed(2)} Mbps / ${Number(t.totalKpps||0).toFixed(2)} Kpps`}function drawPortChart(name){const c=$("#portLineChart"),h=portHistory[name]||[];if(!c||!h.length)return;const rx=h.map(x=>x.rx),tx=h.map(x=>x.tx),ctx=c.getContext("2d"),w=c.width,ht=c.height,max=Math.max(1,...rx,...tx);ctx.clearRect(0,0,w,ht);ctx.strokeStyle=getComputedStyle(document.body).getPropertyValue("--line").trim();ctx.beginPath();for(let y=24;y<ht;y+=34){ctx.moveTo(0,y);ctx.lineTo(w,y)}ctx.stroke();function line(vals,color){ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();vals.forEach((v,i)=>{const x=i*(w/Math.max(1,vals.length-1)),y=ht-18-(v/max)*(ht-36);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke()}line(rx,"#2563eb");line(tx,"#0f766e");ctx.fillStyle=getComputedStyle(document.body).getPropertyValue("--muted").trim();ctx.fillText("RX blue / TX green",10,14)}
    function rows(headers,items,map){return `<thead><tr>${headers.map(h=>`<th>${h}</th>`).join("")}</tr></thead><tbody>${items.map(item=>`<tr>${map(item).map(v=>`<td>${esc(v)}</td>`).join("")}</tr>`).join("")}</tbody>`}function renderExtra(state){const alerts=state.alerts||[];el.alertList.innerHTML=alerts.length?alerts.map(a=>`<li data-severity="${esc(a.severity)}"><b>${esc(a.title)}</b>${esc(a.message)}</li>`).join(""):"<li>暂无告警</li>";el.lldpList.innerHTML=(state.lldp||[]).length?(state.lldp||[]).map(n=>`<li><b>${esc(n.label)}</b> → ${esc(n.neighbor)} / ${esc(n.neighborPort)}</li>`).join(""):"<li>未发现 LLDP 邻居</li>";const proto=[...(state.protocols?.ospf||[]).map(x=>({type:"OSPF",a:x.neighbor,b:x.state,c:x.interface})),...(state.protocols?.ospfv3||[]).map(x=>({type:"OSPFv3",a:x.neighbor,b:x.state,c:x.interface})),...(state.protocols?.bgp||[]).map(x=>({type:"BGP",a:x.peer,b:x.state,c:x.asn}))];el.protocolTable.innerHTML=rows(["协议","对象","状态","接口/AS"],proto,x=>[x.type,x.a,x.b,x.c]);const tableItems=[...(state.vlans||[]).slice(0,40).map(x=>({type:"VLAN",a:x.id,b:x.name,c:x.status,d:x.ports})),...(state.arp||[]).slice(0,40).map(x=>({type:"ARP",a:x.address,b:x.mac,c:x.interface,d:""})),...(state.fdb||[]).slice(0,40).map(x=>({type:"FDB",a:x.vlan,b:x.mac,c:x.type,d:x.port}))];el.tablesView.innerHTML=rows(["类型","键","值","状态","端口"],tableItems,x=>[x.type,x.a,x.b,x.c,x.d]);const optics=(state.transceivers||[]).filter(x=>x.present!==false).slice(0,96);el.transceiverTable.innerHTML=optics.length?rows(["接口","类型","厂商","型号","序列号","温度","TX/RX","告警"],optics,x=>[x.interface,x.type,x.vendor,x.model,x.serial,x.temperature,`${x.txPower||"-"} / ${x.rxPower||"-"}`,(x.alerts||[]).join("; ")]):rows(["接口","类型","厂商","型号","序列号","温度","TX/RX","告警"],[],x=>[]);const poe=state.poe||{},poeRows=poe.ports||[];el.poeTable.innerHTML=poeRows.length?rows(["接口","Admin","状态","功率","原始行"],poeRows,x=>[x.interface,x.admin,x.state,x.watts,x.raw]):rows(["接口","Admin","状态","功率","原始行"],[{interface:"-",admin:"-",state:poe.supported===false?"当前机型/系统未返回 PoE 数据":"暂无 PoE 数据",watts:"-",raw:""}],x=>[x.interface,x.admin,x.state,x.watts,x.raw]);const i=state.integrations||{};el.integrationView.innerHTML=`<span>Syslog <b>${i.syslog?"ON":"OFF"}</b></span><span>sFlow <b>${i.sflow?"ON":"OFF"}</b></span><span>NetFlow/IPFIX <b>${i.netflow?"ON":"OFF"}</b></span><span>采集 <b>${(state.vlans||[]).length} VLAN / ${(state.arp||[]).length} ARP / ${(state.fdb||[]).length} FDB</b></span>`;if(state.history?.traffic?.length)historyData.splice(0,historyData.length,...state.history.traffic.slice(-80).map(x=>Number(x.totalMbps||0)));drawChart(state.traffic||{})}
    function render(state){const d=state.device||{},h=state.health||{},t=state.traffic||{},ports=state.ports||[],up=ports.filter(p=>p.status==="up").length,media=ports.filter(p=>p.hasMedia&&p.status!=="up").length,err=ports.filter(p=>Number(p.errors||0)>0).length;currentPorts=ports;ports.forEach(p=>{const k=p.name;const saved=(state.history?.ports?.[k]||[]).slice(-80).map(x=>({rx:Number(x.rxMbps||0),tx:Number(x.txMbps||0)}));portHistory[k]=saved.length?saved:(portHistory[k]||[]);if(!saved.length)portHistory[k].push({rx:Number(p.rxMbps||0),tx:Number(p.txMbps||0)});while(portHistory[k].length>80)portHistory[k].shift()});el.hostname.textContent=d.hostname||"-";el.eosVersion.textContent=d.eosVersion||"-";el.forwardingLive.textContent=d.forwardingRate||t.packetRateLabel||"-";el.switchingLive.textContent=d.switchingCapacity||t.throughputLabel||"-";el.trafficSubline.textContent=`RX ${mbps(t.rxMbps)} / TX ${mbps(t.txMbps)}`;el.capacitySubline.textContent=`占用 ${Number(t.capacityUtilization||0).toFixed(4)}% of 2.56Tbps`;const summary=`${up}/${ports.length} up, ${media} media, ${err} error`;el.portSummary.textContent=summary;el.portsPageSummary.textContent=summary;el.lastRefresh.textContent=fmt(d.lastRefresh);el.cpuMeter.value=Number(h.cpu||0);el.cpuValue.textContent=pct(h.cpu);el.memoryMeter.value=Number(h.memory||0);el.memoryValue.textContent=pct(h.memory);el.temperatureMeter.value=Number(h.temperature||0);el.temperatureValue.textContent=Number.isFinite(Number(h.temperature))?`${h.temperature}C`:"-";el.fanStatus.textContent=h.fanStatus||"-";el.psuStatus.textContent=h.psuStatus||"-";el.portGrid.innerHTML=ports.map((p,i)=>`<button class="port" data-index="${i}" data-status="${p.status}" data-media="${Boolean(p.hasMedia)}" data-errors="${Number(p.errors||0)>0}"><div class="port-name"><span>${esc(p.label||p.name)}</span><span class="port-speed">${esc(p.speed)}</span></div><div class="port-detail">${esc(p.media)} / VLAN ${esc(p.vlan)}<br>${esc(p.description||p.status)}</div><div class="port-traffic"><span>RX <b>${mbps(p.rxMbps)}</b></span><span>TX <b>${mbps(p.txMbps)}</b></span></div></button>`).join("");if(activePortIndex!==null&&el.portModal.classList.contains("show"))drawPortChart(currentPorts[activePortIndex]?.name);el.eventList.innerHTML=(state.events||[]).map(e=>`<li data-level="${e.level||"info"}"><span class="event-time">${fmt(e.time)} / ${esc(e.level||"info")}</span><span class="event-message">${esc(e.message)}</span></li>`).join("");renderExtra(state)}
    async function load(){const p=await req("/api/state");render(p.state)}async function refresh(){el.refreshBtn.disabled=true;el.refreshBtn.textContent="刷新中";try{const p=await req("/api/refresh",{method:"POST",body:"{}"});render(p.state);toast("已从 EOS CLI 刷新")}catch(e){toast(e.message)}finally{el.refreshBtn.disabled=false;el.refreshBtn.textContent="刷新"}}
    function opsPayload(dryRun){return{action:el.opsAction.value,confirm:el.opsConfirm.value,dryRun,params:{interface:el.opsInterface.value,state:el.opsState.value,mode:el.opsState.value,vlan:el.opsVlan.value,nativeVlan:el.opsText.value,description:el.opsText.value,name:el.opsText.value,address:el.opsAddress.value,network:el.opsAddress.value,addressFamily:el.opsAddress.value||"ipv4",process:el.opsProcess.value,asn:el.opsProcess.value,area:el.opsArea.value,remoteAs:el.opsArea.value,neighbor:el.opsNeighbor.value}}}async function runOps(dryRun){el.opsOutput.textContent=dryRun?"生成配置中...":"执行配置中...";try{const p=await req("/api/config",{method:"POST",body:JSON.stringify(opsPayload(dryRun))});el.opsOutput.textContent=(p.commands||[]).join("\n")+(p.diff?`\n\nDIFF:\n${p.diff}`:"")+(p.output?`\n\n${p.output}`:"");if(!dryRun){toast("配置已提交");refresh()}}catch(err){el.opsOutput.textContent=`ERROR: ${err.message}`}}
    el.refreshBtn.addEventListener("click",refresh);el.themeBtn.addEventListener("click",()=>setTheme(document.body.dataset.theme==="dark"?"light":"dark"));el.dashboardNav.addEventListener("click",()=>showPage("dashboard"));el.portsNav.addEventListener("click",()=>showPage("ports"));el.openPortsBtn.addEventListener("click",()=>showPage("ports"));el.portGrid.addEventListener("click",e=>{const card=e.target.closest(".port");if(card)showPort(Number(card.dataset.index))});el.modalClose.addEventListener("click",()=>el.portModal.classList.remove("show"));el.portModal.addEventListener("click",e=>{if(e.target===el.portModal)el.portModal.classList.remove("show")});el.opsPreview.addEventListener("click",()=>runOps(true));el.opsForm.addEventListener("submit",e=>{e.preventDefault();runOps(false)});el.commandForm.addEventListener("submit",async e=>{e.preventDefault();const command=el.commandInput.value.trim();if(!command)return;el.commandOutput.textContent=`> ${command}\n运行中...`;try{const p=await req("/api/command",{method:"POST",body:JSON.stringify({command})});el.commandOutput.textContent=`> ${p.command}\n${p.output}`}catch(err){el.commandOutput.textContent=`> ${command}\nERROR: ${err.message}`}});showPage(location.pathname==="/ports"?"ports":"dashboard");load().catch(e=>toast(e.message));setInterval(()=>load().catch(()=>{}),15000);
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
        self.wfile.write(body)

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
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/state":
            if not Handler.cached_state or time.time() - Handler.cached_at > 10:
                Handler.cached_state = collect_state()
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
                Handler.cached_state = collect_state()
                Handler.cached_at = time.time()
                self.send_json(200, {"ok": True, "state": Handler.cached_state})
                return

            if path == "/api/command":
                payload = self.read_json()
                command = str(payload.get("command", "")).strip()
                output = run_cli(command)
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
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    print("Arista 7050QX on-box web console listening on %s://%s:%s" % (scheme, args.host, args.port))
    print("Open %s://<switch-management-ip>:%s/" % (scheme, args.port))
    server.serve_forever()


if __name__ == "__main__":
    main()
