#!/usr/bin/env python3
import argparse
import base64
import csv
import difflib
import getpass
import glob
import hashlib
import hmac
import io
import ipaddress
import json
import math
import os
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import http.cookiejar
import urllib.error
import urllib.request

MODEL = "Arista DCS-7050QX-32S-F"
DATA_DIR = os.environ.get("WEB_DATA_DIR", "/mnt/flash")
HISTORY_FILE = os.environ.get("WEB_HISTORY_FILE", os.path.join(DATA_DIR, "arista7050_web_history.jsonl"))
LEGACY_HISTORY_FILE = os.environ.get("WEB_LEGACY_HISTORY_FILE", os.path.join(DATA_DIR, "arista7050_web_history.json"))
AUDIT_FILE = os.environ.get("WEB_AUDIT_FILE", os.path.join(DATA_DIR, "arista7050_web_audit.jsonl"))
EAPI_URL = os.environ.get("WEB_EAPI_URL", "http://localhost:8080/command-api")
EAPI_ENABLED = os.environ.get("WEB_USE_EAPI", "1").lower() not in ("0", "false", "no")
READ_ONLY = re.compile(r"^(show|ping|traceroute|traceroute6)\b", re.I)
BLOCKED = re.compile(r"^(configure|conf|enable|reload|reboot|write|copy|delete|erase|bash|sudo|install)\b", re.I)
APP_VERSION = os.environ.get("WEB_VERSION", "dev")
ARTIFACT_SHA = os.environ.get("WEB_ARTIFACT_SHA", "unknown")
WEB_STYLE_HASH = "sha256-r0sQUVHXfgXW58YwbR7xcVRpqPsEDHMdXCTvNbexKi0="
WEB_SCRIPT_HASH = "sha256-SN7FUQgaIi0BHCWI3lYORkk7TSwP34pYVa7isN9aPkA="

PASSWORD_ITERATIONS = 310000
SESSION_TTL_SECONDS = 12 * 60 * 60
UNLOCK_TTL_SECONDS = 15 * 60
PREVIEW_TTL_SECONDS = 5 * 60
MAX_REQUEST_BODY = 64 * 1024
MAX_COMMAND_OUTPUT = 256 * 1024
MAX_RUNNING_CONFIG = 2 * 1024 * 1024
MAX_HTTP_WORKERS = 16
TLS_HANDSHAKE_TIMEOUT = 5
HTTP_HEADER_TIMEOUT = 10
HTTP_BODY_TIMEOUT = 15
HTTP_IO_TIMEOUT = 45
HTTP_CONNECTION_TIMEOUT = 120
HISTORY_SAMPLE_SECONDS = 60
HISTORY_MAX_POINTS = 1440
HISTORY_SEGMENT_POINTS = 60
HISTORY_MAX_SEGMENTS = 24
HISTORY_SEGMENT_BYTES = 64 * 1024

_AUTH_RECORD = None
_SESSIONS = {}
_SESSION_LOCK = threading.RLock()
_PREVIEWS = {}
_PREVIEW_LOCK = threading.RLock()
_CONFIG_LOCK = threading.Lock()
_HISTORY_LOCK = threading.Lock()
_TRAFFIC_HISTORY = None
_PORT_HISTORY = {}
_HISTORY_ACTIVE_LINES = 0
_COLLECTION_CONDITION = threading.Condition(threading.RLock())
_COLLECTION_INFLIGHT = set()
_COLLECTION_RESULTS = {}
_AUTH_FAILURES = {}
_AUTH_FAILURE_LOCK = threading.Lock()
_AUDIT_LOCK = threading.Lock()
_EAPI_BREAKER_LOCK = threading.Lock()
_EAPI_FAILURE_UNTIL = 0.0
_COMMAND_SLOTS = threading.BoundedSemaphore(4)


class APIError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = int(status)
        self.code = str(code)
        self.message = str(message)


def now_ms():
    return int(time.time() * 1000)


def read_json_file(path, fallback):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return fallback


def write_json_file(path, payload):
    tmp = None
    try:
        directory = os.path.dirname(path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        tmp = "%s.tmp.%s.%s" % (path, os.getpid(), threading.get_ident())
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
        return True
    except Exception:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return False


def rotate_file(path, max_bytes=1024 * 1024, backups=2):
    try:
        if not os.path.exists(path) or os.path.getsize(path) < max_bytes:
            return
        for index in range(backups, 0, -1):
            source = path if index == 1 else "%s.%s" % (path, index - 1)
            destination = "%s.%s" % (path, index)
            if not os.path.exists(source):
                continue
            if os.path.exists(destination):
                os.unlink(destination)
            os.replace(source, destination)
    except OSError:
        pass


def append_audit(entry):
    record = dict(entry)
    record["time"] = now_ms()
    with _AUDIT_LOCK:
        try:
            rotate_file(AUDIT_FILE)
            directory = os.path.dirname(AUDIT_FILE)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)
            with open(AUDIT_FILE, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            try:
                os.chmod(AUDIT_FILE, 0o600)
            except OSError:
                pass
        except Exception:
            pass


def is_safe_command(command):
    command = command.strip()
    if not command or len(command) > 512 or "\x00" in command:
        return False
    if any(character in command for character in ("\r", "\n", ";", ">", "<", "&", "`")) or "$(" in command:
        return False
    if BLOCKED.search(command) or not READ_ONLY.search(command):
        return False
    if re.match(r"^(?:ping|traceroute|traceroute6)\b", command, re.I):
        match = re.fullmatch(r"(?:ping|traceroute|traceroute6)\s+([^\s]+)", command, re.I)
        if not match:
            return False
        try:
            ipaddress.ip_address(match.group(1))
            return True
        except ValueError:
            return False
    segments = [segment.strip() for segment in command.split("|")]
    if not re.fullmatch(r"show\s+[A-Za-z0-9_.:/ -]+", segments[0], re.I):
        return False
    for modifier in segments[1:]:
        if not re.fullmatch(r"(?:count|json)", modifier, re.I) and not re.fullmatch(r"(?:include|exclude|begin)\s+[A-Za-z0-9_.:/ -]{1,160}", modifier, re.I):
            return False
    return True


def password_record(username, password, salt=None, iterations=PASSWORD_ITERATIONS):
    username = str(username or "").strip()
    if not username or len(username) > 64 or not re.match(r"^[A-Za-z0-9_.@-]+$", username):
        raise ValueError("Invalid authentication username.")
    if not isinstance(password, str) or not password:
        raise ValueError("Password cannot be empty.")
    if salt is None:
        salt = secrets.token_bytes(32)
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Authentication salt must be at least 16 bytes.")
    iterations = int(iterations)
    if iterations < 100000:
        raise ValueError("PBKDF2 iteration count is too low.")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {
        "schemaVersion": 1,
        "username": username,
        "algorithm": "pbkdf2-sha256",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "passwordHash": base64.b64encode(digest).decode("ascii"),
        "createdAt": now_ms(),
    }


def make_password_record(password, username="admin", salt=None, iterations=PASSWORD_ITERATIONS):
    return password_record(username, password, salt=salt, iterations=iterations)


def validate_auth_record(record):
    if not isinstance(record, dict) or record.get("algorithm") != "pbkdf2-sha256":
        raise ValueError("Unsupported authentication configuration.")
    username = str(record.get("username") or "").strip()
    if not username or len(username) > 64 or not re.match(r"^[A-Za-z0-9_.@-]+$", username):
        raise ValueError("Invalid authentication username.")
    iterations = int(record.get("iterations") or 0)
    if iterations < 100000:
        raise ValueError("PBKDF2 iteration count is too low.")
    try:
        salt = base64.b64decode(str(record.get("salt") or ""), validate=True)
        digest = base64.b64decode(str(record.get("passwordHash") or ""), validate=True)
    except Exception as exc:
        raise ValueError("Authentication hash encoding is invalid.") from exc
    if len(salt) < 16 or len(digest) != 32:
        raise ValueError("Authentication hash data is invalid.")
    return record


def verify_password(username, password, record=None):
    if isinstance(password, dict) and record is None:
        record = password
        password = username
        username = record.get("username")
    record = record or _AUTH_RECORD
    if not isinstance(record, dict):
        return False
    try:
        validate_auth_record(record)
        expected_user = str(record["username"])
        supplied_user = str(username or "")
        supplied_password = str(password or "")
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["passwordHash"], validate=True)
        actual = hashlib.pbkdf2_hmac("sha256", supplied_password.encode("utf-8"), salt, int(record["iterations"]))
        return hmac.compare_digest(supplied_user.encode("utf-8"), expected_user.encode("utf-8")) and hmac.compare_digest(actual, expected)
    except Exception:
        return False


def load_auth_config(path):
    if not path or not os.path.isfile(path):
        raise ValueError("Authentication config is required and must exist.")
    if os.name == "posix" and os.stat(path).st_mode & 0o077:
        raise ValueError("Authentication config permissions must be 0600.")
    with open(path, "r", encoding="utf-8") as handle:
        record = json.load(handle)
    return validate_auth_record(record)


def init_auth_config(path, username, password):
    if not path:
        raise ValueError("Authentication config path is required.")
    record = password_record(username, password)
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700)
    if not write_json_file(path, record):
        raise RuntimeError("Unable to write authentication config.")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return record


def _cleanup_sessions(now=None):
    now = time.time() if now is None else float(now)
    expired = [token for token, session in _SESSIONS.items() if float(session.get("expiresAt", 0)) <= now]
    for token in expired:
        _SESSIONS.pop(token, None)


def create_session(username, now=None):
    now = time.time() if now is None else float(now)
    token = secrets.token_urlsafe(32)
    session = {
        "user": str(username),
        "csrfToken": secrets.token_urlsafe(24),
        "createdAt": now,
        "expiresAt": now + SESSION_TTL_SECONDS,
        "unlockedUntil": 0.0,
    }
    with _SESSION_LOCK:
        _cleanup_sessions(now)
        if len(_SESSIONS) >= 256:
            oldest = min(_SESSIONS, key=lambda item: float(_SESSIONS[item].get("createdAt", 0)))
            _SESSIONS.pop(oldest, None)
        _SESSIONS[token] = session
    return token, dict(session)


def get_session(token, now=None):
    if not token:
        return None
    now = time.time() if now is None else float(now)
    with _SESSION_LOCK:
        _cleanup_sessions(now)
        session = _SESSIONS.get(str(token))
        return dict(session) if session else None


def session_csrf_valid(session, supplied_token):
    expected = str((session or {}).get("csrfToken") or "")
    supplied = str(supplied_token or "")
    return bool(expected and supplied) and hmac.compare_digest(expected.encode("utf-8"), supplied.encode("utf-8"))


def secure_compare(left, right):
    return hmac.compare_digest(str(left or "").encode("utf-8"), str(right or "").encode("utf-8"))


def session_is_unlocked(session, now=None):
    now = time.time() if now is None else float(now)
    return bool(session) and float(session.get("unlockedUntil") or 0) > now


def session_payload(session):
    if not session:
        return {"authenticated": False, "user": None, "csrfToken": None, "unlockedUntil": 0}
    return {
        "authenticated": True,
        "user": session.get("user"),
        "csrfToken": session.get("csrfToken"),
        "unlockedUntil": int(float(session.get("unlockedUntil") or 0) * 1000),
    }


def bounded_text(value, limit=MAX_COMMAND_OUTPUT):
    text = str(value or "")
    encoded = text.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return text
    suffix = "\n\n[output truncated at %s bytes]" % limit
    return encoded[:limit].decode("utf-8", "ignore") + suffix


def config_hash(config_text):
    normalized = str(config_text or "").replace("\r\n", "\n").rstrip() + "\n"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def run_bounded_process(command, timeout, max_output=MAX_COMMAND_OUTPUT):
    if not _COMMAND_SLOTS.acquire(timeout=3):
        raise RuntimeError("EOS command executor is busy.")
    process = None
    readers = []
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        output_lock = threading.Lock()
        exceeded = threading.Event()

        def drain(stream, name):
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    return
                with output_lock:
                    current = len(buffers["stdout"]) + len(buffers["stderr"])
                    remaining = int(max_output) + 1 - current
                    if remaining > 0:
                        buffers[name].extend(chunk[:remaining])
                    if current + len(chunk) > int(max_output):
                        exceeded.set()
                        try:
                            process.kill()
                        except OSError:
                            pass
                        return

        readers = [
            threading.Thread(target=drain, args=(process.stdout, "stdout"), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, "stderr"), daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            for reader in readers:
                reader.join(timeout=1)
            raise
        for reader in readers:
            reader.join(timeout=1)
        if exceeded.is_set():
            raise RuntimeError("EOS command output exceeded the %s-byte limit." % int(max_output))
        return subprocess.CompletedProcess(
            command,
            return_code,
            bytes(buffers["stdout"]).decode("utf-8", "replace"),
            bytes(buffers["stderr"]).decode("utf-8", "replace"),
        )
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                    process.wait()
                except OSError:
                    pass
            for reader in readers:
                reader.join(timeout=1)
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except (AttributeError, OSError):
                    pass
        _COMMAND_SLOTS.release()


def run_cli(command, timeout=22):
    if not is_safe_command(command):
        raise ValueError("Only registered read-only EOS commands are allowed.")

    candidates = [
        ["FastCli", "-p", "15", "-c", command],
        ["/usr/bin/FastCli", "-p", "15", "-c", command],
        ["Cli", "-c", command],
        ["/usr/bin/Cli", "-c", command],
    ]

    last_error = None
    for cmd in candidates:
        try:
            result = run_bounded_process(cmd, timeout)
            output = (result.stdout or "").strip()
            error = (result.stderr or "").strip()
            if result.returncode == 0 and output:
                return bounded_text(output)
            last_error = bounded_text(error or output or "command returned %s" % result.returncode, 8192)
        except FileNotFoundError as exc:
            last_error = str(exc)
        except subprocess.TimeoutExpired:
            raise TimeoutError("Command timed out.")

    raise RuntimeError(last_error or "No EOS CLI runner found.")


def run_eapi(commands, fmt="json", timeout=12):
    global _EAPI_FAILURE_UNTIL
    if not EAPI_ENABLED:
        raise RuntimeError("eAPI disabled by WEB_USE_EAPI.")
    with _EAPI_BREAKER_LOCK:
        if time.time() < _EAPI_FAILURE_UNTIL:
            raise RuntimeError("eAPI temporarily disabled after a recent failure.")
    if isinstance(commands, str):
        commands = [commands]
    commands = [str(command).strip() for command in commands if str(command).strip()]
    for command in commands:
        if not is_safe_command(command):
            raise ValueError("Only registered read-only EOS commands are allowed.")
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
            raw_body = response.read(MAX_COMMAND_OUTPUT + 1)
            if len(raw_body) > MAX_COMMAND_OUTPUT:
                raise RuntimeError("eAPI response exceeded the output limit.")
            body = raw_body.decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        with _EAPI_BREAKER_LOCK:
            _EAPI_FAILURE_UNTIL = time.time() + 15
        raise RuntimeError("eAPI unavailable: %s" % exc)
    try:
        data = json.loads(body)
    except ValueError:
        with _EAPI_BREAKER_LOCK:
            _EAPI_FAILURE_UNTIL = time.time() + 15
        raise RuntimeError("eAPI returned non-JSON response.")
    if data.get("error"):
        error = data.get("error") or {}
        details = error.get("data") or error.get("message") or error
        with _EAPI_BREAKER_LOCK:
            _EAPI_FAILURE_UNTIL = time.time() + 15
        raise RuntimeError("eAPI command failed: %s" % details)
    result = data.get("result")
    if not isinstance(result, list):
        with _EAPI_BREAKER_LOCK:
            _EAPI_FAILURE_UNTIL = time.time() + 15
        raise RuntimeError("eAPI returned unexpected result.")
    with _EAPI_BREAKER_LOCK:
        _EAPI_FAILURE_UNTIL = 0.0
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
    mapping = {command: {} for command in commands}
    try:
        results = run_eapi(commands, fmt="json", timeout=timeout)
        for command, result in zip(commands, results):
            mapping[command] = result if isinstance(result, dict) else {}
    except Exception:
        return mapping
    return mapping


def run_eos_script(script, timeout=25):
    runners = [["/usr/bin/FastCli", "-p", "15", "-c", script], ["FastCli", "-p", "15", "-c", script], ["/usr/bin/Cli", "-c", script], ["Cli", "-c", script]]
    last_error = None
    for cmd in runners:
        try:
            result = run_bounded_process(cmd, timeout)
            output = bounded_text(((result.stdout or "") + (result.stderr or "")).strip())
            if result.returncode == 0:
                return output or "OK"
            raise RuntimeError(output or "command returned %s" % result.returncode)
        except FileNotFoundError as exc:
            last_error = str(exc)
    raise RuntimeError(last_error or "No EOS CLI runner found.")


def get_running_config(timeout=25):
    """Read an untruncated baseline; fail closed rather than hash a prefix."""
    runners = [["/usr/bin/FastCli", "-p", "15", "-c", "show running-config"], ["FastCli", "-p", "15", "-c", "show running-config"], ["/usr/bin/Cli", "-c", "show running-config"], ["Cli", "-c", "show running-config"]]
    last_error = None
    for cmd in runners:
        try:
            result = run_bounded_process(cmd, timeout, max_output=MAX_RUNNING_CONFIG)
        except FileNotFoundError as exc:
            last_error = str(exc)
            continue
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0:
            raise RuntimeError(output.strip() or "show running-config returned %s" % result.returncode)
        encoded = output.encode("utf-8", "replace")
        if len(encoded) > MAX_RUNNING_CONFIG:
            raise RuntimeError("Running configuration exceeds the safe baseline limit.")
        if not output.strip():
            raise RuntimeError("Running configuration was empty.")
        return output.strip()
    raise RuntimeError(last_error or "No EOS CLI runner found for running configuration.")


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
    idle_value = cpu_values.get("idle") if isinstance(cpu_values, dict) else None
    idle = float(idle_value) if idle_value is not None else None
    cpu = max(0, min(100, round(100 - idle))) if idle is not None else None

    physical = ((top_data or {}).get("memInfo") or {}).get("physicalMem") or {}
    total_kib = float(physical.get("memTotal") or (version_data or {}).get("memTotal") or 0)
    used_kib = float(physical.get("memUsed") or 0)
    free_kib = float(physical.get("memFree") or (version_data or {}).get("memFree") or 0)
    buffer_kib = float(physical.get("memBuffer") or 0)
    available_kib = free_kib + buffer_kib if buffer_kib else free_kib
    if not used_kib and total_kib:
        used_kib = max(0.0, total_kib - available_kib)
    memory = round((used_kib / total_kib) * 100) if total_kib else None
    health.update(
        {
            "cpu": cpu,
            "memory": memory,
            "memoryTotalMiB": round(total_kib / 1024.0, 1) if total_kib else None,
            "memoryUsedMiB": round(used_kib / 1024.0, 1) if total_kib else None,
            "memoryAvailableMiB": round(available_kib / 1024.0, 1) if total_kib else None,
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
    temperature = round(max(temperatures)) if temperatures else None

    temp_status = re.search(r"System temperature status is:\s*([A-Za-z]+)", output, re.I)
    cooling_status = re.search(r"System cooling status is:\s*([A-Za-z]+)", output, re.I)
    fan_status = "OK" if output.strip() else "UNKNOWN"
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
    psu_status = "CHECK" if psu_fault or psu_redundancy_lost or (psu_statuses and not psu_ok) else ("OK" if output.strip() else "UNKNOWN")

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
    cpu = None
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

    memory = round(((mem_total - mem_avail) / mem_total) * 100) if mem_total else None
    health.update(
        {
            "cpu": cpu,
            "memory": memory,
            "memoryTotalMiB": round(mem_total, 1) if mem_total else None,
            "memoryUsedMiB": round(mem_used, 1) if mem_total else None,
            "memoryAvailableMiB": round(mem_avail, 1) if mem_total else None,
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


def _finite_number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    return round(number, 4) if math.isfinite(number) else 0


def _history_hour(timestamp_ms):
    return time.strftime("%Y%m%d%H", time.localtime(float(timestamp_ms) / 1000.0))


def _history_archive_paths():
    pattern = "%s.*" % HISTORY_FILE
    paths = []
    for path in glob.glob(pattern):
        suffix = path[len(HISTORY_FILE) + 1 :]
        if re.fullmatch(r"\d{10}", suffix):
            paths.append(path)
    return sorted(paths)


def _read_jsonl_points(path):
    points = []
    if not path or not os.path.isfile(path):
        return points
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                if len(line) > 4096:
                    continue
                try:
                    point = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(point, dict) or not point.get("time"):
                    continue
                points.append(
                    {
                        "time": int(point.get("time")),
                        "rxMbps": _finite_number(point.get("rxMbps")),
                        "txMbps": _finite_number(point.get("txMbps")),
                        "totalMbps": _finite_number(point.get("totalMbps")),
                    }
                )
    except (OSError, UnicodeError, ValueError):
        return []
    return points


def _write_jsonl_atomic(path, points):
    tmp = "%s.tmp.%s.%s" % (path, os.getpid(), threading.get_ident())
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700)
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            for point in points:
                handle.write(json.dumps(point, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _fsync_parent_directory(path):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    descriptor = None
    try:
        descriptor = os.open(directory, os.O_RDONLY)
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _persist_grouped_history(points):
    global _HISTORY_ACTIVE_LINES
    points = list(points or [])[-HISTORY_MAX_POINTS:]
    groups = {}
    for point in points:
        groups.setdefault(_history_hour(point["time"]), []).append(point)
    hours = sorted(groups)[-HISTORY_MAX_SEGMENTS:]
    known_paths = _history_archive_paths()
    if os.path.exists(HISTORY_FILE):
        known_paths.append(HISTORY_FILE)
    if not hours:
        for path in known_paths:
            try:
                os.unlink(path)
            except OSError:
                pass
        _fsync_parent_directory(HISTORY_FILE)
        _HISTORY_ACTIVE_LINES = 0
        return

    active_hour = hours[-1]
    transaction = "%s.%s.%s" % (os.getpid(), threading.get_ident(), secrets.token_hex(8))
    staged = []
    for hour in hours:
        path = HISTORY_FILE if hour == active_hour else "%s.%s" % (HISTORY_FILE, hour)
        stage = "%s.stage.%s" % (path, transaction)
        staged.append((stage, path, groups[hour][-HISTORY_SEGMENT_POINTS:]))

    try:
        for stage, _path, grouped_points in staged:
            _write_jsonl_atomic(stage, grouped_points)
    except Exception:
        for stage, _path, _grouped_points in staged:
            try:
                os.unlink(stage)
            except OSError:
                pass
        raise

    target_paths = {path for _stage, path, _grouped_points in staged}
    try:
        for stage, path, _grouped_points in staged:
            os.replace(stage, path)
        for path in known_paths:
            if path not in target_paths:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        _fsync_parent_directory(HISTORY_FILE)
    finally:
        for stage, _path, _grouped_points in staged:
            try:
                os.unlink(stage)
            except OSError:
                pass
    _HISTORY_ACTIVE_LINES = len(groups[active_hour][-HISTORY_SEGMENT_POINTS:])


def _legacy_history():
    if os.path.isfile(HISTORY_FILE):
        payload = read_json_file(HISTORY_FILE, None)
        if isinstance(payload, dict) and isinstance(payload.get("traffic"), list):
            return HISTORY_FILE, payload
        return None, None
    if _history_archive_paths():
        return None, None
    candidates = [LEGACY_HISTORY_FILE]
    if not os.path.isfile(LEGACY_HISTORY_FILE):
        candidates.append("%s.legacy" % LEGACY_HISTORY_FILE)
    for path in candidates:
        if path and os.path.isfile(path):
            payload = read_json_file(path, None)
            if isinstance(payload, dict) and isinstance(payload.get("traffic"), list):
                return path, payload
    return None, None


def _load_history_locked():
    global _TRAFFIC_HISTORY, _PORT_HISTORY, _HISTORY_ACTIVE_LINES
    if _TRAFFIC_HISTORY is not None:
        return
    legacy_path, legacy = _legacy_history()
    if legacy is not None:
        _TRAFFIC_HISTORY = [
            {
                "time": int(point.get("time")),
                "rxMbps": _finite_number(point.get("rxMbps")),
                "txMbps": _finite_number(point.get("txMbps")),
                "totalMbps": _finite_number(point.get("totalMbps")),
            }
            for point in legacy.get("traffic", [])
            if isinstance(point, dict) and point.get("time")
        ][-HISTORY_MAX_POINTS:]
        legacy_ports = legacy.get("ports") if isinstance(legacy.get("ports"), dict) else {}
        _PORT_HISTORY = {name: list(series or [])[-80:] for name, series in legacy_ports.items()}
        backup = "%s.legacy" % legacy_path
        try:
            if os.path.exists(backup):
                os.unlink(backup)
            os.replace(legacy_path, backup)
        except OSError:
            if os.path.abspath(legacy_path) == os.path.abspath(HISTORY_FILE):
                raise RuntimeError("Unable to migrate legacy history safely.")
        _persist_grouped_history(_TRAFFIC_HISTORY)
        return

    archive_points = []
    for path in _history_archive_paths():
        archive_points.extend(_read_jsonl_points(path))
    active_points = _read_jsonl_points(HISTORY_FILE)
    _HISTORY_ACTIVE_LINES = len(active_points)
    _TRAFFIC_HISTORY = (archive_points + active_points)[-HISTORY_MAX_POINTS:]
    _PORT_HISTORY = {}
    if _HISTORY_ACTIVE_LINES > HISTORY_SEGMENT_POINTS or (os.path.exists(HISTORY_FILE) and os.path.getsize(HISTORY_FILE) > HISTORY_SEGMENT_BYTES):
        _persist_grouped_history(_TRAFFIC_HISTORY)


def _history_snapshot_locked():
    return {
        "traffic": list(_TRAFFIC_HISTORY or [])[-HISTORY_MAX_POINTS:],
        "ports": {name: list(series or [])[-80:] for name, series in _PORT_HISTORY.items()},
    }


def read_history():
    with _HISTORY_LOCK:
        _load_history_locked()
        return _history_snapshot_locked()


def _rotate_history_segment_locked(previous_time):
    global _HISTORY_ACTIVE_LINES
    if os.path.isfile(HISTORY_FILE):
        archive = "%s.%s" % (HISTORY_FILE, _history_hour(previous_time))
        if os.path.exists(archive):
            try:
                with open(archive, "ab") as destination, open(HISTORY_FILE, "rb") as source:
                    destination.write(source.read())
                    destination.flush()
                    os.fsync(destination.fileno())
                os.unlink(HISTORY_FILE)
                combined = _read_jsonl_points(archive)
                if len(combined) > HISTORY_SEGMENT_POINTS:
                    _write_jsonl_atomic(archive, combined[-HISTORY_SEGMENT_POINTS:])
            except OSError:
                pass
        else:
            try:
                os.replace(HISTORY_FILE, archive)
            except OSError:
                pass
    archives = _history_archive_paths()
    for stale in archives[: max(0, len(archives) - (HISTORY_MAX_SEGMENTS - 1))]:
        try:
            os.unlink(stale)
        except OSError:
            pass
    _HISTORY_ACTIVE_LINES = 0


def update_history(ports, traffic):
    global _TRAFFIC_HISTORY, _PORT_HISTORY, _HISTORY_ACTIVE_LINES
    persist_error = None
    with _HISTORY_LOCK:
        _load_history_locked()
        timestamp = now_ms()
        previous = _TRAFFIC_HISTORY[-1] if _TRAFFIC_HISTORY else None
        if previous and timestamp - int(previous.get("time") or 0) < HISTORY_SAMPLE_SECONDS * 1000:
            return _history_snapshot_locked()

        point = {
            "time": timestamp,
            "rxMbps": _finite_number(traffic.get("rxMbps")),
            "txMbps": _finite_number(traffic.get("txMbps")),
            "totalMbps": _finite_number(traffic.get("totalMbps")),
        }
        if previous and (
            _history_hour(previous["time"]) != _history_hour(timestamp)
            or _HISTORY_ACTIVE_LINES >= HISTORY_SEGMENT_POINTS
            or (os.path.exists(HISTORY_FILE) and os.path.getsize(HISTORY_FILE) >= HISTORY_SEGMENT_BYTES)
        ):
            _rotate_history_segment_locked(previous["time"])

        try:
            directory = os.path.dirname(HISTORY_FILE)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, mode=0o700)
            with open(HISTORY_FILE, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(point, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(HISTORY_FILE, 0o600)
            except OSError:
                pass
            _HISTORY_ACTIVE_LINES += 1
        except OSError as exc:
            persist_error = exc

        _TRAFFIC_HISTORY.append(point)
        _TRAFFIC_HISTORY = _TRAFFIC_HISTORY[-HISTORY_MAX_POINTS:]
        active_names = set()
        for port in ports:
            name = str(port.get("name") or "")
            if not name:
                continue
            active_names.add(name)
            series = _PORT_HISTORY.setdefault(name, [])
            series.append(
                {
                    "time": timestamp,
                    "rxMbps": _finite_number(port.get("rxMbps")),
                    "txMbps": _finite_number(port.get("txMbps")),
                    "errors": int(port.get("errors") or 0),
                }
            )
            _PORT_HISTORY[name] = series[-80:]
        _PORT_HISTORY = {name: series for name, series in _PORT_HISTORY.items() if name in active_names}
        snapshot = _history_snapshot_locked()
    if persist_error:
        append_audit({"event": "history_persist_failed", "error": bounded_text(persist_error, 512)})
    return snapshot


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
    if health.get("fanStatus") == "CHECK":
        alerts.append({"severity": "critical", "title": "风扇状态异常", "message": "请检查 show environment all。"})
    if health.get("psuStatus") == "CHECK":
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


def safe_text(value, pattern=r"^[\w .:/@+-]{1,80}$"):
    value = str(value or "").strip()
    if any(character in value for character in ("\r", "\n", "\x00")) or not re.fullmatch(pattern, value):
        raise ValueError("Invalid text input.")
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
    if not text or not re.fullmatch(r"[\d,\- ]+", text):
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
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("Expected IPv4 address.")
    if address.version != 4:
        raise ValueError("Expected IPv4 address.")
    return str(address)


def safe_ip(value):
    value = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError("Expected a valid IPv4 or IPv6 address.")


def safe_ip_prefix(value):
    value = str(value or "").strip()
    try:
        interface = ipaddress.ip_interface(value)
    except ValueError:
        raise ValueError("Expected valid IPv4 prefix like 192.168.1.1/24.")
    if interface.version != 4:
        raise ValueError("Expected valid IPv4 prefix like 192.168.1.1/24.")
    return str(interface)


def safe_svi_ip_prefix(value):
    value = safe_ip_prefix(value)
    interface = ipaddress.ip_interface(value)
    network = interface.network
    if network.version != 4:
        raise ValueError("Expected IPv4 prefix.")
    if network.prefixlen < 31 and interface.ip in (network.network_address, network.broadcast_address):
        raise ValueError("SVI address cannot be the network or broadcast address.")
    return value


def safe_asn(value):
    text = str(value or "").strip()
    if not re.fullmatch(r"\d{1,10}", text):
        raise ValueError("ASN must be an integer from 1 to 4294967295.")
    number = int(text)
    if number < 1 or number > 4294967295:
        raise ValueError("ASN must be an integer from 1 to 4294967295.")
    return str(number)


def safe_ospf_area(value):
    text = str(value or "0").strip()
    if re.fullmatch(r"\d{1,10}", text):
        number = int(text)
        if 0 <= number <= 4294967295:
            return str(number)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise ValueError("OSPF area must be 0-4294967295 or dotted IPv4 notation.")
    if address.version != 4:
        raise ValueError("OSPF area must use IPv4 dotted notation.")
    return str(address)


def safe_ospf_process(value):
    text = str(value or "1").strip()
    if not re.fullmatch(r"\d{1,5}", text) or not 1 <= int(text) <= 65535:
        raise ValueError("OSPF process must be 1-65535.")
    return str(int(text))


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
        description = str(params.get("description") or "").strip()
        return ["interface %s" % safe_interface(params.get("interface")), "description %s" % safe_text(description)] if description else ["interface %s" % safe_interface(params.get("interface")), "no description"]
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
        process = safe_ospf_process(params.get("process") or "1")
        network = safe_ip_prefix(params.get("network"))
        area = safe_ospf_area(params.get("area") or "0")
        return ["router ospf %s" % process, "network %s area %s" % (network, area)]
    if action == "ospf_interface":
        area = safe_ospf_area(params.get("area") or "0")
        return ["interface %s" % safe_interface(params.get("interface")), "ip ospf area %s" % area]
    if action == "bgp_neighbor":
        asn = safe_asn(params.get("asn"))
        peer = safe_ipv4(params.get("neighbor"))
        remote_as = safe_asn(params.get("remoteAs"))
        return ["router bgp %s" % asn, "neighbor %s remote-as %s" % (peer, remote_as)]
    if action == "bgp_address_family":
        asn = safe_asn(params.get("asn"))
        family = safe_text(params.get("addressFamily") or "ipv4", r"^(ipv4|ipv6)$")
        peer = safe_ip(params.get("neighbor"))
        if (family == "ipv4" and ipaddress.ip_address(peer).version != 4) or (family == "ipv6" and ipaddress.ip_address(peer).version != 6):
            raise ValueError("Neighbor address does not match the address family.")
        mode = safe_text(params.get("mode") or "activate", r"^(activate|deactivate)$")
        command = "neighbor %s activate" % peer if mode == "activate" else "no neighbor %s activate" % peer
        return ["router bgp %s" % asn, "address-family %s" % family, command]
    if action == "save_config":
        return ["write memory"]
    raise ValueError("Unsupported config action.")


DIAGNOSTIC_COMMANDS = {
    "version": "show version",
    "interfaces_status": "show interfaces status",
    "vlan": "show vlan brief",
    "lldp": "show lldp neighbors detail",
    "environment": "show system environment all",
    "routes": "show ip route",
    "arp": "show arp",
    "mac_table": "show mac address-table",
    "transceivers": "show interfaces transceiver detail",
}


def build_diagnostic_command(command_id, params=None):
    command_id = str(command_id or "").strip().lower()
    params = params or {}
    if command_id in DIAGNOSTIC_COMMANDS:
        return DIAGNOSTIC_COMMANDS[command_id]
    if command_id in ("ping", "traceroute"):
        target = safe_ip(params.get("target"))
        if command_id == "ping":
            return "ping %s" % target
        runner = "traceroute6" if ipaddress.ip_address(target).version == 6 else "traceroute"
        return "%s %s" % (runner, target)
    raise ValueError("Unsupported diagnostic command ID.")


def make_config_session_name(prefix="web"):
    safe_prefix = re.sub(r"[^a-z0-9]", "", str(prefix).lower())[:8] or "web"
    return "%s%x%s" % (safe_prefix, int(time.time()), secrets.token_hex(3))


def _config_output_has_error(output):
    text = str(output or "")
    return bool(
        re.search(r"(?m)^\s*%", text)
        or re.search(r"%\s*(?:Invalid|Incomplete|Ambiguous|Unrecognized|Authorization|Error)\b", text, re.I)
        or re.search(r"configuration session.+(?:locked|failed|error)", text, re.I)
    )


def _locked_script(lock_transaction, command):
    if not lock_transaction:
        return command
    return "configure lock continue transaction %s arista-dashboard\n%s" % (lock_transaction, command)


def _acquire_config_lock(transaction):
    output = run_eos_script("configure lock transaction %s arista-dashboard" % transaction, timeout=10)
    if _config_output_has_error(output):
        raise APIError(409, "config_locked", "EOS configuration is locked by another operator or transaction.")
    return output


def _release_config_lock(transaction):
    output = run_eos_script(
        "configure lock continue transaction %s arista-dashboard\nconfigure unlock transaction %s arista-dashboard" % (transaction, transaction),
        timeout=10,
    )
    if _config_output_has_error(output):
        raise RuntimeError("EOS configuration lock transaction %s could not be released." % transaction)
    return output


def _abort_config_session(name, lock_transaction=None):
    output = run_eos_script(_locked_script(lock_transaction, "configure session %s abort" % name), timeout=10)
    if _config_output_has_error(output):
        raise RuntimeError("EOS failed to abort configuration session %s." % name)
    return output


def _configuration_session_status(name):
    """Best-effort classification used only to resolve an ambiguous commit."""
    try:
        output = run_eos_script("show configuration sessions detail", timeout=10)
    except Exception:
        return "unknown"
    if _config_output_has_error(output):
        return "unknown"
    row = re.search(
        r"(?im)^\s*%s\s+(pending|active|created|completed|committed)\b" % re.escape(str(name)),
        str(output or ""),
    )
    if row:
        return "committed" if row.group(1).lower() in ("completed", "committed") else "pending"
    return "unknown"


def run_config_session_preview(commands):
    if commands == ["write memory"]:
        return "Startup configuration will be replaced with the current running configuration."
    name = make_config_session_name("preview")
    output = None
    error = None
    try:
        script = "configure session %s\n%s\nshow session-config diffs" % (name, "\n".join(commands))
        output = run_eos_script(script, timeout=30)
        if _config_output_has_error(output):
            raise RuntimeError("EOS rejected the configuration preview.")
    except Exception as exc:
        error = exc
    try:
        _abort_config_session(name)
    except Exception as abort_exc:
        if error is not None:
            raise RuntimeError("%s The preview session could not be aborted: %s" % (error, abort_exc))
        raise
    if error is not None:
        raise error
    return bounded_text(output)


def run_config_session_apply(commands, expected_baseline_hash=None):
    if commands == ["write memory"]:
        lock_transaction = make_config_session_name("lock")
        _acquire_config_lock(lock_transaction)
        try:
            if expected_baseline_hash:
                current_hash = config_hash(get_running_config(timeout=25))
                if not hmac.compare_digest(str(current_hash), str(expected_baseline_hash)):
                    raise APIError(409, "config_changed", "Running configuration changed after preview. Generate a new preview.")
            output = run_eos_script(_locked_script(lock_transaction, "write memory"), timeout=45)
            if _config_output_has_error(output):
                raise RuntimeError("EOS failed to save the running configuration.")
            return output
        finally:
            _release_config_lock(lock_transaction)
    name = make_config_session_name("apply")
    lock_transaction = make_config_session_name("lock")
    committed = False
    abort_allowed = False
    lock_held = False
    try:
        _acquire_config_lock(lock_transaction)
        lock_held = True
        stage_script = _locked_script(lock_transaction, "configure session %s\n%s\nshow session-config diffs" % (name, "\n".join(commands)))
        abort_allowed = True
        staged_output = run_eos_script(stage_script, timeout=30)
        if _config_output_has_error(staged_output):
            raise RuntimeError("EOS rejected the configuration session.")

        if expected_baseline_hash:
            current_hash = config_hash(get_running_config(timeout=25))
            if not hmac.compare_digest(str(current_hash), str(expected_baseline_hash)):
                raise APIError(409, "config_changed", "Running configuration changed while the session was staged. Generate a new preview.")

        try:
            commit_output = run_eos_script(_locked_script(lock_transaction, "configure session %s commit" % name), timeout=20)
            if _config_output_has_error(commit_output):
                raise RuntimeError("EOS failed to commit the configuration session.")
        except Exception as commit_error:
            status = _configuration_session_status(name)
            if status == "committed":
                committed = True
                return bounded_text("%s\nCommit completed; the CLI response was interrupted." % staged_output)
            if status == "pending":
                abort_allowed = False
                _abort_config_session(name, lock_transaction)
                raise commit_error
            abort_allowed = False  # Outcome is unknown; never guess by issuing abort or commit again.
            raise APIError(503, "commit_outcome_unknown", "The commit result could not be determined. Inspect EOS configuration sessions before retrying.")
        committed = True
        return bounded_text("%s\n%s" % (staged_output, commit_output or "Configuration committed."))
    except Exception as error:
        if committed or not abort_allowed:
            raise
        try:
            _abort_config_session(name, lock_transaction)
        except Exception as abort_exc:
            raise RuntimeError("%s The configuration session could not be aborted: %s" % (error, abort_exc))
        raise
    finally:
        if lock_held:
            try:
                _release_config_lock(lock_transaction)
            except Exception as release_error:
                if committed:
                    raise APIError(503, "committed_lock_release_failed", "EOS committed the configuration, but its configuration lock could not be released. Do not retry; inspect 'show configuration lock'.")
                raise release_error


def _cleanup_previews(now=None):
    now = time.time() if now is None else float(now)
    expired = [token for token, preview in _PREVIEWS.items() if float(preview.get("expiresAt", 0)) <= now]
    for token in expired:
        _PREVIEWS.pop(token, None)


def store_preview(session_token, action, commands, baseline_hash, diff, now=None):
    now = time.time() if now is None else float(now)
    token = secrets.token_urlsafe(32)
    preview = {
        "sessionToken": str(session_token),
        "action": str(action),
        "commands": list(commands),
        "baselineHash": str(baseline_hash),
        "diff": str(diff or ""),
        "expiresAt": now + PREVIEW_TTL_SECONDS,
    }
    with _PREVIEW_LOCK:
        _cleanup_previews(now)
        if len(_PREVIEWS) >= 128:
            oldest = min(_PREVIEWS, key=lambda item: float(_PREVIEWS[item].get("expiresAt", 0)))
            _PREVIEWS.pop(oldest, None)
        _PREVIEWS[token] = preview
    return token, dict(preview)


def take_preview(token, session_token, now=None):
    now = time.time() if now is None else float(now)
    with _PREVIEW_LOCK:
        _cleanup_previews(now)
        preview = _PREVIEWS.pop(str(token or ""), None)
    if not preview:
        raise APIError(409, "preview_expired", "Configuration preview is missing or expired.")
    if not hmac.compare_digest(str(preview.get("sessionToken") or ""), str(session_token or "")):
        raise APIError(403, "preview_owner_mismatch", "Configuration preview belongs to another session.")
    return preview


def config_diff(before, after):
    if before == after:
        return ""
    return bounded_text("\n".join(
        difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile="before-running-config",
            tofile="after-running-config",
            lineterm="",
        )
    ))


def flatten_alert_scopes(scopes):
    alerts = []
    seen = set()
    for scope_alerts in (scopes or {}).values():
        for alert in scope_alerts or []:
            if not isinstance(alert, dict):
                continue
            key = (str(alert.get("severity") or ""), str(alert.get("title") or ""), str(alert.get("message") or ""))
            if key in seen:
                continue
            seen.add(key)
            alerts.append(alert)
    return alerts[:100]


def merge_state(base, update):
    if not base:
        merged = dict(update)
    else:
        merged = dict(base)
        for key, value in update.items():
            if key == "alerts" and "alertScopes" in update:
                continue
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                child = dict(merged[key])
                child.update(value)
                merged[key] = child
            else:
                merged[key] = value
    if merged.get("ports") and merged.get("transceivers"):
        optics = {str(item.get("interface") or "").lower(): item for item in merged.get("transceivers", [])}
        merged["ports"] = [dict(port, transceiver=optics.get(str(port.get("name") or "").lower(), port.get("transceiver") or {})) for port in merged.get("ports", [])]
    if isinstance(merged.get("alertScopes"), dict):
        merged["alerts"] = flatten_alert_scopes(merged["alertScopes"])
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
            "alertScopes": {"core": alerts},
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
        integration_output = "\n".join(get_optional("show running-config | include %s" % term) for term in ("logging host", "sflow", "netflow", "ip flow", "flow exporter", "flow monitor"))
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
    integration_output = "\n".join(get_optional("show running-config | include %s" % term) for term in ("logging host", "sflow", "netflow", "ip flow", "flow exporter", "flow monitor"))

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
        "alertScopes": {"full": alerts},
        "events": [
            {
                "time": now_ms(),
                "level": "error" if errors else ("warning" if alerts else "success"),
                "message": "; ".join(errors) if errors else ("Active alerts: %s" % len(alerts) if alerts else "Refreshed from local EOS CLI."),
            }
        ],
        "loading": {"core": "done", "tables": "done", "optics": "done", "protocols": "done", "extras": "done"},
    }


def _collect_state_uncached(scope="full"):
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
        history = read_history()
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
            "alertScopes": {"core": alerts},
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
            "alertScopes": {"health": build_alerts([], health, env_output, errors)},
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
        integration_output = "\n".join(get_optional("show running-config | include %s" % term) for term in ("logging host", "sflow", "netflow", "ip flow", "flow exporter", "flow monitor"))
        return {"poe": parse_poe(poe_output), "integrations": parse_integrations(integration_output), "loading": {"extras": "done"}}

    state = collect_state("core")
    for child_scope in ("metrics", "health", "tables", "discovery", "extras", "optics", "protocols"):
        state = merge_state(state, collect_state(child_scope))
    state["history"] = compact_history(read_history())
    state["loading"] = {"core": "done", "metrics": "done", "health": "done", "tables": "done", "discovery": "done", "optics": "done", "protocols": "done", "extras": "done"}
    if state.get("alerts"):
        state["events"] = [{"time": now_ms(), "level": "warning", "message": "Active alerts: %s" % len(state.get("alerts", []))}]
    else:
        state["events"] = [{"time": now_ms(), "level": "success", "message": "Refreshed via eAPI with CLI fallback."}]
    return state


def add_state_meta(state, scope):
    state = dict(state or {})
    meta = dict(state.get("meta") or {})
    meta.update(
        {
            "version": APP_VERSION,
            "artifactSha": ARTIFACT_SHA,
            "collectedAt": now_ms(),
            "scope": str(scope or "full"),
        }
    )
    state["meta"] = meta
    return state


def collect_state(scope="full"):
    scope = str(scope or "full").lower()
    deadline = time.time() + 45
    with _COLLECTION_CONDITION:
        cached = _COLLECTION_RESULTS.get(scope)
        if cached and time.time() - cached[0] < 2:
            return cached[1]
        while scope in _COLLECTION_INFLIGHT:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for state collection.")
            _COLLECTION_CONDITION.wait(min(remaining, 1.0))
            cached = _COLLECTION_RESULTS.get(scope)
            if cached:
                return cached[1]
        _COLLECTION_INFLIGHT.add(scope)
    try:
        state = add_state_meta(_collect_state_uncached(scope), scope)
    except Exception:
        with _COLLECTION_CONDITION:
            _COLLECTION_INFLIGHT.discard(scope)
            _COLLECTION_CONDITION.notify_all()
        raise
    with _COLLECTION_CONDITION:
        _COLLECTION_RESULTS[scope] = (time.time(), state)
        _COLLECTION_INFLIGHT.discard(scope)
        _COLLECTION_CONDITION.notify_all()
    return state


def start_history_sampler(stop_event):
    def sample_loop():
        while not stop_event.wait(HISTORY_SAMPLE_SECONDS):
            try:
                collect_state("metrics")
            except Exception as exc:
                append_audit({"event": "history_sample_failed", "error": bounded_text(exc, 512)})

    thread = threading.Thread(target=sample_loop, name="history-sampler", daemon=True)
    thread.start()
    return thread


def auth_attempt_allowed(client, now=None):
    now = time.time() if now is None else float(now)
    with _AUTH_FAILURE_LOCK:
        failures = [timestamp for timestamp in _AUTH_FAILURES.get(str(client), []) if now - timestamp < 300]
        _AUTH_FAILURES[str(client)] = failures
        return len(failures) < 8


def register_auth_failure(client, now=None):
    now = time.time() if now is None else float(now)
    with _AUTH_FAILURE_LOCK:
        if len(_AUTH_FAILURES) >= 256 and str(client) not in _AUTH_FAILURES:
            oldest = min(_AUTH_FAILURES, key=lambda item: (_AUTH_FAILURES[item] or [now])[-1])
            _AUTH_FAILURES.pop(oldest, None)
        failures = [timestamp for timestamp in _AUTH_FAILURES.get(str(client), []) if now - timestamp < 300]
        failures.append(now)
        _AUTH_FAILURES[str(client)] = failures[-8:]


def clear_auth_failures(client):
    with _AUTH_FAILURE_LOCK:
        _AUTH_FAILURES.pop(str(client), None)


def validate_secure_file(path, label):
    if not path or not os.path.isfile(path):
        raise ValueError("%s is required and must exist." % label)
    if os.name == "posix" and os.stat(path).st_mode & 0o077:
        raise ValueError("%s permissions must be 0600." % label)


def validate_runtime_config(auth_config, tls_cert, tls_key):
    record = load_auth_config(auth_config)
    validate_secure_file(tls_cert, "TLS certificate")
    validate_secure_file(tls_key, "TLS private key")
    context = ssl.SSLContext(getattr(ssl, "PROTOCOL_TLS_SERVER", ssl.PROTOCOL_SSLv23))
    if hasattr(context, "minimum_version") and hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(tls_cert, tls_key)
    return record, context


def smoke_test_authenticated_api(base_url, username, password, record, timeout=20):
    """Exercise the candidate login/session/state/logout path without persisting a secret."""
    if not verify_password(username, password, record):
        raise RuntimeError("Candidate smoke-test credentials do not match the authentication config.")
    base_url = str(base_url or "").rstrip("/")
    if not re.fullmatch(r"https://127\.0\.0\.1:\d{1,5}", base_url):
        raise ValueError("Candidate smoke URL must be loopback HTTPS.")
    port = int(base_url.rsplit(":", 1)[1])
    if port < 1 or port > 65535:
        raise ValueError("Candidate smoke URL port is invalid.")
    cookie_jar = http.cookiejar.CookieJar()
    context = ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookie_jar),
    )

    def request(path, method="GET", payload=None, csrf=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if csrf:
            headers["X-CSRF-Token"] = csrf
        req = urllib.request.Request(base_url + path, data=body, headers=headers, method=method)
        with opener.open(req, timeout=timeout) as response:
            data = json.loads(response.read(MAX_COMMAND_OUTPUT + 1).decode("utf-8"))
            if response.status >= 400:
                raise RuntimeError("Candidate API returned HTTP %s." % response.status)
            return data

    login = request("/api/auth/login", "POST", {"username": username, "password": password})
    csrf = str(login.get("csrfToken") or "")
    if not login.get("authenticated") or not csrf:
        raise RuntimeError("Candidate login did not establish an authenticated CSRF session.")
    state = request("/api/state")
    if not isinstance(state, dict) or not isinstance(state.get("state"), dict) or not isinstance(state["state"].get("device"), dict):
        raise RuntimeError("Candidate core state API returned an invalid payload.")
    request("/api/auth/logout", "POST", {}, csrf=csrf)
    return True


def write_pid_file(path, pid):
    if not path:
        return
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700)
    tmp = "%s.tmp.%s" % (path, os.getpid())
    with open(tmp, "w", encoding="ascii") as handle:
        handle.write("%s\n" % int(pid))
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, tls_context=None, max_workers=MAX_HTTP_WORKERS):
        self._worker_slots = threading.BoundedSemaphore(int(max_workers))
        self._tls_context = tls_context
        super().__init__(server_address, handler_class)

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(False):
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        secure_request = None
        completed = threading.Event()

        def expire_connection():
            if completed.is_set():
                return
            try:
                (secure_request or request).shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        deadline = threading.Timer(HTTP_CONNECTION_TIMEOUT, expire_connection)
        deadline.daemon = True
        deadline.start()
        try:
            if self._tls_context is not None:
                request.settimeout(TLS_HANDSHAKE_TIMEOUT)
                secure_request = self._tls_context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                secure_request.do_handshake()
            else:
                secure_request = request
            secure_request.settimeout(HTTP_IO_TIMEOUT)
            super().process_request_thread(secure_request, client_address)
        except Exception:
            try:
                (secure_request or request).close()
            except OSError:
                pass
        finally:
            completed.set()
            deadline.cancel()
            self._worker_slots.release()


WEB_ASSET_SHA = "ffa30c2d71bd04596b480073e87be797e2f266bfe3ab468e12e0b1a9276a29d6"
# BEGIN GENERATED WEB ASSET
INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="Arista 7050QX 交换机本机监控、诊断与受控配置控制台。" />
    <meta name="theme-color" content="#0b1118" />
    <title>Arista 7050QX 运维台</title>
    <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%230f766e'/%3E%3Cpath d='M16 20h32v8H16zm0 16h32v8H16z' fill='white'/%3E%3C/svg%3E" />
    <style>
:root {
  color-scheme: dark;
  --bg: #0b1118;
  --bg-elevated: #101922;
  --surface: #141f2a;
  --surface-strong: #192733;
  --surface-soft: #101a23;
  --ink: #edf4f7;
  --muted: #91a3b0;
  --subtle: #6f8492;
  --line: #2a3a46;
  --line-strong: #3d5361;
  --accent: #3eb6a7;
  --accent-strong: #70cbbf;
  --accent-ink: #061815;
  --accent-soft: rgba(62, 182, 167, 0.13);
  --good: #63b884;
  --good-soft: rgba(99, 184, 132, 0.13);
  --warning: #d7a958;
  --warning-soft: rgba(215, 169, 88, 0.14);
  --danger: #db766e;
  --danger-soft: rgba(219, 118, 110, 0.14);
  --info: #78a9cf;
  --focus: #70cbbf;
  --shadow: 0 24px 64px rgba(1, 7, 12, 0.28);
  --header-bg: rgba(11, 17, 24, 0.91);
  --mono: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
  --sans: Aptos, "Segoe UI Variable", "Segoe UI", system-ui, sans-serif;
  --radius-outer: 18px;
  --radius-inner: 10px;
}

body[data-theme="light"] {
  color-scheme: light;
  --bg: #eef2f3;
  --bg-elevated: #f7f9f9;
  --surface: #ffffff;
  --surface-strong: #f3f7f6;
  --surface-soft: #f7f9f9;
  --ink: #17242b;
  --muted: #5f717b;
  --subtle: #526873;
  --line: #d7e0e2;
  --line-strong: #b8c7cb;
  --accent: #0f766e;
  --accent-strong: #095f59;
  --accent-ink: #ffffff;
  --accent-soft: rgba(15, 118, 110, 0.1);
  --good: #236b3d;
  --good-soft: rgba(47, 125, 77, 0.1);
  --warning: #76510f;
  --warning-soft: rgba(148, 107, 31, 0.11);
  --danger: #aa443d;
  --danger-soft: rgba(170, 68, 61, 0.1);
  --info: #326d98;
  --focus: #095f59;
  --shadow: 0 22px 56px rgba(33, 58, 69, 0.1);
  --header-bg: rgba(238, 242, 243, 0.92);
}

*,
*::before,
*::after {
  box-sizing: border-box;
}

html {
  min-width: 320px;
  scroll-behavior: smooth;
}

body {
  min-width: 320px;
  min-height: 100dvh;
  margin: 0;
  overflow-x: hidden;
  color: var(--ink);
  background:
    radial-gradient(circle at 15% -10%, rgba(62, 182, 167, 0.09), transparent 34rem),
    radial-gradient(circle at 92% 8%, rgba(120, 169, 207, 0.07), transparent 28rem),
    var(--bg);
  font-family: var(--sans);
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

body.has-overlay {
  overflow: hidden;
}

button,
input,
select {
  min-width: 0;
  font: inherit;
}

button,
a,
input,
select {
  -webkit-tap-highlight-color: transparent;
}

button,
a {
  touch-action: manipulation;
}

button:focus-visible,
a:focus-visible,
input:focus-visible,
select:focus-visible,
[tabindex]:focus-visible {
  outline: 3px solid var(--focus);
  outline-offset: 3px;
}

[hidden] {
  display: none !important;
}

h1,
h2,
h3,
p {
  margin: 0;
}

h1,
h2,
h3 {
  text-wrap: balance;
}

h1 {
  font-size: clamp(1.25rem, 2.4vw, 1.85rem);
  font-weight: 650;
  line-height: 1.12;
  letter-spacing: -0.035em;
}

h2 {
  font-size: clamp(1.65rem, 3.3vw, 2.6rem);
  font-weight: 630;
  line-height: 1.04;
  letter-spacing: -0.045em;
}

h3 {
  font-size: 1rem;
  font-weight: 650;
  letter-spacing: -0.015em;
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.skip-link {
  position: fixed;
  top: 0.75rem;
  left: 0.75rem;
  z-index: 80;
  padding: 0.75rem 1rem;
  border-radius: 0.5rem;
  color: #fff;
  background: #0f766e;
  transform: translateY(-180%);
  transition: transform 160ms ease;
}

.skip-link:focus {
  transform: translateY(0);
}

.eyebrow,
.section-kicker {
  color: var(--accent-strong);
  font-family: var(--mono);
  font-size: 0.69rem;
  font-weight: 650;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.muted-text,
.timestamp,
.form-hint {
  color: var(--muted);
}

.timestamp {
  font-family: var(--mono);
  font-size: 0.72rem;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.brand-mark {
  display: grid;
  place-content: center;
  gap: 0.3rem;
  width: 3.25rem;
  height: 3.25rem;
  border: 1px solid rgba(112, 203, 191, 0.42);
  border-radius: 0.85rem;
  background: var(--accent-soft);
  box-shadow: inset 0 1px rgba(255, 255, 255, 0.08);
}

.brand-mark i {
  display: block;
  width: 1.6rem;
  height: 0.22rem;
  border-radius: 1px;
  background: var(--accent-strong);
}

.brand-mark.compact {
  flex: 0 0 auto;
  width: 2.35rem;
  height: 2.35rem;
  border-radius: 0.65rem;
  gap: 0.22rem;
}

.brand-mark.compact i {
  width: 1.15rem;
  height: 0.16rem;
}

.auth-shell {
  display: grid;
  min-height: 100dvh;
  place-items: center;
  padding: 1.25rem;
}

.auth-card {
  width: min(100%, 28rem);
  padding: clamp(1.5rem, 5vw, 2.5rem);
  border: 1px solid var(--line);
  border-radius: 1.35rem;
  background: color-mix(in srgb, var(--surface) 94%, transparent);
  box-shadow: var(--shadow), inset 0 1px rgba(255, 255, 255, 0.06);
}

.auth-card .brand-mark {
  margin-bottom: 1.6rem;
}

.auth-card h1 {
  margin-top: 0.55rem;
  font-size: clamp(1.8rem, 7vw, 2.65rem);
}

.auth-copy {
  max-width: 38ch;
  margin-top: 0.85rem;
  color: var(--muted);
  text-wrap: pretty;
}

.auth-note {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--line);
  color: var(--subtle);
  font-size: 0.78rem;
}

.stack-form {
  display: grid;
  gap: 0.65rem;
  margin-top: 1.5rem;
}

.stack-form label,
.dynamic-fields label,
.filter-bar label {
  display: grid;
  gap: 0.38rem;
  color: var(--muted);
  font-size: 0.78rem;
  font-weight: 600;
}

input,
select {
  width: 100%;
  min-height: 2.75rem;
  border: 1px solid var(--line);
  border-radius: 0.6rem;
  padding: 0 0.78rem;
  color: var(--ink);
  background: var(--surface-soft);
  transition: border-color 160ms ease, background 160ms ease, box-shadow 160ms ease;
}

input:hover,
select:hover {
  border-color: var(--line-strong);
}

input:focus,
select:focus {
  border-color: var(--accent);
  background: var(--surface);
}

input[type="checkbox"] {
  width: 1.15rem;
  min-height: 1.15rem;
  padding: 0;
  accent-color: var(--accent);
}

.form-error {
  padding: 0.65rem 0.75rem;
  border-left: 3px solid var(--danger);
  color: var(--danger);
  background: var(--danger-soft);
  font-size: 0.8rem;
}

.button,
.icon-button {
  min-height: 2.75rem;
  border: 1px solid var(--line);
  border-radius: 0.6rem;
  padding: 0 0.9rem;
  color: var(--ink);
  background: var(--surface-soft);
  cursor: pointer;
  font-weight: 620;
  transition: transform 150ms ease, border-color 150ms ease, background 150ms ease, color 150ms ease;
}

.button:hover,
.icon-button:hover {
  border-color: var(--line-strong);
  background: var(--surface-strong);
}

.button:active,
.icon-button:active {
  transform: translateY(1px) scale(0.99);
}

.button:disabled,
.icon-button:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.button.primary {
  border-color: var(--accent);
  color: var(--accent-ink);
  background: var(--accent);
}

.button.primary:hover {
  border-color: var(--accent-strong);
  background: var(--accent-strong);
}

.button.secondary {
  min-height: 2.75rem;
  padding: 0 0.72rem;
  font-size: 0.78rem;
}

.button.danger {
  border-color: var(--danger);
  color: #fff;
  background: #a8423d;
}

.button.text-button {
  min-height: 2.75rem;
  border-color: transparent;
  padding: 0 0.45rem;
  color: var(--accent-strong);
  background: transparent;
  font-size: 0.78rem;
}

.icon-button {
  display: inline-grid;
  width: 2.75rem;
  min-height: 2.75rem;
  place-items: center;
  padding: 0;
  font-size: 1.15rem;
}

.app-header {
  position: sticky;
  top: 0;
  z-index: 30;
  border-bottom: 1px solid var(--line);
  background: var(--header-bg);
  backdrop-filter: blur(18px) saturate(130%);
}

.header-row {
  display: flex;
  width: min(100%, 94rem);
  min-width: 0;
  margin: 0 auto;
  padding: 1rem clamp(1rem, 3vw, 2.2rem) 0.75rem;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}

.device-identity,
.device-title-row,
.header-actions {
  display: flex;
  min-width: 0;
  align-items: center;
}

.device-identity {
  gap: 0.75rem;
}

.device-title-row {
  margin-top: 0.18rem;
  gap: 0.65rem;
  flex-wrap: wrap;
}

.device-title-row .muted-text {
  font-family: var(--mono);
  font-size: 0.68rem;
}

.header-actions {
  justify-content: flex-end;
  gap: 0.45rem;
  flex-wrap: wrap;
}

.compact-field select {
  width: auto;
  min-height: 2.75rem;
  padding-right: 1.8rem;
  font-size: 0.78rem;
}

.status-badge,
.section-state {
  display: inline-flex;
  min-height: 1.9rem;
  align-items: center;
  gap: 0.45rem;
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 0.25rem 0.65rem;
  color: var(--muted);
  background: var(--surface-soft);
  font-size: 0.72rem;
  font-weight: 650;
  white-space: nowrap;
}

.status-badge i,
.section-state::before {
  content: "";
  width: 0.45rem;
  height: 0.45rem;
  flex: 0 0 auto;
  border-radius: 50%;
  background: var(--subtle);
}

.status-badge.live,
.status-badge.safe,
.section-state[data-status="ready"] {
  border-color: color-mix(in srgb, var(--good) 42%, var(--line));
  color: var(--good);
  background: var(--good-soft);
}

.status-badge.live i,
.status-badge.safe i,
.section-state[data-status="ready"]::before {
  background: var(--good);
}

.status-badge.warning,
.section-state[data-status="stale"] {
  border-color: color-mix(in srgb, var(--warning) 45%, var(--line));
  color: var(--warning);
  background: var(--warning-soft);
}

.status-badge.warning i,
.section-state[data-status="stale"]::before {
  background: var(--warning);
}

.status-badge.locked,
.section-state[data-status="error"] {
  border-color: color-mix(in srgb, var(--danger) 45%, var(--line));
  color: var(--danger);
  background: var(--danger-soft);
}

.status-badge.locked i,
.section-state[data-status="error"]::before {
  background: var(--danger);
}

.section-state[data-status="loading"]::before {
  animation: pulse 1.2s ease-in-out infinite;
}

.primary-nav {
  display: flex;
  width: min(100%, 94rem);
  margin: 0 auto;
  padding: 0 clamp(1rem, 3vw, 2.2rem);
  gap: 0.15rem;
  overflow-x: auto;
  scrollbar-width: none;
}

.primary-nav::-webkit-scrollbar {
  display: none;
}

.primary-nav a {
  position: relative;
  min-height: 2.85rem;
  padding: 0.78rem 0.86rem;
  color: var(--muted);
  text-decoration: none;
  white-space: nowrap;
  font-size: 0.82rem;
  font-weight: 630;
}

.primary-nav a::after {
  content: "";
  position: absolute;
  right: 0.75rem;
  bottom: -1px;
  left: 0.75rem;
  height: 2px;
  background: var(--accent);
  transform: scaleX(0);
  transition: transform 180ms ease;
}

.primary-nav a:hover {
  color: var(--ink);
}

.primary-nav a[aria-current="page"] {
  color: var(--accent-strong);
}

.primary-nav a[aria-current="page"]::after {
  transform: scaleX(1);
}

.main-content {
  width: min(100%, 94rem);
  min-width: 0;
  margin: 0 auto;
  padding: clamp(1.5rem, 4vw, 3.2rem) clamp(1rem, 3vw, 2.2rem) 4rem;
}

.page {
  min-width: 0;
  animation: page-in 220ms ease both;
}

.page-heading {
  display: flex;
  min-width: 0;
  margin-bottom: 1.7rem;
  align-items: flex-end;
  justify-content: space-between;
  gap: 1rem;
}

.page-heading h2 {
  margin-top: 0.4rem;
}

.page-heading p:not(.eyebrow) {
  max-width: 58ch;
  margin-top: 0.65rem;
  color: var(--muted);
  text-wrap: pretty;
}

.surface {
  min-width: 0;
  border: 1px solid var(--line);
  border-radius: var(--radius-outer);
  padding: clamp(1rem, 2.2vw, 1.4rem);
  background: color-mix(in srgb, var(--surface) 97%, transparent);
  box-shadow: inset 0 1px rgba(255, 255, 255, 0.035);
}

.section-heading {
  display: flex;
  min-width: 0;
  margin-bottom: 1.1rem;
  align-items: flex-start;
  justify-content: space-between;
  gap: 0.75rem;
}

.section-kicker {
  margin-bottom: 0.3rem;
  color: var(--subtle);
}

.count-display {
  font-family: var(--mono);
  font-size: 2rem;
  font-variant-numeric: tabular-nums;
  line-height: 1;
}

.overview-grid,
.network-grid,
.workbench-grid,
.change-layout {
  display: grid;
  min-width: 0;
  gap: 1rem;
}

.overview-grid {
  grid-template-columns: minmax(0, 0.9fr) minmax(0, 1.1fr);
}

.overview-grid.lower-grid {
  grid-template-columns: minmax(0, 1.45fr) minmax(20rem, 0.55fr);
}

.alert-list,
.event-list {
  display: grid;
  gap: 0.55rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.alert-item,
.event-item {
  display: grid;
  min-width: 0;
  border-left: 3px solid var(--line-strong);
  border-radius: 0 var(--radius-inner) var(--radius-inner) 0;
  padding: 0.72rem 0.8rem;
  gap: 0.18rem;
  background: var(--surface-soft);
}

.alert-item[data-severity="critical"],
.event-item[data-level="error"] {
  border-left-color: var(--danger);
}

.alert-item[data-severity="warning"],
.event-item[data-level="warning"] {
  border-left-color: var(--warning);
}

.event-item[data-level="success"] {
  border-left-color: var(--good);
}

.alert-item strong,
.event-item strong {
  overflow-wrap: anywhere;
  font-size: 0.82rem;
}

.alert-item span,
.event-item time,
.event-item span {
  overflow-wrap: anywhere;
  color: var(--muted);
  font-size: 0.74rem;
}

.health-metrics {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0.75rem;
}

.health-metric {
  min-width: 0;
  padding: 0.85rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-inner);
  background: var(--surface-soft);
}

.health-metric span,
.health-metric small {
  display: block;
  color: var(--muted);
  font-size: 0.72rem;
}

.health-metric strong {
  display: block;
  margin: 0.45rem 0 0.65rem;
  font-family: var(--mono);
  font-size: clamp(1.1rem, 2.6vw, 1.55rem);
  font-variant-numeric: tabular-nums;
}

.health-metric progress {
  display: block;
  width: 100%;
  height: 0.38rem;
  overflow: hidden;
  border: 0;
  border-radius: 999px;
  background: var(--line);
  accent-color: var(--accent);
}

.health-metric progress::-webkit-progress-bar {
  border-radius: 999px;
  background: var(--line);
}

.health-metric progress::-webkit-progress-value {
  border-radius: 999px;
  background: var(--accent);
}

.health-metric progress::-moz-progress-bar {
  border-radius: 999px;
  background: var(--accent);
}

.bar {
  height: 0.32rem;
  overflow: hidden;
  border-radius: 999px;
  background: var(--line);
}

.bar i {
  display: block;
  width: var(--value, 0%);
  height: 100%;
  border-radius: inherit;
  background: var(--accent);
}

.metric-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 1rem 0;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: var(--radius-outer);
  background: var(--surface);
}

.metric-strip article {
  min-width: 0;
  padding: 1rem 1.15rem 1.15rem;
  border-right: 1px solid var(--line);
}

.metric-strip article:last-child {
  border-right: 0;
}

.metric-strip span,
.metric-strip small {
  display: block;
  overflow-wrap: anywhere;
  color: var(--muted);
  font-size: 0.72rem;
}

.metric-strip strong {
  display: block;
  margin: 0.4rem 0 0.32rem;
  overflow-wrap: anywhere;
  font-family: var(--mono);
  font-size: clamp(1.05rem, 2.2vw, 1.45rem);
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.035em;
}

.chart-wrap {
  position: relative;
  min-height: 14rem;
}

.chart-wrap canvas {
  display: block;
  width: 100%;
  height: 14rem;
}

.traffic-legend {
  display: flex;
  gap: 0.8rem;
  font-family: var(--mono);
  font-size: 0.72rem;
}

.traffic-legend span::before {
  content: "";
  display: inline-block;
  width: 0.85rem;
  height: 2px;
  margin-right: 0.35rem;
  vertical-align: middle;
  background: var(--accent);
}

.traffic-legend .tx::before {
  background: var(--info);
}

.traffic-summary {
  display: flex;
  min-width: 0;
  padding-top: 0.7rem;
  border-top: 1px solid var(--line);
  gap: 1rem;
  flex-wrap: wrap;
  color: var(--muted);
  font-family: var(--mono);
  font-size: 0.72rem;
}

.events-surface .event-list {
  max-height: 18rem;
  overflow: auto;
  overscroll-behavior: contain;
}

.filter-bar {
  display: grid;
  grid-template-columns: minmax(12rem, 1fr) minmax(9rem, 0.35fr) auto;
  margin-bottom: 1rem;
  align-items: end;
  gap: 0.8rem;
}

.port-legend {
  display: flex;
  min-height: 2.75rem;
  align-items: center;
  justify-content: flex-end;
  gap: 0.75rem;
  color: var(--muted);
  font-size: 0.72rem;
}

.port-legend span {
  display: inline-flex;
  align-items: center;
  gap: 0.34rem;
}

.signal {
  display: inline-block;
  width: 0.48rem;
  height: 0.48rem;
  border-radius: 50%;
  background: var(--subtle);
}

.signal.up {
  background: var(--good);
}

.signal.down {
  background: var(--subtle);
}

.signal.warning {
  background: var(--warning);
}

.port-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 10rem), 1fr));
  min-width: 0;
  gap: 0.65rem;
}

.port-card {
  position: relative;
  display: grid;
  min-width: 0;
  min-height: 9.5rem;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: 0.8rem;
  padding: 0.9rem;
  color: var(--ink);
  background: var(--surface);
  cursor: pointer;
  text-align: left;
  transition: transform 160ms ease, border-color 160ms ease, background 160ms ease;
}

.port-card::before {
  content: "";
  position: absolute;
  inset: 0 auto 0 0;
  width: 3px;
  background: var(--subtle);
}

.port-card[data-status="up"]::before {
  background: var(--good);
}

.port-card[data-errors="true"]::before {
  background: var(--warning);
}

.port-card:hover {
  border-color: var(--line-strong);
  background: var(--surface-strong);
  transform: translateY(-2px);
}

.port-card-head,
.port-traffic,
.drawer-status-row {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
}

.port-card-head strong {
  overflow: hidden;
  font-family: var(--mono);
  font-size: 0.76rem;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.port-status-text {
  flex: 0 0 auto;
  color: var(--muted);
  font-size: 0.68rem;
  font-weight: 650;
  text-transform: uppercase;
}

.port-card[data-status="up"] .port-status-text {
  color: var(--good);
}

.port-description {
  min-height: 2.5rem;
  margin: 0.75rem 0;
  overflow: hidden;
  color: var(--muted);
  font-size: 0.73rem;
  line-height: 1.35;
  text-overflow: ellipsis;
  overflow-wrap: anywhere;
}

.port-meta {
  display: flex;
  gap: 0.35rem;
  flex-wrap: wrap;
}

.port-meta span {
  padding: 0.15rem 0.35rem;
  border: 1px solid var(--line);
  border-radius: 0.3rem;
  color: var(--muted);
  background: var(--surface-soft);
  font-family: var(--mono);
  font-size: 0.64rem;
}

.port-traffic {
  margin-top: auto;
  padding-top: 0.65rem;
  border-top: 1px solid var(--line);
  color: var(--muted);
  font-family: var(--mono);
  font-size: 0.66rem;
  font-variant-numeric: tabular-nums;
}

.empty-state,
.inline-empty {
  display: grid;
  min-height: 10rem;
  place-content: center;
  gap: 0.3rem;
  border: 1px dashed var(--line-strong);
  border-radius: var(--radius-outer);
  color: var(--muted);
  text-align: center;
}

.network-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.network-grid .wide {
  grid-column: 1 / -1;
}

.table-region {
  min-width: 0;
  max-height: 20rem;
  overflow: auto;
  overscroll-behavior: contain;
  border: 1px solid var(--line);
  border-radius: var(--radius-inner);
}

.data-table {
  width: 100%;
  min-width: 32rem;
  border-collapse: collapse;
  font-size: 0.76rem;
}

.data-table caption {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
}

.data-table th,
.data-table td {
  padding: 0.68rem 0.75rem;
  border-bottom: 1px solid var(--line);
  overflow-wrap: anywhere;
  text-align: left;
  vertical-align: top;
}

.data-table th {
  position: sticky;
  top: 0;
  z-index: 1;
  color: var(--muted);
  background: var(--surface-strong);
  font-size: 0.68rem;
  font-weight: 650;
  letter-spacing: 0.04em;
}

.data-table td {
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
}

.data-table tbody tr:last-child td {
  border-bottom: 0;
}

.table-region .inline-empty {
  min-height: 8rem;
  border: 0;
}

.integration-list {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0.6rem;
}

.integration-item {
  display: flex;
  min-width: 0;
  min-height: 4rem;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-inner);
  padding: 0.75rem;
  background: var(--surface-soft);
}

.integration-item span {
  color: var(--muted);
  font-size: 0.76rem;
}

.integration-item strong {
  color: var(--subtle);
  font-family: var(--mono);
  font-size: 0.7rem;
}

.integration-item strong[data-enabled="true"] {
  color: var(--good);
}

.inline-note {
  margin-top: 0.75rem;
  color: var(--muted);
  font-size: 0.75rem;
}

.workbench-grid,
.change-layout {
  grid-template-columns: minmax(17rem, 0.42fr) minmax(0, 0.58fr);
}

.form-surface {
  align-self: start;
}

.dynamic-fields {
  display: grid;
  gap: 0.75rem;
}

.form-hint {
  padding: 0.7rem 0.75rem;
  border-left: 3px solid var(--accent);
  background: var(--accent-soft);
  font-size: 0.78rem;
}

.output-surface pre,
.preview-surface pre,
.drawer pre {
  width: 100%;
  min-height: 20rem;
  max-height: 34rem;
  margin: 0;
  overflow: auto;
  border: 1px solid #293b48;
  border-radius: var(--radius-inner);
  padding: 1rem;
  color: #d7e5e9;
  background: #0a1118;
  font: 0.78rem/1.62 var(--mono);
  tab-size: 2;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.apply-bar {
  display: flex;
  margin-top: 0.8rem;
  align-items: center;
  justify-content: space-between;
  gap: 0.8rem;
}

.confirm-check {
  display: flex;
  min-height: 2.75rem;
  align-items: center;
  gap: 0.45rem;
  color: var(--muted);
  font-size: 0.78rem;
}

.drawer-backdrop,
.modal-layer {
  position: fixed;
  inset: 0;
  z-index: 50;
  background: rgba(3, 9, 13, 0.7);
  backdrop-filter: blur(4px);
}

.drawer {
  position: fixed;
  inset: 0 0 0 auto;
  z-index: 51;
  width: min(32rem, 100%);
  overflow: auto;
  border-left: 1px solid var(--line);
  background: var(--surface);
  box-shadow: -28px 0 68px rgba(0, 0, 0, 0.28);
  transform: translateX(102%);
  transition: transform 220ms ease;
}

.drawer[inert] {
  pointer-events: none;
}

.health-metrics > .inline-empty {
  grid-column: 1 / -1;
  min-height: 8rem;
}

.drawer.open {
  transform: translateX(0);
}

.drawer-header {
  position: sticky;
  top: 0;
  z-index: 2;
  display: flex;
  padding: 1.25rem;
  border-bottom: 1px solid var(--line);
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  background: var(--surface);
}

.drawer-body {
  display: grid;
  padding: 1.25rem;
  gap: 1rem;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.6rem;
}

.detail-item {
  min-width: 0;
  border: 1px solid var(--line);
  border-radius: var(--radius-inner);
  padding: 0.75rem;
  background: var(--surface-soft);
}

.detail-item span {
  display: block;
  color: var(--muted);
  font-size: 0.68rem;
}

.detail-item strong {
  display: block;
  margin-top: 0.3rem;
  overflow-wrap: anywhere;
  font-family: var(--mono);
  font-size: 0.78rem;
}

.drawer .table-region {
  max-height: none;
}

.drawer .data-table {
  min-width: 28rem;
}

.modal-layer {
  display: grid;
  place-items: center;
  padding: 1rem;
}

.modal-dialog {
  width: min(100%, 28rem);
  border: 1px solid var(--line);
  border-radius: var(--radius-outer);
  padding: 1.3rem;
  background: var(--surface);
  box-shadow: var(--shadow);
}

.modal-dialog > p {
  color: var(--muted);
}

.toast-region {
  position: fixed;
  right: 1rem;
  bottom: 1rem;
  z-index: 70;
  display: grid;
  width: min(24rem, calc(100vw - 2rem));
  gap: 0.55rem;
  pointer-events: none;
}

.toast {
  border: 1px solid var(--line-strong);
  border-left: 3px solid var(--accent);
  border-radius: var(--radius-inner);
  padding: 0.78rem 0.9rem;
  color: var(--ink);
  background: var(--surface);
  box-shadow: var(--shadow);
  font-size: 0.8rem;
  animation: toast-in 180ms ease both;
}

.toast[data-tone="error"] {
  border-left-color: var(--danger);
}

.toast[data-tone="success"] {
  border-left-color: var(--good);
}

.skeleton-list,
.skeleton-grid,
.skeleton-block {
  position: relative;
  min-height: 5rem;
  overflow: hidden;
}

.skeleton-list:empty::before,
.skeleton-grid:empty::before,
.skeleton-block:empty::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: var(--radius-inner);
  background: linear-gradient(100deg, var(--surface-soft) 20%, var(--surface-strong) 40%, var(--surface-soft) 60%);
  background-size: 220% 100%;
  animation: skeleton 1.45s ease-in-out infinite;
}

@keyframes skeleton {
  to { background-position-x: -220%; }
}

@keyframes pulse {
  50% { opacity: 0.35; transform: scale(0.75); }
}

@keyframes page-in {
  from { opacity: 0; transform: translateY(0.35rem); }
}

@keyframes toast-in {
  from { opacity: 0; transform: translateY(0.5rem); }
}

@media (max-width: 68rem) {
  .header-row {
    align-items: flex-start;
    flex-direction: column;
  }

  .header-actions {
    width: 100%;
    justify-content: flex-start;
  }

  .overview-grid,
  .overview-grid.lower-grid,
  .workbench-grid,
  .change-layout {
    grid-template-columns: 1fr;
  }

  .network-grid {
    grid-template-columns: 1fr;
  }

  .network-grid .wide {
    grid-column: auto;
  }

  .integration-list {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 48rem) {
  .app-header {
    position: relative;
  }

  .header-row {
    padding: 0.85rem 0.85rem 0.6rem;
  }

  .primary-nav {
    padding: 0 0.65rem;
  }

  .main-content {
    padding: 1.4rem 0.85rem 3rem;
  }

  .page-heading,
  .split-heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .health-metrics,
  .metric-strip {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .metric-strip article:nth-child(2) {
    border-right: 0;
  }

  .metric-strip article:nth-child(-n + 2) {
    border-bottom: 1px solid var(--line);
  }

  .filter-bar {
    grid-template-columns: 1fr 1fr;
  }

  .port-legend {
    grid-column: 1 / -1;
    justify-content: flex-start;
  }

  .integration-list {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 30rem) {
  .device-title-row .muted-text,
  .timestamp,
  .compact-field {
    display: none;
  }

  .header-actions {
    display: grid;
    grid-template-columns: minmax(0, 1fr) repeat(4, auto);
  }

  .header-actions .status-badge {
    min-width: 0;
    overflow: hidden;
  }

  .header-actions .status-badge span {
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .button.secondary {
    width: 2.75rem;
    overflow: hidden;
    padding: 0;
    color: transparent;
    font-size: 0;
  }

  #refreshButton::before,
  #unlockButton::before {
    color: var(--ink);
    font-size: 1rem;
  }

  #refreshButton::before { content: "↻"; }
  #unlockButton::before { content: "⌁"; }

  .surface {
    padding: 0.95rem;
    border-radius: 0.9rem;
  }

  .health-metrics,
  .metric-strip,
  .filter-bar,
  .detail-grid {
    grid-template-columns: 1fr;
  }

  .metric-strip article,
  .metric-strip article:nth-child(2) {
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }

  .metric-strip article:last-child {
    border-bottom: 0;
  }

  .port-legend {
    grid-column: auto;
    flex-wrap: wrap;
  }

  .port-grid {
    grid-template-columns: 1fr;
  }

  .apply-bar {
    align-items: stretch;
    flex-direction: column;
  }

  .toast-region {
    right: 0.75rem;
    bottom: 0.75rem;
    width: calc(100vw - 1.5rem);
  }
}

@media (prefers-reduced-motion: reduce) {
  html {
    scroll-behavior: auto;
  }

  *,
  *::before,
  *::after {
    scroll-behavior: auto !important;
    animation-duration: 1ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 1ms !important;
  }
}
</style>
  </head>
  <body data-theme="dark">
    <a class="skip-link" href="#mainContent">跳到主要内容</a>

    <section id="loginView" class="auth-shell" aria-labelledby="loginTitle">
      <div class="auth-card">
        <div class="brand-mark" aria-hidden="true"><i></i><i></i></div>
        <p class="eyebrow">ON-BOX OPERATIONS</p>
        <h1 id="loginTitle">登录交换机运维台</h1>
        <p class="auth-copy">使用交换机账号登录。凭据仅用于当前 HTTPS 会话。</p>
        <form id="loginForm" class="stack-form" method="post" action="/api/auth/login">
          <label for="loginUsername">用户名</label>
          <input id="loginUsername" name="username" autocomplete="username" required />
          <label for="loginPassword">密码</label>
          <input id="loginPassword" name="password" type="password" autocomplete="current-password" required />
          <p id="loginError" class="form-error" role="alert" hidden></p>
          <button class="button primary" type="submit">登录</button>
        </form>
        <p class="auth-note">连接应显示为 HTTPS。证书首次使用时需要在管理终端确认。</p>
      </div>
    </section>

    <div id="appShell" class="app-shell" hidden>
      <header class="app-header">
        <div class="header-row">
          <div class="device-identity">
            <div class="brand-mark compact" aria-hidden="true"><i></i><i></i></div>
            <div>
              <p class="eyebrow">ARISTA CONTROL PLANE</p>
              <div class="device-title-row">
                <h1 id="deviceHostname">正在连接</h1>
                <span id="deviceModel" class="muted-text">DCS-7050QX</span>
              </div>
            </div>
          </div>
          <div class="header-actions">
            <span id="connectionBadge" class="status-badge neutral"><i></i><span>正在连接</span></span>
            <span id="lastRefresh" class="timestamp">尚未刷新</span>
            <label class="compact-field" for="refreshInterval">
              <span class="sr-only">自动刷新间隔</span>
              <select id="refreshInterval" aria-label="自动刷新间隔">
                <option value="0">手动刷新</option>
                <option value="30000">30 秒</option>
                <option value="60000" selected>60 秒</option>
                <option value="300000">5 分钟</option>
              </select>
            </label>
            <button id="refreshButton" class="button secondary" type="button">刷新</button>
            <button id="unlockButton" class="button secondary" type="button">解锁操作</button>
            <button id="themeButton" class="icon-button" type="button" aria-label="切换为浅色主题" title="切换主题">◐</button>
            <button id="logoutButton" class="icon-button" type="button" aria-label="退出登录" title="退出登录">↪</button>
          </div>
        </div>
        <nav class="primary-nav" aria-label="主导航">
          <a href="/" data-route="overview">概览</a>
          <a href="/ports" data-route="ports">端口</a>
          <a href="/network" data-route="network">网络</a>
          <a href="/diagnostics" data-route="diagnostics">诊断</a>
          <a href="/changes" data-route="changes">变更</a>
        </nav>
      </header>

      <main id="mainContent" class="main-content" tabindex="-1">
        <section id="overviewPage" class="page" data-page="overview" aria-labelledby="overviewTitle">
          <div class="page-heading">
            <div>
              <p class="eyebrow">LIVE OPERATIONS</p>
              <h2 id="overviewTitle">运行概览</h2>
              <p>先看异常，再看容量与变化。</p>
            </div>
            <span id="overviewState" class="section-state" data-status="loading" role="status" aria-live="polite" aria-atomic="true" aria-busy="true">正在加载核心状态</span>
          </div>

          <div class="overview-grid">
            <section class="surface alerts-surface" aria-labelledby="alertsTitle">
              <div class="section-heading">
                <div>
                  <p class="section-kicker">需要处理</p>
                  <h3 id="alertsTitle">告警</h3>
                </div>
                <strong id="alertCount" class="count-display">—</strong>
              </div>
              <div id="alertsList" class="state-content skeleton-list" aria-live="polite"></div>
            </section>

            <section class="surface health-surface" aria-labelledby="healthTitle">
              <div class="section-heading">
                <div>
                  <p class="section-kicker">设备健康</p>
                  <h3 id="healthTitle">系统资源</h3>
                </div>
                <span id="healthLabel" class="status-badge neutral"><i></i><span>待采集</span></span>
              </div>
              <div id="healthMetrics" class="health-metrics skeleton-grid"></div>
            </section>
          </div>

          <section class="metric-strip" aria-label="设备摘要">
            <article><span>逻辑端口</span><strong id="metricPorts">—</strong><small id="metricPortsNote">正在采集</small></article>
            <article><span>EOS</span><strong id="metricEos">—</strong><small id="metricUptime">运行时间 —</small></article>
            <article><span>当前吞吐</span><strong id="metricTraffic">—</strong><small id="metricCapacity">容量占用 —</small></article>
            <article><span>转发能力</span><strong id="metricForwarding">—</strong><small id="metricSource">数据源 —</small></article>
          </section>

          <div class="overview-grid lower-grid">
            <section class="surface traffic-surface" aria-labelledby="trafficTitle">
              <div class="section-heading">
                <div>
                  <p class="section-kicker">最近 24 小时</p>
                  <h3 id="trafficTitle">聚合流量</h3>
                </div>
                <div class="traffic-legend" aria-hidden="true"><span class="rx">RX</span><span class="tx">TX</span></div>
              </div>
              <div class="chart-wrap">
                <canvas id="trafficChart" role="img" aria-labelledby="trafficTitle" aria-describedby="trafficChartDescription"></canvas>
                <p id="trafficChartDescription" class="sr-only">流量历史尚未加载。</p>
              </div>
              <div id="trafficSummary" class="traffic-summary"></div>
            </section>

            <section class="surface events-surface" aria-labelledby="eventsTitle">
              <div class="section-heading">
                <div>
                  <p class="section-kicker">最近变化</p>
                  <h3 id="eventsTitle">事件</h3>
                </div>
              </div>
              <ol id="eventsList" class="event-list skeleton-list"></ol>
            </section>
          </div>
        </section>

        <section id="portsPage" class="page" data-page="ports" aria-labelledby="portsTitle" hidden>
          <div class="page-heading split-heading">
            <div>
              <p class="eyebrow">INTERFACE MAP</p>
              <h2 id="portsTitle">端口</h2>
              <p id="portsSummary">正在采集端口状态。</p>
            </div>
            <span id="portsState" class="section-state" data-status="loading" role="status" aria-live="polite" aria-atomic="true" aria-busy="true">正在加载</span>
          </div>
          <section class="surface filter-bar" aria-label="端口筛选">
            <label class="search-field" for="portSearch"><span>搜索</span><input id="portSearch" type="search" placeholder="端口、描述、VLAN" /></label>
            <label for="portFilter"><span>状态</span><select id="portFilter"><option value="all">全部</option><option value="up">Up</option><option value="down">Down</option><option value="errors">有错误</option><option value="media">已插介质</option></select></label>
            <div class="port-legend" aria-label="状态说明"><span><i class="signal up"></i>Up</span><span><i class="signal down"></i>Down</span><span><i class="signal warning"></i>异常</span></div>
          </section>
          <div id="portGrid" class="port-grid skeleton-grid" aria-live="polite"></div>
          <div id="portsEmpty" class="empty-state" hidden><strong>没有匹配的端口</strong><span>调整搜索或状态筛选。</span></div>
        </section>

        <section id="networkPage" class="page" data-page="network" aria-labelledby="networkTitle" hidden>
          <div class="page-heading split-heading">
            <div>
              <p class="eyebrow">CONTROL &amp; DISCOVERY</p>
              <h2 id="networkTitle">网络数据</h2>
              <p>邻居、转发表、协议和物理介质集中查看。</p>
            </div>
            <span id="networkState" class="section-state" data-status="loading" role="status" aria-live="polite" aria-atomic="true" aria-busy="true">正在加载</span>
          </div>
          <div class="network-grid">
            <section class="surface table-surface wide" aria-labelledby="lldpTitle"><div class="section-heading"><h3 id="lldpTitle">LLDP 邻居</h3><span id="lldpCount" class="muted-text"></span></div><div id="lldpTable" class="table-region skeleton-block"></div></section>
            <section class="surface table-surface" aria-labelledby="vlanTitle"><div class="section-heading"><h3 id="vlanTitle">VLAN</h3></div><div id="vlanTable" class="table-region skeleton-block"></div></section>
            <section class="surface table-surface" aria-labelledby="protocolTitle"><div class="section-heading"><h3 id="protocolTitle">路由协议</h3></div><div id="protocolTable" class="table-region skeleton-block"></div></section>
            <section class="surface table-surface" aria-labelledby="arpTitle"><div class="section-heading"><h3 id="arpTitle">ARP</h3></div><div id="arpTable" class="table-region skeleton-block"></div></section>
            <section class="surface table-surface" aria-labelledby="fdbTitle"><div class="section-heading"><h3 id="fdbTitle">MAC 地址表</h3></div><div id="fdbTable" class="table-region skeleton-block"></div></section>
            <section class="surface table-surface wide" aria-labelledby="opticsTitle"><div class="section-heading"><h3 id="opticsTitle">光模块与 PoE</h3></div><div id="opticsTable" class="table-region skeleton-block"></div><div id="poeSummary" class="inline-note"></div></section>
            <section class="surface integrations-surface wide" aria-labelledby="integrationsTitle"><div class="section-heading"><h3 id="integrationsTitle">遥测集成</h3></div><div id="integrationsList" class="integration-list skeleton-grid"></div></section>
          </div>
        </section>

        <section id="diagnosticsPage" class="page" data-page="diagnostics" aria-labelledby="diagnosticsTitle" hidden>
          <div class="page-heading">
            <div><p class="eyebrow">SAFE DIAGNOSTICS</p><h2 id="diagnosticsTitle">诊断</h2><p>只运行预定义的只读查询，不接受任意 CLI 文本。</p></div>
          </div>
          <div class="workbench-grid">
            <section class="surface form-surface" aria-labelledby="diagnosticFormTitle">
              <div class="section-heading"><h3 id="diagnosticFormTitle">选择诊断</h3><span class="status-badge safe"><i></i><span>只读目录</span></span></div>
              <form id="diagnosticForm" class="stack-form" method="post" action="/api/diagnostics">
                <label for="diagnosticCommand">诊断项目</label>
                <select id="diagnosticCommand" name="commandId"></select>
                <div id="diagnosticParams"></div>
                <button id="diagnosticRun" class="button primary" type="submit">运行诊断</button>
              </form>
            </section>
            <section class="surface output-surface" aria-labelledby="diagnosticOutputTitle">
              <div class="section-heading"><h3 id="diagnosticOutputTitle">输出</h3><button id="copyDiagnostic" class="button text-button" type="button" disabled>复制</button></div>
              <pre id="diagnosticOutput" tabindex="0">选择一项诊断后运行。</pre>
            </section>
          </div>
        </section>

        <section id="changesPage" class="page" data-page="changes" aria-labelledby="changesTitle" hidden>
          <div class="page-heading split-heading">
            <div><p class="eyebrow">CONTROLLED CHANGE</p><h2 id="changesTitle">变更</h2><p>所有配置先生成差异，再由已解锁的会话提交。</p></div>
            <span id="lockStatus" class="status-badge locked"><i></i><span>只读模式</span></span>
          </div>
          <div class="change-layout">
            <section class="surface form-surface" aria-labelledby="changeFormTitle">
              <div class="section-heading"><h3 id="changeFormTitle">变更参数</h3></div>
              <form id="changeForm" class="stack-form" method="post" action="/api/config/preview">
                <label for="changeAction">操作</label>
                <select id="changeAction" name="action"></select>
                <p id="changeDescription" class="form-hint"></p>
                <div id="changeFields" class="dynamic-fields"></div>
                <button id="previewButton" class="button primary" type="submit">生成预览</button>
              </form>
            </section>
            <section class="surface preview-surface" aria-labelledby="previewTitle">
              <div class="section-heading"><div><h3 id="previewTitle">配置预览</h3><p id="previewExpiry" class="muted-text">尚未生成预览</p></div></div>
              <pre id="previewOutput" tabindex="0">选择变更并填写参数。</pre>
              <div id="applyBar" class="apply-bar" hidden>
                <label class="confirm-check"><input id="confirmApply" type="checkbox" /> <span>我已核对命令和差异</span></label>
                <button id="applyButton" class="button danger" type="button" disabled>提交配置</button>
              </div>
            </section>
          </div>
        </section>
      </main>
    </div>

    <div id="drawerBackdrop" class="drawer-backdrop" hidden></div>
    <aside id="portDrawer" class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawerTitle" aria-hidden="true" tabindex="-1" hidden inert>
      <div class="drawer-header"><div><p class="eyebrow">INTERFACE DETAIL</p><h2 id="drawerTitle">端口详情</h2></div><button id="drawerClose" class="icon-button" type="button" aria-label="关闭端口详情">×</button></div>
      <div id="drawerBody" class="drawer-body"></div>
    </aside>

    <div id="unlockLayer" class="modal-layer" hidden>
      <section id="unlockDialog" class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="unlockTitle" tabindex="-1">
        <div class="section-heading"><div><p class="eyebrow">PRIVILEGED SESSION</p><h2 id="unlockTitle">解锁配置操作</h2></div><button id="unlockClose" class="icon-button" type="button" aria-label="关闭">×</button></div>
        <p>再次输入交换机密码。解锁状态将在 15 分钟后自动失效。</p>
        <form id="unlockForm" class="stack-form" method="post" action="/api/auth/unlock">
          <label for="unlockPassword">密码</label>
          <input id="unlockPassword" type="password" autocomplete="current-password" required />
          <p id="unlockError" class="form-error" role="alert" hidden></p>
          <button class="button primary" type="submit">解锁 15 分钟</button>
        </form>
      </section>
    </div>

    <div id="toastRegion" class="toast-region" aria-live="polite" aria-atomic="true"></div>
    <script>
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const ROUTES = {
    "/": "overview",
    "/ports": "ports",
    "/network": "network",
    "/diagnostics": "diagnostics",
    "/changes": "changes"
  };
  const REFRESH_SCOPES = ["core", "metrics", "health", "tables", "discovery", "optics", "protocols", "extras"];
  const DIAGNOSTICS = [
    ["version", "系统版本", "EOS、硬件型号、序列号和运行时间"],
    ["interfaces_status", "端口状态", "所有接口的链路、VLAN、双工和速率"],
    ["vlan", "VLAN", "VLAN 清单和成员端口"],
    ["lldp", "LLDP 邻居", "相邻设备和连接端口"],
    ["environment", "环境传感器", "温度、风扇和电源状态"],
    ["routes", "路由表", "当前 IPv4 路由摘要"],
    ["arp", "ARP", "IPv4 邻居解析表"],
    ["mac_table", "MAC 地址表", "二层转发表"],
    ["transceivers", "光模块", "收发器识别与 DOM 数据"],
    ["ping", "Ping", "向受限目标发送 ICMP 探测"],
    ["traceroute", "Traceroute", "追踪到受限目标的路径"]
  ];
  const CHANGE_ACTIONS = {
    interface_admin: {
      label: "启用或停用接口",
      description: "改变一个物理或逻辑接口的管理状态。停用可能立即中断流量。",
      fields: [field("interface", "接口", "text", "Ethernet1"), choice("state", "状态", [["enable", "启用"], ["disable", "停用"]])]
    },
    poe_control: {
      label: "PoE 控制",
      description: "为指定端口启用或停用 PoE 供电。",
      fields: [field("interface", "接口", "text", "Ethernet1"), choice("state", "状态", [["enable", "启用"], ["disable", "停用"]])]
    },
    description: {
      label: "接口描述",
      description: "更新接口描述，便于资产和链路识别。",
      fields: [field("interface", "接口", "text", "Ethernet1"), field("description", "描述", "text", "rack-01 server uplink")]
    },
    access_vlan: {
      label: "Access VLAN",
      description: "将接口设为 access 模式并分配一个 VLAN。",
      fields: [field("interface", "接口", "text", "Ethernet1"), field("vlan", "VLAN ID", "number", "100", { min: 1, max: 4094 })]
    },
    trunk_vlan: {
      label: "Trunk VLAN",
      description: "将接口设为 trunk，并配置允许的 VLAN 列表和可选 native VLAN。",
      fields: [field("interface", "接口", "text", "Ethernet1"), field("vlan", "允许的 VLAN", "text", "10,20,100-120"), field("nativeVlan", "Native VLAN（可选）", "number", "10", { min: 1, max: 4094, required: false })]
    },
    create_vlan: {
      label: "创建 VLAN",
      description: "创建 VLAN，并可设置便于识别的名称。",
      fields: [field("vlan", "VLAN ID", "number", "100", { min: 1, max: 4094 }), field("name", "名称（可选）", "text", "SERVERS", { required: false })]
    },
    svi_interface: {
      label: "配置 SVI",
      description: "为 VLAN 接口配置 IPv4 地址和可选描述。",
      fields: [field("vlan", "VLAN ID", "number", "100", { min: 1, max: 4094 }), field("address", "IPv4 前缀", "text", "192.0.2.1/24"), field("description", "描述（可选）", "text", "server gateway", { required: false })]
    },
    l3_interface: {
      label: "三层接口",
      description: "关闭二层交换模式，并为接口配置 IPv4 地址。",
      fields: [field("interface", "接口", "text", "Ethernet1"), field("address", "IPv4 前缀", "text", "192.0.2.1/31")]
    },
    ospf_network: {
      label: "OSPF 网络",
      description: "向指定 OSPF 进程添加一个网络和区域。",
      fields: [field("process", "进程 ID", "number", "1", { min: 1, max: 65535 }), field("network", "网络前缀", "text", "192.0.2.0/24"), field("area", "区域", "text", "0")]
    },
    ospf_interface: {
      label: "OSPF 接口",
      description: "在接口上启用指定 OSPF 区域。",
      fields: [field("interface", "接口", "text", "Ethernet1"), field("area", "区域", "text", "0")]
    },
    bgp_neighbor: {
      label: "BGP 邻居",
      description: "为本地 ASN 添加 IPv4 邻居及其远端 ASN。",
      fields: [field("asn", "本地 ASN", "number", "65001", { min: 1 }), field("neighbor", "邻居 IPv4", "text", "192.0.2.2"), field("remoteAs", "远端 ASN", "number", "65002", { min: 1 })]
    },
    bgp_address_family: {
      label: "BGP 地址族",
      description: "在 BGP 地址族中启用或停用一个邻居。",
      fields: [field("asn", "本地 ASN", "number", "65001", { min: 1 }), field("neighbor", "邻居 IP", "text", "192.0.2.2"), choice("addressFamily", "地址族", [["ipv4", "IPv4"], ["ipv6", "IPv6"]]), choice("mode", "状态", [["activate", "启用"], ["deactivate", "停用"]])]
    },
    save_config: {
      label: "保存运行配置",
      description: "将当前 running-config 保存为 startup-config。",
      fields: []
    }
  };

  const elements = {
    loginView: $("loginView"), loginForm: $("loginForm"), loginUsername: $("loginUsername"), loginPassword: $("loginPassword"), loginError: $("loginError"),
    appShell: $("appShell"), deviceHostname: $("deviceHostname"), deviceModel: $("deviceModel"), connectionBadge: $("connectionBadge"), lastRefresh: $("lastRefresh"),
    refreshInterval: $("refreshInterval"), refreshButton: $("refreshButton"), unlockButton: $("unlockButton"), themeButton: $("themeButton"), logoutButton: $("logoutButton"),
    overviewState: $("overviewState"), portsState: $("portsState"), networkState: $("networkState"), alertsList: $("alertsList"), alertCount: $("alertCount"),
    healthMetrics: $("healthMetrics"), healthLabel: $("healthLabel"), metricPorts: $("metricPorts"), metricPortsNote: $("metricPortsNote"), metricEos: $("metricEos"), metricUptime: $("metricUptime"), metricTraffic: $("metricTraffic"), metricCapacity: $("metricCapacity"), metricForwarding: $("metricForwarding"), metricSource: $("metricSource"),
    trafficChart: $("trafficChart"), trafficChartDescription: $("trafficChartDescription"), trafficSummary: $("trafficSummary"), eventsList: $("eventsList"),
    portsSummary: $("portsSummary"), portSearch: $("portSearch"), portFilter: $("portFilter"), portGrid: $("portGrid"), portsEmpty: $("portsEmpty"),
    lldpCount: $("lldpCount"), lldpTable: $("lldpTable"), vlanTable: $("vlanTable"), protocolTable: $("protocolTable"), arpTable: $("arpTable"), fdbTable: $("fdbTable"), opticsTable: $("opticsTable"), poeSummary: $("poeSummary"), integrationsList: $("integrationsList"),
    diagnosticForm: $("diagnosticForm"), diagnosticCommand: $("diagnosticCommand"), diagnosticParams: $("diagnosticParams"), diagnosticRun: $("diagnosticRun"), diagnosticOutput: $("diagnosticOutput"), copyDiagnostic: $("copyDiagnostic"),
    lockStatus: $("lockStatus"), changeForm: $("changeForm"), changeAction: $("changeAction"), changeDescription: $("changeDescription"), changeFields: $("changeFields"), previewButton: $("previewButton"), previewOutput: $("previewOutput"), previewExpiry: $("previewExpiry"), applyBar: $("applyBar"), confirmApply: $("confirmApply"), applyButton: $("applyButton"),
    drawerBackdrop: $("drawerBackdrop"), portDrawer: $("portDrawer"), drawerTitle: $("drawerTitle"), drawerBody: $("drawerBody"), drawerClose: $("drawerClose"),
    unlockLayer: $("unlockLayer"), unlockDialog: $("unlockDialog"), unlockClose: $("unlockClose"), unlockForm: $("unlockForm"), unlockPassword: $("unlockPassword"), unlockError: $("unlockError"),
    toastRegion: $("toastRegion")
  };

  const app = {
    session: { authenticated: false, csrfToken: "", user: "", unlockedUntil: 0 },
    data: {},
    refreshGeneration: 0,
    refreshController: null,
    refreshPromise: null,
    refreshTimer: null,
    lockTimer: null,
    scopeErrors: new Map(),
    portCards: [],
    portByKey: new Map(),
    preview: null,
    previewGeneration: 0,
    previousFocus: null,
    drawerCloseTimer: null
  };

  class ApiError extends Error {
    constructor(message, status, code) {
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.code = code;
    }
  }

  function field(name, label, type, placeholder, options = {}) {
    return { name, label, type, placeholder, required: options.required !== false, min: options.min, max: options.max };
  }

  function choice(name, label, options) {
    return { name, label, type: "select", options, required: true };
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function asArray(value) {
    if (Array.isArray(value)) return value;
    if (value && typeof value === "object") return Object.values(value);
    return [];
  }

  function numeric(value, fallback = 0) {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  }

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, numeric(value)));
  }

  function valueFrom(row, keys, fallback = "—") {
    for (const key of keys) {
      const value = key.split(".").reduce((current, part) => current && current[part], row);
      if (value !== undefined && value !== null && value !== "") return value;
    }
    return fallback;
  }

  function formatTime(value, withDate = false) {
    if (!value) return "—";
    const date = new Date(typeof value === "number" && value < 10_000_000_000 ? value * 1000 : value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat("zh-CN", {
      month: withDate ? "2-digit" : undefined,
      day: withDate ? "2-digit" : undefined,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    }).format(date);
  }

  function formatRate(value) {
    const mbps = numeric(value);
    if (mbps >= 1_000_000) return `${(mbps / 1_000_000).toFixed(2)} Tbps`;
    if (mbps >= 1_000) return `${(mbps / 1_000).toFixed(2)} Gbps`;
    return `${mbps.toFixed(mbps >= 100 ? 0 : 1)} Mbps`;
  }

  function mergeState(base, update) {
    if (!update || typeof update !== "object") return base;
    const merged = { ...(base || {}) };
    for (const [key, value] of Object.entries(update)) {
      if (value && typeof value === "object" && !Array.isArray(value) && merged[key] && typeof merged[key] === "object" && !Array.isArray(merged[key])) {
        merged[key] = mergeState(merged[key], value);
      } else {
        merged[key] = value;
      }
    }
    return merged;
  }

  function sessionPayload(payload) {
    const source = payload && payload.session ? payload.session : payload || {};
    const until = source.unlockedUntil || source.unlocked_until || 0;
    const untilMs = typeof until === "number" && until > 0 && until < 10_000_000_000 ? until * 1000 : until;
    return {
      authenticated: Boolean(source.authenticated ?? payload?.authenticated),
      csrfToken: source.csrfToken || source.csrf_token || payload?.csrfToken || "",
      user: source.user || source.username || payload?.user || "",
      unlockedUntil: untilMs ? new Date(untilMs).getTime() : 0
    };
  }

  async function api(path, options = {}) {
    const method = options.method || "GET";
    const headers = { Accept: "application/json", ...(options.headers || {}) };
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET" && path !== "/api/auth/login" && app.session.csrfToken) {
      headers["X-CSRF-Token"] = app.session.csrfToken;
    }
    const response = await fetch(path, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
      signal: options.signal
    });
    const text = await response.text();
    let payload = {};
    try { payload = text ? JSON.parse(text) : {}; } catch { payload = { error: text || `HTTP ${response.status}` }; }
    if (!response.ok || payload.ok === false) {
      const error = payload.error;
      const message = typeof error === "object" ? error.message : error;
      const code = payload.code || error?.code;
      if (response.status === 401 && code === "authentication_required" && path !== "/api/auth/login") showLogin();
      throw new ApiError(message || payload.message || `HTTP ${response.status}`, response.status, code);
    }
    return payload;
  }

  function toast(message, tone = "info") {
    const item = document.createElement("div");
    item.className = "toast";
    item.dataset.tone = tone;
    item.setAttribute("role", tone === "error" ? "alert" : "status");
    item.textContent = message;
    elements.toastRegion.append(item);
    window.setTimeout(() => item.remove(), 4200);
  }

  function setBusy(button, busy, busyLabel) {
    if (!button.dataset.label) button.dataset.label = button.textContent;
    button.disabled = busy;
    button.textContent = busy ? busyLabel : button.dataset.label;
    button.setAttribute("aria-busy", String(busy));
  }

  function showLogin(message = "") {
    stopTimers();
    clearTimeout(app.drawerCloseTimer);
    app.drawerCloseTimer = null;
    app.previewGeneration += 1;
    resetPreview();
    app.data = {};
    app.scopeErrors.clear();
    app.portCards = [];
    app.portByKey.clear();
    elements.unlockLayer.hidden = true;
    elements.unlockPassword.value = "";
    elements.unlockError.hidden = true;
    elements.portDrawer.classList.remove("open");
    elements.portDrawer.setAttribute("aria-hidden", "true");
    elements.portDrawer.setAttribute("inert", "");
    elements.portDrawer.hidden = true;
    elements.drawerBackdrop.hidden = true;
    document.body.classList.remove("has-overlay");
    app.previousFocus = null;
    app.session = { authenticated: false, csrfToken: "", user: "", unlockedUntil: 0 };
    elements.appShell.hidden = true;
    elements.loginView.hidden = false;
    elements.loginError.hidden = !message;
    elements.loginError.textContent = message;
    window.setTimeout(() => elements.loginUsername.focus(), 0);
  }

  function showApp() {
    elements.loginView.hidden = true;
    elements.appShell.hidden = false;
    renderSession();
    routeTo(location.pathname, false);
    scheduleTimers();
  }

  function isUnlocked() {
    return app.session.unlockedUntil > Date.now();
  }

  function renderSession() {
    const unlocked = isUnlocked();
    elements.lockStatus.className = `status-badge ${unlocked ? "safe" : "locked"}`;
    elements.lockStatus.innerHTML = `<i></i><span>${unlocked ? `已解锁 · ${Math.max(1, Math.ceil((app.session.unlockedUntil - Date.now()) / 60000))} 分钟` : "只读模式"}</span>`;
    elements.unlockButton.textContent = unlocked ? "操作已解锁" : "解锁操作";
    elements.unlockButton.classList.toggle("primary", unlocked);
  }

  function routeName(pathname) {
    const clean = pathname.length > 1 ? pathname.replace(/\/+$/, "") : "/";
    return ROUTES[clean] || "overview";
  }

  function routePath(name) {
    return Object.entries(ROUTES).find(([, route]) => route === name)?.[0] || "/";
  }

  function routeTo(pathname, push = true) {
    const route = routeName(pathname);
    document.querySelectorAll("[data-page]").forEach((page) => { page.hidden = page.dataset.page !== route; });
    document.querySelectorAll("[data-route]").forEach((link) => {
      if (link.dataset.route === route) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    const canonicalPath = routePath(route);
    if (push && location.pathname !== canonicalPath) history.pushState({ route }, "", canonicalPath);
    document.title = `${document.querySelector(`[data-page="${route}"] h2`)?.textContent || "运维台"} · Arista 7050QX`;
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
  }

  function setSectionState(element, status, message) {
    element.dataset.status = status;
    element.setAttribute("aria-busy", String(status === "loading"));
    element.textContent = message;
  }

  function freshnessStatus() {
    if (app.data.meta?.stale === true) return "stale";
    const value = app.data.device?.lastRefresh;
    if (!value) return "loading";
    const time = new Date(value).getTime();
    return Number.isFinite(time) && Date.now() - time > 130_000 ? "stale" : "ready";
  }

  function updateSectionStates(activeScope = "") {
    const loading = app.refreshPromise && activeScope;
    const stale = freshnessStatus() === "stale";
    const coreError = app.scopeErrors.get("core") || app.scopeErrors.get("metrics");
    const overviewError = coreError || app.scopeErrors.get("health");
    const networkError = ["tables", "discovery", "optics", "protocols", "extras"].map((scope) => app.scopeErrors.get(scope)).find(Boolean);
    setSectionState(elements.overviewState, loading && ["core", "metrics", "health"].includes(activeScope) ? "loading" : overviewError ? "error" : stale ? "stale" : "ready", loading ? `正在加载 ${activeScope}` : overviewError ? "部分数据加载失败" : stale ? "数据已过期" : "数据已更新");
    setSectionState(elements.portsState, loading && ["core", "metrics"].includes(activeScope) ? "loading" : coreError ? "error" : stale ? "stale" : "ready", loading ? "正在加载端口" : coreError ? "端口数据加载失败" : stale ? "端口数据已过期" : "端口数据已更新");
    setSectionState(elements.networkState, loading && !["core", "metrics", "health"].includes(activeScope) ? "loading" : networkError ? "error" : stale ? "stale" : "ready", loading ? `正在加载 ${activeScope}` : networkError ? "部分网络数据失败" : stale ? "网络数据已过期" : "网络数据已更新");
  }

  async function refreshAll(options = {}) {
    const generation = ++app.refreshGeneration;
    if (app.refreshController) app.refreshController.abort();
    const controller = new AbortController();
    app.refreshController = controller;
    app.scopeErrors.clear();
    const run = (async () => {
      setBusy(elements.refreshButton, true, "刷新中");
      for (const scope of REFRESH_SCOPES) {
        if (generation !== app.refreshGeneration) return;
        updateSectionStates(scope);
        try {
          const payload = await api("/api/refresh", { method: "POST", body: { scope }, signal: controller.signal });
          if (generation !== app.refreshGeneration) return;
          app.data = mergeState(app.data, payload.state || payload.data || payload);
          renderAll();
        } catch (error) {
          if (error.name === "AbortError") return;
          app.scopeErrors.set(scope, error.message);
          if (!options.silent) toast(`${scope}: ${error.message}`, "error");
        }
      }
      if (!options.silent && !app.scopeErrors.size) toast("状态已刷新", "success");
    })();
    app.refreshPromise = run;
    try {
      await run;
    } finally {
      if (app.refreshGeneration === generation) {
        app.refreshPromise = null;
        app.refreshController = null;
        setBusy(elements.refreshButton, false, "刷新中");
        updateSectionStates();
      }
    }
  }

  function renderAll() {
    renderHeader();
    renderOverview();
    renderPorts();
    renderNetwork();
    updateSectionStates();
  }

  function renderHeader() {
    const device = app.data.device || {};
    elements.deviceHostname.textContent = device.hostname || "Arista 7050QX";
    elements.deviceModel.textContent = device.model || "DCS-7050QX";
    elements.lastRefresh.textContent = device.lastRefresh ? `更新 ${formatTime(device.lastRefresh)}` : "尚未刷新";
    const stale = freshnessStatus() === "stale";
    elements.connectionBadge.className = `status-badge ${stale ? "warning" : "live"}`;
    elements.connectionBadge.innerHTML = `<i></i><span>${stale ? "数据已过期" : "HTTPS 在线"}</span>`;
  }

  function renderOverview() {
    const device = app.data.device || {};
    const health = app.data.health || {};
    const traffic = app.data.traffic || {};
    const ports = asArray(app.data.ports);
    const alerts = asArray(app.data.alerts);
    const events = asArray(app.data.events);
    const up = ports.filter((port) => String(port.status).toLowerCase() === "up").length;
    const errors = ports.filter((port) => numeric(port.errors) > 0).length;
    const healthError = app.scopeErrors.get("health");
    const healthLoading = app.data.loading?.health;
    const healthReported = [health.cpu, health.memory, health.temperature].every((value) => value !== undefined && value !== null && Number.isFinite(Number(value))) && Boolean(health.fanStatus && health.psuStatus);
    const healthReady = !healthError && healthReported && (healthLoading === undefined || healthLoading === "done");

    elements.alertCount.textContent = alerts.length || healthReady ? String(alerts.length) : "—";
    elements.alertsList.className = "state-content alert-list";
    elements.alertsList.innerHTML = alerts.length ? alerts.map((alert) => {
      const severity = String(alert.severity || alert.level || "warning").toLowerCase();
      const title = alert.title || alert.message || alert.name || "设备告警";
      const detail = alert.detail || alert.description || alert.interface || severity;
      return `<article class="alert-item" data-severity="${escapeHtml(severity)}"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span></article>`;
    }).join("") : !healthReady
      ? `<div class="inline-empty"><strong>${healthError ? "部分告警源采集失败" : "仍在采集环境告警"}</strong><span>在健康采集完成前，不将空结果解释为无告警。</span></div>`
      : `<div class="inline-empty"><strong>当前没有活动告警</strong><span>系统未报告需要处理的异常。</span></div>`;

    elements.healthMetrics.className = "health-metrics";
    if (!healthReady) {
      elements.healthMetrics.innerHTML = `<div class="inline-empty"><strong>${healthError ? "健康数据采集失败" : "正在采集健康数据"}</strong><span>CPU、内存、温度、风扇和电源状态当前不可确认。</span></div>`;
      elements.healthLabel.className = `status-badge ${healthError ? "locked" : "neutral"}`;
      elements.healthLabel.innerHTML = `<i></i><span>${healthError ? "采集失败" : "状态未知"}</span>`;
    } else {
      const metrics = [
        ["CPU", health.cpu, 100, "%"],
        ["内存", health.memory, 100, "%"],
        ["温度", health.temperature, 90, "°C"],
        ["风扇", null, null, health.fanStatus],
        ["电源", null, null, health.psuStatus]
      ];
      elements.healthMetrics.innerHTML = metrics.map(([label, value, max, suffix]) => {
        const display = value === null ? suffix : `${numeric(value)}${suffix}`;
        const meter = value === null ? "" : `<progress max="${max}" value="${clamp(value, 0, max)}" aria-label="${label} ${display}"></progress>`;
        return `<div class="health-metric"><span>${label}</span><strong>${escapeHtml(display)}</strong>${meter}</div>`;
      }).join("");
      const healthBad = /check|fail|fault|bad/i.test(`${health.fanStatus} ${health.psuStatus}`) || numeric(health.temperature) >= 70;
      elements.healthLabel.className = `status-badge ${healthBad ? "warning" : "safe"}`;
      elements.healthLabel.innerHTML = `<i></i><span>${healthBad ? "需要检查" : "运行正常"}</span>`;
    }

    elements.metricPorts.textContent = `${up} / ${ports.length || "—"}`;
    elements.metricPortsNote.textContent = `${errors} 个端口有错误`;
    elements.metricEos.textContent = device.eosVersion || "—";
    elements.metricUptime.textContent = `运行时间 ${device.uptime || "—"}`;
    elements.metricTraffic.textContent = formatRate(numeric(traffic.rxMbps) + numeric(traffic.txMbps));
    elements.metricCapacity.textContent = `容量占用 ${numeric(traffic.capacityUtilization).toFixed(4)}%`;
    elements.metricForwarding.textContent = device.forwardingRate || traffic.packetRateLabel || "—";
    elements.metricSource.textContent = `数据源 ${device.source || app.data.meta?.source || "—"}`;

    elements.eventsList.className = "event-list";
    elements.eventsList.innerHTML = events.length ? events.slice(0, 50).map((event) => `<li class="event-item" data-level="${escapeHtml(event.level || "info")}"><time datetime="${escapeHtml(event.time || "")}">${escapeHtml(formatTime(event.time, true))} · ${escapeHtml(event.level || "info")}</time><span>${escapeHtml(event.message || event.title || "")}</span></li>`).join("") : `<li class="inline-empty"><strong>没有事件</strong><span>新的采集或配置事件会显示在这里。</span></li>`;
    drawTrafficChart();
  }

  function trafficPoints() {
    const current = app.data.traffic || {};
    const rows = asArray(app.data.history?.traffic).slice(-80).map((row) => ({
      time: row.time || row.timestamp,
      rx: numeric(row.rxMbps ?? row.rx),
      tx: numeric(row.txMbps ?? row.tx),
      total: numeric(row.totalMbps, numeric(row.rxMbps) + numeric(row.txMbps))
    }));
    if (!rows.length && (current.rxMbps || current.txMbps)) rows.push({ time: Date.now(), rx: numeric(current.rxMbps), tx: numeric(current.txMbps), total: numeric(current.rxMbps) + numeric(current.txMbps) });
    return rows;
  }

  function drawTrafficChart() {
    const canvas = elements.trafficChart;
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const context = canvas.getContext("2d");
    context.scale(dpr, dpr);
    const points = trafficPoints();
    const styles = getComputedStyle(document.body);
    const line = styles.getPropertyValue("--line").trim();
    const muted = styles.getPropertyValue("--muted").trim();
    const rxColor = styles.getPropertyValue("--accent").trim();
    const txColor = styles.getPropertyValue("--info").trim();
    const width = rect.width;
    const height = rect.height;
    const pad = { left: 4, right: 4, top: 12, bottom: 22 };
    context.clearRect(0, 0, width, height);
    context.strokeStyle = line;
    context.lineWidth = 1;
    for (let index = 0; index < 4; index += 1) {
      const y = pad.top + ((height - pad.top - pad.bottom) * index) / 3;
      context.beginPath(); context.moveTo(pad.left, y); context.lineTo(width - pad.right, y); context.stroke();
    }
    if (points.length) {
      const max = Math.max(1, ...points.flatMap((point) => [point.rx, point.tx]));
      const plot = (key, color) => {
        context.beginPath();
        points.forEach((point, index) => {
          const x = pad.left + (points.length === 1 ? 0 : (index / (points.length - 1)) * (width - pad.left - pad.right));
          const y = pad.top + (1 - point[key] / max) * (height - pad.top - pad.bottom);
          if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
        });
        context.strokeStyle = color; context.lineWidth = 2; context.lineJoin = "round"; context.lineCap = "round"; context.stroke();
      };
      plot("rx", rxColor); plot("tx", txColor);
      context.fillStyle = muted; context.font = `11px ${getComputedStyle(document.body).fontFamily}`;
      context.fillText(formatRate(max), pad.left, 10);
      const latest = points[points.length - 1];
      elements.trafficChartDescription.textContent = `流量图包含 ${points.length} 个采样点。最新接收 ${formatRate(latest.rx)}，发送 ${formatRate(latest.tx)}。`;
      elements.trafficSummary.innerHTML = `<span>RX ${escapeHtml(formatRate(latest.rx))}</span><span>TX ${escapeHtml(formatRate(latest.tx))}</span><span>峰值 ${escapeHtml(formatRate(max))}</span>`;
    } else {
      context.fillStyle = muted; context.font = `13px ${getComputedStyle(document.body).fontFamily}`; context.fillText("暂无流量历史", 12, height / 2);
      elements.trafficChartDescription.textContent = "暂无流量历史。";
      elements.trafficSummary.textContent = "等待下一次服务端采样。";
    }
  }

  function groupPorts(ports) {
    const groups = new Map();
    const output = [];
    ports.forEach((port, index) => {
      const name = String(port.name || port.interface || `port-${index}`);
      const match = name.match(/^Ethernet(\d+)\/(\d+)$/i);
      if (!match) {
        output.push({ ...port, name, key: name, kind: "port" });
        return;
      }
      const base = `Ethernet${match[1]}`;
      if (!groups.has(base)) {
        const group = { key: base, name: base, kind: "breakout", lanes: [], description: "Breakout 端口" };
        groups.set(base, group); output.push(group);
      }
      groups.get(base).lanes.push({ ...port, name, lane: Number(match[2]) });
    });
    return output.map((port) => {
      if (port.kind !== "breakout") return port;
      port.lanes.sort((a, b) => a.lane - b.lane);
      const up = port.lanes.filter((lane) => String(lane.status).toLowerCase() === "up").length;
      return {
        ...port,
        status: up ? "up" : "down",
        description: `${up}/${port.lanes.length} lanes up`,
        speed: `${port.lanes.length} × ${port.lanes[0]?.speed || "lane"}`,
        vlan: [...new Set(port.lanes.map((lane) => lane.vlan).filter(Boolean))].join(", ") || "—",
        media: [...new Set(port.lanes.map((lane) => lane.media).filter(Boolean))].join(", ") || "—",
        hasMedia: port.lanes.some((lane) => lane.hasMedia),
        rxMbps: port.lanes.reduce((total, lane) => total + numeric(lane.rxMbps), 0),
        txMbps: port.lanes.reduce((total, lane) => total + numeric(lane.txMbps), 0),
        errors: port.lanes.reduce((total, lane) => total + numeric(lane.errors), 0)
      };
    });
  }

  function renderPorts() {
    const allPorts = asArray(app.data.ports);
    const cards = groupPorts(allPorts);
    const search = elements.portSearch.value.trim().toLowerCase();
    const filter = elements.portFilter.value;
    const filtered = cards.filter((port) => {
      const haystack = [port.name, port.description, port.vlan, port.media, ...(port.lanes || []).map((lane) => `${lane.name} ${lane.description || ""}`)].join(" ").toLowerCase();
      const status = String(port.status || "down").toLowerCase();
      const matchesFilter = filter === "all" || filter === status || (filter === "errors" && numeric(port.errors) > 0) || (filter === "media" && port.hasMedia);
      return matchesFilter && (!search || haystack.includes(search));
    });
    app.portCards = filtered;
    app.portByKey = new Map(filtered.map((port) => [port.key || port.name, port]));
    const up = allPorts.filter((port) => String(port.status).toLowerCase() === "up").length;
    const errors = allPorts.filter((port) => numeric(port.errors) > 0).length;
    elements.portsSummary.textContent = `${up}/${allPorts.length || 0} 个逻辑端口 Up · ${cards.length} 个物理端口 · ${errors} 个错误`;
    elements.portGrid.className = "port-grid";
    elements.portGrid.innerHTML = filtered.map((port) => {
      const status = String(port.status || "down").toLowerCase();
      return `<button class="port-card" type="button" data-port-key="${escapeHtml(port.key || port.name)}" data-status="${escapeHtml(status)}" data-errors="${numeric(port.errors) > 0}" aria-label="查看 ${escapeHtml(port.name)} 详情，状态 ${escapeHtml(status)}">
        <span class="port-card-head"><strong>${escapeHtml(port.name)}</strong><span class="port-status-text">${escapeHtml(status)}</span></span>
        <span class="port-description">${escapeHtml(port.description || "未设置描述")}</span>
        <span class="port-meta"><span>${escapeHtml(port.speed || "—")}</span><span>VLAN ${escapeHtml(port.vlan || "—")}</span><span>${escapeHtml(port.media || "—")}</span></span>
        <span class="port-traffic"><span>RX ${escapeHtml(formatRate(port.rxMbps))}</span><span>TX ${escapeHtml(formatRate(port.txMbps))}</span></span>
      </button>`;
    }).join("");
    elements.portsEmpty.hidden = filtered.length > 0 || !allPorts.length;
    if (!allPorts.length) elements.portGrid.innerHTML = `<div class="empty-state"><strong>尚未收到端口数据</strong><span>刷新后仍为空时，请检查采集状态。</span></div>`;
  }

  function detailItem(label, value) {
    return `<div class="detail-item"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value ?? "—")}</strong></div>`;
  }

  function syncOverlayState() {
    const drawerOpen = !elements.portDrawer.hidden && (elements.portDrawer.classList.contains("open") || elements.portDrawer.getAttribute("aria-hidden") === "false");
    document.body.classList.toggle("has-overlay", drawerOpen || !elements.unlockLayer.hidden);
  }

  function openPortDrawer(port) {
    if (!port) return;
    clearTimeout(app.drawerCloseTimer);
    app.drawerCloseTimer = null;
    app.previousFocus = document.activeElement;
    elements.drawerTitle.textContent = `${port.name} 详情`;
    const optics = port.transceiver || {};
    const details = [
      ["状态", port.status], ["速率", port.speed], ["VLAN", port.vlan], ["双工", port.duplex],
      ["介质", port.media], ["RX", formatRate(port.rxMbps)], ["TX", formatRate(port.txMbps)], ["错误计数", numeric(port.errors)],
      ["描述", port.description], ["光模块", optics.present === false ? "Not present" : optics.type], ["厂商", optics.vendor], ["序列号", optics.serial],
      ["DOM 温度", optics.temperature], ["TX / RX 光功率", `${optics.txPower || "—"} / ${optics.rxPower || "—"}`]
    ];
    let lanes = "";
    if (port.lanes?.length) {
      lanes = renderTableMarkup("Breakout lane 明细", [
        ["Lane", (row) => row.name], ["状态", (row) => row.status], ["VLAN", (row) => row.vlan], ["速率", (row) => row.speed], ["RX", (row) => formatRate(row.rxMbps)], ["TX", (row) => formatRate(row.txMbps)], ["错误", (row) => numeric(row.errors)]
      ], port.lanes);
    }
    const raw = [port.statusLine, port.rateLine, port.errorLine, optics.raw].filter(Boolean).join("\n");
    elements.drawerBody.innerHTML = `<div class="detail-grid">${details.map(([label, value]) => detailItem(label, value)).join("")}</div>${lanes ? `<div class="table-region">${lanes}</div>` : ""}${raw ? `<pre tabindex="0">${escapeHtml(raw)}</pre>` : ""}`;
    elements.portDrawer.hidden = false;
    elements.portDrawer.removeAttribute("inert");
    elements.drawerBackdrop.hidden = false;
    elements.portDrawer.setAttribute("aria-hidden", "false");
    syncOverlayState();
    requestAnimationFrame(() => { elements.portDrawer.classList.add("open"); elements.drawerClose.focus(); });
  }

  function closePortDrawer() {
    if (elements.portDrawer.hidden) return;
    const restoreTarget = app.previousFocus?.isConnected ? app.previousFocus : $("mainContent");
    app.previousFocus = null;
    restoreTarget?.focus?.();
    elements.portDrawer.classList.remove("open");
    elements.portDrawer.setAttribute("aria-hidden", "true");
    elements.portDrawer.setAttribute("inert", "");
    syncOverlayState();
    clearTimeout(app.drawerCloseTimer);
    app.drawerCloseTimer = window.setTimeout(() => {
      elements.portDrawer.hidden = true;
      elements.drawerBackdrop.hidden = true;
      app.drawerCloseTimer = null;
    }, 220);
  }

  function renderTableMarkup(caption, columns, rows) {
    if (!rows.length) return `<div class="inline-empty"><strong>暂无数据</strong><span>采集完成后仍为空表示设备未报告记录。</span></div>`;
    return `<table class="data-table"><caption>${escapeHtml(caption)}</caption><thead><tr>${columns.map(([label]) => `<th scope="col">${escapeHtml(label)}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${columns.map(([, getter]) => `<td>${escapeHtml(getter(row))}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  }

  function renderTable(target, caption, columns, source) {
    const rows = asArray(source);
    target.className = "table-region";
    target.innerHTML = renderTableMarkup(caption, columns, rows);
  }

  function renderNetwork() {
    const lldp = asArray(app.data.lldp);
    const vlans = asArray(app.data.vlans);
    const arp = asArray(app.data.arp);
    const fdb = asArray(app.data.fdb);
    const optics = asArray(app.data.transceivers);
    const protocols = app.data.protocols || {};
    const protocolRows = Object.entries(protocols).flatMap(([protocol, rows]) => asArray(rows).map((row) => ({ ...row, protocol: protocol.toUpperCase() })));
    elements.lldpCount.textContent = `${lldp.length} 条`;
    renderTable(elements.lldpTable, "LLDP 邻居", [
      ["本地端口", (row) => valueFrom(row, ["localPort", "interface", "port"])], ["邻居", (row) => valueFrom(row, ["neighbor", "systemName", "neighborDevice", "chassisId"])], ["邻居端口", (row) => valueFrom(row, ["neighborPort", "portId", "portDescription"])], ["管理地址", (row) => valueFrom(row, ["managementAddress", "managementIp", "address"])], ["描述", (row) => valueFrom(row, ["description", "systemDescription"])]
    ], lldp);
    renderTable(elements.vlanTable, "VLAN", [
      ["ID", (row) => valueFrom(row, ["id", "vlan", "vlanId"])], ["名称", (row) => valueFrom(row, ["name"])], ["状态", (row) => valueFrom(row, ["status", "state"])], ["端口", (row) => valueFrom(row, ["ports", "interfaces"])]
    ], vlans);
    renderTable(elements.protocolTable, "路由协议", [
      ["协议", (row) => row.protocol], ["邻居", (row) => valueFrom(row, ["neighbor", "peer", "routerId"])], ["状态", (row) => valueFrom(row, ["state", "status"])], ["接口 / 前缀", (row) => valueFrom(row, ["interface", "prefixes", "network"])], ["时间", (row) => valueFrom(row, ["uptime", "duration", "deadTime"])]
    ], protocolRows);
    renderTable(elements.arpTable, "ARP", [
      ["IP", (row) => valueFrom(row, ["ip", "address", "ipAddress"])], ["MAC", (row) => valueFrom(row, ["mac", "macAddress"] )], ["接口", (row) => valueFrom(row, ["interface", "port"])], ["年龄", (row) => valueFrom(row, ["age", "ageSeconds"])]
    ], arp);
    renderTable(elements.fdbTable, "MAC 地址表", [
      ["VLAN", (row) => valueFrom(row, ["vlan", "vlanId"])], ["MAC", (row) => valueFrom(row, ["mac", "macAddress"])], ["类型", (row) => valueFrom(row, ["type", "entryType"])], ["端口", (row) => valueFrom(row, ["interface", "port", "destination"])]
    ], fdb);
    renderTable(elements.opticsTable, "光模块", [
      ["接口", (row) => valueFrom(row, ["interface", "name", "port"])], ["类型", (row) => valueFrom(row, ["type", "media", "partNumber"])], ["厂商", (row) => valueFrom(row, ["vendor", "manufacturer"])], ["温度", (row) => valueFrom(row, ["temperature"])], ["TX", (row) => valueFrom(row, ["txPower"])], ["RX", (row) => valueFrom(row, ["rxPower"])], ["告警", (row) => asArray(row.alerts).join(", ") || "—"]
    ], optics);
    const poe = app.data.poe || {};
    elements.poeSummary.textContent = poe.supported === false ? "此型号或当前 EOS 未报告 PoE 数据。" : `PoE：${asArray(poe.ports).length} 个端口有采集记录。`;
    const integrations = app.data.integrations || {};
    const integrationRows = [["Syslog", integrations.syslog], ["sFlow", integrations.sflow], ["NetFlow / IPFIX", integrations.netflow], ["Streaming telemetry", integrations.telemetry]];
    elements.integrationsList.className = "integration-list";
    elements.integrationsList.innerHTML = integrationRows.map(([label, enabled]) => `<div class="integration-item"><span>${label}</span><strong data-enabled="${Boolean(enabled)}">${enabled ? "已配置" : "未配置"}</strong></div>`).join("");
  }

  function renderDiagnosticFields() {
    const commandId = elements.diagnosticCommand.value;
    elements.diagnosticParams.innerHTML = ["ping", "traceroute"].includes(commandId) ? `<label for="diagnosticTarget">目标 IP 地址</label><input id="diagnosticTarget" name="target" type="text" placeholder="192.0.2.1 或 2001:db8::1" required pattern="[A-Fa-f0-9:.]+" />` : "";
  }

  function renderChangeFields() {
    const definition = CHANGE_ACTIONS[elements.changeAction.value];
    elements.changeDescription.textContent = definition.description;
    elements.changeFields.innerHTML = definition.fields.map((item) => {
      const required = item.required ? "required" : "";
      if (item.type === "select") {
        return `<label for="change-${escapeHtml(item.name)}">${escapeHtml(item.label)}<select id="change-${escapeHtml(item.name)}" name="${escapeHtml(item.name)}" ${required}>${item.options.map(([value, label]) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join("")}</select></label>`;
      }
      const min = item.min === undefined ? "" : `min="${item.min}"`;
      const max = item.max === undefined ? "" : `max="${item.max}"`;
      return `<label for="change-${escapeHtml(item.name)}">${escapeHtml(item.label)}<input id="change-${escapeHtml(item.name)}" name="${escapeHtml(item.name)}" type="${escapeHtml(item.type)}" placeholder="${escapeHtml(item.placeholder)}" ${min} ${max} ${required} /></label>`;
    }).join("");
    invalidatePreview();
  }

  function resetPreview() {
    app.preview = null;
    elements.previewOutput.textContent = "选择变更并填写参数。";
    elements.previewExpiry.textContent = "尚未生成预览";
    elements.applyBar.hidden = true;
    elements.confirmApply.checked = false;
    elements.applyButton.disabled = true;
  }

  function invalidatePreview() {
    app.previewGeneration += 1;
    resetPreview();
  }

  function changeRequest() {
    const entries = [...new FormData(elements.changeForm).entries()].map(([name, value]) => [name, String(value)]);
    const action = entries.find(([name]) => name === "action")?.[1] || "";
    const params = Object.fromEntries(entries.filter(([name]) => name !== "action"));
    return { action, params, snapshot: JSON.stringify(entries) };
  }

  function previewExpiryMs(value) {
    if (!value) return 0;
    if (typeof value === "number") return value < 10_000_000_000 ? value * 1000 : value;
    const parsed = new Date(value).getTime();
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function setChangeRegionBusy(busy) {
    const region = elements.changeForm.closest(".change-layout");
    region?.setAttribute("aria-busy", String(busy));
    [...elements.changeForm.elements].forEach((control) => { control.disabled = busy; });
    elements.confirmApply.disabled = busy;
    elements.applyButton.disabled = busy || !app.preview || !elements.confirmApply.checked;
  }

  async function runDiagnostic(event) {
    event.preventDefault();
    const commandId = elements.diagnosticCommand.value;
    const target = $("diagnosticTarget")?.value.trim();
    setBusy(elements.diagnosticRun, true, "运行中");
    elements.diagnosticOutput.textContent = "正在执行预定义诊断…";
    try {
      const payload = await api("/api/diagnostics", { method: "POST", body: { commandId, params: target ? { target } : {} } });
      const output = typeof payload.output === "string" ? payload.output : JSON.stringify(payload.output ?? payload.result ?? payload, null, 2);
      elements.diagnosticOutput.textContent = output || "命令完成，没有文本输出。";
      elements.copyDiagnostic.disabled = false;
      toast("诊断已完成", "success");
    } catch (error) {
      elements.diagnosticOutput.textContent = `ERROR: ${error.message}`;
      elements.copyDiagnostic.disabled = true;
      toast(error.message, "error");
    } finally {
      setBusy(elements.diagnosticRun, false, "运行中");
    }
  }

  async function previewChange(event) {
    event.preventDefault();
    const request = changeRequest();
    const generation = ++app.previewGeneration;
    resetPreview();
    setBusy(elements.previewButton, true, "生成中");
    elements.previewOutput.textContent = "正在生成配置会话与差异…";
    try {
      const payload = await api("/api/config/preview", { method: "POST", body: { action: request.action, params: request.params } });
      if (generation !== app.previewGeneration || request.snapshot !== changeRequest().snapshot) return;
      const token = payload.previewToken || payload.preview_token;
      if (!token) throw new Error("服务端未返回 preview token。");
      app.preview = { token, action: request.action, snapshot: request.snapshot, expiresAt: payload.expiresAt || payload.expires_at || 0 };
      const commands = asArray(payload.commands).join("\n");
      const diff = payload.diff || "（运行配置未产生可显示的差异）";
      elements.previewOutput.textContent = `COMMANDS\n${commands || "—"}\n\nDIFF\n${diff}\n\nBASELINE\n${payload.baselineHash || payload.baseline_hash || "—"}`;
      elements.previewExpiry.textContent = app.preview.expiresAt ? `预览有效至 ${formatTime(app.preview.expiresAt)}` : "短期预览令牌已生成";
      elements.applyBar.hidden = false;
      elements.confirmApply.checked = false;
      elements.applyButton.disabled = true;
      toast("预览已生成，请核对差异", "success");
    } catch (error) {
      if (generation !== app.previewGeneration) return;
      resetPreview();
      elements.previewOutput.textContent = `ERROR: ${error.message}`;
      toast(error.message, "error");
    } finally {
      setBusy(elements.previewButton, false, "生成中");
    }
  }

  async function applyChange() {
    if (!app.preview || !elements.confirmApply.checked) return;
    if (app.preview.snapshot !== changeRequest().snapshot) {
      invalidatePreview();
      toast("变更参数已修改，请重新生成预览", "error");
      return;
    }
    if (previewExpiryMs(app.preview.expiresAt) && previewExpiryMs(app.preview.expiresAt) <= Date.now()) {
      invalidatePreview();
      toast("配置预览已过期，请重新生成", "error");
      return;
    }
    if (!isUnlocked()) {
      openUnlockDialog();
      toast("先解锁配置操作", "error");
      return;
    }
    const preview = app.preview;
    setBusy(elements.applyButton, true, "提交中");
    setChangeRegionBusy(true);
    try {
      const payload = await api("/api/config/apply", { method: "POST", body: { previewToken: preview.token } });
      const commands = asArray(payload.commands).join("\n");
      elements.previewOutput.textContent = `APPLIED\n${commands || preview.action}\n\n${payload.diff || ""}\n\n${payload.output || "配置已提交。"}`;
      elements.previewExpiry.textContent = "配置已提交";
      elements.applyBar.hidden = true;
      app.preview = null;
      app.previewGeneration += 1;
      toast("配置已提交", "success");
      refreshAll({ silent: true });
    } catch (error) {
      if (["preview_expired", "preview_not_found", "config_changed"].includes(error.code)) {
        invalidatePreview();
        elements.previewOutput.textContent = `ERROR: ${error.message}`;
      } else {
        elements.previewOutput.textContent += `\n\nERROR\n${error.message}`;
      }
      toast(error.message, "error");
    } finally {
      setBusy(elements.applyButton, false, "提交中");
      setChangeRegionBusy(false);
    }
  }

  function focusable(container) {
    return [...container.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])')].filter((item) => !item.hidden);
  }

  function trapFocus(container, event) {
    if (event.key !== "Tab") return;
    const items = focusable(container);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }

  function openUnlockDialog() {
    app.previousFocus = document.activeElement;
    elements.unlockError.hidden = true;
    elements.unlockPassword.value = "";
    elements.unlockLayer.hidden = false;
    syncOverlayState();
    window.setTimeout(() => elements.unlockPassword.focus(), 0);
  }

  function closeUnlockDialog() {
    elements.unlockLayer.hidden = true;
    elements.unlockPassword.value = "";
    syncOverlayState();
    app.previousFocus?.focus?.();
  }

  async function unlockSession(event) {
    event.preventDefault();
    const submit = elements.unlockForm.querySelector('button[type="submit"]');
    setBusy(submit, true, "验证中");
    try {
      const payload = await api("/api/auth/unlock", { method: "POST", body: { password: elements.unlockPassword.value } });
      const updated = sessionPayload(payload);
      app.session = {
        ...app.session,
        ...updated,
        authenticated: true,
        csrfToken: updated.csrfToken || app.session.csrfToken,
        user: updated.user || app.session.user
      };
      if (!app.session.unlockedUntil) app.session.unlockedUntil = Date.now() + 15 * 60_000;
      renderSession();
      closeUnlockDialog();
      toast("配置操作已解锁 15 分钟", "success");
    } catch (error) {
      elements.unlockError.textContent = error.message;
      elements.unlockError.hidden = false;
      elements.unlockPassword.select();
    } finally {
      setBusy(submit, false, "验证中");
    }
  }

  function stopTimers() {
    clearInterval(app.refreshTimer); clearInterval(app.lockTimer);
    app.refreshTimer = null; app.lockTimer = null;
    app.refreshController?.abort();
  }

  function scheduleTimers() {
    clearInterval(app.refreshTimer);
    const interval = Number(elements.refreshInterval.value);
    if (interval > 0) {
      app.refreshTimer = window.setInterval(() => {
        if (!document.hidden && !app.refreshPromise) refreshAll({ silent: true });
      }, interval);
    }
    clearInterval(app.lockTimer);
    app.lockTimer = window.setInterval(renderSession, 30_000);
  }

  async function bootstrap() {
    applyTheme(localStorage.getItem("arista-theme") || "dark");
    const savedInterval = localStorage.getItem("arista-refresh");
    if (savedInterval && [...elements.refreshInterval.options].some((option) => option.value === savedInterval)) elements.refreshInterval.value = savedInterval;
    elements.diagnosticCommand.innerHTML = DIAGNOSTICS.map(([value, label, description]) => `<option value="${value}">${escapeHtml(label)} — ${escapeHtml(description)}</option>`).join("");
    elements.changeAction.innerHTML = Object.entries(CHANGE_ACTIONS).map(([value, definition]) => `<option value="${value}">${escapeHtml(definition.label)}</option>`).join("");
    renderDiagnosticFields(); renderChangeFields();
    try {
      const payload = await api("/api/auth/session");
      app.session = sessionPayload(payload);
      if (!app.session.authenticated) return showLogin();
      showApp();
      await refreshAll({ silent: true });
    } catch (error) {
      if (error.status !== 401) showLogin(`无法读取会话：${error.message}`);
      else showLogin();
    }
  }

  function applyTheme(theme) {
    const next = theme === "light" ? "light" : "dark";
    document.body.dataset.theme = next;
    localStorage.setItem("arista-theme", next);
    elements.themeButton.setAttribute("aria-label", `切换为${next === "dark" ? "浅色" : "深色"}主题`);
    requestAnimationFrame(drawTrafficChart);
  }

  elements.loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = elements.loginForm.querySelector('button[type="submit"]');
    setBusy(submit, true, "登录中");
    elements.loginError.hidden = true;
    try {
      const payload = await api("/api/auth/login", { method: "POST", body: { username: elements.loginUsername.value.trim(), password: elements.loginPassword.value } });
      app.session = sessionPayload(payload);
      if (!app.session.authenticated) throw new Error("服务端未建立登录会话。");
      elements.loginPassword.value = "";
      showApp();
      await refreshAll({ silent: true });
    } catch (error) {
      elements.loginError.textContent = error.message;
      elements.loginError.hidden = false;
      elements.loginPassword.value = "";
      elements.loginPassword.focus();
    } finally {
      setBusy(submit, false, "登录中");
    }
  });

  document.querySelector(".primary-nav").addEventListener("click", (event) => {
    const link = event.target.closest("a[data-route]");
    if (!link) return;
    event.preventDefault(); routeTo(link.pathname);
  });
  window.addEventListener("popstate", () => routeTo(location.pathname, false));
  elements.refreshButton.addEventListener("click", () => refreshAll());
  elements.refreshInterval.addEventListener("change", () => { localStorage.setItem("arista-refresh", elements.refreshInterval.value); scheduleTimers(); });
  elements.themeButton.addEventListener("click", () => applyTheme(document.body.dataset.theme === "dark" ? "light" : "dark"));
  elements.logoutButton.addEventListener("click", async () => {
    elements.logoutButton.disabled = true;
    elements.logoutButton.setAttribute("aria-busy", "true");
    try {
      await api("/api/auth/logout", { method: "POST", body: {} });
      showLogin();
    } catch (error) {
      if (error.code === "authentication_required") showLogin();
      else toast(`退出失败：${error.message}`, "error");
    } finally {
      elements.logoutButton.disabled = false;
      elements.logoutButton.setAttribute("aria-busy", "false");
    }
  });
  elements.unlockButton.addEventListener("click", openUnlockDialog);
  elements.portSearch.addEventListener("input", renderPorts);
  elements.portFilter.addEventListener("change", renderPorts);
  elements.portGrid.addEventListener("click", (event) => openPortDrawer(app.portByKey.get(event.target.closest("[data-port-key]")?.dataset.portKey)));
  elements.drawerClose.addEventListener("click", closePortDrawer);
  elements.drawerBackdrop.addEventListener("click", closePortDrawer);
  elements.diagnosticCommand.addEventListener("change", renderDiagnosticFields);
  elements.diagnosticForm.addEventListener("submit", runDiagnostic);
  elements.copyDiagnostic.addEventListener("click", async () => { await navigator.clipboard.writeText(elements.diagnosticOutput.textContent); toast("诊断输出已复制", "success"); });
  elements.changeAction.addEventListener("change", renderChangeFields);
  elements.changeForm.addEventListener("input", (event) => { if (event.target !== elements.changeAction) invalidatePreview(); });
  elements.changeForm.addEventListener("change", (event) => { if (event.target !== elements.changeAction) invalidatePreview(); });
  elements.changeForm.addEventListener("submit", previewChange);
  elements.confirmApply.addEventListener("change", () => { elements.applyButton.disabled = !elements.confirmApply.checked || !app.preview; });
  elements.applyButton.addEventListener("click", applyChange);
  elements.unlockClose.addEventListener("click", closeUnlockDialog);
  elements.unlockLayer.addEventListener("click", (event) => { if (event.target === elements.unlockLayer) closeUnlockDialog(); });
  elements.unlockForm.addEventListener("submit", unlockSession);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      if (!elements.unlockLayer.hidden) closeUnlockDialog();
      else if (elements.portDrawer.classList.contains("open")) closePortDrawer();
    }
    if (!elements.unlockLayer.hidden) trapFocus(elements.unlockDialog, event);
    else if (elements.portDrawer.classList.contains("open")) trapFocus(elements.portDrawer, event);
  });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && app.session.authenticated && freshnessStatus() === "stale" && !app.refreshPromise) refreshAll({ silent: true }); });
  new ResizeObserver(() => requestAnimationFrame(drawTrafficChart)).observe(elements.trafficChart);

  bootstrap();
})();
</script>
  </body>
</html>
"""
# END GENERATED WEB ASSET


class Handler(BaseHTTPRequestHandler):
    cached_state = None
    cached_at = 0
    cache_lock = threading.RLock()
    session_cookie = "arista_session"

    def _deadline_timer(self, seconds):
        completed = threading.Event()

        def expire():
            if completed.is_set():
                return
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(float(seconds), expire)
        timer.daemon = True
        timer.start()
        return completed, timer

    def handle_one_request(self):
        """Bound the entire request-line/header phase, not only each recv call."""
        completed, timer = self._deadline_timer(HTTP_HEADER_TIMEOUT)
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                return
        except (OSError, TimeoutError):
            self.close_connection = True
            return
        finally:
            completed.set()
            timer.cancel()

        method_name = "do_" + self.command
        if not hasattr(self, method_name):
            self.send_error(501, "Unsupported method (%r)" % self.command)
            return
        try:
            getattr(self, method_name)()
            self.wfile.flush()
        except (OSError, TimeoutError):
            self.close_connection = True

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def request_id(self):
        if not hasattr(self, "_request_id"):
            self._request_id = secrets.token_hex(8)
        return self._request_id

    def _csp_hash(self, value):
        value = str(value or "").strip()
        if not re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", value):
            raise RuntimeError("Embedded asset CSP hash is missing or invalid.")
        return "'%s'" % value

    def send_security_headers(self):
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        csp = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; connect-src 'self'; style-src 'self' %s; script-src 'self' %s" % (self._csp_hash(WEB_STYLE_HASH), self._csp_hash(WEB_SCRIPT_HASH))
        self.send_header("Content-Security-Policy", csp)

    def send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-ID", self.request_id())
        self.send_security_headers()
        for name, value in (extra_headers or {}).items():
            self.send_header(str(name), str(value))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_html(self):
        body = INDEX_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-ID", self.request_id())
        self.send_security_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def read_json(self):
        if self.headers.get("Transfer-Encoding"):
            raise APIError(400, "unsupported_transfer_encoding", "Chunked request bodies are not supported.")
        raw_size = self.headers.get("Content-Length", "0") or "0"
        try:
            size = int(raw_size)
        except ValueError:
            raise APIError(400, "invalid_content_length", "Invalid Content-Length header.")
        if size < 0 or size > MAX_REQUEST_BODY:
            raise APIError(413, "request_too_large", "Request body is too large.")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if size and content_type != "application/json":
            raise APIError(415, "unsupported_media_type", "Content-Type must be application/json.")
        try:
            if size:
                completed, timer = self._deadline_timer(HTTP_BODY_TIMEOUT)
                try:
                    raw_bytes = self.rfile.read(size)
                finally:
                    completed.set()
                    timer.cancel()
                if len(raw_bytes) != size:
                    raise APIError(400, "incomplete_body", "Request body ended before Content-Length bytes were received.")
                raw = raw_bytes.decode("utf-8")
            else:
                raw = "{}"
        except UnicodeDecodeError:
            raise APIError(400, "invalid_json", "Request body must be UTF-8 JSON.")
        try:
            payload = json.loads(raw or "{}")
        except ValueError:
            raise APIError(400, "invalid_json", "Request body must be valid JSON.")
        if not isinstance(payload, dict):
            raise APIError(400, "invalid_json", "Request JSON must be an object.")
        return payload

    def cookie_token(self):
        try:
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
            morsel = cookie.get(self.session_cookie)
            return morsel.value if morsel else ""
        except Exception:
            return ""

    def current_session(self):
        token = self.cookie_token()
        return token, get_session(token)

    def require_auth(self):
        token, session = self.current_session()
        if not session:
            raise APIError(401, "authentication_required", "Authentication is required.")
        return token, session

    def require_csrf(self, session):
        if not session_csrf_valid(session, self.headers.get("X-CSRF-Token", "")):
            raise APIError(403, "csrf_failed", "CSRF validation failed.")

    def send_error_payload(self, exc):
        if isinstance(exc, APIError):
            status, code, message = exc.status, exc.code, exc.message
        elif isinstance(exc, ValueError):
            status, code, message = 400, "invalid_request", str(exc)
        elif isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
            status, code, message = 504, "operation_timeout", "The operation timed out."
        else:
            status, code, message = 500, "internal_error", "The request could not be completed."
            print("request %s failed: %s" % (self.request_id(), bounded_text(exc, 1024)))
        self.send_json(status, {"ok": False, "error": {"code": code, "message": message, "requestId": self.request_id()}})

    def do_GET(self):
        try:
            self.connection.settimeout(35)
            path = urlparse(self.path).path
            if path == "/healthz":
                self.send_json(200, {"ok": True, "version": APP_VERSION, "artifactSha": ARTIFACT_SHA})
                return
            if path == "/api/auth/session":
                _token, session = self.current_session()
                self.send_json(200, dict({"ok": True}, **session_payload(session)))
                return
            if path in ("/", "/ports", "/network", "/diagnostics", "/changes"):
                self.send_html()
                return
            self.require_auth()
            if path == "/api/state":
                with Handler.cache_lock:
                    state = Handler.cached_state
                    stale = not state or time.time() - Handler.cached_at > 60
                if stale:
                    fresh = collect_state("core")
                    with Handler.cache_lock:
                        Handler.cached_state = fresh if not Handler.cached_state else merge_state(Handler.cached_state, fresh)
                        Handler.cached_at = time.time()
                        state = Handler.cached_state
                self.send_json(200, {"ok": True, "state": state})
                return
            raise APIError(404, "not_found", "Not found.")
        except Exception as exc:
            self.send_error_payload(exc)

    def _login(self):
        client = self.client_address[0]
        if not auth_attempt_allowed(client):
            append_audit({"event": "login_rate_limited", "client": client, "requestId": self.request_id()})
            raise APIError(429, "login_rate_limited", "Too many failed login attempts. Try again later.")
        payload = self.read_json()
        username = str(payload.get("username") or "")
        password = str(payload.get("password") or "")
        if len(username) > 64 or len(password) > 1024 or not verify_password(username, password):
            register_auth_failure(client)
            append_audit({"event": "login_failed", "client": client, "user": username[:64], "requestId": self.request_id()})
            raise APIError(401, "invalid_credentials", "Invalid username or password.")
        clear_auth_failures(client)
        token, session = create_session(username)
        cookie = "%s=%s; Path=/; Max-Age=%s; Secure; HttpOnly; SameSite=Strict" % (self.session_cookie, token, SESSION_TTL_SECONDS)
        append_audit({"event": "login_succeeded", "client": client, "user": username, "requestId": self.request_id()})
        self.send_json(200, dict({"ok": True}, **session_payload(session)), {"Set-Cookie": cookie})

    def _logout(self, token, session):
        self.require_csrf(session)
        with _SESSION_LOCK:
            _SESSIONS.pop(token, None)
        append_audit({"event": "logout", "client": self.client_address[0], "user": session.get("user"), "requestId": self.request_id()})
        cookie = "%s=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict" % self.session_cookie
        self.send_json(200, {"ok": True, "authenticated": False, "user": None, "csrfToken": None, "unlockedUntil": 0}, {"Set-Cookie": cookie})

    def _unlock(self, token, session):
        self.require_csrf(session)
        rate_key = "unlock:%s" % self.client_address[0]
        if not auth_attempt_allowed(rate_key):
            raise APIError(429, "unlock_rate_limited", "Too many failed unlock attempts. Try again later.")
        payload = self.read_json()
        password = str(payload.get("password") or "")
        if len(password) > 1024 or not verify_password(session.get("user"), password):
            register_auth_failure(rate_key)
            append_audit({"event": "unlock_failed", "client": self.client_address[0], "user": session.get("user"), "requestId": self.request_id()})
            raise APIError(401, "invalid_credentials", "Invalid username or password.")
        clear_auth_failures(rate_key)
        unlocked_until = time.time() + UNLOCK_TTL_SECONDS
        with _SESSION_LOCK:
            current = _SESSIONS.get(token)
            if not current:
                raise APIError(401, "authentication_required", "Authentication is required.")
            current["unlockedUntil"] = unlocked_until
            session = dict(current)
        append_audit({"event": "operations_unlocked", "client": self.client_address[0], "user": session.get("user"), "until": int(unlocked_until * 1000), "requestId": self.request_id()})
        self.send_json(200, dict({"ok": True}, **session_payload(session)))

    def _config_preview(self, session_token, session):
        payload = self.read_json()
        action = str(payload.get("action") or "")
        commands = build_config_action(action, payload.get("params") or {})
        if not _CONFIG_LOCK.acquire(timeout=3):
            raise APIError(409, "config_busy", "Another configuration operation is in progress.")
        try:
            before = get_running_config(timeout=25)
            baseline_hash = config_hash(before)
            diff = run_config_session_preview(commands)
            preview_token, preview = store_preview(session_token, action, commands, baseline_hash, diff)
        finally:
            _CONFIG_LOCK.release()
        append_audit({"event": "config_preview", "client": self.client_address[0], "user": session.get("user"), "action": action, "commands": commands, "baselineHash": baseline_hash, "requestId": self.request_id()})
        self.send_json(
            200,
            {
                "ok": True,
                "previewToken": preview_token,
                "baselineHash": baseline_hash,
                "commands": commands,
                "diff": diff,
                "expiresAt": int(preview["expiresAt"] * 1000),
            },
        )

    def _config_apply(self, session_token, session):
        if not session_is_unlocked(session):
            raise APIError(403, "operations_locked", "Re-enter your password to unlock configuration changes.")
        payload = self.read_json()
        preview_token = str(payload.get("previewToken") or "")
        if not preview_token:
            raise ValueError("previewToken is required.")
        if not _CONFIG_LOCK.acquire(timeout=3):
            raise APIError(409, "config_busy", "Another configuration operation is in progress.")
        preview = None
        verification_error = None
        try:
            preview = take_preview(preview_token, session_token)
            before = get_running_config(timeout=25)
            current_hash = config_hash(before)
            if not hmac.compare_digest(current_hash, preview["baselineHash"]):
                append_audit({"event": "config_conflict", "client": self.client_address[0], "user": session.get("user"), "action": preview.get("action"), "baselineHash": preview.get("baselineHash"), "currentHash": current_hash, "requestId": self.request_id()})
                raise APIError(409, "config_changed", "Running configuration changed after preview. Generate a new preview.")
            output = run_config_session_apply(preview["commands"], expected_baseline_hash=preview["baselineHash"])
            try:
                after = get_running_config(timeout=25)
                diff = config_diff(before, after)
            except Exception as exc:
                verification_error = exc
                diff = None
        except Exception:
            raise
        finally:
            _CONFIG_LOCK.release()
        with Handler.cache_lock:
            Handler.cached_state = None
            Handler.cached_at = 0
        with _COLLECTION_CONDITION:
            _COLLECTION_RESULTS.clear()
        if verification_error is not None:
            append_audit({"event": "config_committed_unverified", "client": self.client_address[0], "user": session.get("user"), "action": preview.get("action"), "commands": preview.get("commands"), "requestId": self.request_id(), "error": bounded_text(verification_error, 512)})
            self.send_json(202, {"ok": True, "committed": True, "verified": False, "action": preview.get("action"), "commands": preview.get("commands"), "diff": None, "output": output, "warning": "EOS committed the session, but post-commit verification failed. Inspect the running configuration before another change."})
            return
        append_audit({"event": "config_committed", "client": self.client_address[0], "user": session.get("user"), "action": preview.get("action"), "commands": preview.get("commands"), "diff": diff, "requestId": self.request_id()})
        self.send_json(200, {"ok": True, "committed": True, "verified": True, "action": preview.get("action"), "commands": preview.get("commands"), "diff": diff, "output": output})

    def do_POST(self):
        path = urlparse(self.path).path
        session = None
        try:
            self.connection.settimeout(45)
            if path == "/api/auth/login":
                self._login()
                return
            token, session = self.require_auth()
            if path in ("/api/command", "/api/config"):
                raise APIError(410, "endpoint_removed", "This endpoint has been removed. Use the structured API.")
            if path == "/api/auth/logout":
                self._logout(token, session)
                return
            if path == "/api/auth/unlock":
                self._unlock(token, session)
                return
            self.require_csrf(session)
            if path == "/api/refresh":
                payload = self.read_json()
                scope = str(payload.get("scope") or "full").lower()
                if scope not in ("core", "metrics", "health", "tables", "discovery", "optics", "protocols", "extras", "full"):
                    raise ValueError("Unknown refresh scope.")
                state = collect_state(scope)
                with Handler.cache_lock:
                    Handler.cached_state = state if scope == "full" else merge_state(Handler.cached_state, state)
                    Handler.cached_at = time.time()
                    response_state = Handler.cached_state
                self.send_json(200, {"ok": True, "state": response_state})
                return
            if path == "/api/diagnostics":
                payload = self.read_json()
                command_id = str(payload.get("commandId") or "")
                command = build_diagnostic_command(command_id, payload.get("params") or {})
                output = run_read_command(command, timeout=25)
                append_audit({"event": "diagnostic", "client": self.client_address[0], "user": session.get("user"), "commandId": command_id, "requestId": self.request_id()})
                self.send_json(200, {"ok": True, "commandId": command_id, "output": output})
                return
            if path == "/api/config/preview":
                self._config_preview(token, session)
                return
            if path == "/api/config/apply":
                self._config_apply(token, session)
                return
            raise APIError(404, "not_found", "Not found.")
        except Exception as exc:
            if path != "/api/auth/login":
                event = "config_apply_failed" if path == "/api/config/apply" else "request_failed"
                append_audit({
                    "event": event,
                    "client": self.client_address[0],
                    "user": (session or {}).get("user"),
                    "path": path,
                    "requestId": self.request_id(),
                    "code": getattr(exc, "code", "invalid_request" if isinstance(exc, ValueError) else "internal_error"),
                    "error": bounded_text(exc, 512),
                })
            self.send_error_payload(exc)


def main():
    global _AUTH_RECORD, APP_VERSION, ARTIFACT_SHA
    parser = argparse.ArgumentParser(description="On-box web console for Arista DCS-7050QX-32S-F.")
    parser.add_argument("--host", default=os.environ.get("WEB_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("WEB_PORT", "2480")))
    parser.add_argument("--daemon", action="store_true", help="Run in the background on EOS.")
    parser.add_argument("--log", default="/mnt/flash/arista7050_web.log")
    parser.add_argument("--tls-cert", default=os.environ.get("WEB_TLS_CERT", "/mnt/flash/arista7050_web.crt"))
    parser.add_argument("--tls-key", default=os.environ.get("WEB_TLS_KEY", "/mnt/flash/arista7050_web.key"))
    parser.add_argument("--auth-config", default=os.environ.get("WEB_AUTH_CONFIG", "/mnt/flash/arista7050_web_auth.json"))
    parser.add_argument("--init-auth-config", metavar="PATH", help="Create a PBKDF2 authentication config, then exit.")
    parser.add_argument("--auth-user", default="admin", help="Username stored by --init-auth-config.")
    parser.add_argument("--pid-file", default=os.environ.get("WEB_PID_FILE", "/mnt/flash/arista7050_web.pid"))
    parser.add_argument("--version", dest="app_version", default=APP_VERSION)
    parser.add_argument("--artifact-sha", default=ARTIFACT_SHA)
    parser.add_argument("--check-config", action="store_true", help="Validate auth and TLS files, then exit.")
    parser.add_argument("--smoke-url", help="Interactively verify candidate HTTPS login, session, state, CSRF, and logout, then exit.")
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{64}", str(WEB_ASSET_SHA or "")):
        parser.error("Embedded web asset metadata is missing or invalid; rebuild the on-box artifact.")
    for asset_hash in (WEB_STYLE_HASH, WEB_SCRIPT_HASH):
        if not re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", str(asset_hash or "")):
            parser.error("Embedded CSP hashes are missing or invalid; rebuild the on-box artifact.")

    if args.init_auth_config:
        password = getpass.getpass("Dashboard password: ")
        confirmation = getpass.getpass("Confirm dashboard password: ")
        if not hmac.compare_digest(password.encode("utf-8"), confirmation.encode("utf-8")):
            parser.error("Passwords do not match.")
        init_auth_config(args.init_auth_config, args.auth_user, password)
        print("Authentication config initialized at %s" % args.init_auth_config)
        return

    if args.smoke_url:
        try:
            auth_record, _tls_context = validate_runtime_config(args.auth_config, args.tls_cert, args.tls_key)
        except Exception as exc:
            parser.error(str(exc))
        password = getpass.getpass("Dashboard password for candidate smoke test: ")
        try:
            smoke_test_authenticated_api(args.smoke_url, args.auth_user, password, auth_record)
        except Exception as exc:
            parser.error(str(exc))
        finally:
            password = None
        print("Candidate authenticated API smoke test passed.")
        return

    try:
        auth_record, tls_context = validate_runtime_config(args.auth_config, args.tls_cert, args.tls_key)
    except Exception as exc:
        parser.error(str(exc))
    if args.check_config:
        print("Configuration valid: auth, TLS certificate, and TLS private key loaded.")
        return

    _AUTH_RECORD = auth_record
    APP_VERSION = str(args.app_version or "dev").strip()
    ARTIFACT_SHA = str(args.artifact_sha or "unknown").strip()
    if not re.fullmatch(r"[A-Za-z0-9_./:@+-]{1,128}", APP_VERSION):
        parser.error("--version contains invalid characters.")
    if not re.fullmatch(r"[A-Za-z0-9_./:@+-]{1,128}", ARTIFACT_SHA):
        parser.error("--artifact-sha contains invalid characters.")

    if args.daemon:
        if os.fork() > 0:
            print("Arista 7050QX web console launch requested.")
            return
        os.setsid()
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        if os.fork() > 0:
            os._exit(0)
        os.chdir("/")
        sys.stdin.close()
        rotate_file(args.log, max_bytes=2 * 1024 * 1024, backups=2)
        log = open(args.log, "a", buffering=1)
        try:
            os.chmod(args.log, 0o600)
        except OSError:
            pass
        os.dup2(log.fileno(), sys.stdout.fileno())
        os.dup2(log.fileno(), sys.stderr.fileno())

    server = BoundedThreadingHTTPServer((args.host, args.port), Handler, tls_context)
    write_pid_file(args.pid_file, os.getpid())
    stop_event = threading.Event()
    sampler = start_history_sampler(stop_event)
    print("Arista 7050QX on-box web console listening on https://%s:%s" % (args.host, args.port))
    print("Version %s / artifact %s" % (APP_VERSION, ARTIFACT_SHA))
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def stop_server(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop_server)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        sampler.join(timeout=2)
        server.server_close()
        signal.signal(signal.SIGTERM, previous_sigterm)
        try:
            with open(args.pid_file, "r", encoding="ascii") as handle:
                owned_pid = int(handle.read().strip())
            if owned_pid == os.getpid():
                os.unlink(args.pid_file)
        except (OSError, ValueError):
            pass


if __name__ == "__main__":
    main()
