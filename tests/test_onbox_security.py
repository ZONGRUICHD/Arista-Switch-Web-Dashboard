import http.client
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "onbox" / "arista7050_web.py"


def load_module():
    spec = importlib.util.spec_from_file_location("arista7050_web_security", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


web = load_module()


class PasswordAndSessionTests(unittest.TestCase):
    def setUp(self):
        web._SESSIONS.clear()
        web._PREVIEWS.clear()
        web._AUTH_FAILURES.clear()

    def test_password_record_is_salted_and_never_contains_plaintext(self):
        record = web.password_record("admin", "correct horse", salt=b"s" * 32, iterations=100000)
        serialized = json.dumps(record)
        self.assertNotIn("correct horse", serialized)
        self.assertTrue(web.verify_password("admin", "correct horse", record))
        self.assertFalse(web.verify_password("admin", "wrong", record))
        self.assertFalse(web.verify_password("other", "correct horse", record))

    def test_session_csrf_expiry_and_unlock_state(self):
        token, session = web.create_session("admin", now=100)
        self.assertTrue(web.session_csrf_valid(session, session["csrfToken"]))
        self.assertFalse(web.session_csrf_valid(session, "wrong"))
        self.assertIsNotNone(web.get_session(token, now=100 + web.SESSION_TTL_SECONDS - 1))
        self.assertIsNone(web.get_session(token, now=100 + web.SESSION_TTL_SECONDS + 1))

    def test_preview_is_one_time_scoped_and_expires(self):
        token, preview = web.store_preview("session-a", "create_vlan", ["vlan 10"], "base", "diff", now=100)
        self.assertEqual(preview["baselineHash"], "base")
        self.assertEqual(web.take_preview(token, "session-a", now=101)["commands"], ["vlan 10"])
        with self.assertRaises(web.APIError) as reused:
            web.take_preview(token, "session-a", now=102)
        self.assertEqual(reused.exception.code, "preview_expired")

        expired, _ = web.store_preview("session-a", "create_vlan", ["vlan 20"], "base", "diff", now=100)
        with self.assertRaises(web.APIError) as error:
            web.take_preview(expired, "session-a", now=100 + web.PREVIEW_TTL_SECONDS + 1)
        self.assertEqual(error.exception.code, "preview_expired")


class CommandAndValidationTests(unittest.TestCase):
    def test_raw_command_injection_is_rejected(self):
        payloads = (
            "show version\nconfigure terminal\ninterface Ethernet1\nshutdown",
            "show version; reload now",
            "show version > /mnt/flash/output",
            "show version | include x | redirect flash:test",
            "show version | include x | bash",
            "ping 192.0.2.1 -c 1000000",
            "more /etc/shadow",
            "dir /mnt/flash",
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertFalse(web.is_safe_command(payload))

    def test_safe_command_grammar_allows_only_bounded_read_modifiers(self):
        allowed = (
            "show version",
            "show interfaces status | json",
            "show logging | include Ethernet1 down",
            "show ip route | count",
            "ping 192.0.2.1",
            "traceroute6 2001:db8::1",
        )
        for command in allowed:
            with self.subTest(command=command):
                self.assertTrue(web.is_safe_command(command))

    def test_diagnostics_are_registry_backed_and_targets_are_strict(self):
        self.assertEqual(web.build_diagnostic_command("version"), "show version")
        self.assertEqual(web.build_diagnostic_command("ping", {"target": "192.0.2.10"}), "ping 192.0.2.10")
        with self.assertRaises(ValueError):
            web.build_diagnostic_command("ping", {"target": "example.com"})
        with self.assertRaises(ValueError):
            web.build_diagnostic_command("unknown", {})

    def test_ip_asn_and_config_validation(self):
        for invalid in ("999.999.999.999", "192.168.1", "example.com", "::1"):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                web.safe_ipv4(invalid)
        self.assertEqual(web.safe_asn("4294967295"), "4294967295")
        for invalid in ("0", "4294967296", "1.2"):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                web.safe_asn(invalid)
        with self.assertRaises(ValueError):
            web.build_config_action("bgp_neighbor", {"asn": "4294967296", "neighbor": "192.0.2.1", "remoteAs": "64512"})

    def test_config_hash_normalizes_line_endings(self):
        self.assertEqual(web.config_hash("a\r\nb\r\n"), web.config_hash("a\nb\n"))

    def test_alert_scopes_merge_without_overwriting_core_alerts(self):
        core = {"alertScopes": {"core": [{"severity": "warning", "title": "port", "message": "down"}]}}
        health = {"alertScopes": {"health": [{"severity": "critical", "title": "psu", "message": "loss"}]}}
        merged = web.merge_state(core, health)
        self.assertEqual({item["title"] for item in merged["alerts"]}, {"port", "psu"})

    def test_eapi_batch_failure_is_not_retried_per_command(self):
        with mock.patch.object(web, "run_eapi", side_effect=RuntimeError("down")) as run_eapi:
            result = web.run_eapi_json_map(["show version", "show hostname", "show uptime"])
        self.assertEqual(run_eapi.call_count, 1)
        self.assertEqual(result, {"show version": {}, "show hostname": {}, "show uptime": {}})

    def test_bounded_subprocess_rejects_output_before_returning_it(self):
        command = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 4096)"]
        with self.assertRaisesRegex(RuntimeError, "64-byte limit"):
            web.run_bounded_process(command, timeout=5, max_output=64)

        small = web.run_bounded_process(
            [sys.executable, "-c", "import sys; sys.stdout.write('out'); sys.stderr.write('err')"],
            timeout=5,
            max_output=64,
        )
        self.assertEqual(small.returncode, 0)
        self.assertEqual(small.stdout, "out")
        self.assertEqual(small.stderr, "err")

    def test_missing_health_samples_remain_unknown(self):
        environment = web.parse_environment("")
        self.assertIsNone(environment["temperature"])
        self.assertEqual(environment["fanStatus"], "UNKNOWN")
        self.assertEqual(environment["psuStatus"], "UNKNOWN")

        text_health = web.parse_system_health("", "", "")
        json_health = web.parse_system_health_json({}, "", {})
        for health in (text_health, json_health):
            with self.subTest(health=health):
                self.assertIsNone(health["cpu"])
                self.assertIsNone(health["memory"])
                self.assertIsNone(health["temperature"])
                self.assertEqual(health["fanStatus"], "UNKNOWN")
                self.assertEqual(health["psuStatus"], "UNKNOWN")


class ConfigurationSessionTests(unittest.TestCase):
    COMMANDS = ["interface Ethernet1", "shutdown"]

    @staticmethod
    def fixed_session_name(prefix="web"):
        return "%s-session" % prefix

    def test_preview_success_always_aborts_session(self):
        scripts = []

        def runner(script, timeout):
            scripts.append((script, timeout))
            return "candidate diff" if "show session-config diffs" in script else "OK"

        with mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name), mock.patch.object(
            web, "run_eos_script", side_effect=runner
        ):
            result = web.run_config_session_preview(self.COMMANDS)

        self.assertEqual(result, "candidate diff")
        self.assertEqual(
            scripts,
            [
                ("configure session preview-session\ninterface Ethernet1\nshutdown\nshow session-config diffs", 30),
                ("configure session preview-session abort", 10),
            ],
        )

    def test_preview_cli_error_aborts_before_raising(self):
        scripts = []

        def runner(script, timeout):
            scripts.append(script)
            return "% Invalid input" if "show session-config diffs" in script else "OK"

        with mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name), mock.patch.object(
            web, "run_eos_script", side_effect=runner
        ):
            with self.assertRaisesRegex(RuntimeError, "rejected the configuration preview"):
                web.run_config_session_preview(self.COMMANDS)

        self.assertEqual(scripts[-1], "configure session preview-session abort")

    def test_preview_timeout_aborts_before_propagating_timeout(self):
        scripts = []

        def runner(script, timeout):
            scripts.append(script)
            if "show session-config diffs" in script:
                raise subprocess.TimeoutExpired(script, timeout)
            return "OK"

        with mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name), mock.patch.object(
            web, "run_eos_script", side_effect=runner
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                web.run_config_session_preview(self.COMMANDS)

        self.assertEqual(scripts[-1], "configure session preview-session abort")

    def test_preview_abort_failure_is_not_hidden(self):
        def runner(script, timeout):
            return "% Error: abort failed" if script.endswith(" abort") else "candidate diff"

        with mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name), mock.patch.object(
            web, "run_eos_script", side_effect=runner
        ):
            with self.assertRaisesRegex(RuntimeError, "failed to abort configuration session"):
                web.run_config_session_preview(self.COMMANDS)

    def test_apply_success_uses_lock_continue_then_commit_and_unlock(self):
        scripts = []

        def runner(script, timeout):
            scripts.append((script, timeout))
            if "show session-config diffs" in script:
                return "candidate diff"
            if " commit" in script:
                return "commit complete"
            return "OK"

        baseline = "hostname leaf1"
        with mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name), mock.patch.object(
            web, "run_eos_script", side_effect=runner
        ), mock.patch.object(web, "get_running_config", return_value=baseline):
            result = web.run_config_session_apply(self.COMMANDS, expected_baseline_hash=web.config_hash(baseline))

        self.assertIn("commit complete", result)
        self.assertEqual(
            scripts,
            [
                ("configure lock transaction lock-session arista-dashboard", 10),
                (
                    "configure lock continue transaction lock-session arista-dashboard\n"
                    "configure session apply-session\ninterface Ethernet1\nshutdown\nshow session-config diffs",
                    30,
                ),
                (
                    "configure lock continue transaction lock-session arista-dashboard\n"
                    "configure session apply-session commit",
                    20,
                ),
                (
                    "configure lock continue transaction lock-session arista-dashboard\n"
                    "configure unlock transaction lock-session arista-dashboard",
                    10,
                ),
            ],
        )
        self.assertFalse(any(" abort" in script for script, _timeout in scripts))

    def test_write_memory_error_is_reported_and_lock_is_released(self):
        scripts = []

        def runner(script, timeout):
            scripts.append((script, timeout))
            if script.endswith("write memory"):
                return "% Error: flash write failed"
            return "OK"

        with mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name), mock.patch.object(
            web, "run_eos_script", side_effect=runner
        ):
            with self.assertRaisesRegex(RuntimeError, "failed to save"):
                web.run_config_session_apply(["write memory"])

        self.assertEqual(scripts[0], ("configure lock transaction lock-session arista-dashboard", 10))
        self.assertEqual(
            scripts[1],
            (
                "configure lock continue transaction lock-session arista-dashboard\nwrite memory",
                45,
            ),
        )
        self.assertTrue(scripts[-1][0].endswith("configure unlock transaction lock-session arista-dashboard"))

    def test_write_memory_rechecks_baseline_under_lock(self):
        scripts = []

        def runner(script, timeout):
            scripts.append((script, timeout))
            return "OK"

        with mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name), mock.patch.object(
            web, "run_eos_script", side_effect=runner
        ), mock.patch.object(web, "get_running_config", return_value="hostname changed"):
            with self.assertRaises(web.APIError) as error:
                web.run_config_session_apply(
                    ["write memory"],
                    expected_baseline_hash=web.config_hash("hostname previewed"),
                )

        self.assertEqual(error.exception.code, "config_changed")
        self.assertFalse(any(script.endswith("write memory") for script, _timeout in scripts))
        self.assertTrue(scripts[-1][0].endswith("configure unlock transaction lock-session arista-dashboard"))

    def test_apply_stage_failure_aborts_under_lock_then_releases_lock(self):
        scripts = []

        def runner(script, timeout):
            scripts.append(script)
            if "show session-config diffs" in script:
                return "% Invalid input"
            return "OK"

        with mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name), mock.patch.object(
            web, "run_eos_script", side_effect=runner
        ):
            with self.assertRaisesRegex(RuntimeError, "rejected the configuration session"):
                web.run_config_session_apply(self.COMMANDS)

        self.assertIn(
            "configure lock continue transaction lock-session arista-dashboard\nconfigure session apply-session abort",
            scripts,
        )
        self.assertTrue(scripts[-1].endswith("configure unlock transaction lock-session arista-dashboard"))
        self.assertFalse(any(" apply-session commit" in script for script in scripts))

    def test_apply_baseline_conflict_aborts_without_commit(self):
        scripts = []

        def runner(script, timeout):
            scripts.append(script)
            return "candidate diff" if "show session-config diffs" in script else "OK"

        with mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name), mock.patch.object(
            web, "run_eos_script", side_effect=runner
        ), mock.patch.object(web, "get_running_config", return_value="hostname changed"):
            with self.assertRaises(web.APIError) as error:
                web.run_config_session_apply(self.COMMANDS, expected_baseline_hash=web.config_hash("hostname original"))

        self.assertEqual(error.exception.code, "config_changed")
        self.assertTrue(any("apply-session abort" in script for script in scripts))
        self.assertFalse(any("apply-session commit" in script for script in scripts))
        self.assertTrue(scripts[-1].endswith("configure unlock transaction lock-session arista-dashboard"))

    def _run_commit_exception(self, status):
        scripts = []

        def runner(script, timeout):
            scripts.append(script)
            if "show session-config diffs" in script:
                return "candidate diff"
            if " apply-session commit" in script:
                raise TimeoutError("commit response interrupted")
            return "OK"

        patches = (
            mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name),
            mock.patch.object(web, "run_eos_script", side_effect=runner),
            mock.patch.object(web, "_configuration_session_status", return_value=status),
        )
        with patches[0], patches[1], patches[2] as classifier:
            if status == "committed":
                result = web.run_config_session_apply(self.COMMANDS)
                error = None
            else:
                try:
                    web.run_config_session_apply(self.COMMANDS)
                except Exception as exc:  # asserted by each caller
                    result = None
                    error = exc
                else:
                    self.fail("commit exception unexpectedly succeeded")
        return result, error, scripts, classifier

    def test_commit_exception_classified_committed_does_not_replay_or_abort(self):
        result, error, scripts, classifier = self._run_commit_exception("committed")
        self.assertIsNone(error)
        self.assertIn("Commit completed; the CLI response was interrupted.", result)
        classifier.assert_called_once_with("apply-session")
        self.assertEqual(sum("apply-session commit" in script for script in scripts), 1)
        self.assertFalse(any("apply-session abort" in script for script in scripts))
        self.assertTrue(scripts[-1].endswith("configure unlock transaction lock-session arista-dashboard"))

    def test_commit_exception_classified_pending_aborts_once_without_replay(self):
        _result, error, scripts, classifier = self._run_commit_exception("pending")
        self.assertIsInstance(error, TimeoutError)
        classifier.assert_called_once_with("apply-session")
        self.assertEqual(sum("apply-session commit" in script for script in scripts), 1)
        self.assertEqual(sum("apply-session abort" in script for script in scripts), 1)
        self.assertTrue(scripts[-1].endswith("configure unlock transaction lock-session arista-dashboard"))

    def test_commit_exception_classified_unknown_never_replays_or_aborts(self):
        _result, error, scripts, classifier = self._run_commit_exception("unknown")
        self.assertIsInstance(error, web.APIError)
        self.assertEqual(error.code, "commit_outcome_unknown")
        classifier.assert_called_once_with("apply-session")
        self.assertEqual(sum("apply-session commit" in script for script in scripts), 1)
        self.assertFalse(any("apply-session abort" in script for script in scripts))
        self.assertTrue(scripts[-1].endswith("configure unlock transaction lock-session arista-dashboard"))

    def test_apply_abort_failure_is_reported_and_lock_is_still_released(self):
        scripts = []

        def runner(script, timeout):
            scripts.append(script)
            if "show session-config diffs" in script:
                raise RuntimeError("stage failed")
            if "apply-session abort" in script:
                return "% Error: abort failed"
            return "OK"

        with mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name), mock.patch.object(
            web, "run_eos_script", side_effect=runner
        ):
            with self.assertRaisesRegex(RuntimeError, "could not be aborted"):
                web.run_config_session_apply(self.COMMANDS)

        self.assertEqual(sum("apply-session abort" in script for script in scripts), 1)
        self.assertTrue(scripts[-1].endswith("configure unlock transaction lock-session arista-dashboard"))

    def test_session_classifier_ignores_adjacent_session_states(self):
        outputs = [
            "other completed user\napply-session pending user\nnext committed user",
            "previous pending user\napply-session committed user\nnext pending user",
        ]
        with mock.patch.object(web, "run_eos_script", side_effect=outputs):
            self.assertEqual(web._configuration_session_status("apply-session"), "pending")
            self.assertEqual(web._configuration_session_status("apply-session"), "committed")

    def test_config_lock_acquire_failure_stops_before_stage_or_release(self):
        scripts = []

        def runner(script, timeout):
            scripts.append(script)
            return "% Configuration lock is held"

        with mock.patch.object(web, "make_config_session_name", side_effect=self.fixed_session_name), mock.patch.object(
            web, "run_eos_script", side_effect=runner
        ):
            with self.assertRaises(web.APIError) as error:
                web.run_config_session_apply(self.COMMANDS)

        self.assertEqual(error.exception.code, "config_locked")
        self.assertEqual(scripts, ["configure lock transaction lock-session arista-dashboard"])


class CandidateSmokeHelperTests(unittest.TestCase):
    class FakeResponse:
        def __init__(self, payload, status=200):
            self.payload = payload
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self, limit=-1):
            return json.dumps(self.payload).encode("utf-8")[:limit]

    class FakeOpener:
        def __init__(self):
            self.requests = []

        def open(self, request, timeout):
            self.requests.append((request, timeout))
            path = request.full_url.split(":2481", 1)[1]
            if path == "/api/auth/login":
                return CandidateSmokeHelperTests.FakeResponse({"authenticated": True, "csrfToken": "csrf-token"})
            if path == "/api/state":
                return CandidateSmokeHelperTests.FakeResponse({"state": {"device": {"hostname": "leaf1"}}})
            if path == "/api/auth/logout":
                return CandidateSmokeHelperTests.FakeResponse({"ok": True})
            raise AssertionError("unexpected smoke request %s" % path)

    def test_smoke_helper_exercises_login_state_csrf_logout(self):
        opener = self.FakeOpener()
        record = {"not": "used because verification is mocked"}
        with mock.patch.object(web, "verify_password", return_value=True) as verify, mock.patch.object(
            web.urllib.request, "build_opener", return_value=opener
        ):
            self.assertTrue(web.smoke_test_authenticated_api("https://127.0.0.1:2481", "admin", "secret", record))

        verify.assert_called_once_with("admin", "secret", record)
        self.assertEqual([request.method for request, _timeout in opener.requests], ["POST", "GET", "POST"])
        self.assertEqual(
            [request.full_url.rsplit(":2481", 1)[1] for request, _timeout in opener.requests],
            ["/api/auth/login", "/api/state", "/api/auth/logout"],
        )
        self.assertIsNone(opener.requests[1][0].get_header("X-csrf-token"))
        self.assertEqual(opener.requests[2][0].get_header("X-csrf-token"), "csrf-token")

    def test_smoke_helper_rejects_non_loopback_or_non_https_targets(self):
        with mock.patch.object(web, "verify_password", return_value=True):
            for url in ("http://127.0.0.1:2481", "https://192.168.0.248:2481", "https://127.0.0.1:0"):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    web.smoke_test_authenticated_api(url, "admin", "secret", {})


class HistoryPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.original = {
            "HISTORY_FILE": web.HISTORY_FILE,
            "LEGACY_HISTORY_FILE": web.LEGACY_HISTORY_FILE,
            "AUDIT_FILE": web.AUDIT_FILE,
        }
        web.HISTORY_FILE = str(root / "history.jsonl")
        web.LEGACY_HISTORY_FILE = str(root / "history.json")
        web.AUDIT_FILE = str(root / "audit.jsonl")
        web._TRAFFIC_HISTORY = None
        web._PORT_HISTORY = {}
        web._HISTORY_ACTIVE_LINES = 0

    def tearDown(self):
        for name, value in self.original.items():
            setattr(web, name, value)
        web._TRAFFIC_HISTORY = None
        web._PORT_HISTORY = {}
        web._HISTORY_ACTIVE_LINES = 0
        self.tempdir.cleanup()

    def test_legacy_json_migrates_and_new_samples_append(self):
        legacy = {
            "traffic": [{"time": 1_000, "rxMbps": 1, "txMbps": 2, "totalMbps": 3}],
            "ports": {"Ethernet1": [{"time": 1_000, "rxMbps": 1, "txMbps": 2, "errors": 0}]},
        }
        Path(web.LEGACY_HISTORY_FILE).write_text(json.dumps(legacy), encoding="utf-8")
        snapshot = web.read_history()
        self.assertEqual(len(snapshot["traffic"]), 1)
        self.assertTrue(Path(web.LEGACY_HISTORY_FILE + ".legacy").exists())
        self.assertTrue(Path(web.HISTORY_FILE).exists())

        ports = [{"name": "Ethernet1", "rxMbps": 4, "txMbps": 5, "errors": 0}]
        with mock.patch.object(web, "now_ms", return_value=61_001):
            web.update_history(ports, {"rxMbps": 4, "txMbps": 5, "totalMbps": 9})
        lines = Path(web.HISTORY_FILE).read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(len(web.read_history()["ports"]["Ethernet1"]), 2)

    def test_sampling_interval_prevents_client_driven_rewrites(self):
        ports = [{"name": "Ethernet1", "rxMbps": 1, "txMbps": 2, "errors": 0}]
        with mock.patch.object(web, "now_ms", return_value=100_000):
            web.update_history(ports, {"rxMbps": 1, "txMbps": 2, "totalMbps": 3})
        with mock.patch.object(web, "now_ms", return_value=110_000):
            web.update_history(ports, {"rxMbps": 9, "txMbps": 9, "totalMbps": 18})
        self.assertEqual(len(Path(web.HISTORY_FILE).read_text(encoding="utf-8").splitlines()), 1)

    def test_grouped_history_write_failure_preserves_complete_existing_set(self):
        active = Path(web.HISTORY_FILE)
        archive = Path(web.HISTORY_FILE + ".1999010100")
        active.write_bytes(b"old-active\n")
        archive.write_bytes(b"old-archive\n")
        original_active = active.read_bytes()
        original_archive = archive.read_bytes()
        web._HISTORY_ACTIVE_LINES = 7

        base_time = 1_700_000_000_000
        points = [
            {"time": base_time, "rxMbps": 1, "txMbps": 2, "totalMbps": 3},
            {"time": base_time + 86_400_000, "rxMbps": 4, "txMbps": 5, "totalMbps": 9},
        ]
        real_write = web._write_jsonl_atomic
        calls = []

        def fail_second_stage(path, grouped_points):
            calls.append(path)
            if len(calls) == 2:
                raise OSError("injected grouped-history write failure")
            return real_write(path, grouped_points)

        with mock.patch.object(web, "_write_jsonl_atomic", side_effect=fail_second_stage):
            with self.assertRaisesRegex(OSError, "injected grouped-history write failure"):
                web._persist_grouped_history(points)

        self.assertEqual(len(calls), 2)
        self.assertEqual(active.read_bytes(), original_active)
        self.assertEqual(archive.read_bytes(), original_archive)
        self.assertEqual(web._HISTORY_ACTIVE_LINES, 7)
        leftovers = [path.name for path in active.parent.iterdir() if ".stage." in path.name or ".tmp." in path.name]
        self.assertEqual(leftovers, [])


class HttpApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        web.AUDIT_FILE = str(Path(cls.tempdir.name) / "audit.jsonl")
        web._AUTH_RECORD = web.password_record("admin", "dashboard-password", salt=b"a" * 32, iterations=100000)
        web._SESSIONS.clear()
        web._AUTH_FAILURES.clear()
        web.Handler.cached_state = None
        cls.server = web.BoundedThreadingHTTPServer(("127.0.0.1", 0), web.Handler, max_workers=4)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.tempdir.cleanup()

    def request(self, method, path, payload=None, headers=None):
        body = None if payload is None else json.dumps(payload)
        request_headers = {"Accept": "application/json", **(headers or {})}
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        raw = response.read()
        result = response.status, dict(response.getheaders()), json.loads(raw.decode("utf-8"))
        connection.close()
        return result

    def login(self):
        status, headers, payload = self.request("POST", "/api/auth/login", {"username": "admin", "password": "dashboard-password"})
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        return cookie, payload["csrfToken"]

    def test_auth_csrf_and_removed_endpoints(self):
        status, _headers, _payload = self.request("GET", "/api/state")
        self.assertEqual(status, 401)
        cookie, csrf = self.login()

        status, _headers, payload = self.request("POST", "/api/refresh", {"scope": "core"}, {"Cookie": cookie})
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "csrf_failed")

        status, _headers, payload = self.request(
            "POST", "/api/command", {"command": "show version"}, {"Cookie": cookie, "X-CSRF-Token": csrf}
        )
        self.assertEqual(status, 410)
        self.assertEqual(payload["error"]["code"], "endpoint_removed")

        status, _headers, payload = self.request(
            "POST", "/api/config/apply", {"previewToken": "missing"}, {"Cookie": cookie, "X-CSRF-Token": csrf}
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "operations_locked")

    def test_health_exposes_only_release_metadata(self):
        status, _headers, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(set(payload), {"ok", "version", "artifactSha"})

    def test_post_commit_readback_failure_reports_committed_unverified(self):
        cookie, csrf = self.login()
        session_token = cookie.split("=", 1)[1]
        with web._SESSION_LOCK:
            web._SESSIONS[session_token]["unlockedUntil"] = time.time() + 60

        before = "hostname leaf1"
        preview_token, _preview = web.store_preview(
            session_token,
            "create_vlan",
            ["vlan 10"],
            web.config_hash(before),
            "+ vlan 10",
        )
        with mock.patch.object(web, "get_running_config", side_effect=[before, RuntimeError("readback failed")]), mock.patch.object(
            web, "run_config_session_apply", return_value="commit complete"
        ) as apply, mock.patch.object(web, "append_audit") as audit:
            status, _headers, payload = self.request(
                "POST",
                "/api/config/apply",
                {"previewToken": preview_token},
                {"Cookie": cookie, "X-CSRF-Token": csrf},
            )

        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["committed"])
        self.assertFalse(payload["verified"])
        self.assertIsNone(payload["diff"])
        self.assertIn("post-commit verification failed", payload["warning"])
        apply.assert_called_once_with(["vlan 10"], expected_baseline_hash=web.config_hash(before))
        self.assertTrue(any(call.args[0].get("event") == "config_committed_unverified" for call in audit.call_args_list))


if __name__ == "__main__":
    unittest.main()
