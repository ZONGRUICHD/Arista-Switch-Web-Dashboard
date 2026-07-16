import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"


class InstallerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = INSTALLER.read_text(encoding="utf-8").replace("\r\n", "\n")
        cls.sh = shutil.which("sh")

    def function_text(self, name):
        match = re.search(r"(?ms)^%s\(\) \{\n.*?^\}\n" % re.escape(name), self.script)
        self.assertIsNotNone(match, "missing shell function %s" % name)
        return match.group(0)

    def shell_path(self, path):
        path = str(path)
        if os.name != "nt" or not self.sh:
            return path
        converted = subprocess.run(
            [self.sh, "-lc", 'cygpath -u "$1"', "sh", path],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return converted or path

    def run_shell(self, source, env=None):
        if not self.sh:
            self.skipTest("POSIX sh is not available")
        return subprocess.run(
            [self.sh, "-s"],
            input=source,
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )

    def installer_env(self, root, **overrides):
        root = Path(root)
        posix_root = self.shell_path(root)
        env = os.environ.copy()
        env.update(
            {
                "REPO": "ZONGRUICHD/Arista-Switch-Web-Dashboard",
                "REF": "a" * 40,
                "ARTIFACT_SHA": "b" * 64,
                "APP_URL": "",
                "APP_SOURCE": "",
                "APP_PATH": posix_root + "/app.py",
                "STATE_DIR": posix_root + "/state",
                "AUTH_CONFIG": posix_root + "/state/auth.json",
                "TLS_CERT": posix_root + "/state/dashboard.crt",
                "TLS_KEY": posix_root + "/state/dashboard.key",
                "PID_FILE": posix_root + "/state/dashboard.pid",
                "WRAPPER_PATH": posix_root + "/state/start-dashboard.sh",
                "RELEASE_FILE": posix_root + "/state/release",
                "LOG": posix_root + "/state/dashboard.log",
                "INSTALL_LOCK": posix_root + "/state/install.lock",
                "HOST": "127.0.0.1",
                "PORT": "2480",
                "CANDIDATE_PORT": "2481",
                "TLS_IP": "192.0.2.10",
                "TLS_HOSTNAME": "Arista7050",
                "TLS_DAYS": "1",
                "AUTH_USER": "admin",
                "ROTATE_AUTH": "0",
                "STARTUP": "1",
                "EVENT_HANDLER": "codex-webui-start",
                "PYTHON": "python3",
                "MIN_FREE_KB": "1",
                "MAX_LOG_BYTES": "1",
                "HEALTH_ATTEMPTS": "1",
                "LEGACY_PID": "",
            }
        )
        env.update({key: str(value) for key, value in overrides.items()})
        return env

    def run_installer_guard(self, root, **overrides):
        if not self.sh:
            self.skipTest("POSIX sh is not available")
        return subprocess.run(
            [self.sh, self.shell_path(INSTALLER)],
            cwd=ROOT,
            env=self.installer_env(root, **overrides),
            capture_output=True,
            text=True,
        )

    def test_installer_has_valid_posix_shell_syntax(self):
        if not self.sh:
            self.skipTest("POSIX sh is not available")
        result = subprocess.run(
            [self.sh, "-n", self.shell_path(INSTALLER)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ref_must_be_exactly_40_hex_before_any_mutation(self):
        cases = (
            ("a" * 39, "REF must be exactly 40 hexadecimal characters."),
            ("a" * 41, "REF must be exactly 40 hexadecimal characters."),
            ("a" * 39 + "g", "REF must be the full 40-character hexadecimal Git commit."),
        )
        for ref, message in cases:
            with self.subTest(ref=ref), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "guard"
                root.mkdir()
                result = self.run_installer_guard(root, REF=ref)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertEqual(list(root.iterdir()), [], "validation must precede filesystem mutation")

    def test_invalid_ports_and_booleans_fail_before_any_mutation(self):
        cases = (
            ({"PORT": "0"}, "PORT must be between 1 and 65535."),
            ({"PORT": "65536"}, "PORT must be between 1 and 65535."),
            ({"PORT": "not-a-port"}, "PORT must be an unsigned integer."),
            ({"CANDIDATE_PORT": "70000"}, "CANDIDATE_PORT must be between 1 and 65535."),
            ({"STARTUP": "maybe"}, "STARTUP must be one of"),
            ({"ROTATE_AUTH": "2"}, "ROTATE_AUTH must be one of"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "guard"
                root.mkdir()
                result = self.run_installer_guard(root, **overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertEqual(list(root.iterdir()), [], "validation must precede filesystem mutation")

    def test_process_shutdown_is_pid_scoped_without_wildcard_kills(self):
        self.assertNotRegex(self.script, r"(?m)\b(?:pkill|killall)\b")
        self.assertNotRegex(self.script, r"(?m)\bkill\b[^\n]*\*")
        force_targets = re.findall(r"\bkill -(?:TERM|KILL)\s+([^\s;|]+)", self.script)
        self.assertEqual(set(force_targets), {'"$stop_pid"'})
        for target in re.findall(r"\bkill -0\s+([^\s;|]+)", self.script):
            self.assertRegex(target, r'^"\$[A-Za-z_][A-Za-z0-9_]*"$')

    def test_authenticated_candidate_smoke_precedes_cutover(self):
        main = self.script[self.script.index('[ -n "$REF" ]') :]
        candidate = main.index("Starting isolated candidate")
        smoke = main.index('--smoke-url "https://127.0.0.1:$CANDIDATE_PORT"')
        cleanup = main.index("cleanup_candidate || die", smoke)
        cutover = main.index("cutover_attempted=1")
        self.assertLess(candidate, smoke)
        self.assertLess(smoke, cleanup)
        self.assertLess(cleanup, cutover)
        smoke_block = main[smoke : cleanup]
        self.assertIn('--auth-config "$AUTH_CONFIG"', smoke_block)
        self.assertIn('--tls-cert "$TLS_CERT"', smoke_block)
        self.assertIn('--tls-key "$TLS_KEY"', smoke_block)
        self.assertIn('--auth-user "$AUTH_USER" < /dev/tty', smoke_block)

    def test_candidate_runtime_data_is_isolated_from_production(self):
        main = self.script[self.script.index('[ -n "$REF" ]') :]
        launch = main[main.index('WEB_HISTORY_FILE="$candidate_history"') : main.index('wait_for_health "https://127.0.0.1:$CANDIDATE_PORT/healthz"')]
        self.assertIn('WEB_LEGACY_HISTORY_FILE="$candidate_legacy_history"', launch)
        self.assertIn('WEB_AUDIT_FILE="$candidate_audit"', launch)
        cleanup = self.function_text("cleanup")
        self.assertIn('rm -f "$candidate_history" "$candidate_history".*', cleanup)

    def test_production_binds_and_health_checks_the_management_ip(self):
        self.assertIn('TLS_IP="${TLS_IP:-192.168.0.248}"\nHOST="${HOST:-$TLS_IP}"', self.script)
        self.assertIn('wait_for_health "https://$TLS_IP:$PORT/healthz"', self.script)
        self.assertIn('wait_for_expected_health "https://$TLS_IP:$PORT/healthz"', self.script)
        self.assertNotIn('https://127.0.0.1:$PORT/healthz', self.script)

    def test_offline_source_remains_commit_and_digest_pinned(self):
        main = self.script[self.script.index('[ -n "$REF" ]') :]
        source_guard = main.index('[ -f "$APP_SOURCE" ] && [ -r "$APP_SOURCE" ]')
        mutation = main.index('mkdir -p "$STATE_DIR"')
        digest = main.index('actual_sha="$(sha256_file "$tmp"')
        self.assertLess(source_guard, mutation)
        self.assertIn('cp "$APP_SOURCE" "$tmp"', main)
        self.assertLess(main.index('cp "$APP_SOURCE" "$tmp"'), digest)
        self.assertIn('[ -z "$APP_URL" ] || die "Set only one of APP_SOURCE or APP_URL."', main)
        self.assertIn('if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then', main)

    def test_legacy_rollback_deliberately_leaves_http_app_stopped(self):
        restart = self.function_text("restart_previous")
        self.assertIn('sh "$WRAPPER_PATH"', restart)
        self.assertIn("unauthenticated HTTP service was deliberately left stopped", restart)
        self.assertNotRegex(restart, r'(?m)^\s*"?\$PYTHON"?\s+"?\$APP_PATH"?')

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app_path = root / "legacy.py"
            wrapper_path = root / "missing-wrapper.sh"
            marker = root / "python-was-started"
            fake_python = root / "fake-python.sh"
            app_path.write_text("# legacy fixture\n", encoding="utf-8")
            fake_python.write_text(
                "#!/usr/bin/env sh\ntouch %s\n" % shlex.quote(self.shell_path(marker)),
                encoding="utf-8",
                newline="\n",
            )
            fake_python.chmod(0o700)
            harness = "\n".join(
                [
                    restart,
                    "production_was_running=1",
                    "previous_managed=0",
                    "legacy_rollback_stopped=0",
                    "WRAPPER_PATH=%s" % shlex.quote(self.shell_path(wrapper_path)),
                    "APP_PATH=%s" % shlex.quote(self.shell_path(app_path)),
                    "PYTHON=%s" % shlex.quote(self.shell_path(fake_python)),
                    "PORT=2480",
                    "restart_previous",
                    'printf "legacy=%s\\n" "$legacy_rollback_stopped"',
                ]
            )
            result = self.run_shell(harness)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("legacy=1", result.stdout)
            self.assertIn("deliberately left stopped", result.stderr)
            self.assertFalse(marker.exists(), "legacy rollback must not execute the Python app")

    def test_event_handler_mutation_captures_output_and_readback_verifies(self):
        capture = self.function_text("capture_event_handler")
        configure = self.function_text("configure_startup")
        verify = self.function_text("verify_event_handler_matches")
        self.assertIn('show running-config section event-handler $EVENT_HANDLER', capture)
        self.assertIn('> "$event_backup_tmp"', capture)
        self.assertRegex(
            configure,
            r'(?s)run_eos_cli "configure terminal.*write memory" > "\$event_cli_output_tmp" 2>&1',
        )
        self.assertIn('cli_output_is_clean "$event_cli_output_tmp"', configure)
        self.assertIn('verify_event_handler_matches "$expected_event"', configure)
        self.assertIn('show running-config section event-handler $EVENT_HANDLER', verify)
        self.assertIn('> "${event_verify_tmp}.raw" 2>&1', verify)
        self.assertIn('cmp -s "${event_verify_tmp}.actual" "${event_verify_tmp}.expected"', verify)

        main = self.script[self.script.index('[ -n "$REF" ]') :]
        self.assertLess(main.index("capture_event_handler"), main.index("transaction_active=1"))
        configure_call = main.index("if ! configure_startup; then")
        installed = main.index("installed=1", configure_call)
        committed = main.index("transaction_active=0", installed)
        self.assertLess(configure_call, installed)
        self.assertLess(installed, committed)

    def test_backup_pruning_is_prefix_bounded_and_keeps_two(self):
        prune = self.function_text("prune_backups")
        self.assertIn('ls -1t "${APP_PATH}.bak."*', prune)
        self.assertIn("awk 'NR > 2'", prune)
        self.assertIn('case "$old_backup" in', prune)
        self.assertIn('"${APP_PATH}.bak."*) rm -f "$old_backup"', prune)
        self.assertNotIn("rm -rf", prune)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app_path = root / "dashboard.py"
            backups = []
            for index in range(1, 5):
                backup = root / ("dashboard.py.bak.%s" % index)
                backup.write_text(str(index), encoding="ascii")
                os.utime(backup, (index * 10, index * 10))
                backups.append(backup)
            unrelated = root / "dashboard.py.backup.keep"
            unrelated.write_text("keep", encoding="ascii")
            harness = "\n".join(
                [
                    prune,
                    "APP_PATH=%s" % shlex.quote(self.shell_path(app_path)),
                    "prune_backups",
                ]
            )
            result = self.run_shell(harness)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([path.exists() for path in backups], [False, False, True, True])
            self.assertTrue(unrelated.exists())

    def test_tls_validation_uses_openssl_102_compatible_rsa_and_text_commands(self):
        validate = self.function_text("validate_tls_pair")
        self.assertIn('openssl rsa -in "$validate_key" -noout -check', validate)
        self.assertIn('openssl x509 -in "$validate_cert" -noout -modulus', validate)
        self.assertIn('openssl rsa -in "$validate_key" -noout -modulus', validate)
        self.assertIn('openssl x509 -in "$validate_cert" -noout -text', validate)
        self.assertNotRegex(self.script, r"\bopenssl\s+pkey\b")
        self.assertNotIn("-addext", self.script)

        with tempfile.TemporaryDirectory() as temp:
            log_path = Path(temp) / "openssl-calls"
            harness = "\n".join(
                [
                    'die() { echo "ERROR: $*" >&2; return 1; }',
                    'TLS_IP="192.0.2.10"',
                    'TLS_HOSTNAME="Arista7050"',
                    "OPENSSL_LOG=%s" % shlex.quote(self.shell_path(log_path)),
                    "openssl() {",
                    '  printf "%s\\n" "$*" >> "$OPENSSL_LOG"',
                    '  case "$*" in',
                    '    x509*"-noout -modulus"*) echo "Modulus=fixture" ;;',
                    '    rsa*"-noout -modulus"*) echo "Modulus=fixture" ;;',
                    '    x509*"-noout -text"*) printf "X509v3 Subject Alternative Name: IP Address:%s, DNS:%s\\n" "$TLS_IP" "$TLS_HOSTNAME" ;;',
                    "  esac",
                    "  return 0",
                    "}",
                    validate,
                    'validate_tls_pair "/tmp/cert.pem" "/tmp/key.pem"',
                ]
            )
            result = self.run_shell(harness)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                calls,
                [
                    "x509 -in /tmp/cert.pem -noout -checkend 86400",
                    "rsa -in /tmp/key.pem -noout -check",
                    "x509 -in /tmp/cert.pem -noout -modulus",
                    "rsa -in /tmp/key.pem -noout -modulus",
                    "x509 -in /tmp/cert.pem -noout -text",
                ],
            )


if __name__ == "__main__":
    unittest.main()
