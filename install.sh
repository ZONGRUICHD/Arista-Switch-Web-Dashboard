#!/usr/bin/env sh
set -eu
umask 077

# Secure, transactional installer for the on-box dashboard. Production installs
# intentionally have no mutable branch default: REF and ARTIFACT_SHA are required.

REPO="${REPO:-ZONGRUICHD/Arista-Switch-Web-Dashboard}"
REF="${REF:-}"
ARTIFACT_SHA="${ARTIFACT_SHA:-}"
APP_URL="${APP_URL:-}"
APP_SOURCE="${APP_SOURCE:-}"

APP_PATH="${APP_PATH:-/mnt/flash/arista7050_web.py}"
STATE_DIR="${STATE_DIR:-/mnt/flash/arista-dashboard}"
AUTH_CONFIG="${AUTH_CONFIG:-$STATE_DIR/auth.json}"
TLS_CERT="${TLS_CERT:-$STATE_DIR/dashboard.crt}"
TLS_KEY="${TLS_KEY:-$STATE_DIR/dashboard.key}"
PID_FILE="${PID_FILE:-$STATE_DIR/dashboard.pid}"
WRAPPER_PATH="${WRAPPER_PATH:-$STATE_DIR/start-dashboard.sh}"
RELEASE_FILE="${RELEASE_FILE:-$STATE_DIR/release}"
LOG="${LOG:-$STATE_DIR/dashboard.log}"
INSTALL_LOCK="${INSTALL_LOCK:-$STATE_DIR/install.lock}"

TLS_IP="${TLS_IP:-192.168.0.248}"
HOST="${HOST:-$TLS_IP}"
PORT="${PORT:-2480}"
CANDIDATE_PORT="${CANDIDATE_PORT:-2481}"
TLS_HOSTNAME="${TLS_HOSTNAME:-Arista7050}"
TLS_DAYS="${TLS_DAYS:-825}"
AUTH_USER="${AUTH_USER:-admin}"
ROTATE_AUTH="${ROTATE_AUTH:-0}"
STARTUP="${STARTUP:-1}"
EVENT_HANDLER="${EVENT_HANDLER:-codex-webui-start}"
PYTHON="${PYTHON:-python3}"
MIN_FREE_KB="${MIN_FREE_KB:-8192}"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-2097152}"
HEALTH_ATTEMPTS="${HEALTH_ATTEMPTS:-20}"
LEGACY_PID="${LEGACY_PID:-}"

tmp=""
cert_cfg=""
cert_tmp=""
key_tmp=""
tls_generated=0
tls_key_promoted=0
tls_cert_promoted=0
wrapper_tmp=""
release_tmp=""
candidate_pid="${PID_FILE}.candidate"
candidate_log="${LOG}.candidate"
candidate_history="/tmp/arista-dashboard-candidate.$$.history"
candidate_legacy_history="/tmp/arista-dashboard-candidate.$$.legacy-history"
candidate_audit="/tmp/arista-dashboard-candidate.$$.audit"
candidate_app=""
candidate_launched=0
backup=""
backup_tmp=""
saved_wrapper=""
saved_wrapper_tmp=""
saved_release=""
saved_release_tmp=""
saved_auth=""
auth_backup_tmp=""
auth_created=0
event_backup=""
event_backup_tmp=""
event_verify_tmp=""
event_cli_output_tmp=""
event_mutation_started=0
previous_managed=0
previous_ref=""
previous_sha=""
production_was_running=0
production_stop_started=0
application_replaced=0
wrapper_replaced=0
release_replaced=0
cutover_attempted=0
preserve_recovery=0
installed=0
transaction_active=0
lock_acquired=0
legacy_rollback_stopped=0

die() {
  echo "ERROR: $*" >&2
  exit 1
}

note() {
  echo "==> $*"
}

cleanup() {
  cleanup_status="$?"
  trap - HUP INT TERM
  set +e
  if [ "$candidate_launched" -eq 1 ]; then
    cleanup_candidate
  fi
  if [ "$installed" -eq 0 ] && [ "$transaction_active" -eq 1 ]; then
    rollback_install || preserve_recovery=1
  fi
  if [ "$installed" -eq 0 ]; then
    if [ -n "$saved_auth" ] && [ -f "$saved_auth" ]; then
      if mv "$saved_auth" "$AUTH_CONFIG"; then
        saved_auth=""
      else
        preserve_recovery=1
        echo "ERROR: could not restore authentication config from $saved_auth." >&2
      fi
    elif [ "$auth_created" -eq 1 ]; then
      rm -f "$AUTH_CONFIG"
    fi
    if [ "$tls_generated" -eq 1 ] || [ "$tls_key_promoted" -eq 1 ]; then
      rm -f "$TLS_KEY"
    fi
    if [ "$tls_generated" -eq 1 ] || [ "$tls_cert_promoted" -eq 1 ]; then
      rm -f "$TLS_CERT"
    fi
  fi
  [ -z "$tmp" ] || rm -f "$tmp"
  rm -f "$candidate_history" "$candidate_history".* "$candidate_legacy_history" "$candidate_audit" "$candidate_audit".*
  [ -z "$cert_cfg" ] || rm -f "$cert_cfg"
  [ -z "$cert_tmp" ] || rm -f "$cert_tmp"
  [ -z "$key_tmp" ] || rm -f "$key_tmp"
  [ -z "$auth_backup_tmp" ] || rm -f "$auth_backup_tmp"
  [ -z "$event_backup_tmp" ] || rm -f "$event_backup_tmp"
  [ -z "$event_verify_tmp" ] || rm -f "$event_verify_tmp" "${event_verify_tmp}.raw" "${event_verify_tmp}.expected" "${event_verify_tmp}.actual"
  [ -z "$event_cli_output_tmp" ] || rm -f "$event_cli_output_tmp"
  [ -z "$backup_tmp" ] || rm -f "$backup_tmp"
  [ -z "$saved_wrapper_tmp" ] || rm -f "$saved_wrapper_tmp"
  [ -z "$saved_release_tmp" ] || rm -f "$saved_release_tmp"
  [ -z "$wrapper_tmp" ] || rm -f "$wrapper_tmp"
  [ -z "$release_tmp" ] || rm -f "$release_tmp"
  if [ "$candidate_launched" -eq 0 ] && [ -n "$candidate_log" ]; then
    rm -f "$candidate_log"
  fi
  if [ "$installed" -eq 0 ] && [ "$cutover_attempted" -eq 0 ] && [ "$preserve_recovery" -eq 0 ]; then
    [ -z "$backup" ] || rm -f "$backup"
    [ -z "$saved_wrapper" ] || rm -f "$saved_wrapper"
    [ -z "$saved_release" ] || rm -f "$saved_release"
    [ -z "$event_backup" ] || rm -f "$event_backup"
  fi
  if [ "$lock_acquired" -eq 1 ]; then
    rm -f "$INSTALL_LOCK/pid"
    rmdir "$INSTALL_LOCK" 2>/dev/null || true
    lock_acquired=0
  fi
  return "$cleanup_status"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

validate_safe_value() {
  value_name="$1"
  value_data="$2"
  case "$value_data" in
    ''|*[!A-Za-z0-9_./:@+-]*)
      die "$value_name contains unsupported characters."
      ;;
  esac
}

validate_uint() {
  number_name="$1"
  number_data="$2"
  case "$number_data" in
    ''|*[!0-9]*) die "$number_name must be an unsigned integer." ;;
  esac
}

validate_boolean() {
  boolean_name="$1"
  boolean_data="$2"
  case "$boolean_data" in
    1|true|yes|0|false|no) ;;
    *) die "$boolean_name must be one of: 1, true, yes, 0, false, no." ;;
  esac
}

validate_port() {
  port_name="$1"
  port_data="$2"
  validate_uint "$port_name" "$port_data"
  [ "$port_data" -ge 1 ] && [ "$port_data" -le 65535 ] || \
    die "$port_name must be between 1 and 65535."
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required."
}

acquire_install_lock() {
  if ! mkdir "$INSTALL_LOCK" 2>/dev/null; then
    lock_owner="$(sed -n '1p' "$INSTALL_LOCK/pid" 2>/dev/null || true)"
    case "$lock_owner" in
      ''|*[!0-9]*) lock_owner="" ;;
    esac
    if [ -n "$lock_owner" ] && kill -0 "$lock_owner" 2>/dev/null; then
      die "Another installer process is active with PID $lock_owner."
    fi
    rm -f "$INSTALL_LOCK/pid"
    rmdir "$INSTALL_LOCK" 2>/dev/null || \
      die "Stale install lock $INSTALL_LOCK cannot be removed safely."
    mkdir "$INSTALL_LOCK" || die "Unable to acquire install lock $INSTALL_LOCK."
  fi
  lock_acquired=1
  chmod 700 "$INSTALL_LOCK" || die "Cannot secure install lock directory."
  printf '%s\n' "$$" > "$INSTALL_LOCK/pid"
  chmod 600 "$INSTALL_LOCK/pid" || die "Cannot secure install lock PID file."
}

download() {
  download_url="$1"
  download_target="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --connect-timeout 15 --max-time 120 -o "$download_target" "$download_url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$download_target" "$download_url"
  else
    die "curl or wget is required."
  fi
}

sha256_file() {
  sha_file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$sha_file" | awk '{print $1}'
  else
    openssl dgst -sha256 "$sha_file" | awk '{print $NF}'
  fi
}

https_get() {
  get_url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fkSs --connect-timeout 2 --max-time 4 "$get_url"
  else
    wget --no-check-certificate -q -T 4 -O - "$get_url"
  fi
}

port_is_listening() {
  listen_port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk -v suffix=":$listen_port" '$1 == "LISTEN" && $4 ~ (suffix "$") {found=1} END {exit !found}'
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk -v suffix=":$listen_port" '$1 ~ /^tcp/ && $4 ~ (suffix "$") {found=1} END {exit !found}'
  else
    return 1
  fi
}

wait_for_expected_health() {
  health_url="$1"
  health_ref="$2"
  health_sha="$3"
  health_try=1
  while [ "$health_try" -le "$HEALTH_ATTEMPTS" ]; do
    health_body="$(https_get "$health_url" 2>/dev/null || true)"
    if [ -n "$health_body" ] && \
       printf '%s' "$health_body" | grep -F -e "$health_ref" >/dev/null 2>&1 && \
       printf '%s' "$health_body" | grep -F -e "$health_sha" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    health_try=$((health_try + 1))
  done
  return 1
}

wait_for_health() {
  wait_for_expected_health "$1" "$REF" "$ARTIFACT_SHA"
}

wait_for_port() {
  wait_port="$1"
  wait_try=1
  while [ "$wait_try" -le "$HEALTH_ATTEMPTS" ]; do
    if port_is_listening "$wait_port"; then
      return 0
    fi
    sleep 1
    wait_try=$((wait_try + 1))
  done
  return 1
}

assert_pid_matches() {
  check_pid="$1"
  expected_path="$2"
  case "$check_pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  kill -0 "$check_pid" 2>/dev/null || return 1
  [ -r "/proc/$check_pid/cmdline" ] || return 1
  tr '\000' '\n' < "/proc/$check_pid/cmdline" | \
    grep -F -x -e "$expected_path" >/dev/null 2>&1
}

candidate_process_path() {
  candidate_check_pid="$1"
  candidate_prefix="${APP_PATH}.download."
  case "$candidate_check_pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  kill -0 "$candidate_check_pid" 2>/dev/null || return 1
  [ -r "/proc/$candidate_check_pid/cmdline" ] || return 1
  tr '\000' '\n' < "/proc/$candidate_check_pid/cmdline" | \
    awk -v prefix="$candidate_prefix" '
      index($0, prefix) == 1 {
        suffix = substr($0, length(prefix) + 1)
        if (suffix ~ /^[0-9]+$/) { print; found = 1; exit }
      }
      END { if (!found) exit 1 }
    '
}

stop_pid_file() {
  stop_file="$1"
  expected_path="$2"
  stop_role="${3:-}"
  [ -f "$stop_file" ] || return 0
  stop_pid="$(sed -n '1p' "$stop_file" 2>/dev/null || true)"
  case "$stop_pid" in
    ''|*[!0-9]*)
      echo "ERROR: Invalid PID '$stop_pid' in $stop_file." >&2
      return 1
      ;;
  esac
  if ! kill -0 "$stop_pid" 2>/dev/null; then
    rm -f "$stop_file"
    return 0
  fi
  if ! assert_pid_matches "$stop_pid" "$expected_path"; then
    echo "ERROR: Refusing to stop PID $stop_pid because its command does not match $expected_path." >&2
    return 1
  fi

  if [ "$stop_role" = "production" ]; then
    production_stop_started=1
  fi
  kill -TERM "$stop_pid" || return 1
  stop_wait=0
  while kill -0 "$stop_pid" 2>/dev/null && [ "$stop_wait" -lt 10 ]; do
    sleep 1
    stop_wait=$((stop_wait + 1))
  done
  if kill -0 "$stop_pid" 2>/dev/null; then
    kill -KILL "$stop_pid" || return 1
    stop_wait=0
    while kill -0 "$stop_pid" 2>/dev/null && [ "$stop_wait" -lt 5 ]; do
      sleep 1
      stop_wait=$((stop_wait + 1))
    done
    if kill -0 "$stop_pid" 2>/dev/null; then
      echo "ERROR: PID $stop_pid did not exit after SIGKILL." >&2
      return 1
    fi
  fi
  rm -f "$stop_file"
}

cleanup_candidate() {
  candidate_cleanup_try=0
  if [ "$candidate_launched" -eq 1 ]; then
    while [ ! -f "$candidate_pid" ] && [ "$candidate_cleanup_try" -lt 3 ]; do
      sleep 1
      candidate_cleanup_try=$((candidate_cleanup_try + 1))
    done
  fi
  if [ -f "$candidate_pid" ]; then
    if [ -z "$candidate_app" ]; then
      candidate_cleanup_pid="$(sed -n '1p' "$candidate_pid" 2>/dev/null || true)"
      case "$candidate_cleanup_pid" in
        ''|*[!0-9]*)
          echo "ERROR: Invalid candidate PID '$candidate_cleanup_pid' in $candidate_pid." >&2
          return 1
          ;;
      esac
      if kill -0 "$candidate_cleanup_pid" 2>/dev/null; then
        candidate_app="$(candidate_process_path "$candidate_cleanup_pid")" || {
          echo "ERROR: Refusing to stop an unverified candidate PID $candidate_cleanup_pid." >&2
          return 1
        }
      else
        rm -f "$candidate_pid"
      fi
    fi
    if [ -f "$candidate_pid" ]; then
      stop_pid_file "$candidate_pid" "$candidate_app" || return 1
    fi
  fi
  candidate_launched=0
  if port_is_listening "$CANDIDATE_PORT"; then
    echo "ERROR: Candidate port $CANDIDATE_PORT remains occupied; manual PID investigation is required." >&2
    return 1
  fi
  return 0
}

prepare_candidate() {
  candidate_app=""
  if [ -f "$candidate_pid" ]; then
    stale_candidate_pid="$(sed -n '1p' "$candidate_pid" 2>/dev/null || true)"
    case "$stale_candidate_pid" in
      ''|*[!0-9]*) die "Invalid candidate PID '$stale_candidate_pid' in $candidate_pid." ;;
    esac
    if kill -0 "$stale_candidate_pid" 2>/dev/null; then
      stale_candidate_app="$(candidate_process_path "$stale_candidate_pid")" || \
        die "Candidate PID file points to an unverified process; investigate PID $stale_candidate_pid manually."
      stop_pid_file "$candidate_pid" "$stale_candidate_app" || \
        die "Could not stop the verified stale candidate process."
    else
      rm -f "$candidate_pid"
    fi
  fi
  if port_is_listening "$CANDIDATE_PORT"; then
    die "Candidate port $CANDIDATE_PORT already has an unmanaged listener."
  fi
  rm -f "$candidate_log"
}

adopt_legacy_pid() {
  [ -n "$LEGACY_PID" ] || return 0
  [ ! -f "$PID_FILE" ] || die "PID_FILE already exists; do not also set LEGACY_PID."
  assert_pid_matches "$LEGACY_PID" "$APP_PATH" || die "LEGACY_PID does not identify the exact existing dashboard process."
  printf '%s\n' "$LEGACY_PID" > "$PID_FILE"
  chmod 600 "$PID_FILE" || die "Cannot secure $PID_FILE with mode 0600."
  note "Adopted explicitly supplied legacy PID $LEGACY_PID."
}

rotate_log() {
  rotate_path="$1"
  [ -f "$rotate_path" ] || return 0
  rotate_size="$(wc -c < "$rotate_path" | tr -d ' ')"
  case "$rotate_size" in ''|*[!0-9]*) rotate_size=0 ;; esac
  if [ "$rotate_size" -gt "$MAX_LOG_BYTES" ]; then
    rm -f "${rotate_path}.1"
    mv "$rotate_path" "${rotate_path}.1"
    chmod 600 "${rotate_path}.1" || die "Cannot secure rotated log ${rotate_path}.1."
  fi
}

prune_backups() {
  # APP_PATH is restricted to safe characters, so line-oriented processing is safe.
  ls -1t "${APP_PATH}.bak."* 2>/dev/null | awk 'NR > 2' | while IFS= read -r old_backup; do
    case "$old_backup" in
      "${APP_PATH}.bak."*) rm -f "$old_backup" ;;
    esac
  done
}

validate_tls_pair() {
  validate_cert="$1"
  validate_key="$2"
  openssl x509 -in "$validate_cert" -noout -checkend 86400 >/dev/null 2>&1 || \
    die "TLS certificate is invalid or expires within 24 hours."
  openssl rsa -in "$validate_key" -noout -check >/dev/null 2>&1 || \
    die "TLS private key is invalid."
  cert_modulus="$(openssl x509 -in "$validate_cert" -noout -modulus 2>/dev/null)" || \
    die "Unable to read the TLS certificate public key."
  key_modulus="$(openssl rsa -in "$validate_key" -noout -modulus 2>/dev/null)" || \
    die "Unable to read the TLS private key public component."
  [ -n "$cert_modulus" ] && [ "$cert_modulus" = "$key_modulus" ] || \
    die "TLS certificate and private key do not match."
  cert_sans="$(openssl x509 -in "$validate_cert" -noout -text 2>/dev/null)" || \
    die "Unable to read TLS certificate SANs."
  printf '%s' "$cert_sans" | grep -F -e "IP Address:$TLS_IP" >/dev/null 2>&1 || \
    die "TLS certificate does not contain IP SAN $TLS_IP."
  printf '%s' "$cert_sans" | grep -F -e "DNS:$TLS_HOSTNAME" >/dev/null 2>&1 || \
    die "TLS certificate does not contain DNS SAN $TLS_HOSTNAME."
}

run_eos_cli() {
  eos_cli_script="$1"
  if [ -x /usr/bin/FastCli ]; then
    /usr/bin/FastCli -p 15 -c "$eos_cli_script"
  elif command -v FastCli >/dev/null 2>&1; then
    FastCli -p 15 -c "$eos_cli_script"
  elif [ -x /usr/bin/Cli ]; then
    /usr/bin/Cli -c "$eos_cli_script"
  elif command -v Cli >/dev/null 2>&1; then
    Cli -c "$eos_cli_script"
  else
    return 127
  fi
}

capture_event_handler() {
  event_backup_tmp="${STATE_DIR}/event-handler.before.$$.tmp"
  if ! run_eos_cli "show running-config section event-handler $EVENT_HANDLER" > "$event_backup_tmp"; then
    die "Unable to capture the existing event-handler; refusing to modify startup configuration."
  fi
  event_capture_body="${event_backup_tmp}.body"
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^[[:space:]]*$/d' -e '/^[[:space:]]*!/d' \
    "$event_backup_tmp" > "$event_capture_body"
  rm -f "$event_backup_tmp"
  event_backup_tmp="$event_capture_body"
  if [ -s "$event_backup_tmp" ] && \
     ! grep -F -x -e "event-handler $EVENT_HANDLER" "$event_backup_tmp" >/dev/null 2>&1; then
    die "Unexpected event-handler capture output; refusing to modify startup configuration."
  fi
  chmod 600 "$event_backup_tmp" || die "Cannot secure event-handler backup."
  event_backup="${STATE_DIR}/event-handler.before.$$"
  mv "$event_backup_tmp" "$event_backup"
  event_backup_tmp=""
}

normalize_event_handler_file() {
  normalize_source="$1"
  normalize_target="$2"
  sed -e 's/[[:space:]]*$//' -e '/^[[:space:]]*$/d' -e '/^[[:space:]]*!/d' \
    "$normalize_source" > "$normalize_target"
}

cli_output_is_clean() {
  cli_output_file="$1"
  ! grep -E '^[[:space:]]*%' "$cli_output_file" >/dev/null 2>&1
}

verify_event_handler_matches() {
  expected_event_file="$1"
  event_verify_tmp="${STATE_DIR}/event-handler.verify.$$.tmp"
  if ! run_eos_cli "show running-config section event-handler $EVENT_HANDLER" > "${event_verify_tmp}.raw" 2>&1; then
    return 1
  fi
  cli_output_is_clean "${event_verify_tmp}.raw" || return 1
  normalize_event_handler_file "${event_verify_tmp}.raw" "${event_verify_tmp}.actual"
  normalize_event_handler_file "$expected_event_file" "${event_verify_tmp}.expected"
  LC_ALL=C sort "${event_verify_tmp}.actual" -o "${event_verify_tmp}.actual"
  LC_ALL=C sort "${event_verify_tmp}.expected" -o "${event_verify_tmp}.expected"
  if ! cmp -s "${event_verify_tmp}.actual" "${event_verify_tmp}.expected"; then
    return 1
  fi
  rm -f "$event_verify_tmp" "${event_verify_tmp}.raw" "${event_verify_tmp}.expected" "${event_verify_tmp}.actual"
  event_verify_tmp=""
}

restore_event_handler() {
  [ -n "$event_backup" ] && [ -f "$event_backup" ] || return 0
  restore_body="$(cat "$event_backup")"
  event_cli_output_tmp="${STATE_DIR}/event-handler.restore.$$.tmp"
  if ! run_eos_cli "configure terminal
no event-handler $EVENT_HANDLER
$restore_body
end
write memory" > "$event_cli_output_tmp" 2>&1; then
    return 1
  fi
  cli_output_is_clean "$event_cli_output_tmp" || return 1
  rm -f "$event_cli_output_tmp"
  event_cli_output_tmp=""
  verify_event_handler_matches "$event_backup"
}

configure_startup() {
  [ "$startup_enabled" -eq 1 ] || return 0
  event_mutation_started=1
  event_cli_output_tmp="${STATE_DIR}/event-handler.configure.$$.tmp"
  if ! run_eos_cli "configure terminal
no event-handler $EVENT_HANDLER
event-handler $EVENT_HANDLER
trigger on-boot
delay 60
timeout 120
asynchronous
action bash $WRAPPER_PATH
end
write memory" > "$event_cli_output_tmp" 2>&1; then
    return 1
  fi
  cli_output_is_clean "$event_cli_output_tmp" || return 1
  rm -f "$event_cli_output_tmp"
  event_cli_output_tmp=""
  expected_event="${STATE_DIR}/event-handler.expected.$$.tmp"
  {
    echo "event-handler $EVENT_HANDLER"
    echo "trigger on-boot"
    echo "delay 60"
    echo "timeout 120"
    echo "asynchronous"
    echo "action bash $WRAPPER_PATH"
  } > "$expected_event"
  if ! verify_event_handler_matches "$expected_event"; then
    rm -f "$expected_event"
    return 1
  fi
  rm -f "$expected_event"
}

restart_previous() {
  [ "$production_was_running" -eq 1 ] || return 0
  if [ "$previous_managed" -eq 1 ] && [ -f "$WRAPPER_PATH" ]; then
    sh "$WRAPPER_PATH" || return 1
    if [ -n "$previous_ref" ] && [ -n "$previous_sha" ]; then
      wait_for_expected_health "https://$TLS_IP:$PORT/healthz" "$previous_ref" "$previous_sha"
    else
      wait_for_port "$PORT"
    fi
  elif [ -f "$APP_PATH" ]; then
    legacy_rollback_stopped=1
    echo "WARNING: legacy files were restored, but the unauthenticated HTTP service was deliberately left stopped." >&2
    echo "Inspect the rollback state locally; do not expose the legacy listener on the management network." >&2
  else
    return 1
  fi
}

rollback_install() {
  transaction_active=0
  set +e
  rollback_ok=1
  echo "ERROR: deployment failed; rolling back the application and startup handler." >&2
  if { [ "$production_stop_started" -eq 1 ] || [ "$application_replaced" -eq 1 ]; } && [ -f "$PID_FILE" ]; then
    stop_pid_file "$PID_FILE" "$APP_PATH" || rollback_ok=0
  fi
  if [ "$application_replaced" -eq 1 ]; then
    if [ -n "$backup" ] && [ -f "$backup" ]; then
      if mv "$backup" "$APP_PATH"; then
        backup=""
      else
        rollback_ok=0
      fi
    else
      rm -f "$APP_PATH" || rollback_ok=0
    fi
  fi
  if [ "$wrapper_replaced" -eq 1 ]; then
    if [ -n "$saved_wrapper" ] && [ -f "$saved_wrapper" ]; then
      if mv "$saved_wrapper" "$WRAPPER_PATH"; then
        saved_wrapper=""
      else
        rollback_ok=0
      fi
    else
      rm -f "$WRAPPER_PATH" || rollback_ok=0
    fi
  fi
  if [ "$release_replaced" -eq 1 ]; then
    if [ -n "$saved_release" ] && [ -f "$saved_release" ]; then
      if mv "$saved_release" "$RELEASE_FILE"; then
        saved_release=""
      else
        rollback_ok=0
      fi
    else
      rm -f "$RELEASE_FILE" || rollback_ok=0
    fi
  fi
  if [ -n "$saved_auth" ] && [ -f "$saved_auth" ]; then
    if mv "$saved_auth" "$AUTH_CONFIG"; then
      saved_auth=""
    else
      rollback_ok=0
    fi
  elif [ "$auth_created" -eq 1 ]; then
    rm -f "$AUTH_CONFIG" || rollback_ok=0
  fi
  if [ "$event_mutation_started" -eq 1 ]; then
    restore_event_handler || rollback_ok=0
  fi
  if [ "$production_was_running" -eq 1 ] && \
     { [ "$production_stop_started" -eq 1 ] || [ "$application_replaced" -eq 1 ]; } && \
     ! restart_previous; then
    rollback_ok=0
  fi
  if [ "$rollback_ok" -eq 1 ]; then
    if [ -n "$backup" ] && [ "$application_replaced" -eq 0 ]; then
      rm -f "$backup" || echo "WARNING: could not remove unused backup $backup." >&2
      backup=""
    fi
    if [ -n "$saved_wrapper" ]; then
      rm -f "$saved_wrapper" || echo "WARNING: could not remove unused wrapper snapshot $saved_wrapper." >&2
      saved_wrapper=""
    fi
    if [ -n "$saved_release" ]; then
      rm -f "$saved_release" || echo "WARNING: could not remove unused release snapshot $saved_release." >&2
      saved_release=""
    fi
    if [ -n "$event_backup" ]; then
      rm -f "$event_backup" || echo "WARNING: could not remove event-handler snapshot $event_backup." >&2
      event_backup=""
    fi
    if [ "$legacy_rollback_stopped" -eq 1 ]; then
      echo "==> Legacy files restored; insecure legacy service remains stopped by design." >&2
    else
      echo "==> Previous secure deployment restored and verified." >&2
    fi
    return 0
  fi
  preserve_recovery=1
  echo "ERROR: automatic rollback could not verify the previous service." >&2
  echo "Recovery files were preserved. Inspect $APP_PATH, $WRAPPER_PATH, $PID_FILE, and $LOG." >&2
  if [ "$previous_managed" -eq 1 ]; then
    echo "After resolving the cause, restart with: sh $WRAPPER_PATH" >&2
  else
    echo "After resolving the cause, restart the legacy app explicitly with $PYTHON $APP_PATH." >&2
  fi
  return 1
}

[ -n "$REF" ] || die "REF is required and must identify the reviewed release commit."
[ -n "$ARTIFACT_SHA" ] || die "ARTIFACT_SHA is required."
case "$REF" in
  *[!0-9A-Fa-f]*|'') die "REF must be the full 40-character hexadecimal Git commit." ;;
esac
[ "${#REF}" -eq 40 ] || die "REF must be exactly 40 hexadecimal characters."
case "$ARTIFACT_SHA" in
  *[!0-9A-Fa-f]*|'') die "ARTIFACT_SHA must be a 64-character SHA-256 digest." ;;
esac
[ "${#ARTIFACT_SHA}" -eq 64 ] || die "ARTIFACT_SHA must be exactly 64 hexadecimal characters."

validate_safe_value REPO "$REPO"
validate_safe_value REF "$REF"
if [ -n "$APP_SOURCE" ]; then
  validate_safe_value APP_SOURCE "$APP_SOURCE"
fi
validate_safe_value APP_PATH "$APP_PATH"
validate_safe_value STATE_DIR "$STATE_DIR"
validate_safe_value AUTH_CONFIG "$AUTH_CONFIG"
validate_safe_value TLS_CERT "$TLS_CERT"
validate_safe_value TLS_KEY "$TLS_KEY"
validate_safe_value PID_FILE "$PID_FILE"
validate_safe_value WRAPPER_PATH "$WRAPPER_PATH"
validate_safe_value RELEASE_FILE "$RELEASE_FILE"
validate_safe_value LOG "$LOG"
validate_safe_value INSTALL_LOCK "$INSTALL_LOCK"
validate_safe_value HOST "$HOST"
validate_safe_value TLS_IP "$TLS_IP"
validate_safe_value TLS_HOSTNAME "$TLS_HOSTNAME"
validate_safe_value AUTH_USER "$AUTH_USER"
validate_safe_value EVENT_HANDLER "$EVENT_HANDLER"
validate_safe_value PYTHON "$PYTHON"
validate_port PORT "$PORT"
validate_port CANDIDATE_PORT "$CANDIDATE_PORT"
validate_uint TLS_DAYS "$TLS_DAYS"
validate_uint MIN_FREE_KB "$MIN_FREE_KB"
validate_uint MAX_LOG_BYTES "$MAX_LOG_BYTES"
validate_uint HEALTH_ATTEMPTS "$HEALTH_ATTEMPTS"
validate_boolean ROTATE_AUTH "$ROTATE_AUTH"
validate_boolean STARTUP "$STARTUP"
[ -z "$LEGACY_PID" ] || validate_uint LEGACY_PID "$LEGACY_PID"

case "$ROTATE_AUTH" in 1|true|yes) auth_init=1 ;; *) auth_init=0 ;; esac
case "$STARTUP" in 1|true|yes) startup_enabled=1 ;; *) startup_enabled=0 ;; esac

[ "$PORT" -ne "$CANDIDATE_PORT" ] || die "PORT and CANDIDATE_PORT must differ."
[ "$TLS_DAYS" -ge 1 ] || die "TLS_DAYS must be at least 1."
[ "$MIN_FREE_KB" -ge 1 ] || die "MIN_FREE_KB must be at least 1."
[ "$MAX_LOG_BYTES" -ge 1 ] || die "MAX_LOG_BYTES must be at least 1."
[ "$HEALTH_ATTEMPTS" -ge 1 ] || die "HEALTH_ATTEMPTS must be at least 1."
installer_uid="$(id -u 2>/dev/null || true)"
[ "$installer_uid" = "0" ] || die "Installer must run as root (on EOS, use: sudo -n env ... sh install.sh)."
if [ -n "$APP_SOURCE" ]; then
  [ -z "$APP_URL" ] || die "Set only one of APP_SOURCE or APP_URL."
  [ -f "$APP_SOURCE" ] && [ -r "$APP_SOURCE" ] || die "APP_SOURCE must be a readable regular file."
else
  [ -n "$APP_URL" ] || APP_URL="https://raw.githubusercontent.com/$REPO/$REF/onbox/arista7050_web.py"
  case "$APP_URL" in https://*) ;; *) die "APP_URL must use HTTPS." ;; esac
fi

require_command "$PYTHON"
require_command openssl
require_command awk
require_command grep
require_command sed
require_command tr
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  die "curl or wget is required."
fi
if ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
  die "ss or netstat is required for safe listener verification."
fi
if ! run_eos_cli "show configuration lock" >/dev/null 2>&1; then
  die "A privilege-15 EOS FastCli/Cli runner is required."
fi
"$PYTHON" -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$TLS_IP" \
  >/dev/null 2>&1 || die "TLS_IP is not a valid IP address."

app_dir="$(dirname "$APP_PATH")"
[ -d "$app_dir" ] || die "Application directory does not exist: $app_dir"
[ -w "$app_dir" ] || die "Application directory is not writable: $app_dir"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR" || die "Cannot secure $STATE_DIR with mode 0700."
acquire_install_lock
if [ ! -e "$LOG" ]; then
  : > "$LOG"
fi
chmod 600 "$LOG" || die "Runtime log must be mode 0600."

free_kb="$(df -Pk "$app_dir" 2>/dev/null | awk 'NR == 2 {print $4}')"
case "$free_kb" in ''|*[!0-9]*) die "Unable to determine free flash space." ;; esac
[ "$free_kb" -ge "$MIN_FREE_KB" ] || die "Only ${free_kb} KiB free; at least ${MIN_FREE_KB} KiB is required."
state_free_kb="$(df -Pk "$STATE_DIR" 2>/dev/null | awk 'NR == 2 {print $4}')"
case "$state_free_kb" in ''|*[!0-9]*) die "Unable to determine free state-directory space." ;; esac
[ "$state_free_kb" -ge "$MIN_FREE_KB" ] || \
  die "Only ${state_free_kb} KiB free in $STATE_DIR; at least ${MIN_FREE_KB} KiB is required."

note "Pinned source: $REPO@$REF"
note "Expected artifact SHA-256: $ARTIFACT_SHA"
note "Target: $APP_PATH"
note "HTTPS listener: $HOST:$PORT"

tmp="${APP_PATH}.download.$$"
if [ -n "$APP_SOURCE" ]; then
  note "Using locally transferred artifact: $APP_SOURCE"
  cp "$APP_SOURCE" "$tmp" || die "Unable to copy APP_SOURCE into the verified staging path."
else
  download "$APP_URL" "$tmp"
fi
actual_sha="$(sha256_file "$tmp" | tr 'A-F' 'a-f')"
expected_sha="$(printf '%s' "$ARTIFACT_SHA" | tr 'A-F' 'a-f')"
[ "$actual_sha" = "$expected_sha" ] || die "Artifact digest mismatch: got $actual_sha."
"$PYTHON" -m py_compile "$tmp"

if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then
  [ ! -f "$TLS_CERT" ] && [ ! -f "$TLS_KEY" ] || die "TLS certificate/key pair is incomplete; refusing insecure startup."
  note "Generating self-signed RSA certificate for $TLS_HOSTNAME and $TLS_IP."
  cert_cfg="${STATE_DIR}/openssl.$$"
  cert_tmp="${TLS_CERT}.new.$$"
  key_tmp="${TLS_KEY}.new.$$"
  cat > "$cert_cfg" <<EOF
[req]
prompt = no
distinguished_name = dn
x509_extensions = server_ext

[dn]
CN = $TLS_HOSTNAME

[server_ext]
subjectAltName = @alt_names
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = $TLS_HOSTNAME
IP.1 = $TLS_IP
EOF
  chmod 600 "$cert_cfg" || die "Cannot secure temporary OpenSSL configuration."
  openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days "$TLS_DAYS" \
    -keyout "$key_tmp" -out "$cert_tmp" -config "$cert_cfg" >/dev/null 2>&1
  chmod 600 "$key_tmp" "$cert_tmp" || die "Cannot secure generated TLS files."
  validate_tls_pair "$cert_tmp" "$key_tmp"
  tls_key_promoted=1
  mv "$key_tmp" "$TLS_KEY"
  key_tmp=""
  tls_cert_promoted=1
  mv "$cert_tmp" "$TLS_CERT"
  cert_tmp=""
  tls_generated=1
fi
chmod 600 "$TLS_CERT" "$TLS_KEY" || die "TLS files must be mode 0600."
validate_tls_pair "$TLS_CERT" "$TLS_KEY"

if [ ! -f "$AUTH_CONFIG" ] || [ "$auth_init" -eq 1 ]; then
  [ -r /dev/tty ] || die "Interactive /dev/tty is required to initialize authentication."
  if [ -f "$AUTH_CONFIG" ]; then
    auth_backup_tmp="${AUTH_CONFIG}.before.$$.tmp"
    cp "$AUTH_CONFIG" "$auth_backup_tmp"
    chmod 600 "$auth_backup_tmp" || die "Cannot secure authentication backup."
    saved_auth="${AUTH_CONFIG}.before.$$"
    mv "$auth_backup_tmp" "$saved_auth"
    auth_backup_tmp=""
  else
    auth_created=1
  fi
  note "Initializing authentication for '$AUTH_USER'; enter the EOS password at the protected prompt."
  "$PYTHON" "$tmp" --init-auth-config "$AUTH_CONFIG" --auth-user "$AUTH_USER" < /dev/tty
fi
[ -f "$AUTH_CONFIG" ] || die "Authentication initialization did not create $AUTH_CONFIG."
chmod 600 "$AUTH_CONFIG" || die "Authentication config must be mode 0600."

"$PYTHON" "$tmp" --check-config \
  --auth-config "$AUTH_CONFIG" --tls-cert "$TLS_CERT" --tls-key "$TLS_KEY"

prepare_candidate
note "Starting isolated candidate on https://127.0.0.1:$CANDIDATE_PORT/."
candidate_app="$tmp"
candidate_launched=1
if ! WEB_HISTORY_FILE="$candidate_history" WEB_LEGACY_HISTORY_FILE="$candidate_legacy_history" \
  WEB_AUDIT_FILE="$candidate_audit" \
  "$PYTHON" "$tmp" --host 127.0.0.1 --port "$CANDIDATE_PORT" \
  --auth-config "$AUTH_CONFIG" --tls-cert "$TLS_CERT" --tls-key "$TLS_KEY" \
  --pid-file "$candidate_pid" --version "$REF" --artifact-sha "$ARTIFACT_SHA" \
  --daemon --log "$candidate_log"; then
  cleanup_candidate || true
  die "Candidate process could not be launched."
fi
if ! wait_for_health "https://127.0.0.1:$CANDIDATE_PORT/healthz"; then
  cleanup_candidate || echo "WARNING: candidate process cleanup failed; investigate port $CANDIDATE_PORT." >&2
  failed_candidate_log="${STATE_DIR}/candidate-failed.log"
  rm -f "$failed_candidate_log"
  if [ -f "$candidate_log" ]; then
    mv "$candidate_log" "$failed_candidate_log"
    chmod 600 "$failed_candidate_log" || true
  fi
  candidate_log=""
  die "Candidate health check failed. See $failed_candidate_log."
fi
[ -r /dev/tty ] || die "Interactive /dev/tty is required for the authenticated candidate smoke test."
note "Verifying candidate login, session cookie, CSRF, core state API, and logout."
if ! "$PYTHON" "$tmp" --smoke-url "https://127.0.0.1:$CANDIDATE_PORT" \
  --auth-config "$AUTH_CONFIG" --tls-cert "$TLS_CERT" --tls-key "$TLS_KEY" \
  --auth-user "$AUTH_USER" < /dev/tty; then
  cleanup_candidate || echo "WARNING: candidate process cleanup failed; investigate port $CANDIDATE_PORT." >&2
  die "Candidate authenticated API smoke test failed."
fi
if ! chmod 600 "$candidate_pid"; then
  cleanup_candidate || true
  die "Candidate PID file must be mode 0600."
fi
cleanup_candidate || die "Could not stop the verified candidate process."

if [ ! -f "$PID_FILE" ] && [ -z "$LEGACY_PID" ] && port_is_listening "$PORT"; then
  die "Port $PORT already has an unmanaged listener. Supply its verified PID as LEGACY_PID if it is the legacy dashboard."
fi

wrapper_tmp="${WRAPPER_PATH}.new.$$"
cat > "$wrapper_tmp" <<EOF
#!/usr/bin/env sh
set -eu
if [ -f "$LOG" ]; then
  size=\$(wc -c < "$LOG" | tr -d ' ')
  case "\$size" in ''|*[!0-9]*) size=0 ;; esac
  if [ "\$size" -gt "$MAX_LOG_BYTES" ]; then
    rm -f "${LOG}.1"
    mv "$LOG" "${LOG}.1"
    chmod 600 "${LOG}.1"
  fi
fi
exec "$PYTHON" "$APP_PATH" --host "$HOST" --port "$PORT" \
  --auth-config "$AUTH_CONFIG" --tls-cert "$TLS_CERT" --tls-key "$TLS_KEY" \
  --pid-file "$PID_FILE" --version "$REF" --artifact-sha "$ARTIFACT_SHA" \
  --daemon --log "$LOG"
EOF
chmod 700 "$wrapper_tmp" || die "Cannot secure startup wrapper."

release_tmp="${RELEASE_FILE}.new.$$"
{
  echo "ref=$REF"
  echo "artifact_sha=$ARTIFACT_SHA"
  echo "installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$release_tmp"
chmod 600 "$release_tmp" || die "Cannot secure release metadata."

[ "$startup_enabled" -eq 0 ] || capture_event_handler
if [ -f "$APP_PATH" ]; then
  backup_tmp="${APP_PATH}.bak.$(date -u +%Y%m%d%H%M%S).$$.tmp"
  cp "$APP_PATH" "$backup_tmp"
  chmod 600 "$backup_tmp" 2>/dev/null || true
  backup="${backup_tmp%.tmp}"
  mv "$backup_tmp" "$backup"
  backup_tmp=""
  note "Backup: $backup"
fi
if [ -f "$WRAPPER_PATH" ]; then
  previous_managed=1
  saved_wrapper_tmp="${WRAPPER_PATH}.before.$$.tmp"
  cp "$WRAPPER_PATH" "$saved_wrapper_tmp"
  chmod 700 "$saved_wrapper_tmp" || die "Cannot secure previous startup wrapper."
  saved_wrapper="${WRAPPER_PATH}.before.$$"
  mv "$saved_wrapper_tmp" "$saved_wrapper"
  saved_wrapper_tmp=""
fi
if [ -f "$RELEASE_FILE" ]; then
  previous_ref="$(sed -n 's/^ref=//p' "$RELEASE_FILE" | sed -n '1p')"
  previous_sha="$(sed -n 's/^artifact_sha=//p' "$RELEASE_FILE" | sed -n '1p')"
  saved_release_tmp="${RELEASE_FILE}.before.$$.tmp"
  cp "$RELEASE_FILE" "$saved_release_tmp"
  chmod 600 "$saved_release_tmp" || die "Cannot secure previous release metadata."
  saved_release="${RELEASE_FILE}.before.$$"
  mv "$saved_release_tmp" "$saved_release"
  saved_release_tmp=""
fi

adopt_legacy_pid
if [ -f "$PID_FILE" ]; then
  production_pid="$(sed -n '1p' "$PID_FILE" 2>/dev/null || true)"
  case "$production_pid" in
    ''|*[!0-9]*) die "Invalid PID '$production_pid' in $PID_FILE." ;;
  esac
  if kill -0 "$production_pid" 2>/dev/null; then
    assert_pid_matches "$production_pid" "$APP_PATH" || \
      die "Production PID $production_pid does not contain the exact application argv path."
    production_was_running=1
  else
    rm -f "$PID_FILE"
  fi
fi
transaction_active=1
cutover_attempted=1
if [ "$production_was_running" -eq 1 ]; then
  if ! stop_pid_file "$PID_FILE" "$APP_PATH" production; then
    if [ "$production_stop_started" -eq 1 ]; then
      rollback_install || true
    else
      transaction_active=0
      cutover_attempted=0
    fi
    die "Could not stop the verified production process."
  fi
fi
if port_is_listening "$PORT"; then
  rollback_install
  die "Port $PORT remained occupied after the managed process stopped."
fi

chmod 600 "$tmp" 2>/dev/null || true
application_replaced=1
mv "$tmp" "$APP_PATH"
tmp=""
rotate_log "$LOG"

if ! sh "$wrapper_tmp" || ! wait_for_health "https://$TLS_IP:$PORT/healthz"; then
  rollback_install
  exit 1
fi
if ! chmod 600 "$PID_FILE"; then
  rollback_install
  exit 1
fi

wrapper_replaced=1
mv "$wrapper_tmp" "$WRAPPER_PATH"
wrapper_tmp=""
release_replaced=1
mv "$release_tmp" "$RELEASE_FILE"
release_tmp=""

if ! configure_startup; then
  rollback_install
  exit 1
fi

installed=1
transaction_active=0

if [ -n "$event_backup" ]; then
  rm -f "$event_backup" || echo "WARNING: could not remove $event_backup." >&2
  event_backup=""
fi
if [ -n "$saved_wrapper" ]; then
  rm -f "$saved_wrapper" || echo "WARNING: could not remove $saved_wrapper." >&2
  saved_wrapper=""
fi
if [ -n "$saved_release" ]; then
  rm -f "$saved_release" || echo "WARNING: could not remove $saved_release." >&2
  saved_release=""
fi
if [ -n "$saved_auth" ]; then
  rm -f "$saved_auth" || echo "WARNING: could not remove $saved_auth." >&2
  saved_auth=""
fi
prune_backups || echo "WARNING: old application backups could not be pruned." >&2

note "Deployment verified."
echo "Open: https://$TLS_IP:$PORT/"
echo "Certificate: $TLS_CERT (self-signed; verify/import its fingerprint before trusting it)."
echo "Release: $REF ($ARTIFACT_SHA)"
echo "No switch reboot was performed."
