#!/usr/bin/env bash
# Install or upgrade DaemonSight on Debian 12 or 13, Ubuntu or Fedora. Run as root from the repo.
#
#   sudo ./install.sh              collector + web UI, or the options used last time
#   sudo ./install.sh --collector  collector only, no web UI
#   sudo ./install.sh --web        collector + web UI (to switch back from --collector)
#   sudo ./install.sh --fail2ban   also install the login jail for fail2ban
#
# Later updates: sudo daemonsight-update
set -euo pipefail

PREFIX=/opt/daemonsight
ETC=/etc/daemonsight
DATA=/var/lib/daemonsight
USER_NAME=daemonsight
WITH_WEB=1
WITH_F2B=0
OPTIONS_FILE=$ETC/install.options

# With no options, reuse the ones recorded by the last install.
if [[ $# -eq 0 && -f $OPTIONS_FILE ]]; then
  grep -q '^WITH_WEB=0$' "$OPTIONS_FILE" && WITH_WEB=0
  grep -q '^WITH_F2B=1$' "$OPTIONS_FILE" && WITH_F2B=1
fi

for arg in "$@"; do
  case "$arg" in
    --collector) WITH_WEB=0 ;;
    --web) WITH_WEB=1 ;;
    --fail2ban) WITH_F2B=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo ./install.sh)." >&2; exit 1; }
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$REPO/pyproject.toml" ]] || { echo "Run this from the DaemonSight repo." >&2; exit 1; }

# Missing-package hints follow the host's package manager. On Fedora the venv
# module comes with python3 itself; there is no python3-venv package.
if command -v dnf >/dev/null 2>&1; then
  HINT_PY="dnf install python3"; HINT_VENV="dnf install python3"; HINT_GIT="dnf install git"
else
  HINT_PY="apt install python3"; HINT_VENV="apt install python3-venv"; HINT_GIT="apt install git"
fi
command -v python3 >/dev/null 2>&1 || { echo "Install python3 first: $HINT_PY" >&2; exit 1; }
python3 - <<'EOF' || { echo "Python 3.11 or newer is required." >&2; exit 1; }
import sys
sys.exit(0 if sys.version_info >= (3, 11) else 1)
EOF
python3 -c "import venv, ensurepip" 2>/dev/null || { echo "Install the venv module first: $HINT_VENV" >&2; exit 1; }
command -v git >/dev/null 2>&1 || echo "git is not installed; daemonsight-update needs it (as root: $HINT_GIT)." >&2

echo "==> User and folders"
if ! getent passwd "$USER_NAME" >/dev/null; then
  useradd --system --user-group --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
fi
# setgid so the database and its -wal/-shm files get the daemonsight group.
install -d -m 2750 -o root -g "$USER_NAME" "$DATA"
install -d -m 0750 -o root -g "$USER_NAME" "$ETC"

echo "==> Python environment in $PREFIX/venv"
install -d -m 0755 "$PREFIX"
[[ -x "$PREFIX/venv/bin/python" ]] || python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet -r "$REPO/requirements.txt"
"$PREFIX/venv/bin/pip" install --quiet --no-deps --force-reinstall "$REPO"
ln -sf "$PREFIX/venv/bin/daemonsight" /usr/local/bin/daemonsight
install -m 0755 -o root -g root "$REPO/packaging/daemonsight-update" /usr/local/sbin/daemonsight-update
# The commit this install came from, shown by `daemonsight --version` and in the UI.
REV=$(git -c safe.directory="$REPO" -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo "local")
if [[ $REV != local ]] && ! git -c safe.directory="$REPO" -C "$REPO" diff --quiet HEAD 2>/dev/null; then
  REV="$REV-modified"
fi
echo "$REV" > "$PREFIX/REVISION"
chmod 0644 "$PREFIX/REVISION"

# SELinux (Fedora enforces it). Files under /opt get usr_t by default and a
# systemd service running them gets the unconfined_service_t domain, so no
# policy is needed (unconfined_service_selinux(8)). This only fixes labels on
# files that were moved in rather than created here.
if command -v restorecon >/dev/null 2>&1; then
  restorecon -R "$PREFIX" "$ETC" "$DATA" 2>/dev/null || true
fi

echo "==> Configuration"
if [[ ! -f "$ETC/config.toml" ]]; then
  install -m 0640 -o root -g "$USER_NAME" "$REPO/packaging/config.example.toml" "$ETC/config.toml"
fi
(umask 027 && daemonsight init)
printf 'WITH_WEB=%s\nWITH_F2B=%s\n' "$WITH_WEB" "$WITH_F2B" > "$OPTIONS_FILE"
chmod 0644 "$OPTIONS_FILE"

echo "==> systemd units"
install -m 0644 "$REPO/packaging/systemd/daemonsight-collector.service" /etc/systemd/system/
install -m 0644 "$REPO/packaging/systemd/daemonsight-update.service" "$REPO/packaging/systemd/daemonsight-update.path" \
  /etc/systemd/system/
if [[ $WITH_WEB -eq 1 ]]; then
  install -m 0644 "$REPO/packaging/systemd/daemonsight-web.service" /etc/systemd/system/
fi
systemctl daemon-reload
systemctl enable --now daemonsight-collector.service
systemctl restart daemonsight-collector.service
# Installs updates the hub asks for; [upload] remote_update = false turns that off.
systemctl enable --now daemonsight-update.path

if [[ $WITH_F2B -eq 1 ]]; then
  if [[ -d /etc/fail2ban/filter.d ]]; then
    echo "==> fail2ban jail"
    install -m 0644 "$REPO/packaging/fail2ban/filter.d/daemonsight.conf" /etc/fail2ban/filter.d/
    install -m 0644 "$REPO/packaging/fail2ban/jail.d/daemonsight.conf" /etc/fail2ban/jail.d/
    systemctl reload fail2ban || systemctl restart fail2ban
  else
    echo "fail2ban is not installed; skipped the jail." >&2
  fi
fi

if [[ $WITH_WEB -eq 1 ]]; then
  systemctl enable daemonsight-web.service
  if [[ -s "$ETC/password" ]]; then
    systemctl restart daemonsight-web.service
    echo "Web UI restarted."
  else
    echo
    echo "Set the login password, then start the web UI:"
    echo "  sudo daemonsight set-password"
    echo "  sudo systemctl start daemonsight-web"
  fi
fi

echo
echo "Done. Collector status: systemctl status daemonsight-collector"
