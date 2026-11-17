#!/usr/bin/env bash
# Install or upgrade DaemonSight on Debian 12 or 13. Run as root from the repo.
#
#   sudo ./install.sh              collector + web UI
#   sudo ./install.sh --no-web     collector only (agent)
#   sudo ./install.sh --fail2ban   also install the login jail for fail2ban
set -euo pipefail

PREFIX=/opt/daemonsight
ETC=/etc/daemonsight
DATA=/var/lib/daemonsight
USER_NAME=daemonsight
WITH_WEB=1
WITH_F2B=0

for arg in "$@"; do
  case "$arg" in
    --no-web) WITH_WEB=0 ;;
    --fail2ban) WITH_F2B=1 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo ./install.sh)." >&2; exit 1; }
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$REPO/pyproject.toml" ]] || { echo "Run this from the DaemonSight repo." >&2; exit 1; }

python3 - <<'EOF' || { echo "Python 3.11 or newer is required." >&2; exit 1; }
import sys
sys.exit(0 if sys.version_info >= (3, 11) else 1)
EOF
python3 -c "import venv, ensurepip" 2>/dev/null || { echo "Install python3-venv first: apt install python3-venv" >&2; exit 1; }

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

echo "==> Configuration"
if [[ ! -f "$ETC/config.toml" ]]; then
  install -m 0640 -o root -g "$USER_NAME" "$REPO/packaging/config.example.toml" "$ETC/config.toml"
fi
(umask 027 && daemonsight init)

echo "==> systemd units"
install -m 0644 "$REPO/packaging/systemd/daemonsight-collector.service" /etc/systemd/system/
if [[ $WITH_WEB -eq 1 ]]; then
  install -m 0644 "$REPO/packaging/systemd/daemonsight-web.service" /etc/systemd/system/
fi
systemctl daemon-reload
systemctl enable --now daemonsight-collector.service
systemctl restart daemonsight-collector.service

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
