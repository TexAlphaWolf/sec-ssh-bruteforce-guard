#!/bin/sh
# Install sshguard as a hardened systemd service. Run as root from the repository root.
# It starts in dry-run mode: read `journalctl -u sshguard -f`, then edit the config and restart.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 (3.11+) is required" >&2; exit 1; }

id -u sshguard >/dev/null 2>&1 || useradd --system --user-group --no-create-home \
  --home-dir /var/lib/sshguard --shell /usr/sbin/nologin sshguard
for group in adm systemd-journal; do
  getent group "$group" >/dev/null && usermod -aG "$group" sshguard
done

python3 -m venv /opt/sshguard/venv
/opt/sshguard/venv/bin/pip install --quiet .

install -d -m 0755 /etc/sshguard
[ -e /etc/sshguard/config.toml ] || install -m 0644 deploy/config.example.toml /etc/sshguard/config.toml
install -m 0644 deploy/sshguard.service /etc/systemd/system/sshguard.service
systemctl daemon-reload
/opt/sshguard/venv/bin/sshguard check-config -c /etc/sshguard/config.toml
systemctl enable --now sshguard
echo "sshguard is running in the mode set in /etc/sshguard/config.toml (default: dry-run)"
