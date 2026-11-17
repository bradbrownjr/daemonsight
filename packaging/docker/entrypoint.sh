#!/bin/sh
# Start the DaemonSight hub. On the first start, write /data/config.toml
# from the template and create the session secret and the database.
set -eu

CONFIG="${DAEMONSIGHT_CONFIG:-/data/config.toml}"
if [ ! -f "$CONFIG" ]; then
    (umask 077 && cp /etc/daemonsight/hub.toml "$CONFIG")
    echo "Wrote $CONFIG. Edit it, then restart the container."
fi

(umask 027 && daemonsight init)

if [ "${1:-}" = "web" ] && [ ! -s /data/password ]; then
    echo "No login password yet. Set one with:"
    echo "  docker exec -it <container> daemonsight set-password"
fi

exec daemonsight "$@"
