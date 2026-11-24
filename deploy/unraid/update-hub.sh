#!/usr/bin/env bash
# Update the DaemonSight hub container on an Unraid server, then ask the hosts
# to update. Run it on the Unraid server as root:
#
#   bash update-hub.sh [expected-commit-sha]
#
# What it does, in order:
#   1. Takes the lock /tmp/daemonsight-update.lock, so two runs can't overlap.
#   2. Pulls ghcr.io/bradbrownjr/daemonsight:edge. With a commit sha, it checks
#      the image's org.opencontainers.image.revision label starts with it. If
#      not, it stops here and leaves every container as it was.
#   3. Builds the container's `docker run` command from its Unraid template
#      (/boot/config/plugins/dockerMan/templates-user/my-daemonsight.xml),
#      using Unraid's own PHP, and checks the command names the container
#      before anything is stopped.
#   4. Stops the hub (20 s), removes it and runs the new command.
#   5. Waits up to 5 minutes for the hub to be healthy and prints its version.
#   6. If a container named daemonsight-docker-reader exists, recreates it the
#      same way from its own template.
#   7. Runs `daemonsight hub update --all` in the hub, which asks every host
#      that is behind to install the hub's version.
#
# It never deletes data: the hub's /data folder is a host folder that
# `docker rm` leaves alone, and the script touches nothing else.
#
# It does not call Unraid's rebuild_container or update_container scripts:
# they once failed without an error and left no container.
#
# The PHP below includes Unraid's webgui code (DockerClient.php under
# /usr/local/emhttp/plugins/dynamix.docker.manager). Tested on Unraid 7.x; a
# later release that moves those files makes step 3 fail, and the script stops
# before stopping anything.
#
# Exit codes:
#   0  done
#   1  not run as root, wrong usage, or Docker or Unraid's files are missing
#   2  another run holds the lock
#   3  the image could not be pulled, or has no revision label
#   4  the image is not the expected commit; nothing was changed
#   5  the run command could not be built from the template; nothing was changed
#   6  the hub container could not be stopped, removed or started
#   7  the hub did not become healthy in time
#   8  the Docker reader could not be recreated
#   9  `hub update --all` failed

set -uo pipefail

IMAGE="ghcr.io/bradbrownjr/daemonsight:edge"
HUB="daemonsight"
READER="daemonsight-docker-reader"
LOCK="/tmp/daemonsight-update.lock"
HEALTH_WAIT=300   # seconds
EXPECT="${1:-}"

die() { local code=$1; shift; echo "update-hub: $*" >&2; exit "$code"; }
say() { echo "==> $*"; }

[[ $# -le 1 ]] || die 1 "usage: update-hub.sh [expected-commit-sha]"
[[ -z $EXPECT || $EXPECT =~ ^[0-9a-fA-F]{7,40}$ ]] || die 1 "'$EXPECT' is not a commit sha (7 to 40 hex digits)"
[[ $EUID -eq 0 ]] || die 1 "run as root"
command -v docker >/dev/null 2>&1 || die 1 "docker not found"
command -v php >/dev/null 2>&1 || die 1 "php not found (this script is for Unraid)"
command -v flock >/dev/null 2>&1 || die 1 "flock not found"
[[ -f /usr/local/emhttp/plugins/dynamix.docker.manager/include/DockerClient.php ]] \
  || die 1 "Unraid's DockerClient.php is missing; is this an Unraid server?"

# 1. One run at a time.
exec 9>"$LOCK"
flock -n 9 || die 2 "another update is running (lock $LOCK)"

WORK="$(mktemp -d /tmp/daemonsight-update.XXXXXX)" || die 1 "cannot make a temporary folder"
trap 'rm -rf "$WORK"' EXIT

# 3 (written first so step 2 can fail early). Rebuild a container's run command
# from its Unraid template. Same PHP as Unraid's own helper; var.ini is loaded
# so TZ and HOST_HOSTNAME are set, and warnings go to stderr.
cat > "$WORK/cmd.php" <<'PHP'
<?php
ini_set("display_errors", "stderr"); error_reporting(E_ALL);
$docroot = "/usr/local/emhttp";
require_once "$docroot/plugins/dynamix.docker.manager/include/DockerClient.php";
$var = parse_ini_file("/var/local/emhttp/var.ini");
$DockerClient = new DockerClient(); $DockerTemplates = new DockerTemplates();
$custom = DockerUtil::custom(); $subnet = DockerUtil::network($custom); $cpus = DockerUtil::cpus();
[$cmd, $name, $repo] = xmlToCommand($DockerTemplates->getUserTemplate($argv[1] ?? "daemonsight"));
echo str_replace("/docker create ", "/docker run -d ", $cmd), "\n";
PHP

# make_cmd NAME FILE: write NAME's run command to FILE; fail if it is not for NAME.
make_cmd() {
  local name=$1 file=$2
  php "$WORK/cmd.php" "$name" > "$file" 2> "$WORK/php.err" || { cat "$WORK/php.err" >&2; return 1; }
  [[ -s $file ]] || { echo "the template for $name gave an empty command" >&2; return 1; }
  grep -q -- "--name='$name'" "$file" || { echo "the command for $name does not contain --name='$name'" >&2; return 1; }
}

# recreate NAME FILE: stop and remove NAME, then run the command in FILE.
recreate() {
  local name=$1 file=$2
  docker stop -t 20 "$name" >/dev/null || return 1
  docker rm "$name" >/dev/null || return 1
  bash "$file" >/dev/null
}

# 2. Pull the image.
say "Pulling $IMAGE"
docker pull "$IMAGE" || die 3 "docker pull failed; nothing was changed"
REV="$(docker image inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$IMAGE" 2>/dev/null)" \
  || die 3 "cannot read the image's labels; nothing was changed"
[[ -n $REV ]] || die 3 "the image has no org.opencontainers.image.revision label; nothing was changed"
echo "image revision: $REV"
if [[ -n $EXPECT ]]; then
  expect_lc="${EXPECT,,}"
  [[ ${REV,,} == "$expect_lc"* ]] \
    || die 4 "the image is revision ${REV:0:12}, not $EXPECT. CI may not have published it yet; nothing was changed"
fi

# 3. Build the commands (before stopping anything).
say "Building the run command from the Unraid template"
make_cmd "$HUB" "$WORK/hub.sh" || die 5 "cannot build the hub's command; nothing was changed"
HAVE_READER=0
if docker container inspect "$READER" >/dev/null 2>&1; then
  HAVE_READER=1
  make_cmd "$READER" "$WORK/reader.sh" || die 5 "cannot build the reader's command; nothing was changed"
fi

# 4. Recreate the hub.
say "Recreating $HUB"
recreate "$HUB" "$WORK/hub.sh" || die 6 "could not recreate $HUB; check 'docker ps -a' and the Docker tab. Data in /data is untouched"

# 5. Wait for health.
say "Waiting for $HUB to be healthy (up to $((HEALTH_WAIT / 60)) minutes)"
status=""
for ((t = 0; t < HEALTH_WAIT; t += 5)); do
  status="$(docker inspect -f '{{ if .State.Running }}{{ if .State.Health }}{{ .State.Health.Status }}{{ else }}nohealthcheck{{ end }}{{ else }}stopped{{ end }}' "$HUB" 2>/dev/null)"
  [[ $status == healthy ]] && break
  [[ $status == stopped ]] && break
  sleep 5
done
[[ $status == healthy ]] || die 7 "$HUB is '$status', not healthy; see 'docker logs $HUB'"
docker exec "$HUB" daemonsight --version || die 7 "$HUB is healthy but 'daemonsight --version' failed"

# 6. The Docker reader, if there is one.
if [[ $HAVE_READER -eq 1 ]]; then
  say "Recreating $READER"
  recreate "$READER" "$WORK/reader.sh" || die 8 "could not recreate $READER; check 'docker ps -a'. The hub is already updated"
  sleep 3
  [[ "$(docker inspect -f '{{ .State.Running }}' "$READER" 2>/dev/null)" == true ]] \
    || die 8 "$READER is not running after the update; see 'docker logs $READER'"
fi

# 7. Ask the hosts.
say "Asking the hosts to update"
docker exec "$HUB" daemonsight hub update --all || die 9 "'hub update --all' failed; the hub is updated, the hosts are not"

say "Done. Each host shows 'Updated to ...' under Recent changes when it has installed the update."
