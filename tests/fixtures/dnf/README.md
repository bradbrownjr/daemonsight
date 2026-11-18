# dnf5 and rpm captures

Real output from `fedora:44` containers (dnf5 5.4.6.0, `dnf5-plugins` installed;
Fedora 44 ships it by default), captured 2026-11-18 and trimmed to a few
packages. The container has no systemd or D-Bus.

- `check-upgrade.json`: `dnf check-upgrade -C --json` (exit 100)
- `check-upgrade-security.json`: `dnf check-upgrade -C --security --json` (exit 100)
- `needs-restarting-reboot.json`: `dnf needs-restarting -C --json` after `dnf reinstall glibc` (exit 1)
- `nocache.txt`: what `-C` prints with no metadata cache (exit 1)
- `versionlock-list.txt`: `dnf versionlock list` after `dnf versionlock add tzdata`
- `rpm-evr.txt`: `rpm -q --qf '%{NAME}\t%{ARCH}\t%{EVR}\n' ...`
- `kernel-core-rpm-qp.txt`: `rpm -qp kernel-core-*.rpm --qf '%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n'`
- `os-release-fedora44.txt`, `dnf-version.txt`: `/etc/os-release` (trimmed), `dnf --version`

The package list in the two check-upgrade files was cut from the full output.
`dnf needs-restarting -s` could not be captured (no D-Bus in a container).
