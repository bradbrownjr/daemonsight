# Bundled release data

`debian.csv` and `ubuntu.csv` are copied unchanged from the Debian
`distro-info-data` package. DaemonSight reads them to tell whether a host's
Debian or Ubuntu release still gets security updates.

- Source: https://salsa.debian.org/debian/distro-info-data (files under `main`)
  - https://salsa.debian.org/debian/distro-info-data/-/raw/main/debian.csv
  - https://salsa.debian.org/debian/distro-info-data/-/raw/main/ubuntu.csv
- Licence: ISC. The upstream notice is in `COPYRIGHT` (from `debian/copyright`,
  https://salsa.debian.org/debian/distro-info-data/-/raw/main/debian/copyright).
  Copyright 2009-2024 Benjamin Drung, 2009-2021 Stefano Rivera.
- Fetched: 2026-11-18

At run time DaemonSight prefers `/usr/share/distro-info/<distro>.csv` when the
host has the `distro-info-data` package and the file has the release. Update
the bundled copies by downloading the two files again and changing the date
above.
