# End-of-life dates for other base images

`alpine.csv` and `centos.csv` have one row per release: `version` (Alpine's
cycle such as `3.17`, CentOS's major version such as `8`), `released` and
`eol` (the date security support ends). DaemonSight reads them to tell whether a
container image's base operating system still gets security updates (see
`distro.evaluate_image`). Debian, Ubuntu and Fedora images use the same data as
hosts: `data/distro-info` and `data/fedora`.

- Source: https://endoflife.date/api/v1/products/alpine-linux/ and
  https://endoflife.date/api/v1/products/centos/ (`name`, `releaseDate`,
  `eolFrom`). The address `/api/v1/products/alpine/` redirects to
  `alpine-linux`.
- Licence: MIT, endoflife.date contributors
  (https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE).
- Fetched: 2026-11-20.
- `centos.csv` is CentOS Linux (5 to 8). CentOS Stream is a separate product
  that endoflife.date lists as `centos-stream`; it is not judged here.

Update by downloading the JSON again and rewriting the CSV, then change the
date above.
