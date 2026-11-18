# Fedora release data

`fedora.csv` has one row per Fedora release: `version`, `eol` (end-of-life
date; empty when unknown) and `state` (`archived` once past end of life,
`current` once released, `pending` before release). DaemonSight reads it to
tell whether a host's Fedora release still gets security updates. Fedora has
no LTS: a release is supported until its end-of-life date, which Fedora's
policy sets four weeks after the release two versions later
(https://docs.fedoraproject.org/en-US/releases/lifecycle/).

- Source: https://endoflife.date/api/v1/products/fedora (`name`,
  `releaseDate`, `isEol`, `eolFrom`).
- Licence: MIT, endoflife.date contributors
  (https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE).
- Fetched: 2026-11-18.
- Cross-check: Fedora's Bodhi API agrees on every date except Fedora 43
  (Bodhi: 2026-12-02). A Fedora 44 host's `/etc/os-release` says
  `SUPPORT_END=2027-05-19`, an estimate set when the release was built.

Update by downloading the JSON again and rewriting the CSV, then change the
date above.
