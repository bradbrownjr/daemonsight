Real files from the OPNsense changelog repository (https://github.com/opnsense/changelog, BSD 2-Clause, the LICENSE file
here), copied unchanged on 2026-11-24 from community/<series>/<release>. They are the samples the changelog parser
(src/daemonsight/cve/opnsense.py) is tested on: releases with a CVE in a footnote, inline in a bullet, in a lead line,
only in prose (not counted), hotfix sections, advisories without a CVE id, a four-part version and a release candidate.
tests/test_opnsense_cves.py builds a tarball like the one codeload.github.com serves from these.
