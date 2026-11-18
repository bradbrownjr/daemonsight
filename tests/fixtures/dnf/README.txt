Output of `dnf advisory list --updates --security --json -C` and
`dnf advisory info --updates --security --json -C` on fedora:44 (dnf5 5.4.x),
2026-11-18, whole except that each advisory's "collections.packages" is cut to
three entries (the real lists name every architecture and subpackage). The
default filter (`--available`) printed the same four advisories. The collector
takes package names from the list output, which holds installed packages only.
