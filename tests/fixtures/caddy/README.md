# Caddy adapter test cases

Copied unchanged from Caddy v2.11.9,
`caddytest/integration/caddyfile_adapt/` (Apache License 2.0,
https://github.com/caddyserver/caddy). Each file is a Caddyfile, a line of
dashes, and the JSON config Caddy's adapter produces from it. The tests parse
the JSON half, so DaemonSight is checked against real Caddy output.
