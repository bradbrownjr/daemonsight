# GitHub repository settings (manual)

Not applied by any script. The owner sets these in the repository's web UI.

## About description

Settings via the gear next to "About" on the repository page (350 characters at most).

```
Self-hosted security dashboard for Linux servers, Docker, Unraid and OPNsense. Shows what the internet can reach, CVEs ranked by CISA KEV and EPSS, and what to fix, with the command. Read-only, no agent on Unraid or OPNsense.
```

## Topics

At most 20, lowercase letters, numbers and hyphens (GitHub Docs: classifying your repository with topics).

```
self-hosted homelab security attack-surface vulnerability-scanner cve docker unraid opnsense crowdsec fail2ban caddy linux server-monitoring dashboard python fastapi htmx
```

## Social preview

Upload `docs/images/social-preview.png` (1280 x 640 px, PNG, under 1 MB) at Settings, then Social preview, Edit, Upload an image. GitHub asks for at least 640 x 320 px, 1280 x 640 px for the best display.
Remake it with `python scripts/social_preview.py`.
