# Unraid API fixtures

Responses to the queries in `src/daemonsight/remote/unraid.py`, captured from
a real Unraid 7.3.2 server (read-only queries only) and trimmed. Serials,
host and server names, container and VM names, images, notification text and
the CPU model were replaced with placeholders. The numbers (sizes, usage,
temperatures, error counts, parity history) are the real ones.

- `me_admin.json`: what `me` returned for an Admin key (first four permissions only).
- `me_viewer.json` and `me_viewer_with_write.json`: not captured. A Viewer key's
  reply has the same shape as `me_admin.json`, with `roles: ["VIEWER"]` and no
  explicit permissions (see `api/src/unraid-api/auth/auth.service.ts`,
  `validateApiKeyCasbin`, which returns the stored roles and permissions).
