# Unraid API fixtures

Responses to the queries in `src/daemonsight/remote/unraid.py`, captured from
a real Unraid 7.3.2 server (read-only queries only) and trimmed. Serials,
host and server names, container and VM names, images and the CPU model were
replaced with placeholders. `notifications.json` keeps Unraid's real notification
titles, subjects and descriptions (the classification depends on them) with the
server name changed to `tower-test`, disk model and serial strings replaced by
`EXAMPLE-DISK`, and ids made up; it is trimmed to 56 of the 235 unread warnings and
alerts (all 13 "Unclean shutdown detected" alerts are kept). The numbers (sizes, usage,
temperatures, error counts, parity history) are the real ones.

- `me_admin.json`: what `me` returned for an Admin key (first four permissions only).
- `me_viewer.json` and `me_viewer_with_write.json`: not captured. A Viewer key's
  reply has the same shape as `me_admin.json`, with `roles: ["VIEWER"]` and no
  explicit permissions (see `api/src/unraid-api/auth/auth.service.ts`,
  `validateApiKeyCasbin`, which returns the stored roles and permissions).
- `folders.json`: the Docker tab's folder tree (`docker { organizer }`). The shape is the real one (checked against
  a live read: depth-first `flatEntries`, `root` folder, container ids that are the Docker names); the folders and
  container names are placeholders matching `docker.json`, with a nested folder and one container Docker no
  longer has.
- `release.json`: not captured. The reply of `https://releases.unraid.net/os?branch=stable`, in the shape
  read from that public page (`version`, `name`, `date`, `changelogPretty`, ...).
- `docker.json`: each container has an `id` in Unraid's PrefixedID form (`<server id>:<64 hex digits>`); the ids
  here are made up (the server part is a counting pattern, the rest a SHA-256 of the container name). The
  statistics subscription (`dockerContainerStats`) is not a fixture: `tests/fake_unraid.py` builds its messages,
  from the shape read in the schema and seen live (one message per container, the first of each refresh with a
  terminal control code in front of its id).
