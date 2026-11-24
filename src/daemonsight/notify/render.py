"""One message, drawn four ways: for Ntfy, Slack, Discord and email.

A `Note` is what to say (built in engine.py from the changes, or from a digest's window): sections of findings, a headline
and a footer. Each renderer below turns it into the service's own payload and stays inside that service's published
limits (docs/DESIGN.md, "Alert channels", lists them with their sources). What does not fit is cut off with "and N more" and
a link to the hub, never by cutting a line in half.

Text from findings (titles, host names) can hold anything a package name or a server's own message holds, so each renderer
neutralises it for its service:
  Ntfy     plain text only (no Markdown flag is sent)
  Slack    & < > become entities, so `<!channel>` and `<@U123>` can't form; * _ ~ ` get a zero-width space so a title can't
           turn bold or italic; an @ gets one too
  Discord  Markdown characters are backslash-escaped, < is escaped, an @ gets a zero-width space, and the message carries
           allowed_mentions with an empty `parse`, which is Discord's own switch for "mention nobody"
  Email    every value goes through html.escape; links are only ever the hub's own address
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from urllib.parse import quote

ZWSP = "​"
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
SEV_ORDER = ("critical", "high", "medium", "low", "info")
# Discord's embed colour is an integer (docs: "color code of the embed"); Ntfy's priority 1 to 5 (5 = max/urgent).
SEV_COLOR = {"critical": 0xD63939, "high": 0xF76707, "medium": 0xF59F00, "low": 0x4299E1, "info": 0x667382}
GOOD_COLOR, TEST_COLOR = 0x2FB344, 0x0D9488
NTFY_PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
NTFY_TAGS = {"critical": "rotating_light", "high": "warning", "medium": "large_orange_diamond", "low": "information_source",
             "info": "information_source"}

# Service limits (see DESIGN.md for where each comes from). The budgets leave room under the documented maximum.
NTFY_MESSAGE_BYTES, NTFY_BUDGET = 4096, 3700           # "Each message can be up to 4,096 bytes long."
NTFY_TITLE_CHARS = 250                                  # "The message title is limited to 1 KB"
SLACK_BLOCKS, SLACK_SECTION_CHARS, SLACK_HEADER_CHARS = 50, 3000, 150
SLACK_SECTION_BUDGET = 2800
DISCORD_TITLE, DISCORD_DESC, DISCORD_TOTAL = 256, 4096, 6000
DISCORD_DESC_BUDGET = 3800
DISCORD_FIELD_NAME, DISCORD_FIELD_VALUE, DISCORD_FIELDS, DISCORD_FOOTER = 256, 1024, 25, 2048
EMAIL_SECTION_ITEMS = 100
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ]")


@dataclass
class Item:
    severity: str
    title: str
    host: str = ""
    url: str | None = None
    deadline: str | None = None        # "due Thu 26 Nov 14:00 EST", "overdue since Mon 23 Nov"
    prev: str | None = None            # the severity before, for a finding that got worse


@dataclass
class Section:
    label: str
    items: list[Item]


@dataclass
class Note:
    kind: str                           # alert, digest, test
    headline: str
    sections: list[Section] = field(default_factory=list)
    footer: str = ""                    # "DaemonSight 0.1.0 (abc1234) · https://hub.example.com"
    hub_url: str | None = None
    summary: str | None = None          # a digest's one-line state: "No changes; 7 open (critical, high)"
    counts: list[tuple[str, int]] = field(default_factory=list)   # a digest: open by severity
    good: bool = False                  # only resolutions: green, not red

    @property
    def top(self) -> str:
        found = [i.severity for s in self.sections for i in s.items]
        for sev in SEV_ORDER:
            if sev in found:
                return sev
        return "info"

    @property
    def total(self) -> int:
        return sum(len(s.items) for s in self.sections)


def clean(text: object, limit: int = 300) -> str:
    """One line of plain text: control characters and line breaks become spaces, and it is cut to `limit` characters."""
    out = " ".join(_CONTROL.sub(" ", str(text if text is not None else "")).split())
    return out if len(out) <= limit else out[:limit - 1].rstrip() + "…"


def sev_label(sev: str) -> str:
    return SEV_LABEL.get(sev, str(sev).capitalize())


def _safe_url(url: str | None) -> str | None:
    """A link only if it is http(s) and has no character that could end a Slack or Markdown link early."""
    if not url or not re.match(r"^https?://[^\s<>|()\[\]\"'\\]+$", url):
        return None
    return url


def finding_url(hub_url: str | None, host: str, link: str | None) -> str | None:
    """The finding's address on the hub: pages live under /h/<host>. Anything that is not an address on the hub's own
    site (a link must start with one slash) is left out."""
    if not hub_url:
        return None
    base = hub_url.rstrip("/") + "/h/" + quote(host, safe="")
    if link and link.startswith("/") and not link.startswith("//"):
        return _safe_url(base + quote(link, safe="/#-._~:@!$&'*+,;=%"))
    return _safe_url(base + "/")


# --- plain text (Ntfy, and the plain part of an email) ---------------------------------

def _plain_line(i: Item, with_url: bool) -> list[str]:
    bits = [f"{sev_label(i.severity).upper()}: {clean(i.title)}"]
    meta = [m for m in (clean(i.host, 80) or None, i.deadline) if m]
    if i.prev:
        meta.append(f"was {i.prev}")
    if meta:
        bits.append(f"({'; '.join(meta)})")
    lines = [" ".join(bits)]
    if with_url and i.url:
        lines.append("  " + i.url)
    return lines


def _more(n: int, hub_url: str | None) -> str:
    return f"and {n} more" + (f". See {hub_url}" if hub_url else ".")


def plain_text(note: Note, budget: int | None = None, with_urls: bool = True, per_section: int | None = None) -> str:
    """The note as text. With `budget` (bytes, UTF-8) it stops before going over and says how many it left out."""
    size = (lambda s: len(s.encode("utf-8"))) if budget else (lambda s: 0)
    lines: list[str] = []
    used = 0
    hidden = 0

    def add(block: list[str]) -> bool:
        nonlocal used
        cost = size("\n".join(block)) + 1
        if budget and used + cost > budget:
            return False
        lines.extend(block)
        used += cost
        return True

    if note.summary:
        add([note.summary, ""])
    if note.counts:
        add(["Open now: " + ", ".join(f"{n} {sev}" for sev, n in note.counts if n), ""])
    reserve = size(_more(999, note.hub_url)) + size("\n" + note.footer) + 8 if budget else 0
    for sec in note.sections:
        if not sec.items:
            continue
        head = [f"{sec.label} ({len(sec.items)})"]
        if budget and used + size(head[0]) + reserve > budget:
            hidden += len(sec.items)
            continue
        lines.extend(head)
        used += size(head[0]) + 1
        shown = 0
        for it in sec.items:
            if per_section is not None and shown >= per_section:
                break
            block = _plain_line(it, with_urls)
            if budget and used + size("\n".join(block)) + 1 + reserve > budget:
                break
            lines.extend(block)
            used += size("\n".join(block)) + 1
            shown += 1
        hidden += len(sec.items) - shown
        lines.append("")
        used += 1
    if hidden:
        lines.append(_more(hidden, note.hub_url))
        lines.append("")
    if note.footer:
        lines.append(note.footer)
    return "\n".join(lines).strip()


# --- Ntfy ------------------------------------------------------------------------------

def ntfy_payload(note: Note, topic: str) -> dict:
    """The JSON for a POST to the Ntfy server's root: topic, title, message, priority, tags and click, all documented fields."""
    top = note.top
    title = clean(note.headline, NTFY_TITLE_CHARS)
    if note.kind == "alert" and not note.good:
        priority, tags = NTFY_PRIORITY[top], [NTFY_TAGS[top], top]
    elif note.kind == "test":
        priority, tags = 3, ["bell", "daemonsight"]
    else:                                   # a digest, or an alert that only has resolutions
        priority, tags = 3, ["white_check_mark" if note.good else "clipboard", "daemonsight"]
    items = [i for s in note.sections for i in s.items]
    click = items[0].url if len(items) == 1 and items[0].url else note.hub_url
    body = plain_text(note, NTFY_BUDGET)
    payload = {"topic": topic, "title": title, "message": body, "priority": priority, "tags": tags}
    if click:
        payload["click"] = click
    return payload


# --- Slack -----------------------------------------------------------------------------

def slack_escape(text: object, limit: int = 300) -> str:
    """Text safe to put in Slack mrkdwn: & < > become entities (Slack's own rule for control characters), so a mention or
    link can't be written into a title; formatting characters and @ get a zero-width space."""
    t = clean(text, limit).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = re.sub(r"([*_~`])", r"\1" + ZWSP, t)
    return t.replace("@", "@" + ZWSP)


def _slack_line(i: Item) -> str:
    title = slack_escape(i.title)
    url = _safe_url(i.url)
    head = f"*{sev_label(i.severity)}* " + (f"<{url}|{title}>" if url else title)
    meta = [m for m in (slack_escape(i.host, 80) or None, slack_escape(i.deadline) if i.deadline else None) if m]
    if i.prev:
        meta.append(f"was {slack_escape(i.prev, 20)}")
    return head + (" · " + " · ".join(meta) if meta else "")


def slack_payload(note: Note) -> dict:
    blocks: list[dict] = [{"type": "header", "text": {"type": "plain_text", "text": clean(note.headline, SLACK_HEADER_CHARS)[:SLACK_HEADER_CHARS]}}]
    fallback = slack_escape(note.headline, 300)      # the top-level text is mrkdwn too
    if note.summary:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": slack_escape(note.summary, 500)}})
    if note.counts:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text":
                       "Open now: " + ", ".join(f"{n} {slack_escape(sev, 20)}" for sev, n in note.counts if n)}})
    cap = SLACK_BLOCKS - 2           # leave room for the "and N more" block and the footer
    hidden = 0
    for sec in note.sections:
        if not sec.items:
            continue
        head = f"*{slack_escape(sec.label, 60)}* ({len(sec.items)})"
        chunks, cur = [], [head]
        for it in sec.items:
            line = _slack_line(it)
            if len(line) > SLACK_SECTION_BUDGET:
                line = line[:SLACK_SECTION_BUDGET - 1] + "…"
            if len("\n".join(cur + [line])) > SLACK_SECTION_BUDGET:
                chunks.append(cur)
                cur = [line]
            else:
                cur.append(line)
        chunks.append(cur)
        shown = 0
        for n, chunk in enumerate(chunks):
            if len(blocks) >= cap:
                break
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(chunk)}})
            shown += len(chunk) - (1 if n == 0 else 0)
        hidden += len(sec.items) - shown
    if hidden:
        more = f"and {hidden} more"
        url = _safe_url(note.hub_url)
        more += f". <{url}|Open DaemonSight>" if url else "."
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": more}})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": slack_escape(note.footer, 300)}]})
    return {"text": fallback, "blocks": blocks[:SLACK_BLOCKS]}


# --- Discord -----------------------------------------------------------------------------

_DISCORD_MD = re.compile(r"([\\*_~`|>#\[\]<])")


def discord_escape(text: object, limit: int = 300) -> str:
    t = _DISCORD_MD.sub(r"\\\1", clean(text, limit))
    return t.replace("@", "@" + ZWSP)


def _discord_line(i: Item) -> str:
    title = discord_escape(i.title)
    url = _safe_url(i.url)
    head = f"**{sev_label(i.severity)}** " + (f"[{title}]({url})" if url else title)
    meta = [m for m in (discord_escape(i.host, 80) or None, discord_escape(i.deadline) if i.deadline else None) if m]
    if i.prev:
        meta.append(f"was {discord_escape(i.prev, 20)}")
    return head + (" · " + " · ".join(meta) if meta else "")


def discord_payload(note: Note, timestamp: str | None = None) -> dict:
    """A webhook body: one embed, coloured by the worst severity, and `allowed_mentions` with an empty `parse` so nothing in
    a finding can ping anyone. Total embed text is held under Discord's 6000-character limit."""
    title = clean(note.headline, DISCORD_TITLE)
    footer = clean(note.footer, DISCORD_FOOTER)
    fields = []
    for sev, n in note.counts[:DISCORD_FIELDS]:
        if n:
            fields.append({"name": sev_label(sev)[:DISCORD_FIELD_NAME], "value": str(n)[:DISCORD_FIELD_VALUE], "inline": True})
    lines: list[str] = []
    if note.summary:
        lines += [discord_escape(note.summary, 500), ""]
    fixed = len(title) + len(footer) + sum(len(f["name"]) + len(f["value"]) for f in fields)
    budget = min(DISCORD_DESC_BUDGET, DISCORD_TOTAL - 200 - fixed)
    used = sum(len(x) + 1 for x in lines)
    hidden = 0
    more_room = 120
    for sec in note.sections:
        if not sec.items:
            continue
        head = f"__{discord_escape(sec.label, 60)}__ ({len(sec.items)})"
        if used + len(head) + more_room > budget:
            hidden += len(sec.items)
            continue
        lines.append(head)
        used += len(head) + 1
        shown = 0
        for it in sec.items:
            line = _discord_line(it)
            if len(line) > 600:
                line = line[:599] + "…"
            if used + len(line) + 1 + more_room > budget:
                break
            lines.append(line)
            used += len(line) + 1
            shown += 1
        hidden += len(sec.items) - shown
        lines.append("")
        used += 1
    if hidden:
        url = _safe_url(note.hub_url)
        lines.append(f"and {hidden} more" + (f". [Open DaemonSight]({url})" if url else "."))
    description = "\n".join(lines).strip()[:DISCORD_DESC]
    color = GOOD_COLOR if note.good else TEST_COLOR if note.kind == "test" else SEV_COLOR[note.top]
    embed = {"title": title, "color": color, "footer": {"text": footer}}
    if description:
        embed["description"] = description
    if fields:
        embed["fields"] = fields
    url = _safe_url(note.hub_url)
    if url:
        embed["url"] = url
    if timestamp:
        embed["timestamp"] = timestamp
    return {"embeds": [embed], "allowed_mentions": {"parse": []}}


def discord_embed_size(payload: dict) -> int:
    """Characters Discord counts toward the 6000 limit: title, description, field names and values, footer, author name."""
    total = 0
    for e in payload.get("embeds", []):
        total += len(e.get("title", "")) + len(e.get("description", "")) + len(e.get("footer", {}).get("text", ""))
        total += len(e.get("author", {}).get("name", ""))
        total += sum(len(f["name"]) + len(f["value"]) for f in e.get("fields", []))
    return total


# --- email -----------------------------------------------------------------------------

LOGO_PATH = Path(__file__).resolve().parent.parent / "web" / "static" / "logo-256.png"   # the same file as assets/logo-256.png


def _h(text: object, limit: int = 300) -> str:
    return html.escape(clean(text, limit), quote=True)


def email_html(note: Note, logo_cid: str | None) -> str:
    sev_css = {"critical": "#d63939", "high": "#f76707", "medium": "#b07a00", "low": "#2b6cb0", "info": "#667382"}
    out = ['<!doctype html><html><body style="margin:0;padding:0;background:#f4f6fa;">',
           '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6fa;"><tr><td align="center" style="padding:16px;">',
           '<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%;background:#ffffff;'
           'border-radius:6px;font-family:Arial,Helvetica,sans-serif;color:#1f2933;font-size:14px;line-height:1.45;">',
           '<tr><td style="padding:20px 24px 8px 24px;">']
    if logo_cid:
        out.append(f'<img src="cid:{html.escape(logo_cid, quote=True)}" width="48" height="48" alt="DaemonSight" '
                   'style="vertical-align:middle;border:0;margin-right:10px;">')
    out.append(f'<span style="font-size:18px;font-weight:bold;vertical-align:middle;">{_h(note.headline, 200)}</span></td></tr>')
    if note.summary:
        out.append(f'<tr><td style="padding:4px 24px 8px 24px;">{_h(note.summary, 500)}</td></tr>')
    if note.counts and any(n for _s, n in note.counts):
        cells = "".join(f'<td style="padding:6px 14px;text-align:center;border:1px solid #e1e5ea;">'
                        f'<div style="font-size:20px;font-weight:bold;color:{sev_css.get(s, "#1f2933")};">{n}</div>'
                        f'<div style="font-size:12px;color:#52606d;">{_h(sev_label(s), 20)}</div></td>' for s, n in note.counts)
        out.append('<tr><td style="padding:4px 24px 8px 24px;"><table role="presentation" cellpadding="0" cellspacing="0"><tr>'
                   f'{cells}</tr></table></td></tr>')
    for sec in note.sections:
        if not sec.items:
            continue
        out.append(f'<tr><td style="padding:12px 24px 4px 24px;font-weight:bold;border-top:1px solid #e1e5ea;">{_h(sec.label, 60)} ({len(sec.items)})</td></tr>')
        out.append('<tr><td style="padding:0 24px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0">')
        for it in sec.items[:EMAIL_SECTION_ITEMS]:
            url = _safe_url(it.url)
            title = _h(it.title)
            title_html = f'<a href="{html.escape(url, quote=True)}" style="color:#0b6e99;text-decoration:none;">{title}</a>' if url else title
            meta = [m for m in (_h(it.host, 80) or None, _h(it.deadline) if it.deadline else None,
                                f"was {_h(it.prev, 20)}" if it.prev else None) if m]
            out.append('<tr><td style="padding:6px 0;border-bottom:1px solid #f0f2f5;">'
                       f'<span style="display:inline-block;min-width:62px;font-weight:bold;color:{sev_css.get(it.severity, "#1f2933")};">'
                       f'{_h(sev_label(it.severity), 20)}</span> {title_html}'
                       + (f'<div style="color:#52606d;font-size:12px;margin-left:66px;">{" &middot; ".join(meta)}</div>' if meta else "")
                       + '</td></tr>')
        out.append('</table></td></tr>')
        if len(sec.items) > EMAIL_SECTION_ITEMS:
            more = len(sec.items) - EMAIL_SECTION_ITEMS
            url = _safe_url(note.hub_url)
            tail = f' <a href="{html.escape(url, quote=True)}">Open DaemonSight</a>' if url else ""
            out.append(f'<tr><td style="padding:4px 24px;">and {more} more.{tail}</td></tr>')
    out.append(f'<tr><td style="padding:16px 24px;border-top:1px solid #e1e5ea;color:#52606d;font-size:12px;">{_h(note.footer, 400)}</td></tr>')
    out.append('</table></td></tr></table></body></html>')
    return "".join(out)


def email_subject(note: Note) -> str:
    return clean(note.headline, 150)


def build_email(note: Note, sender: str, recipients: list[str], logo: bytes | None = None) -> EmailMessage:
    """A multipart message: plain text, then HTML with the logo as an inline image by Content-ID (a related part of the HTML
    alternative, as in the Python documentation's email example), not a remote URL. No Bcc, and the headers hold nothing a
    finding wrote."""
    msg = EmailMessage()
    msg["Subject"] = email_subject(note)
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=False)
    domain = sender.rsplit("@", 1)[-1] if "@" in sender else "daemonsight.invalid"
    msg["Message-ID"] = make_msgid(domain=domain)
    msg["X-Auto-Response-Suppress"] = "All"
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(plain_text(note, None, True, per_section=EMAIL_SECTION_ITEMS) + "\n")
    cid = make_msgid(domain="daemonsight.invalid") if logo else None
    msg.add_alternative(email_html(note, cid[1:-1] if cid else None), subtype="html")
    if logo and cid:
        msg.get_payload()[1].add_related(logo, "image", "png", cid=cid, filename="daemonsight.png", disposition="inline")
    return msg


def load_logo() -> bytes | None:
    try:
        return LOGO_PATH.read_bytes()
    except OSError:
        return None
