"""The jump menus beside the nav tabs: web/sections.py lists each page's sections, and every anchor it lists
exists in the rendered page. The Unraid and OPNsense hosts are checked in tests/test_remote_web.py and
tests/test_opnsense.py, which hold their fixtures."""
import re

from daemonsight.web import sections

from .test_hub import hub_cfg, token  # noqa: F401 (fixtures)
from .test_remote import KEY
from .test_web import client, login, seeded  # noqa: F401 (fixture)

PAGE_KEYS = {"": {"overview", "exposure", "routes", "services", "packages", "vulnerabilities", "fail2ban", "report"},
             "unraid": {"overview", "disks", "containers", "docker", "vms", "notifications", "report"},
             "opnsense": {"overview", "firewall", "vpn", "network", "report"},
             "hub": {"hosts"}}


def page_path(prefix, key):
    return prefix + ("/" if key == "overview" else f"/{key}")


def check_registry(c, prefix, kind, skip=()):
    """Every anchor listed for this host kind is in its page, and the nav has a menu for each page of 2+ sections."""
    for key, secs in sections.SECTIONS[kind].items():
        assert key in PAGE_KEYS[kind], (kind, key)
        if key in skip:
            continue
        r = c.get("/" if key == "hosts" else page_path(prefix, key))
        assert r.status_code == 200, (kind, key)
        for anchor, label in secs:
            assert f'id="{anchor}"' in r.text, (kind, key, anchor)
            assert label, (kind, key, anchor)
        # The menu is in the nav of the page's own host, with a link for each section and an accessible name.
        if key != "hosts" or kind == "hub":
            assert f'id="ds-sec-{key}"' in r.text and f'aria-label="Sections of ' in r.text, (kind, key)
            for anchor, label in secs:
                assert re.search(r'href="[^"]*#' + re.escape(anchor) + '"', r.text), (kind, key, anchor)


def test_registry_shape():
    for kind, pages in sections.SECTIONS.items():
        for key, secs in pages.items():
            assert key in PAGE_KEYS[kind], (kind, key)
            # a page with fewer gets no menu, so it has no entry; Hosts' menu also lists the hosts, so its tail is one
            assert len(secs) >= 2 or (kind, key) == ("hub", "hosts"), (kind, key)
            anchors = [a for a, _ in secs]
            assert len(set(anchors)) == len(anchors), (kind, key)
    assert sections.for_host(None)["exposure"] and sections.for_host("opnsense")["firewall"]
    assert "exposure" not in sections.for_host("unraid") and "hosts" in sections.for_host("unraid")


def test_collector_pages_have_every_listed_anchor(seeded):
    c = login(client(seeded))
    check_registry(c, "", "", skip=("vulnerabilities",))      # that page has data only on a hub


def test_vulnerabilities_page_on_a_hub(hub_cfg, token, tmp_path):
    from .test_cve import seed_hub
    c = seed_hub(hub_cfg, token, tmp_path)
    for anchor, _ in sections.SECTIONS[""]["vulnerabilities"]:
        assert f'id="{anchor}"' in c.get("/h/testhost/vulnerabilities").text, anchor


def test_a_page_with_one_section_has_no_menu(seeded):
    c = login(client(seeded))
    html = c.get("/").text
    assert 'id="ds-sec-overview"' in html
    # Phone: the Overview page's own list is there (it is the current page).
    assert 'id="ds-secl-overview"' in html


def test_active_tab_has_live_menu_and_other_tabs_follow_the_registry(seeded):
    c = login(client(seeded))
    # Routes has fewer than 2 registry sections: still a live menu on its own page, none on the other tabs.
    assert len(sections.SECTIONS[""].get("routes", [])) < 2
    r = c.get("/routes")
    assert 'id="ds-sec-routes"' in r.text and 'data-ds-sections="live"' in r.text
    assert re.search(r'<ul class="ds-sec-inline[^"]*" id="ds-secl-routes" data-ds-sections="live"', r.text)
    assert 'id="ds-sec-exposure"' in r.text and 'data-ds-sections="live"' not in r.text.split('id="ds-sec-exposure"')[1].split("</div>")[0]
    # Registry items stay inside the active tab's menu as the no-JavaScript fallback.
    r = c.get("/exposure")
    pop = r.text.split('id="ds-sec-exposure"')[1].split("</div>")[0]
    assert 'data-ds-sections="live"' in pop and 'href="/exposure#listeners"' in pop
    assert r.text.count('data-ds-sections="live"') == 4        # chevron, popover, phone toggle, phone list
    # A non-active tab with fewer than 2 registry sections has no chevron.
    assert 'id="ds-sec-routes"' not in r.text


def test_phone_menu_is_one_disclosure_per_page_with_sections(seeded):
    """Each page with sections has a toggle (aria-expanded, aria-controls) and a list with that id. The current
    page's list starts open and the others closed (hidden); without JavaScript app.css shows them all."""
    c = login(client(seeded))
    html = c.get("/exposure").text
    toggles = re.findall(r'<button type="button" class="ds-sec-tgl"[^>]*>', html)
    assert len(toggles) >= 2
    keys = set()
    for t in toggles:
        ctl = re.search(r'aria-controls="([^"]+)"', t).group(1)
        exp = re.search(r'aria-expanded="([^"]+)"', t).group(1)
        assert ctl.startswith("ds-secl-") and html.count(f'id="{ctl}"') == 1, ctl
        ul = re.search(r'<ul class="ds-sec-inline[^"]*" id="' + ctl + r'"([^>]*)>', html).group(1)
        key = ctl[len("ds-secl-"):]
        keys.add(key)
        if key == "exposure":
            assert exp == "true" and " hidden" not in ul
        else:
            assert exp == "false" and " hidden" in ul, key
        assert 'aria-label="Sections of ' in t
    assert "exposure" in keys and "routes" not in keys     # routes has under 2 registry sections here
    # The current page's list holds a link to each registry section; the others hold theirs too (the registry).
    ul = html.split('id="ds-secl-exposure"')[1].split("</ul>")[0]
    for anchor, _ in sections.SECTIONS[""]["exposure"]:
        assert f"#{anchor}" in ul
    css = open("src/daemonsight/web/static/app.css").read()
    assert "html:not(.ds-js) .ds-sec-inline[hidden] { display: block; }" in css


# ---- The Hosts tab's menu: the hosts A to Z, a line, then Recent hub changes --------------------------------------

def hosts_menu_hub(hub_cfg):
    from daemonsight import db, hub
    from daemonsight.remote import store
    conn = db.connect_writer(hub_cfg.db_path)
    for name in ("zeta", "Alpha", "beta"):
        hub.add_host(conn, name)
    conn.execute("UPDATE hosts SET last_seen = ? WHERE id IN ('zeta', 'Alpha')", (db.now(),))
    store.add(conn, hub_cfg.data_dir, "unraid-box", "unraid", "https://10.0.0.2", KEY)
    conn.close()
    return login(client(hub_cfg))


def hosts_popover(html):
    return html.split('id="ds-sec-hosts"')[1].split("</div>")[0]


def test_hosts_menu_lists_every_host_a_to_z_then_recent_changes(hub_cfg):
    c = hosts_menu_hub(hub_cfg)
    for html in (c.get("/").text, c.get("/settings").text):
        pop = hosts_popover(html)
        hrefs = re.findall(r'href="([^"]+)"', pop)
        assert hrefs == ["/h/Alpha/", "/h/beta/", "/h/unraid-box/", "/h/zeta/", "/#hub-events"]
        assert pop.count('class="ds-acct-sep"') == 1
        assert pop.index('ds-acct-sep') > pop.index("/h/zeta/") and pop.index('ds-acct-sep') < pop.index("/#hub-events")
        assert "Recent hub changes" in pop.split('ds-acct-sep')[1]
        # status dot before each name: fresh collectors green, the silent one and the unread API system red
        assert re.search(r'status-green[^>]*></span><span class="ds-sec-text">Alpha<', pop)
        assert re.search(r'status-red[^>]*></span><span class="ds-sec-text">beta<', pop)
        assert re.search(r'status-red[^>]*></span><span class="ds-sec-text">unraid-box<', pop)
        # the phone list has the same items, with a matching separator item
        ul = html.split('id="ds-secl-hosts"')[1].split("</ul>")[0]
        assert re.findall(r'href="([^"]+)"', ul) == hrefs
        assert ul.count('role="separator"') == 1


def test_hosts_menu_marks_the_current_host(hub_cfg):
    c = hosts_menu_hub(hub_cfg)
    pop = hosts_popover(c.get("/h/beta/").text)
    assert pop.count('aria-current="page"') == 1
    assert re.search(r'href="/h/beta/" aria-current="page"', pop)
    assert 'aria-current' not in hosts_popover(c.get("/").text)


def test_hosts_menu_is_never_live(hub_cfg):
    c = hosts_menu_hub(hub_cfg)
    html = c.get("/").text           # on the Hosts page itself
    assert 'data-ds-sections="live"' not in html.split('id="ds-sec-hosts"')[0].rsplit('<li class="nav-item ds-tab', 1)[1]
    hosts_li = html.split('<li class="nav-item ds-tab', 1)[1].split("</li>")[0]
    assert "data-ds-sections" not in hosts_li
    # the phone list starts open only on the Hosts page
    assert 'aria-expanded="true" aria-controls="ds-secl-hosts"' in html
    assert 'aria-expanded="false" aria-controls="ds-secl-hosts"' in c.get("/settings").text


def test_no_hosts_menu_outside_hub_mode(seeded):
    c = login(client(seeded))
    html = c.get("/").text
    assert 'id="ds-sec-hosts"' not in html and "Recent hub changes" not in html
    assert "ds-sec-dot" not in html
