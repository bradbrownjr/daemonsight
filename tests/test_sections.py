"""The jump menus beside the nav tabs: web/sections.py lists each page's sections, and every anchor it lists
exists in the rendered page. The Unraid and OPNsense hosts are checked in tests/test_remote_web.py and
tests/test_opnsense.py, which hold their fixtures."""
import re

from daemonsight.web import sections

from .test_hub import hub_cfg, token  # noqa: F401 (fixtures)
from .test_web import client, login, seeded  # noqa: F401 (fixture)

PAGE_KEYS = {"": {"overview", "exposure", "routes", "services", "packages", "vulnerabilities", "fail2ban", "report"},
             "unraid": {"overview", "disks", "containers", "vms", "notifications", "report"},
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
            assert len(secs) >= 2, (kind, key)      # a page with fewer gets no menu, so it has no entry
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
    # Phone: the active tab's sections are listed under it, and only that tab's.
    assert html.count('class="ds-sec-inline"') == 1
