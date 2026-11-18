"""Unraid's unread warnings and alerts: what is dropped as covered by a live check, what is grouped into findings,
the unclean-shutdown rule, the inbox summary, and the parity text that uses them. Responses come from the trimmed
real ones in tests/fixtures/unraid/."""

import copy

import pytest

from daemonsight import findings as rules_mod
from daemonsight.remote import unraid_notify, unraid_rules

from .test_remote import NOW, all_data, by_rule, parsed, rules_for


def item(title, subject, importance="WARNING", time=1_790_000_000.0, description="", id=None):
    return {"id": id or f"{title}-{time}.notify", "title": title, "subject": subject, "description": description,
            "link": "/Main", "importance": importance, "time": time}


def notes(**kw):
    return {"unread": {"info": 0, "warning": 0, "alert": 0, "total": 0}, "items": [], **kw}


def fixture_items():
    return parsed("unraid_notifications")["items"]


# --- the classification table ------------------------------------------------------------------------------

def test_what_each_real_notification_is():
    got = {}
    for i in fixture_items():
        k = unraid_notify.classify(i)
        got.setdefault(k.key, set()).add(i["title"])
    assert got["disk_usage"] == {"Unraid Disk 3 disk utilization", "Unraid Disk 5 disk utilization", "Unraid Disk 1 disk utilization"}
    assert got["disk_temp"] == {"Unraid Disk 4 temperature", "Unraid Disk 3 temperature"}
    assert {"Unraid Parity check", "Unraid Parity-Check"} <= got["parity_run"] and "Parity Check Tuning" in got["parity_run"]
    assert got["array_job"] == {"Unraid Data-Rebuild"}
    assert got["unclean_shutdown"] == {"Parity Check Tuning"}
    assert got["fcp"] == {"Fix Common Problems - tower-test"}
    assert got["smart"] == {"Unraid Disk 4 SMART health [197]", "Unraid Disk 4 SMART health [5]", "Unraid Disk 1 SMART health [187]"}
    assert got["array_errors"] == {"Unraid array errors"} and got["disk_error"] == {"Unraid Disk 4 error"}
    assert got["docker_image"] == {"Docker high image disk utilization"}
    assert "other" not in got                      # nothing in the real inbox falls through the table


@pytest.mark.parametrize("title,subject,kind", [
    ("Unraid Cache disk utilization", "Alert [S] - Cache is low on space (96%)", "disk_usage"),
    ("Unraid Disk 2 temperature", "Alert [S] - Disk 2 overheated (60 C)", "disk_temp"),
    ("Parity Check Tuning", "[S] Manual Non-Correcting Read-Check finished (0 errors)", "parity_run"),
    ("Parity Check Tuning", "[S] Automatic Correcting Parity-Check canceled (0 errors)", "parity_run"),
    ("Parity Check Tuning", "[S] Array operation will not be restarted", "parity_tuning"),     # not a result
    ("Parity Problem Assistant", "[S] Unclean shutdown detected", "unclean_shutdown"),
    ("Docker - radarr [5.1]", "Notice [S] - Version update 5.1", "container_update"),
    ("Docker critical image disk utilization", "Alert [S] - Docker image disk utilization of 99%", "docker_image"),
    ("Something New", "Whatever", "other"),
])
def test_classification_table(title, subject, kind):
    assert unraid_notify.classify(item(title, subject)).key == kind


def test_covered_notifications_are_not_findings_and_say_which_check_covers_them():
    covered = {k.key: k.covered_by for k in unraid_notify.KINDS.values() if k.covered_by}
    assert covered["disk_usage"] == "unraid.disk_full" and covered["disk_temp"] == "unraid.disk_temp"
    assert "unraid.parity_errors" in covered["parity_run"] and covered["container_update"] == "unraid.container_updates"
    f = rules_for()
    titles = " ".join(x.title for x in by_rule(f, "unraid.notification"))
    for gone in ("Disk 3 disk utilization", "Disk 5 disk utilization", "temperature", "Parity check", "Parity-Check", "Data-Rebuild"):
        assert gone not in titles, gone
    state, how = unraid_notify.disposition(item("Unraid Disk 3 disk utilization", "x", "ALERT"))
    assert state == "covered" and "unraid.disk_full" in how
    assert unraid_notify.disposition(item("Fix Common Problems - S", "x"))[0] == "finding"


# --- grouping ---------------------------------------------------------------------------------------------------

def test_repeats_group_into_one_finding_with_count_and_newest_date():
    items = fixture_items()
    fcp = [i for i in items if i["title"].startswith("Fix Common Problems")]
    f = by_rule(rules_for(), "unraid.notification")
    one = [x for x in f if x.key == fcp[0]["title"]]
    assert len(one) == 1
    x = one[0]
    assert x.severity == "medium"                       # one of them is an alert
    assert f"{len(fcp)} unread with this title" in x.detail
    assert "newest from 2026-11-01" in x.detail and "oldest from" in x.detail
    assert "Errors have been found" in x.detail          # the most serious one is named when it is not the newest
    assert x.title == "Unraid alert: Fix Common Problems - tower-test"
    assert x.basis == "2026-11-01T09:21:00Z"
    assert "Settings → User Utilities → Fix Common Problems" in x.howto
    docker = [x for x in f if x.key == "Docker high image disk utilization"][0]
    assert docker.severity == "low" and "5 unread with this title" in docker.detail and "newest from 2026-05-19" in docker.detail
    # one finding per distinct title, and no title twice
    assert len({x.key for x in f}) == len(f)


def test_every_notification_finding_shows_its_date_and_a_howto():
    f = by_rule(rules_for(), "unraid.notification") + by_rule(rules_for(), "unraid.unclean_shutdown")
    assert len(f) >= 8
    for x in f:
        if x.key == "inbox":
            continue
        assert "from 20" in x.detail.lower() or "From 20" in x.detail, x.title
        assert x.howto and x.link.startswith("/notifications")


def test_text_from_the_server_is_capped_in_a_finding():
    f = rules_for(notifications=lambda n: n.update(items=[item("t" * 120, "s" * 200, description="d" * 300)]))
    x = by_rule(f, "unraid.notification")[0]
    assert len(x.detail) <= 900 and len(x.key) <= 200
    assert unraid_rules.evaluate({**all_data(), "notifications": None}, NOW) is not None


def test_a_known_source_has_its_own_steps_and_the_rest_get_the_generic_ones():
    f = {x.key: x for x in by_rule(rules_for(), "unraid.notification")}
    assert "SMART report" in f["Unraid Disk 4 SMART health [197]"].howto
    assert "Container Size" in f["Docker high image disk utilization"].howto
    other = unraid_notify.notification_findings(notes(items=[item("Something New", "Odd")]))
    assert other[0].howto == "Read it in Unraid (the bell icon) and archive it once it is handled"


# --- unclean shutdowns --------------------------------------------------------------------------------------------

def test_unclean_shutdowns_are_one_finding_with_every_date():
    crashes = [i for i in fixture_items() if i["subject"].endswith("Unclean shutdown detected")]
    assert len(crashes) == 13
    f = by_rule(rules_for(), "unraid.unclean_shutdown")
    assert len(f) == 1 and not [x for x in by_rule(rules_for(), "unraid.notification") if "Unclean" in x.title]
    x = f[0]
    assert x.severity == "medium" and x.title == "Unraid shut down uncleanly 13 times since 2025-12-11"
    for d in ("2025-12-11", "2026-06-15", "2026-06-18", "2026-10-01"):
        assert d in x.detail
    assert "System crashed" in x.detail
    # The basis is the set of dates: a new crash, not a changed count of something else, brings back an acceptance.
    stamps = sorted(unraid_notify.time.strftime("%Y-%m-%dT%H:%M:%SZ", unraid_notify.time.gmtime(i["time"])) for i in crashes)
    assert x.basis == ",".join(stamps)
    more = rules_for(notifications=lambda n: n["items"].append(item("Parity Check Tuning", "[S] Unclean shutdown detected",
                                                                    "ALERT", NOW - 100, "System crashed")))
    y = by_rule(more, "unraid.unclean_shutdown")[0]
    assert y.title.startswith("Unraid shut down uncleanly 14 times") and y.basis != x.basis
    assert rules_for()[0].key and by_rule(rules_for(), "unraid.unclean_shutdown")[0].basis == x.basis      # stable


def test_unclean_shutdown_howto_says_what_to_do():
    x = by_rule(rules_for(), "unraid.unclean_shutdown")[0]
    h = x.howto
    assert "crash" in h and "power loss" in h and "forced" in h
    assert "sync errors" in h and "expected" in h
    assert "Settings → Syslog Server" in h and "Mirror syslog to boot drive" in h and "syslog server" in h
    assert "UPS" in h and "archive" in h.lower()


def test_one_unclean_shutdown_is_singular():
    f = unraid_notify.notification_findings(notes(items=[item("Parity Check Tuning", "[S] Unclean shutdown detected", "ALERT",
                                                              1_790_000_000.0, "Unable to stop array")]))
    x = [y for y in f if y.rule == "unraid.unclean_shutdown"][0]
    assert x.title == "Unraid shut down uncleanly 1 time since 2026-09-21" and "Unable to stop array" in x.detail


# --- the inbox summary ---------------------------------------------------------------------------------------------

def test_the_inbox_is_one_low_summary_and_archived_alerts_drop_out():
    f = [x for x in by_rule(rules_for(), "unraid.notification") if x.key == "inbox"]
    assert len(f) == 1
    x = f[0]
    assert x.severity == "low" and x.title == "235 unread Unraid alerts and warnings" and x.link == "/notifications"
    assert x.howto == "Read and archive them in the Unraid web UI (bell icon, Archive all)"
    assert "49 alerts and 186 warnings" in x.detail and "Archived alerts drop out" in x.detail
    assert x.basis == "inbox"                        # the count drifts; accepting it stays accepted
    one = unraid_notify.notification_findings(notes(unread={"alert": 0, "warning": 1, "info": 0, "total": 1},
                                                    items=[item("Something New", "Odd")]))
    assert [y.title for y in one if y.key == "inbox"] == ["1 unread Unraid alert or warning"]
    assert not unraid_notify.notification_findings(notes())          # nothing unread: no finding
    assert "more unread notifications than DaemonSight reads" in [y for y in unraid_notify.notification_findings(
        notes(unread={"alert": 1, "warning": 0, "info": 0, "total": 1}, items=[item("X", "y")], truncated=True)) if y.key == "inbox"][0].detail


def test_old_stored_notifications_without_description_still_work():
    old = {"unread": {"info": 0, "warning": 1, "alert": 0, "total": 1},
           "items": [{"id": "a", "title": "Something New", "subject": "Odd", "importance": "WARNING", "time": 1.0}]}
    assert unraid_notify.notification_findings(old)


# --- parity text ----------------------------------------------------------------------------------------------------

def _errors(a, when=NOW - 86400 * 10, crash=None):
    a["parity_history"] = [{"status": "COMPLETED", "date": when, "errors": 2, "duration": 135000, "speed": ""}]
    a["parity_check"] = {"status": "NEVER_RUN", "running": False}


def test_parity_errors_explain_sync_errors_and_where_the_sectors_are():
    x = by_rule(rules_for(array=_errors), "unraid.parity_errors")[0]
    assert "4 KiB block" in x.detail and "first 100" in x.detail and "syslog" in x.detail
    assert "No check has finished since" in x.detail
    assert "without corrections" in x.howto and "Write corrections to parity" in x.howto and "SMART" in x.howto and "unclean shutdown" in x.howto


def test_parity_errors_name_a_crash_before_the_check():
    def edit(d):
        _errors(d)
    data = all_data()
    _errors(data["array"])
    crash = NOW - 86400 * 12
    data["notifications"]["items"].append(item("Parity Check Tuning", "[S] Unclean shutdown detected", "ALERT", crash, "System crashed"))
    x = by_rule(unraid_rules.evaluate(data, NOW), "unraid.parity_errors")[0]
    assert "unclean shutdown on" in x.detail and "usual cause" in x.detail
    data["notifications"]["items"] = [i for i in data["notifications"]["items"] if i["time"] != crash]
    far = item("Parity Check Tuning", "[S] Unclean shutdown detected", "ALERT", NOW - 86400 * 60, "System crashed")
    data["notifications"]["items"].append(far)
    assert "usual cause" not in by_rule(unraid_rules.evaluate(data, NOW), "unraid.parity_errors")[0].detail


def test_a_later_clean_check_ends_the_parity_errors_finding():
    def clean_later(a):
        _errors(a)
        a["parity_history"].insert(0, {"status": "COMPLETED", "date": NOW - 86400, "errors": 0, "duration": 100000, "speed": ""})
    assert not by_rule(rules_for(array=clean_later), "unraid.parity_errors")


def test_a_later_cancelled_check_is_named_and_does_not_count():
    def cancelled(a):
        _errors(a)
        a["parity_history"].insert(0, {"status": "CANCELLED", "date": NOW - 86400, "errors": 0, "duration": 27, "speed": "0"})
    x = by_rule(rules_for(array=cancelled), "unraid.parity_errors")[0]
    assert "was cancelled after 27 seconds" in x.detail and "doesn't count" in x.detail and "No check has finished" not in x.detail


def test_parity_old_says_when_the_last_check_was_started_and_stopped():
    x = by_rule(rules_for(), "unraid.parity_old")[0]          # the real history: a check on 2026-10-01 cancelled after 27 s
    assert "ended on 2026-08-04" in x.detail and "started 2026-10-01 13:38 UTC and was cancelled after 27 seconds" in x.detail
    assert "Settings → Scheduler → Parity Check" in x.howto and "Main → Array Operation → Check" in x.howto
    def plain(a):
        a["parity_history"] = [h for h in a["parity_history"] if h["status"] == "COMPLETED"]
    assert "cancelled" not in by_rule(rules_for(array=plain), "unraid.parity_old")[0].detail


# --- every rule says what to do -------------------------------------------------------------------------------------

def test_every_other_unraid_rule_has_steps():
    def trouble(a):
        a["state"] = "STOPPED"
        a["disks"][2]["status"] = "DISK_DSBL"
        a["disks"][3]["errors"] = 3
        a["disks"][1]["temp"] = 60
    def smart(d):
        d["disks"][2]["smart"] = "UNKNOWN"
    def ups(u):
        u["devices"][0].update(status="ONBATT", charge=20, health="Replace")
    f = rules_for(array=trouble, disks=smart, ups=ups)
    seen = {x.rule for x in f}
    assert {"unraid.array_state", "unraid.disk_state", "unraid.disk_errors", "unraid.disk_temp", "unraid.disk_smart",
            "unraid.ups", "unraid.disk_full"} <= seen
    for x in f:
        assert x.howto, x.rule
    full = [x for x in f if x.rule == "unraid.disk_full"][0].howto
    for term in ("Shares", "Allocation method", "Split level", "Minimum free space"):
        assert term in full
    assert "Main → Array Operation" in by_rule(f, "unraid.array_state")[0].howto
    assert "Settings → UPS Settings" in by_rule(f, "unraid.ups")[0].howto
    assert "Settings → Disk Settings" in by_rule(f, "unraid.disk_temp")[0].howto
    assert "SMART" in by_rule(f, "unraid.disk_state")[0].howto and "Replacing disks" in by_rule(f, "unraid.disk_state")[0].howto


def test_the_hubs_own_rules_outside_unraid_have_steps():
    from daemonsight.remote import poll
    from daemonsight.cve import match
    assert "Hosts" in poll.HOWTO_UNREACHABLE and "API Keys" in poll.HOWTO_UNREACHABLE
    assert match.stale_finding([("x", None)], {}).howto
