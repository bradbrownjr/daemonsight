// DaemonSight page tools: column sorting, a row filter, "hide empty
// sections" and the account menu. No dependencies; served from 'self' under the CSP.
//
// Markup it reads:
//   [data-section]          a card the filter and "hide empty" act on
//   [data-section][data-empty]  the card has no data from its source
//   [data-row]              a row or list item the filter can hide
//   table[data-table=key]   a sortable table; key names its saved sort
//   th[data-sort=num|text]  a sortable column
//   td[data-v]              raw value to sort by instead of the cell text
//   [data-status-filter]    a card whose rows carry data-status (unexpected, accepted, changed, expected);
//                           its [data-status-mode] buttons pick "all" or "attention" (Unexpected and Changed)
//
// Sort order, the hide-empty switch and the findings filter are saved in localStorage. All of it
// is applied again after every HTMX refresh.
(function () {
  "use strict";

  var store = {
    get: function (key) {
      try { return JSON.parse(window.localStorage.getItem("daemonsight:" + key)); } catch (e) { return null; }
    },
    set: function (key, value) {
      try { window.localStorage.setItem("daemonsight:" + key, JSON.stringify(value)); } catch (e) { /* private mode */ }
    }
  };
  var collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
  var sorts = store.get("sort") || {};
  var filterInput, hideEmptySwitch;

  function each(list, fn) { Array.prototype.forEach.call(list, fn); }

  function cellValue(row, col, numeric) {
    var cell = row.cells[col];
    if (!cell) return null;
    var raw = cell.hasAttribute("data-v") ? cell.getAttribute("data-v") : cell.textContent.trim();
    if (raw === "" || raw === "—") return null;
    if (!numeric) return raw;
    var n = parseFloat(raw);
    return isNaN(n) ? null : n;
  }

  function addSortButtons(table) {
    each(table.querySelectorAll("th[data-sort]"), function (th) {
      if (th.querySelector(".ds-sort")) return;
      var button = document.createElement("button");
      button.type = "button";
      button.className = "ds-sort";
      while (th.firstChild) button.appendChild(th.firstChild);
      th.appendChild(button);
    });
  }

  function sortTable(table) {
    var key = table.getAttribute("data-table");
    var head = table.tHead && table.tHead.rows[0];
    if (!table.tBodies.length || !head) return;
    var state = sorts[key];
    var col = state ? state.col : -1;
    each(head.cells, function (th, i) {
      if (!th.hasAttribute("data-sort")) return;
      th.setAttribute("aria-sort", i === col ? (state.dir > 0 ? "ascending" : "descending") : "none");
    });
    var numeric = col >= 0 && head.cells[col] && head.cells[col].getAttribute("data-sort") === "num";
    // A table may hold several bodies (the containers, one per folder): each is sorted on its own, so a folder
    // heading stays above its rows.
    each(table.tBodies, function (body) { sortBody(body, col, state, numeric); });
  }

  function sortBody(body, col, state, numeric) {
    var rows = Array.prototype.filter.call(body.rows, function (r) { return r.hasAttribute("data-row"); });
    // Remember the server's order so "unsorted" can restore it.
    each(rows, function (r, i) { if (!r.hasAttribute("data-i")) r.setAttribute("data-i", String(i)); });
    rows.sort(function (a, b) {
      if (col >= 0) {
        var va = cellValue(a, col, numeric), vb = cellValue(b, col, numeric);
        if (va === null && vb !== null) return 1;   // blanks last either way
        if (vb === null && va !== null) return -1;
        if (va !== null && vb !== null) {
          var c = numeric ? va - vb : collator.compare(va, vb);
          if (c) return c * state.dir;
        }
      }
      return Number(a.getAttribute("data-i")) - Number(b.getAttribute("data-i"));
    });
    each(rows, function (r) { body.appendChild(r); });
  }

  function onSortClick(event) {
    var button = event.target.closest(".ds-sort");
    if (!button) return;
    var th = button.closest("th");
    var table = th.closest("table[data-table]");
    if (!table) return;
    var key = table.getAttribute("data-table");
    var col = th.cellIndex;
    // Numbers start largest first, text starts A to Z; the third click clears.
    var first = th.getAttribute("data-sort") === "num" ? -1 : 1;
    var state = sorts[key];
    if (!state || state.col !== col) sorts[key] = { col: col, dir: first };
    else if (state.dir === first) sorts[key] = { col: col, dir: -first };
    else delete sorts[key];
    store.set("sort", sorts);
    sortTable(table);
  }

  // A row's searchable text, without the hidden source panel inside it.
  function rowText(row) {
    if (row._dsText === undefined) {
      var copy = row.cloneNode(true);
      each(copy.querySelectorAll("[popover]"), function (p) { p.remove(); });
      row._dsText = copy.textContent.toLowerCase();
    }
    return row._dsText;
  }

  function popoverOpen() {
    try { return document.querySelector(":popover-open") !== null; } catch (e) { return false; }
  }

  // Copy the text next to a button (.ds-copy-text), or, with data-copy-from,
  // the text of the element with that id (a textarea). navigator.clipboard
  // is available only in secure contexts (HTTPS):
  // https://developer.mozilla.org/en-US/docs/Web/API/Clipboard/writeText
  // On plain HTTP it selects the text and tries the old copy command instead.
  function copyText(button) {
    var fromId = button.getAttribute("data-copy-from");
    var code = fromId ? document.getElementById(fromId) : button.parentNode.querySelector(".ds-copy-text");
    if (!code) return;
    var text = fromId ? code.value : code.textContent;
    var label = button.getAttribute("data-label-orig") || button.textContent;
    button.setAttribute("data-label-orig", label);
    var done = function () {
      button.textContent = "Copied";
      setTimeout(function () { button.textContent = label; }, 1500);
    };
    var fallback = function () {
      if (fromId) {
        code.select();
      } else {
        var range = document.createRange();
        range.selectNodeContents(code);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
      try { if (document.execCommand("copy")) { done(); return; } } catch (e) { /* not allowed */ }
      button.textContent = "Selected";
      setTimeout(function () { button.textContent = label; }, 1500);
    };
    if (window.isSecureContext && navigator.clipboard) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else {
      fallback();
    }
  }

  function applyFilter() {
    var terms = filterInput ? filterInput.value.toLowerCase().split(/\s+/).filter(Boolean) : [];
    each(document.querySelectorAll("[data-section]"), function (section) {
      var rows = section.querySelectorAll("[data-row]:not(.ds-status-hidden)");
      var shown = 0;
      each(rows, function (row) {
        var text = rowText(row);
        var match = terms.every(function (t) { return text.indexOf(t) !== -1; });
        row.classList.toggle("ds-filtered", !match);
        if (match) shown += 1;
      });
      var noMatch = terms.length > 0 && rows.length > 0 && shown === 0;
      section.toggleAttribute("data-nomatch", noMatch);
      // A folder heading goes when the filter hides every row under it.
      each(section.querySelectorAll("tbody[data-group]"), function (body) {
        var visible = body.querySelectorAll("[data-row]:not(.ds-filtered)").length;
        each(body.querySelectorAll(".ds-group-head"), function (h) { h.classList.toggle("ds-filtered", visible === 0 && terms.length > 0); });
      });
      var count = section.querySelector(".ds-shown");
      if (count) count.textContent = terms.length && rows.length ? shown + " match · " : "";
    });
  }

  // "All" lists every finding, accepted ones included; "attention" hides the
  // ones that don't need any (Accepted, Expected). Saved; applied again after each refresh.
  function statusMode() { return store.get("findingsFilter") === "attention" ? "attention" : "all"; }

  function applyStatusFilter() {
    var mode = statusMode();
    each(document.querySelectorAll("[data-status-filter]"), function (section) {
      var rows = section.querySelectorAll("[data-row][data-status]");
      var hidden = 0;
      each(rows, function (row) {
        var st = row.getAttribute("data-status");
        var hide = mode === "attention" && st !== "unexpected" && st !== "changed";
        row.classList.toggle("ds-status-hidden", hide);
        if (hide) hidden += 1;
      });
      section.toggleAttribute("data-status-empty", rows.length > 0 && hidden === rows.length);
      each(section.querySelectorAll("[data-status-mode]"), function (b) {
        var on = b.getAttribute("data-status-mode") === mode;
        b.setAttribute("aria-pressed", on ? "true" : "false");
        b.classList.toggle("active", on);
      });
    });
  }

  function setHideEmpty(on) {
    document.documentElement.classList.toggle("ds-hide-empty", on);
    if (hideEmptySwitch) hideEmptySwitch.checked = on;
  }

  function applyAll() {
    each(document.querySelectorAll("table[data-table]"), function (table) {
      addSortButtons(table);
      sortTable(table);
    });
    applyStatusFilter();
    applyFilter();
  }

  var phone = window.matchMedia("(max-width: 767.98px)");

  // Phone menu: the nav and the account panel (Settings, Theme, Hide empty sections, Log out).
  function initMenu() {
    var header = document.getElementById("ds-header");
    var button = document.getElementById("ds-menu-btn");
    if (!header || !button) return;
    function set(open, refocus) {
      header.classList.toggle("ds-menu-open", open);
      button.setAttribute("aria-expanded", open ? "true" : "false");
      if (!open && refocus) button.focus();
    }
    button.addEventListener("click", function () {
      set(button.getAttribute("aria-expanded") !== "true");
    });
    header.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && button.getAttribute("aria-expanded") === "true") {
        set(false, header.contains(document.activeElement) && document.activeElement !== button);
      }
    });
    header.addEventListener("click", function (e) {
      if (e.target.closest("nav a")) set(false);
    });
    phone.addEventListener("change", function () { set(false); });
  }

  // Account menu: put the panel under its button, and move focus into it, so the keyboard can reach the
  // items. Escape and a click outside close a popover natively, and focus goes back to the button:
  // https://developer.mozilla.org/en-US/docs/Web/API/HTMLElement/toggle_event
  function initAccount() {
    var pop = document.getElementById("ds-acct-pop");
    var button = document.getElementById("ds-acct-btn");
    if (!pop || !button || !pop.showPopover) return;
    pop.addEventListener("toggle", function (e) {
      if (e.newState !== "open") return;
      var r = button.getBoundingClientRect();
      pop.style.top = Math.round(r.bottom + 6) + "px";
      pop.style.right = Math.max(8, Math.round(document.documentElement.clientWidth - r.right)) + "px";
      var first = pop.querySelector("a[href], button, input");
      if (first) first.focus();
    });
  }

  // Section menus beside the nav tabs: put the panel under its tab and focus the first item. Escape and a
  // click outside close a popover natively. A link to a section of the page you are on scrolls there
  // itself, so it works when the address already has that hash too.
  // The active tab's menu (data-ds-sections="live") lists the cards on this page, in page order, so cards that
  // only some systems have are in it. Fewer than two cards: no chevron and no phone list. The registry items the
  // server rendered stay as they are without JavaScript.
  function cardLabel(title) {
    var t = "";
    each(title.childNodes, function (n) { if (n.nodeType === 3) t += n.nodeValue; });
    if (!t.trim()) { var c = title.cloneNode(true); each(c.querySelectorAll("button"), function (b) { b.remove(); }); t = c.textContent; }
    return t.replace(/\s+/g, " ").trim();
  }
  function liveSections() {
    var out = [];
    each(document.querySelectorAll("main section[id]"), function (sec) {
      var title = sec.querySelector(".card-title");
      if (!sec.classList.contains("card") || !title) return;
      var label = cardLabel(title);
      if (label) out.push({ id: sec.id, label: label });
    });
    return out;
  }
  function esc(s) { var d = document.createElement("div"); d.textContent = s; return d.innerHTML.replace(/"/g, "&quot;"); }
  function updateLiveMenus() {
    var live = document.querySelectorAll('[data-ds-sections="live"]');
    if (!live.length) return;
    var secs = liveSections();
    var tab = document.querySelector(".ds-tab > .nav-link.active");
    var path = tab ? new URL(tab.href, window.location.href).pathname : window.location.pathname;
    var few = secs.length < 2;
    var key = JSON.stringify(secs);
    each(live, function (el) {
      var inline = el.classList.contains("ds-sec-inline");
      var tgl = inline ? document.querySelector('[aria-controls="' + el.id + '"]') : null;
      // A phone list is also closed while its toggle says so; the toggle and the chevron go with "few".
      el.hidden = few || (inline && !!tgl && tgl.getAttribute("aria-expanded") !== "true");
      if (few) { if (el.matches("[popover]") && el.hidePopover) { try { el.hidePopover(); } catch (err) { /* closed */ } } return; }
      if (el.getAttribute("data-ds-built") === key) return;
      el.setAttribute("data-ds-built", key);
      if (el.classList.contains("ds-sec-btn") || el.classList.contains("ds-sec-tgl")) return;
      var html = secs.map(function (s) {
        var a = '<a class="' + (inline ? "" : "ds-acct-item ") + 'ds-sec-item" href="' + esc(path) + "#" + esc(s.id) + '">' + esc(s.label) + "</a>";
        return inline ? "<li>" + a + "</li>" : a;
      }).join("");
      el.innerHTML = html;
    });
    var li = document.querySelector(".ds-tab > .nav-link.active");
    if (li) li.parentNode.classList.toggle("ds-has-sec", !few);
  }

  // Phone menu: a toggle beside each page opens and closes that page's section list (the disclosure pattern:
  // aria-expanded on the button, the list hidden while closed).
  function initSectionToggles() {
    document.addEventListener("click", function (e) {
      var tgl = e.target.closest(".ds-sec-tgl");
      if (!tgl) return;
      var list = document.getElementById(tgl.getAttribute("aria-controls"));
      if (!list) return;
      var open = tgl.getAttribute("aria-expanded") !== "true";
      tgl.setAttribute("aria-expanded", open ? "true" : "false");
      list.hidden = !open;
    });
  }

  function initSectionMenus() {
    initSectionToggles();
    updateLiveMenus();
    document.body.addEventListener("htmx:afterSwap", updateLiveMenus);
    each(document.querySelectorAll(".ds-sec-pop"), function (pop) {
      pop.addEventListener("toggle", function (e) {
        if (e.newState !== "open") return;
        var tab = pop.closest(".ds-tab");
        var r = (tab || pop).getBoundingClientRect();
        var w = pop.offsetWidth;
        pop.style.top = Math.round(r.bottom + 4) + "px";
        pop.style.left = Math.max(8, Math.min(Math.round(r.left), document.documentElement.clientWidth - w - 8)) + "px";
        var first = pop.querySelector("a[href]");
        if (first) first.focus();
      });
    });
    document.addEventListener("click", function (e) {
      var link = e.target.closest("a.ds-sec-item");
      if (!link) return;
      var pop = link.closest("[popover]");
      if (pop && pop.hidePopover) { try { pop.hidePopover(); } catch (err) { /* already closed */ } }
      var url = new URL(link.href, window.location.href);
      if (url.pathname !== window.location.pathname || e.ctrlKey || e.metaKey || e.shiftKey) return;
      e.preventDefault();
      if (window.location.hash !== url.hash) window.history.pushState(null, "", url.hash);
      showTarget();
    });
  }

  document.documentElement.classList.add("ds-js");
  if (!Object.prototype.hasOwnProperty.call(HTMLElement.prototype, "popover")) {
    document.documentElement.classList.add("ds-no-popover");
  }
  setHideEmpty(store.get("hideEmpty") === true);

  // A finding links to its row, e.g. /exposure#port-2083-tcp. Saved sort
  // orders are applied after the browser has scrolled to the row, so scroll
  // again, clear a filter that hides it, and flash it once.
  function showTarget() {
    var id = decodeURIComponent(window.location.hash.slice(1));
    var el = id && document.getElementById(id);
    if (!el) return;
    if (el.classList.contains("ds-filtered") && filterInput) { filterInput.value = ""; applyFilter(); }
    // A card that "Hide empty sections" or the filter has hidden: show it for this visit (the saved switch is unchanged).
    if (!el.getClientRects().length) {
      if (filterInput && filterInput.value) { filterInput.value = ""; applyFilter(); }
      if (document.documentElement.classList.contains("ds-hide-empty")) setHideEmpty(false);
    }
    el.scrollIntoView({ block: el.tagName === "TR" ? "center" : "start" });
    el.classList.remove("ds-flash");
    void el.offsetWidth; // restart the animation
    el.classList.add("ds-flash");
  }

  // Dependent options: an element with data-ds-when="<select id>=<value>" shows only while that select has that
  // value (the Shodan key under Source). Without JavaScript it always shows.
  function bindDependents() {
    document.querySelectorAll("[data-ds-when]").forEach(function (el) {
      var rule = el.getAttribute("data-ds-when").split("=");
      var select = document.getElementById(rule[0]);
      if (!select) return;
      var sync = function () { el.hidden = select.value !== rule[1]; };
      select.addEventListener("change", sync);
      sync();
    });
  }

  // "What to do" steps are folded (details.ds-howto). Printing (the Report is made to be printed) opens the
  // folded ones and closes them again afterwards, so the paper has every step.
  var printOpened = [];
  window.addEventListener("beforeprint", function () {
    printOpened = [];
    document.querySelectorAll("details.ds-howto:not([open])").forEach(function (d) { d.open = true; printOpened.push(d); });
  });
  window.addEventListener("afterprint", function () {
    printOpened.forEach(function (d) { d.open = false; });
    printOpened = [];
  });

  document.addEventListener("DOMContentLoaded", function () {
    bindDependents();
    filterInput = document.getElementById("ds-filter");
    hideEmptySwitch = document.getElementById("ds-hide-empty");
    if (filterInput) {
      filterInput.addEventListener("input", applyFilter);
      filterInput.addEventListener("keydown", function (e) {
        if (e.key === "Escape") { filterInput.value = ""; applyFilter(); }
      });
    }
    if (hideEmptySwitch) {
      hideEmptySwitch.checked = document.documentElement.classList.contains("ds-hide-empty");
      hideEmptySwitch.addEventListener("change", function () {
        setHideEmpty(hideEmptySwitch.checked);
        store.set("hideEmpty", hideEmptySwitch.checked);
      });
    }
    // "/" jumps to the filter, as on GitHub.
    document.addEventListener("keydown", function (e) {
      if (e.key !== "/" || !filterInput || e.ctrlKey || e.metaKey || e.altKey) return;
      var t = e.target;
      if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
      e.preventDefault();
      filterInput.focus();
    });
    document.addEventListener("click", onSortClick);
    document.addEventListener("click", function (e) {
      var b = e.target.closest("[data-status-mode]");
      if (!b) return;
      store.set("findingsFilter", b.getAttribute("data-status-mode") === "attention" ? "attention" : "all");
      applyStatusFilter();
      applyFilter();
    });
    document.addEventListener("click", function (e) {
      var copy = e.target.closest(".ds-copy");
      if (copy) { copyText(copy); return; }
      // Following a link to another place closes the panel it was in.
      var link = e.target.closest(".ds-pop-link");
      var pop = link && link.closest("[popover]");
      if (pop && pop.hidePopover) { try { pop.hidePopover(); } catch (err) { /* already closed */ } }
    });
    // Hold the 30-second refresh while a panel or an accept form is open, or the swap would close it.
    document.body.addEventListener("htmx:beforeRequest", function (e) {
      var elt = e.detail && e.detail.elt;
      if (elt && /every/.test(elt.getAttribute("hx-trigger") || "") &&
          (popoverOpen() || document.querySelector("details.ds-accept[open]"))) e.preventDefault();
    });
    document.body.addEventListener("htmx:afterSettle", function () { applyAll(); });
    initMenu();
    initAccount();
    initSectionMenus();
    window.addEventListener("hashchange", showTarget);
    applyAll();
    showTarget();
  });
}());
