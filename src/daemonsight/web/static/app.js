// DaemonSight page tools: column sorting, a row filter and "hide empty
// sections". No dependencies; served from 'self' under the CSP.
//
// Markup it reads:
//   [data-section]          a card the filter and "hide empty" act on
//   [data-section][data-empty]  the card has no data from its source
//   [data-row]              a row or list item the filter can hide
//   table[data-table=key]   a sortable table; key names its saved sort
//   th[data-sort=num|text]  a sortable column
//   td[data-v]              raw value to sort by instead of the cell text
//
// Sort order and the hide-empty switch are saved in localStorage. All of it
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
    var body = table.tBodies[0];
    var head = table.tHead && table.tHead.rows[0];
    if (!body || !head) return;
    var state = sorts[key];
    var col = state ? state.col : -1;
    each(head.cells, function (th, i) {
      if (!th.hasAttribute("data-sort")) return;
      th.setAttribute("aria-sort", i === col ? (state.dir > 0 ? "ascending" : "descending") : "none");
    });
    var rows = Array.prototype.filter.call(body.rows, function (r) { return r.hasAttribute("data-row"); });
    // Remember the server's order so "unsorted" can restore it.
    each(rows, function (r, i) { if (!r.hasAttribute("data-i")) r.setAttribute("data-i", String(i)); });
    var numeric = col >= 0 && head.cells[col] && head.cells[col].getAttribute("data-sort") === "num";
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

  function copyText(button) {
    var code = button.parentNode.querySelector(".ds-copy-text");
    if (!code) return;
    var done = function () {
      button.textContent = "Copied";
      setTimeout(function () { button.textContent = "Copy"; }, 1500);
    };
    var fallback = function () {
      // Plain HTTP on a LAN address has no Clipboard API: select the text instead.
      var range = document.createRange();
      range.selectNodeContents(code);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      try { if (document.execCommand("copy")) { done(); return; } } catch (e) { /* not allowed */ }
      button.textContent = "Selected";
      setTimeout(function () { button.textContent = "Copy"; }, 1500);
    };
    if (window.isSecureContext && navigator.clipboard) {
      navigator.clipboard.writeText(code.textContent).then(done, fallback);
    } else {
      fallback();
    }
  }

  function applyFilter() {
    var terms = filterInput ? filterInput.value.toLowerCase().split(/\s+/).filter(Boolean) : [];
    each(document.querySelectorAll("[data-section]"), function (section) {
      var rows = section.querySelectorAll("[data-row]");
      var shown = 0;
      each(rows, function (row) {
        var text = rowText(row);
        var match = terms.every(function (t) { return text.indexOf(t) !== -1; });
        row.classList.toggle("ds-filtered", !match);
        if (match) shown += 1;
      });
      var noMatch = terms.length > 0 && rows.length > 0 && shown === 0;
      section.toggleAttribute("data-nomatch", noMatch);
      var count = section.querySelector(".ds-shown");
      if (count) count.textContent = terms.length && rows.length ? shown + " match · " : "";
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
    applyFilter();
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
    el.scrollIntoView({ block: el.tagName === "TR" ? "center" : "start" });
    el.classList.remove("ds-flash");
    void el.offsetWidth; // restart the animation
    el.classList.add("ds-flash");
  }

  document.addEventListener("DOMContentLoaded", function () {
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
      var copy = e.target.closest(".ds-copy");
      if (copy) { copyText(copy); return; }
      // Following a link to another place closes the panel it was in.
      var link = e.target.closest(".ds-pop-link");
      var pop = link && link.closest("[popover]");
      if (pop && pop.hidePopover) { try { pop.hidePopover(); } catch (err) { /* already closed */ } }
    });
    // Hold the 30-second refresh while a panel is open, or the swap would close it.
    document.body.addEventListener("htmx:beforeRequest", function (e) {
      var elt = e.detail && e.detail.elt;
      if (elt && /every/.test(elt.getAttribute("hx-trigger") || "") && popoverOpen()) e.preventDefault();
    });
    document.body.addEventListener("htmx:afterSettle", applyAll);
    window.addEventListener("hashchange", showTarget);
    applyAll();
    showTarget();
  });
}());
