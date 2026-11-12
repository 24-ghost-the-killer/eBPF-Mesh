// SPDX-License-Identifier: MIT OR Apache-2.0
// Polls the platform's public status; when it cannot be reached, says so and
// shows the last known state (kept in this browser). Incidents come from
// incidents.json next to this file, edited by operators.
(function () {
  "use strict";
  var cfg = window.SENTINEL_STATUS || {};
  var $ = function (id) { return document.getElementById(id); };
  var KEY = "sentinel-status-last";

  function text(el, s) { el.textContent = s; }
  function fmt(ms) { return ms ? new Date(ms).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "–"; }

  function render(pops, when, live) {
    var up = pops.filter(function (p) { return p.status === "up"; }).length;
    text($("summary"), pops.length === 0 ? "No PoP has reported yet"
      : up === pops.length ? "All systems operational"
      : up === 0 ? "Major outage" : "Partial outage: " + up + " of " + pops.length + " PoPs up");
    text($("updated"), (live ? "Updated " : "Last known state from ") + fmt(when));
    var body = $("pops").querySelector("tbody");
    body.textContent = "";
    pops.forEach(function (p) {
      var tr = document.createElement("tr");
      [p.id, p.region].forEach(function (v) { var td = document.createElement("td"); td.textContent = v; tr.appendChild(td); });
      var td = document.createElement("td");
      var b = document.createElement("span");
      b.className = "badge " + (p.status === "up" ? "ok" : p.status === "draining" ? "warn" : "bad");
      b.textContent = p.status;
      td.appendChild(b);
      tr.appendChild(td);
      body.appendChild(tr);
    });
    $("pops").hidden = pops.length === 0;
    $("nopops").hidden = pops.length !== 0;
  }

  function unreachable(why) {
    var banner = $("banner");
    banner.hidden = false;
    text(banner, "We cannot reach the platform right now (" + why + "). This may be an outage; we are looking into it.");
    var last = null;
    try { last = JSON.parse(localStorage.getItem(KEY) || "null"); } catch (e) { last = null; }
    if (last && last.pops) { render(last.pops, last.at, false); } else { text($("summary"), "Status unknown"); text($("updated"), ""); }
  }

  function poll() {
    if (!cfg.api) { unreachable("status page not configured"); return; }
    var ctl = new AbortController();
    var t = setTimeout(function () { ctl.abort(); }, 5000);
    fetch(cfg.api, { signal: ctl.signal, credentials: "omit", cache: "no-store" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (d) {
        $("banner").hidden = true;
        var now = Date.now();
        render(d.pops || [], now, true);
        try { localStorage.setItem(KEY, JSON.stringify({ pops: d.pops || [], at: now })); } catch (e) { /* private mode */ }
      })
      .catch(function (e) { unreachable(e.name === "AbortError" ? "timed out" : "no answer"); })
      .finally(function () { clearTimeout(t); });
  }

  function incidents() {
    fetch("incidents.json", { cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : []; })
      .catch(function () { return []; })
      .then(function (list) {
        var ol = $("incidents");
        ol.textContent = "";
        (list || []).forEach(function (i) {
          var li = document.createElement("li");
          var h = document.createElement("h3");
          h.textContent = i.title;
          var meta = document.createElement("p");
          meta.className = "muted";
          meta.textContent = (i.date || "") + (i.status ? " · " + i.status : "");
          var p = document.createElement("p");
          p.textContent = i.text || "";
          li.appendChild(h); li.appendChild(meta); li.appendChild(p);
          ol.appendChild(li);
        });
        $("noinc").hidden = (list || []).length !== 0;
      });
  }

  if (cfg.portal) {
    var a = document.createElement("a");
    a.href = cfg.portal;
    a.textContent = "Go to the portal";
    $("portal").appendChild(a);
  }
  poll();
  incidents();
  setInterval(poll, Math.max(5, cfg.refreshSeconds || 15) * 1000);
})();
