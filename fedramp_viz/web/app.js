/* fedramp-viz dashboard. No dependencies, works under a strict CSP.
   All data from the API is inserted with textContent; nothing is rendered as HTML. */
(function () {
  "use strict";

  const STATUS = {
    pass: { label: "Pass", glyph: "✓", token: "--good" },
    fail: { label: "Fail", glyph: "!", token: "--critical" },
    manual: { label: "Manual", glyph: "?", token: "--warning" },
    not_applicable: { label: "Deferred", glyph: "↓", token: "--neutral" },
    not_assessed: { label: "Not assessed", glyph: "·", token: "--neutral" },
  };
  const SEV_RANK = { high: 0, medium: 1, low: 2 };
  const LEVEL_LABEL = { low: "Low", moderate: "Moderate", high: "High" };

  const state = {
    level: "moderate",
    data: null,
    sub: "",
    group: "",
    type: "",
    search: "",
    failOnly: true,
    selectedResource: null,
    tab: "findings",
    token: null,
  };

  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  };
  const svgEl = (tag, attrs) => {
    const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  };
  const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const fmt = (n) => (n === null || n === undefined ? "n/a" : Number(n).toLocaleString());

  // ---- API ---------------------------------------------------------------

  async function api(path, opts) {
    const headers = {};
    if (state.token) headers["Authorization"] = "Bearer " + state.token;
    const res = await fetch(path, Object.assign({ headers }, opts || {}));
    if (res.status === 401) {
      const t = window.prompt("This server requires an access token.");
      if (!t) throw new Error("token required");
      state.token = t.trim();
      try { sessionStorage.setItem("fedramp-viz-token", state.token); } catch (e) { /* private mode */ }
      return api(path, opts);
    }
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch (e) { /* not json */ }
      throw new Error(detail);
    }
    return res.json();
  }

  async function load() {
    document.body.classList.add("loading");
    try {
      const [meta, data] = await Promise.all([api("/api/meta"), api("/api/assessment?level=" + state.level)]);
      state.data = data;
      $("meta-line").textContent =
        (meta.source ? meta.source : "live " + meta.provider) + " · " + fmt(meta.resources) + " resources · " +
        fmt(data.summary.subscriptions) + " subscriptions · " + fmt(meta.rules) + " rules";
      $("foot").textContent =
        "Generated " + data.generated_at + ". Catalog: " + data.catalog_source +
        (data.warnings.length ? " Warnings: " + data.warnings.join("; ") : "");
      fillFilters();
      render();
    } catch (e) {
      $("meta-line").textContent = "error: " + e.message;
    } finally {
      document.body.classList.remove("loading");
    }
  }

  // ---- filters ------------------------------------------------------------

  const subLabel = (r) => r.subscription_name || r.subscription;

  function fillFilters() {
    const subs = new Map();
    for (const r of state.data.resources) subs.set(r.subscription, subLabel(r));
    const subValues = [...subs.entries()].sort((a, b) => a[1].localeCompare(b[1]));
    const groups = [...new Set(state.data.resources.map((r) => r.resource_group))].sort().map((g) => [g, g]);
    const types = [...new Set(state.data.resources.map((r) => r.type))].sort().map((t) => [t, t]);
    fillSelect($("f-sub"), subValues, state.sub, "All subscriptions");
    fillSelect($("f-group"), groups, state.group, "All resource groups");
    fillSelect($("f-type"), types, state.type, "All resource types");
  }

  // values: [value, label] pairs
  function fillSelect(sel, values, current, allLabel) {
    sel.replaceChildren();
    const all = el("option", null, allLabel);
    all.value = "";
    sel.appendChild(all);
    for (const [v, label] of values) {
      const o = el("option", null, label);
      o.value = v;
      sel.appendChild(o);
    }
    sel.value = values.some(([v]) => v === current) ? current : "";
  }

  function resourceMatches(r) {
    if (state.sub && r.subscription !== state.sub) return false;
    if (state.group && r.resource_group !== state.group) return false;
    if (state.type && r.type !== state.type) return false;
    if (state.selectedResource && r.id !== state.selectedResource) return false;
    return true;
  }

  function findingMatches(f) {
    if (state.sub && f.subscription !== state.sub) return false;
    if (state.group && f.resource_group !== state.group) return false;
    if (state.type && f.resource_type !== state.type) return false;
    if (state.selectedResource && f.resource_id !== state.selectedResource) return false;
    if (state.failOnly && f.status !== "fail" && f.status !== "manual") return false;
    if (state.search) {
      const hay = [f.rule_id, f.rule_title, f.resource_name, f.resource_type, f.message, f.controls.join(" ")].join(" ").toLowerCase();
      if (!hay.includes(state.search)) return false;
    }
    return true;
  }

  // ---- render -------------------------------------------------------------

  function render() {
    const d = state.data;
    renderKpis(d);
    renderFamilyChart(d);
    renderResourceMap(d);
    renderFindings(d);
    renderControls(d);
    renderResources(d);
  }

  function renderKpis(d) {
    const s = d.summary;
    $("hero-level").textContent = LEVEL_LABEL[d.level];
    $("hero-score").textContent = s.score === null ? "n/a" : s.score.toFixed(1) + "%";
    $("hero-sub").textContent =
      fmt(s.pass) + " pass, " + fmt(s.fail) + " fail, weighted by severity. Manual and deferred checks do not count. " +
      s.rules_active + " of " + s.rules_total + " rules apply at this level.";
    $("k-resources").textContent = fmt(s.resources);
    $("k-resources-sub").textContent = fmt(s.resources_failing) + " with at least one failing check";
    $("k-fail").textContent = fmt(s.fail);
    const sev = s.fail_by_severity;
    $("k-fail-sub").textContent = fmt(sev.high) + " high, " + fmt(sev.medium) + " medium, " + fmt(sev.low) + " low";
    $("k-manual").textContent = fmt(s.manual);
    $("k-manual-sub").textContent = s.deferred ? fmt(s.deferred) + " more checks apply at a higher level" : "checks a person has to close out";
    $("k-coverage").textContent = fmt(s.controls_with_evidence) + " of " + fmt(s.baseline_controls);
    $("k-coverage-fill").style.width = Math.max(0, Math.min(100, s.coverage)) + "%";
    $("k-coverage-sub").textContent = s.coverage + "% of the " + LEVEL_LABEL[d.level] + " baseline has an automated check; " + fmt(s.controls_failing) + " controls failing";
  }

  // Horizontal stacked bar per family: pass / fail / manual counts of findings.
  function renderFamilyChart(d) {
    const host = $("family-chart");
    host.replaceChildren();
    const rows = d.families.filter((f) => f.pass + f.fail + f.manual > 0).sort((a, b) => b.fail - a.fail || b.pass + b.manual - (a.pass + a.manual));
    renderLegend($("family-legend"), ["pass", "fail", "manual"]);
    if (!rows.length) {
      host.appendChild(el("div", "empty", "No checks ran. Is the inventory empty?"));
      return;
    }
    const barH = 18, gap = 10, left = 190, right = 40, top = 8, bottom = 24;
    const W = 640, H = top + rows.length * (barH + gap) + bottom;
    const max = Math.max(...rows.map((r) => r.pass + r.fail + r.manual));
    const plotW = W - left - right;
    const x = (v) => left + (v / max) * plotW;
    const svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Checks by control family" });

    const ticks = niceTicks(max, 4);
    for (const t of ticks) {
      svg.appendChild(svgEl("line", { x1: x(t), x2: x(t), y1: top, y2: H - bottom, class: "gridline" }));
      const tx = svgEl("text", { x: x(t), y: H - 6, "text-anchor": "middle", class: "tick" });
      tx.textContent = fmt(t);
      svg.appendChild(tx);
    }
    svg.appendChild(svgEl("line", { x1: left, x2: left, y1: top, y2: H - bottom, class: "baseline" }));

    rows.forEach((r, i) => {
      const y = top + i * (barH + gap);
      const label = svgEl("text", { x: left - 8, y: y + barH / 2 + 4, "text-anchor": "end", class: "fam-label" });
      label.textContent = r.id + " " + shorten(r.name, 20);
      label.appendChild(svgTitle(r.name));
      svg.appendChild(label);
      let cursor = 0;
      const total = r.pass + r.fail + r.manual;
      for (const key of ["fail", "manual", "pass"]) {
        const v = r[key];
        if (!v) continue;
        const x0 = x(cursor), x1 = x(cursor + v);
        const isLast = cursor + v === total;
        const w = Math.max(0, x1 - x0 - (isLast ? 0 : 2));
        const rect = svgEl("rect", { x: x0, y, width: w, height: barH, fill: cssVar(STATUS[key].token), class: "seg", tabindex: 0, rx: isLast ? 4 : 0 });
        rect.addEventListener("pointermove", (e) => showTip(e, r.id + " " + r.name, [["Fail", r.fail], ["Manual", r.manual], ["Pass", r.pass], ["Controls in baseline", r.controls], ["Controls failing", r.controls_failing]]));
        rect.addEventListener("pointerleave", hideTip);
        rect.addEventListener("focus", (e) => showTip(e, r.id + " " + r.name, [["Fail", r.fail], ["Manual", r.manual], ["Pass", r.pass]]));
        rect.addEventListener("blur", hideTip);
        rect.addEventListener("click", () => { state.search = r.id.toLowerCase() + "-"; $("f-search").value = r.id + "-"; renderFindings(state.data); });
        svg.appendChild(rect);
        cursor += v;
      }
      if (r.fail) {
        const t = svgEl("text", { x: x(total) + 6, y: y + barH / 2 + 4, class: "tick" });
        t.textContent = r.fail + " fail";
        svg.appendChild(t);
      }
    });
    host.appendChild(svg);
  }

  function renderLegend(host, keys) {
    host.replaceChildren();
    for (const k of keys) {
      const key = el("span", "key");
      const sw = el("span", "swatch");
      sw.style.background = cssVar(STATUS[k].token);
      key.appendChild(sw);
      key.appendChild(el("span", null, STATUS[k].glyph + " " + STATUS[k].label));
      host.appendChild(key);
    }
  }

  function renderResourceMap(d) {
    const host = $("resource-map");
    host.replaceChildren();
    // Grouped by subscription plus resource group: group names repeat across subscriptions.
    const byGroup = new Map();
    for (const r of d.resources) {
      if (state.sub && r.subscription !== state.sub) continue;
      if (state.group && r.resource_group !== state.group) continue;
      if (state.type && r.type !== state.type) continue;
      const key = r.subscription + "|" + r.resource_group;
      if (!byGroup.has(key)) byGroup.set(key, []);
      byGroup.get(key).push(r);
    }
    const manySubs = d.summary.subscriptions > 1;
    const order = [...byGroup.entries()].sort((a, b) => sumFail(b[1]) - sumFail(a[1]) || a[0].localeCompare(b[0]));
    for (const [, list] of order) {
      const g = el("div", "group");
      const head = el("div", "group-name");
      head.appendChild(el("b", null, list[0].resource_group));
      head.appendChild(el("span", null, list.length + " · " + sumFail(list) + " fail"));
      g.appendChild(head);
      if (manySubs) g.appendChild(el("div", "group-sub", subLabel(list[0])));
      const cells = el("div", "cells");
      list.sort((a, b) => rank(a.status) - rank(b.status) || a.name.localeCompare(b.name));
      for (const r of list) {
        const c = el("button", "cell " + r.status, STATUS[r.status].glyph);
        c.type = "button";
        c.style.background = cssVar(STATUS[r.status].token);
        c.setAttribute("aria-label", r.name + ": " + STATUS[r.status].label);
        if (state.selectedResource === r.id) c.classList.add("selected");
        c.addEventListener("pointermove", (e) => showTip(e, r.name, [["Type", r.type], ["Fail", r.fail], ["Manual", r.manual], ["Pass", r.pass], ["Deferred", r.deferred]]));
        c.addEventListener("pointerleave", hideTip);
        c.addEventListener("focus", (e) => showTip(e, r.name, [["Type", r.type], ["Fail", r.fail], ["Manual", r.manual], ["Pass", r.pass]]));
        c.addEventListener("blur", hideTip);
        c.addEventListener("click", () => {
          state.selectedResource = state.selectedResource === r.id ? null : r.id;
          renderResourceMap(state.data);
          renderFindings(state.data);
          renderResources(state.data);
          selectTab("findings");
        });
        cells.appendChild(c);
      }
      g.appendChild(cells);
      host.appendChild(g);
    }
    if (!order.length) host.appendChild(el("div", "empty", "No resources match the filters."));
  }

  function renderFindings(d) {
    const tbody = $("findings-table").querySelector("tbody");
    tbody.replaceChildren();
    const rows = d.findings.filter(findingMatches).filter((f) => f.status !== "not_applicable" || !state.failOnly);
    if (!rows.length) {
      const tr = el("tr");
      const td = el("td", "empty", "Nothing matches. Clear a filter or untick 'Failing and manual only'.");
      td.colSpan = 6;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const f of rows) {
      const tr = el("tr", "expandable");
      tr.appendChild(tdStatus(f.status));
      tr.appendChild(el("td", "sev", f.severity));
      const tdRule = el("td");
      tdRule.appendChild(el("div", null, f.rule_title));
      tdRule.appendChild(el("span", "sub mono", f.rule_id));
      tr.appendChild(tdRule);
      const tdRes = el("td");
      tdRes.appendChild(el("div", null, f.resource_name));
      tdRes.appendChild(el("span", "sub", f.resource_type + " · " + f.resource_group));
      tr.appendChild(tdRes);
      tr.appendChild(el("td", "mono", f.controls.join(", ")));
      tr.appendChild(el("td", null, f.message));
      tr.addEventListener("click", () => toggleDetail(tr, f));
      tbody.appendChild(tr);
    }
  }

  function toggleDetail(tr, f) {
    const next = tr.nextElementSibling;
    if (next && next.classList.contains("detail")) { next.remove(); return; }
    const dtr = el("tr", "detail");
    const td = el("td");
    td.colSpan = 6;
    if (f.remediation) {
      td.appendChild(el("div", null, "Remediation: " + f.remediation));
    }
    td.appendChild(el("div", null, "Resource id: " + f.resource_id));
    if (f.evidence && Object.keys(f.evidence).length) {
      const code = el("code", null, JSON.stringify(f.evidence, null, 2));
      td.appendChild(el("div", null, "Evidence:"));
      td.appendChild(code);
    }
    dtr.appendChild(td);
    tr.after(dtr);
  }

  function renderControls(d) {
    const tbody = $("controls-table").querySelector("tbody");
    tbody.replaceChildren();
    const q = state.search;
    const rows = d.controls.filter((c) => {
      if (state.failOnly && c.status !== "fail" && c.status !== "manual") return false;
      if (q && !(c.id + " " + c.title + " " + c.family).toLowerCase().includes(q)) return false;
      return true;
    });
    if (!rows.length) {
      const tr = el("tr");
      const td = el("td", "empty", state.failOnly ? "No failing controls match. Untick 'Failing and manual only' to see the whole baseline." : "No controls match.");
      td.colSpan = 8;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const c of rows) {
      const tr = el("tr");
      tr.appendChild(el("td", "mono", c.id));
      tr.appendChild(el("td", null, c.title));
      tr.appendChild(el("td", null, c.family));
      tr.appendChild(tdStatus(c.status));
      tr.appendChild(el("td", "num", c.pass));
      tr.appendChild(el("td", "num", c.fail));
      tr.appendChild(el("td", "num", c.manual));
      tr.appendChild(el("td", "mono muted", c.rules.join(", ")));
      tbody.appendChild(tr);
    }
  }

  function renderResources(d) {
    const tbody = $("resources-table").querySelector("tbody");
    tbody.replaceChildren();
    const q = state.search;
    const rows = d.resources.filter(resourceMatches).filter((r) => {
      if (state.failOnly && r.status !== "fail" && r.status !== "manual") return false;
      if (q && !(r.name + " " + r.type + " " + r.resource_group).toLowerCase().includes(q)) return false;
      return true;
    }).sort((a, b) => rank(a.status) - rank(b.status) || b.fail - a.fail || a.name.localeCompare(b.name));
    for (const r of rows) {
      const tr = el("tr");
      tr.appendChild(tdStatus(r.status));
      tr.appendChild(el("td", null, r.name));
      tr.appendChild(el("td", "mono", r.type));
      tr.appendChild(el("td", null, r.resource_group));
      tr.appendChild(el("td", null, subLabel(r)));
      tr.appendChild(el("td", null, r.location));
      tr.appendChild(el("td", "num", r.pass));
      tr.appendChild(el("td", "num", r.fail));
      tr.appendChild(el("td", "num", r.manual));
      tr.appendChild(el("td", "num", r.deferred));
      tbody.appendChild(tr);
    }
    if (!rows.length) {
      const tr = el("tr");
      const td = el("td", "empty", "No resources match.");
      td.colSpan = 10;
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  }

  // ---- bits -----------------------------------------------------------------

  function tdStatus(status) {
    const td = el("td");
    const s = el("span", "status " + status);
    s.appendChild(el("span", "dot", STATUS[status].glyph));
    s.appendChild(el("span", null, STATUS[status].label));
    td.appendChild(s);
    return td;
  }
  const rank = (s) => ({ fail: 0, manual: 1, pass: 2, not_assessed: 3, not_applicable: 4 })[s] ?? 5;
  const sumFail = (list) => list.reduce((a, r) => a + r.fail, 0);
  const shorten = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
  function svgTitle(text) { const t = svgEl("title", {}); t.textContent = text; return t; }
  function niceTicks(max, count) {
    if (max <= 0) return [0];
    const raw = max / count;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const step = [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) || mag * 10;
    const out = [];
    for (let v = 0; v <= max; v += step) out.push(v);
    return out;
  }

  const tip = $("tooltip");
  function showTip(e, title, rows) {
    tip.replaceChildren();
    tip.appendChild(el("b", null, title));
    for (const [k, v] of rows) {
      if (v === undefined || v === null) continue;
      const r = el("div", "row");
      r.appendChild(el("span", "muted", k));
      r.appendChild(el("span", null, v));
      tip.appendChild(r);
    }
    tip.hidden = false;
    const pad = 14;
    let x = e.clientX + pad, y = e.clientY + pad;
    const rect = tip.getBoundingClientRect();
    if (x + rect.width > window.innerWidth - 8) x = e.clientX - rect.width - pad;
    if (y + rect.height > window.innerHeight - 8) y = e.clientY - rect.height - pad;
    tip.style.left = x + "px";
    tip.style.top = y + "px";
  }
  function hideTip() { tip.hidden = true; }

  function selectTab(name) {
    state.tab = name;
    document.querySelectorAll('[role="tab"]').forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
    for (const n of ["findings", "controls", "resources"]) $("tab-" + n).hidden = n !== name;
  }

  // ---- wiring ---------------------------------------------------------------

  try { state.token = sessionStorage.getItem("fedramp-viz-token"); } catch (e) { /* ignore */ }

  $("level-picker").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-level]");
    if (!b) return;
    state.level = b.dataset.level;
    document.querySelectorAll("#level-picker button").forEach((x) => x.setAttribute("aria-checked", String(x === b)));
    load();
  });
  $("f-sub").addEventListener("change", (e) => { state.sub = e.target.value; state.selectedResource = null; render(); });
  $("f-group").addEventListener("change", (e) => { state.group = e.target.value; state.selectedResource = null; render(); });
  $("f-type").addEventListener("change", (e) => { state.type = e.target.value; state.selectedResource = null; render(); });
  $("f-search").addEventListener("input", (e) => { state.search = e.target.value.trim().toLowerCase(); renderFindings(state.data); renderControls(state.data); renderResources(state.data); });
  $("f-fail-only").addEventListener("change", (e) => { state.failOnly = e.target.checked; renderFindings(state.data); renderControls(state.data); renderResources(state.data); });
  document.querySelector(".tabs").addEventListener("click", (e) => {
    const b = e.target.closest('[role="tab"]');
    if (b) selectTab(b.dataset.tab);
  });
  $("rescan").addEventListener("click", async () => {
    $("rescan").disabled = true;
    try { await api("/api/rescan", { method: "POST" }); await load(); }
    catch (err) { $("meta-line").textContent = "rescan failed: " + err.message; }
    finally { $("rescan").disabled = false; }
  });
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { if (state.data) render(); });

  load();
})();
