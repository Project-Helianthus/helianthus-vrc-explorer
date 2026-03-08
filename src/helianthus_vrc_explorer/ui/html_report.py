# ruff: noqa: E501

from __future__ import annotations

import json
from html import escape as _escape_html
from typing import Any


def _json_for_html(obj: Any) -> str:
    """Dump JSON in a form that is safe to embed inside an HTML <script> tag."""

    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    # Prevent `</script>` breaks and avoid HTML parser surprises.
    return raw.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


_TEMPLATE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>__TITLE__</title>
    <style>
      :root {
        --bg: #0f1115;
        --bg-2: #151a21;
        --panel: #1c2230;
        --panel-2: #141a24;
        --ink: #e9eef7;
        --muted: #a7b0c0;
        --accent: #66e3c4;
        --accent-2: #7aa2ff;
        --warn: #ffcf6e;
        --danger: #ff7a7a;
        --grid: rgba(255, 255, 255, 0.08);
        --shadow: 0 20px 50px rgba(0, 0, 0, 0.35);
        --radius: 14px;
        --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial,
          "Apple Color Emoji", "Segoe UI Emoji";
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        font-family: var(--sans);
        color: var(--ink);
        background:
          radial-gradient(1200px 800px at 10% -20%, rgba(102, 227, 196, 0.18), transparent 60%),
          radial-gradient(900px 600px at 90% -10%, rgba(122, 162, 255, 0.18), transparent 60%),
          linear-gradient(180deg, #0b0d12 0%, #0f1115 60%, #10131a 100%);
        min-height: 100vh;
      }

      .page {
        max-width: 1280px;
        margin: 0 auto;
        padding: 28px 18px 60px;
        display: grid;
        gap: 14px;
      }

      header {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }

      .title {
        font-size: clamp(22px, 4vw, 34px);
        font-weight: 650;
        letter-spacing: -0.01em;
      }

      .subtitle {
        color: var(--muted);
        font-size: 13px;
        line-height: 1.4;
      }

      .pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 8px;
        border-radius: 999px;
        background: rgba(122, 162, 255, 0.12);
        color: var(--accent-2);
        font-size: 11px;
        font-family: var(--mono);
        border: 1px solid rgba(122, 162, 255, 0.25);
      }

      .sheet-card {
        background: linear-gradient(180deg, rgba(28, 34, 48, 0.95), rgba(18, 22, 32, 0.95));
        border: 1px solid rgba(255, 255, 255, 0.06);
        box-shadow: var(--shadow);
        border-radius: var(--radius);
        padding: 14px;
        display: grid;
        gap: 10px;
      }

      .tabs {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }

      .tab {
        padding: 7px 11px;
        border-radius: 999px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        background: rgba(255, 255, 255, 0.04);
        color: var(--muted);
        cursor: pointer;
        transition: all 0.18s ease;
        user-select: none;
        font-size: 12px;
      }

      .tab.active {
        background: rgba(102, 227, 196, 0.15);
        border-color: rgba(102, 227, 196, 0.4);
        color: var(--ink);
      }

      .table-wrap {
        overflow-x: auto;
        overflow-y: auto;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.06);
        background: #0f1420;
        max-height: 74vh;
      }

      table {
        width: max-content;
        min-width: 100%;
        border-collapse: collapse;
        min-width: 820px;
      }

      thead th {
        position: sticky;
        top: 0;
        z-index: 2;
        background: #121826;
        color: var(--muted);
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        padding: 9px 8px;
        border-bottom: 1px solid var(--grid);
        min-width: 140px;
      }

      tbody td {
        border-bottom: 1px solid var(--grid);
        padding: 8px;
        vertical-align: top;
        font-size: 13px;
        min-width: 140px;
      }

      tbody tr:nth-child(even) {
        background: rgba(255, 255, 255, 0.02);
      }

      .offset-cell {
        min-width: 220px;
      }

      .offset-label {
        font-family: var(--mono);
        font-size: 12px;
        color: var(--muted);
      }

      .offset-name {
        margin-top: 4px;
        font-size: 12px;
        color: var(--ink);
        opacity: 0.9;
        word-break: break-word;
      }

      .offset-name-secondary {
        margin-top: 2px;
        font-size: 11px;
        color: var(--muted);
        opacity: 0.95;
        word-break: break-word;
      }

      .offset-meta {
        margin-top: 4px;
        display: flex;
        gap: 6px;
        flex-wrap: wrap;
      }

      .type-select {
        margin-top: 8px;
        width: 100%;
        background: #0c111a;
        color: var(--ink);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 10px;
        font-size: 12px;
        padding: 6px 8px;
        font-family: var(--sans);
      }

      .cell-value {
        font-weight: 650;
        font-family: var(--sans);
      }

      .cell-raw {
        font-family: var(--mono);
        font-size: 11px;
        color: var(--muted);
        margin-top: 5px;
        word-break: break-all;
      }

      .cell-error {
        margin-top: 5px;
        font-size: 11px;
        color: rgba(255, 122, 122, 0.95);
        word-break: break-word;
      }

      .cell-missing {
        color: rgba(255, 255, 255, 0.5);
        font-family: var(--mono);
      }

      .cell-bad {
        background: rgba(255, 122, 122, 0.14);
      }

      .meta-row {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        align-items: center;
      }

      .filters {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        align-items: center;
        margin-bottom: 8px;
      }

      .filter-chip {
        display: inline-flex;
        gap: 6px;
        align-items: center;
        font-size: 12px;
        color: var(--muted);
      }

      .filter-input {
        min-width: 260px;
        background: #0c111a;
        color: var(--ink);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 10px;
        font-size: 12px;
        padding: 6px 8px;
        font-family: var(--sans);
      }

      @media (max-width: 860px) {
        .page {
          padding: 22px 14px 54px;
        }
        .offset-cell {
          min-width: 200px;
        }
        table {
          min-width: 740px;
        }
      }
    </style>
  </head>
  <body>
    <div class="page">
      <header>
        <div class="title">B524 Scan Results</div>
        <div class="subtitle">
          This report is generated from the scan artifact.
          <span class="pill" id="metaDst"></span>
          <span class="pill" id="metaTs"></span>
          <span class="pill" id="metaIncomplete" style="display: none"></span>
        </div>
      </header>

      <section class="sheet-card">
        <div class="tabs" id="tabs"></div>
        <div id="sheetArea"></div>
      </section>
    </div>

    <script id="artifact-data" type="application/json">
__ARTIFACT_JSON__
    </script>

    <script>
      const artifact = JSON.parse(document.getElementById("artifact-data").textContent || "{}");

      const metaDst = document.getElementById("metaDst");
      const metaTs = document.getElementById("metaTs");
      const metaIncomplete = document.getElementById("metaIncomplete");

      function safeMetaString(v) {
        return typeof v === "string" ? v : "";
      }

      const meta = artifact && typeof artifact === "object" ? artifact.meta || {} : {};
      metaDst.textContent = safeMetaString(meta.destination_address || meta.dest || meta.dst || "dst=?");
      metaTs.textContent = safeMetaString(meta.scan_timestamp || meta.ts || "ts=?");
      if (meta && meta.incomplete) {
        metaIncomplete.style.display = "inline-flex";
        metaIncomplete.textContent = "incomplete";
      }

      function parseHexKey(key) {
        if (typeof key !== "string") return NaN;
        const n = Number(key);
        if (Number.isFinite(n)) return n;
        try {
          return parseInt(key, 0);
        } catch (e) {
          return NaN;
        }
      }

      function sortedHexKeys(keys) {
        return (keys || [])
          .filter((k) => typeof k === "string")
          .slice()
          .sort((a, b) => {
            const na = parseHexKey(a);
            const nb = parseHexKey(b);
            if (!Number.isFinite(na) && !Number.isFinite(nb)) return String(a).localeCompare(String(b));
            if (!Number.isFinite(na)) return 1;
            if (!Number.isFinite(nb)) return -1;
            return na - nb;
          });
      }

      function getGroupObject(groupObj) {
        if (!groupObj || typeof groupObj !== "object") return { name: "Unknown", instances: {} };
        // New schema: { name, descriptor_type, instances: { "0x00": { present, registers: {...} } } }
        if (groupObj.instances && typeof groupObj.instances === "object") return groupObj;
        // Legacy-ish: groupObj might itself be an instances map.
        return { name: "Unknown", instances: groupObj };
      }

      function getInstanceObject(instanceObj) {
        if (!instanceObj || typeof instanceObj !== "object") return { present: true, registers: {} };
        // New schema: { present, registers }
        if (instanceObj.registers && typeof instanceObj.registers === "object") return instanceObj;
        // Legacy-ish: instanceObj might itself be registers.
        return { present: true, registers: instanceObj };
      }

      function candidateTypeSpecsForLength(n) {
        if (!Number.isFinite(n) || n <= 0) return [];
        if (n === 1) return ["UCH", "I8", "BOOL", "HEX:1"];
        if (n === 2) return ["UIN", "I16", "HEX:2"];
        if (n === 3) return ["HDA:3", "HTI", "HEX:3"];
        if (n === 4) return ["EXP", "U32", "I32", "HEX:4"];
        return [`HEX:${n}`, "STR:*"];
      }

      function bytesFromHex(rawHex) {
        if (typeof rawHex !== "string" || rawHex.length % 2) return null;
        const out = new Uint8Array(rawHex.length / 2);
        for (let i = 0; i < out.length; i++) {
          const byteStr = rawHex.slice(i * 2, i * 2 + 2);
          const v = parseInt(byteStr, 16);
          if (!Number.isFinite(v)) return null;
          out[i] = v;
        }
        return out;
      }

      function decodeLatin1(bytes) {
        if (!bytes || bytes.length === 0) return "";
        let s = "";
        for (let i = 0; i < bytes.length; i++) {
          if (bytes[i] === 0x00) break;
          s += String.fromCharCode(bytes[i]);
        }
        return s;
      }

      function decodeBcdByte(b) {
        const hi = (b >> 4) & 0x0f;
        const lo = b & 0x0f;
        if (hi > 9 || lo > 9) return null;
        return hi * 10 + lo;
      }

      function parseTypedValue(typeSpec, bytes) {
        const t = String(typeSpec || "").trim().toUpperCase();
        if (!bytes) return { value: null, error: "missing bytes" };

        if (t.startsWith("STR:")) {
          return { value: decodeLatin1(bytes), error: null };
        }
        if (t.startsWith("HEX:")) {
          const parts = t.split(":", 2);
          const expected = parseInt(parts[1] || "", 10);
          if (bytes.length !== expected) return { value: null, error: `HEX expects ${expected} bytes` };
          let hx = "";
          for (let i = 0; i < bytes.length; i++) hx += bytes[i].toString(16).padStart(2, "0");
          return { value: "0x" + hx, error: null };
        }

        function expectLen(n) {
          if (bytes.length !== n) throw new Error(`${t} expects ${n} bytes`);
        }

        try {
          switch (t) {
            case "UCH": {
              expectLen(1);
              return { value: bytes[0], error: null };
            }
            case "I8": {
              expectLen(1);
              const v = (bytes[0] << 24) >> 24;
              return { value: v, error: null };
            }
            case "BOOL": {
              expectLen(1);
              return { value: bytes[0] !== 0x00, error: null };
            }
            case "UIN": {
              expectLen(2);
              return { value: bytes[0] | (bytes[1] << 8), error: null };
            }
            case "I16": {
              expectLen(2);
              let v = bytes[0] | (bytes[1] << 8);
              if (v & 0x8000) v = v - 0x10000;
              return { value: v, error: null };
            }
            case "U32": {
              expectLen(4);
              const v = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0;
              return { value: v, error: null };
            }
            case "I32": {
              expectLen(4);
              const v = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
              return { value: v, error: null };
            }
            case "EXP": {
              expectLen(4);
              const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
              const f = dv.getFloat32(0, true);
              if (Number.isNaN(f)) return { value: null, error: null };
              return { value: f, error: null };
            }
            case "HDA:3": {
              expectLen(3);
              const dd = decodeBcdByte(bytes[0]);
              const mm = decodeBcdByte(bytes[1]);
              const yy = decodeBcdByte(bytes[2]);
              if (dd === null || mm === null || yy === null) throw new Error("invalid BCD date");
              const yyyy = 2000 + yy;
              const iso = `${yyyy.toString().padStart(4, "0")}-${mm.toString().padStart(2, "0")}-${dd
                .toString()
                .padStart(2, "0")}`;
              return { value: iso, error: null };
            }
            case "HTI": {
              expectLen(3);
              const hh = decodeBcdByte(bytes[0]);
              const mi = decodeBcdByte(bytes[1]);
              const ss = decodeBcdByte(bytes[2]);
              if (hh === null || mi === null || ss === null) throw new Error("invalid BCD time");
              if (hh > 23 || mi > 59 || ss > 59) throw new Error("time out of range");
              const txt = `${hh.toString().padStart(2, "0")}:${mi.toString().padStart(2, "0")}:${ss
                .toString()
                .padStart(2, "0")}`;
              return { value: txt, error: null };
            }
            default:
              return { value: null, error: `unknown type: ${typeSpec}` };
          }
        } catch (e) {
          return { value: null, error: String(e && e.message ? e.message : e) };
        }
      }

      function formatValue(v) {
        if (v === null || typeof v === "undefined") return "null";
        if (typeof v === "number" && !Number.isFinite(v)) return String(v);
        if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(6).replace(/0+$/, "").replace(/\\.$/, "");
        return String(v);
      }

      const state = {
        activeTab: null,
        overrides: (meta && typeof meta === "object" && meta.type_overrides) || {},
        b509Filters: {
          search: "",
          hideTimeout: false,
          hideEmpty: false,
          hideDecodeErrors: false,
        },
      };

      const tabsEl = document.getElementById("tabs");
      const sheetArea = document.getElementById("sheetArea");

      function getRowOverride(groupKey, rrKey) {
        const g = state.overrides && state.overrides[groupKey];
        return g && typeof g === "object" ? g[rrKey] : null;
      }

      function setRowOverride(groupKey, rrKey, typeSpec) {
        if (!state.overrides || typeof state.overrides !== "object") state.overrides = {};
        if (!state.overrides[groupKey] || typeof state.overrides[groupKey] !== "object") state.overrides[groupKey] = {};
        state.overrides[groupKey][rrKey] = typeSpec;
      }

      function _isB509Tab(tabId) {
        return tabId === "b509";
      }

      function _isB524Tab(tabId) {
        return typeof tabId === "string" && tabId.startsWith("b524:");
      }

      function _groupKeyFromTab(tabId) {
        if (!_isB524Tab(tabId)) return null;
        return tabId.slice("b524:".length);
      }

      function _syncActiveTabClasses() {
        for (const el of tabsEl.querySelectorAll(".tab")) {
          if (el.dataset && el.dataset.tabId === state.activeTab) el.classList.add("active");
          else el.classList.remove("active");
        }
      }

      function buildTabs(groupKeys, hasB509) {
        tabsEl.innerHTML = "";
        const groupsRoot = artifact && typeof artifact === "object" ? artifact.groups || {} : {};
        const orderedTabIds = [];

        if (hasB509) {
          const btn = document.createElement("div");
          btn.className = "tab";
          btn.textContent = "B509 Dump";
          btn.dataset.tabId = "b509";
          btn.addEventListener("click", () => {
            state.activeTab = "b509";
            _syncActiveTabClasses();
            renderActiveTab();
          });
          tabsEl.appendChild(btn);
          orderedTabIds.push("b509");
        }

        for (const key of groupKeys) {
          const btn = document.createElement("div");
          btn.className = "tab";
          const groupObj = getGroupObject(groupsRoot[key]);
          const groupName = typeof groupObj.name === "string" && groupObj.name ? groupObj.name : "Unknown";
          btn.textContent = groupName !== "Unknown" ? `${key} (${groupName})` : key;
          const tabId = `b524:${key}`;
          btn.dataset.tabId = tabId;
          btn.addEventListener("click", () => {
            state.activeTab = tabId;
            _syncActiveTabClasses();
            renderActiveTab();
          });
          tabsEl.appendChild(btn);
          orderedTabIds.push(tabId);
        }

        if (!state.activeTab || !orderedTabIds.includes(state.activeTab)) {
          state.activeTab = orderedTabIds[0] || null;
        }
        _syncActiveTabClasses();
      }

      function renderB509Tab() {
        const b509 = artifact && typeof artifact === "object" ? artifact.b509_dump : null;
        if (!b509 || typeof b509 !== "object") {
          sheetArea.innerHTML = "<div class='subtitle'>No B509 dump in artifact.</div>";
          return;
        }
        const devices = b509.devices && typeof b509.devices === "object" ? b509.devices : {};
        const rows = [];
        for (const dstKey of sortedHexKeys(Object.keys(devices))) {
          const dev = devices[dstKey];
          if (!dev || typeof dev !== "object") continue;
          const regs = dev.registers && typeof dev.registers === "object" ? dev.registers : {};
          for (const addrKey of sortedHexKeys(Object.keys(regs))) {
            const entry = regs[addrKey];
            if (!entry || typeof entry !== "object") continue;
            rows.push({ dstKey, addrKey, entry });
          }
        }

        const card = document.createElement("div");

        const filters = document.createElement("div");
        filters.className = "filters";

        const search = document.createElement("input");
        search.className = "filter-input";
        search.type = "text";
        search.placeholder = "Search by register or name...";
        search.value = state.b509Filters.search || "";
        search.addEventListener("input", () => {
          state.b509Filters.search = search.value || "";
          renderB509Tab();
        });
        filters.appendChild(search);

        function mkCheck(labelText, key) {
          const label = document.createElement("label");
          label.className = "filter-chip";
          const cb = document.createElement("input");
          cb.type = "checkbox";
          cb.checked = !!state.b509Filters[key];
          cb.addEventListener("change", () => {
            state.b509Filters[key] = !!cb.checked;
            renderB509Tab();
          });
          label.appendChild(cb);
          label.appendChild(document.createTextNode(labelText));
          filters.appendChild(label);
        }
        mkCheck("Hide timeouts", "hideTimeout");
        mkCheck("Hide empty", "hideEmpty");
        mkCheck("Hide decode errors", "hideDecodeErrors");
        card.appendChild(filters);

        const filtered = rows.filter((row) => {
          const entry = row.entry;
          const errTxt = typeof entry.error === "string" ? entry.error : "";
          const rawHex = typeof entry.raw_hex === "string" ? entry.raw_hex : "";
          const replyHex = typeof entry.reply_hex === "string" ? entry.reply_hex : "";
          const ebusdName = typeof entry.ebusd_name === "string" ? entry.ebusd_name : "";
          const myName = typeof entry.myvaillant_name === "string" ? entry.myvaillant_name : "";
          const addrText = String(row.addrKey || "");
          const haystack = `${row.dstKey} ${addrText} ${ebusdName} ${myName}`.toLowerCase();
          const q = String(state.b509Filters.search || "").trim().toLowerCase();
          if (q && !haystack.includes(q)) return false;
          if (state.b509Filters.hideTimeout && errTxt.toLowerCase().includes("timeout")) return false;
          if (state.b509Filters.hideEmpty && !rawHex && !replyHex) return false;
          if (
            state.b509Filters.hideDecodeErrors &&
            (errTxt.toLowerCase().startsWith("parse_error:") || errTxt.toLowerCase().startsWith("decode_error:"))
          ) {
            return false;
          }
          return true;
        });

        if (!filtered.length) {
          const msg = document.createElement("div");
          msg.className = "subtitle";
          msg.textContent = "No B509 rows match current filters.";
          card.appendChild(msg);
          sheetArea.innerHTML = "";
          sheetArea.appendChild(card);
          return;
        }

        const wrap = document.createElement("div");
        wrap.className = "table-wrap";

        const table = document.createElement("table");
        const thead = document.createElement("thead");
        const trHead = document.createElement("tr");
        for (const col of ["Dst", "Register", "Name", "Type", "Value", "Raw", "Error"]) {
          const th = document.createElement("th");
          th.textContent = col;
          trHead.appendChild(th);
        }
        thead.appendChild(trHead);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        for (const row of filtered) {
          const tr = document.createElement("tr");
          const entry = row.entry;
          const errTxt = typeof entry.error === "string" ? entry.error : "";
          const rawHex = typeof entry.raw_hex === "string" ? entry.raw_hex : "";
          const replyHex = typeof entry.reply_hex === "string" ? entry.reply_hex : "";

          function appendText(value, klass) {
            const td = document.createElement("td");
            if (klass) td.className = klass;
            td.textContent = value;
            tr.appendChild(td);
            return td;
          }

          appendText(row.dstKey, "offset-label");
          appendText(row.addrKey, "offset-label");

          const nameTd = document.createElement("td");
          const myName = typeof entry.myvaillant_name === "string" ? entry.myvaillant_name : "";
          const ebusdName = typeof entry.ebusd_name === "string" ? entry.ebusd_name : "";
          if (myName) {
            const top = document.createElement("div");
            top.className = "offset-name";
            top.textContent = myName;
            nameTd.appendChild(top);
          }
          if (ebusdName) {
            const sub = document.createElement("div");
            sub.className = myName ? "offset-name-secondary" : "offset-name";
            sub.textContent = myName ? `ebusd: ${ebusdName}` : ebusdName;
            nameTd.appendChild(sub);
          }
          if (!myName && !ebusdName) {
            nameTd.innerHTML = "<div class='cell-missing'>—</div>";
          }
          tr.appendChild(nameTd);

          appendText(typeof entry.type === "string" ? entry.type : "—");
          appendText(formatValue(entry.value));
          appendText(rawHex || replyHex || "—", "cell-raw");

          const errTd = appendText(errTxt || "—", errTxt ? "cell-error" : "");
          if (errTxt) errTd.parentElement.classList.add("cell-bad");
          if (replyHex && rawHex && replyHex !== rawHex) {
            tr.title = `reply_hex=${replyHex}\\nraw_hex=${rawHex}`;
          }
          tbody.appendChild(tr);
        }

        table.appendChild(tbody);
        wrap.appendChild(table);
        card.appendChild(wrap);

        sheetArea.innerHTML = "";
        sheetArea.appendChild(card);
      }

      function renderActiveGroup(groupKey) {
        const groupsRoot = artifact && typeof artifact === "object" ? artifact.groups || {} : {};
        if (!groupKey || !groupsRoot[groupKey]) {
          sheetArea.innerHTML = "<div class='subtitle'>No groups.</div>";
          return;
        }

        const groupObj = getGroupObject(groupsRoot[groupKey]);
        const instancesObj = groupObj.instances || {};
        const instanceKeys = sortedHexKeys(Object.keys(instancesObj));

        let rrSet = new Set();
        for (const iiKey of instanceKeys) {
          const inst = getInstanceObject(instancesObj[iiKey]);
          const regs = inst.registers || {};
          for (const rrKey of Object.keys(regs)) rrSet.add(rrKey);
        }
        const rrKeys = sortedHexKeys(Array.from(rrSet));

        const wrap = document.createElement("div");
        wrap.className = "table-wrap";

        const table = document.createElement("table");
        const thead = document.createElement("thead");
        const trHead = document.createElement("tr");
        const th0 = document.createElement("th");
        th0.className = "offset-cell";
        const groupName = typeof groupObj.name === "string" && groupObj.name ? groupObj.name : "Unknown";
        th0.innerHTML = `Register <span style="opacity:.7;font-weight:500">(${groupKey} · ${groupName})</span>`;
        trHead.appendChild(th0);
        for (const iiKey of instanceKeys) {
          const th = document.createElement("th");
          const inst = getInstanceObject(instancesObj[iiKey]);
          const present = inst.present === false ? " (absent)" : "";
          th.textContent = `${iiKey}${present}`;
          trHead.appendChild(th);
        }
        thead.appendChild(trHead);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");

        for (const rrKey of rrKeys) {
          // Pick a row label/name from any instance that has an entry.
          let rowMyvaillantName = "";
          let rowEbusdNames = new Set();
          let rowTypeDefault = null;
          let rowLen = null;
          for (const iiKey of instanceKeys) {
            const inst = getInstanceObject(instancesObj[iiKey]);
            const regs = inst.registers || {};
            const entry = regs && typeof regs === "object" ? regs[rrKey] : null;
            if (!entry || typeof entry !== "object") continue;
            if (!rowMyvaillantName && typeof entry.myvaillant_name === "string" && entry.myvaillant_name) {
              rowMyvaillantName = entry.myvaillant_name;
            }
            if (typeof entry.ebusd_name === "string" && entry.ebusd_name) {
              rowEbusdNames.add(entry.ebusd_name);
            }
            if (!rowTypeDefault && typeof entry.type === "string" && entry.type) rowTypeDefault = entry.type;
            if (rowLen === null && typeof entry.raw_hex === "string" && entry.raw_hex) {
              const b = bytesFromHex(entry.raw_hex);
              if (b) rowLen = b.length;
            }
          }

          const ebusdNameList = Array.from(rowEbusdNames);
          ebusdNameList.sort();

          const override = getRowOverride(groupKey, rrKey);
          const rowType = override || rowTypeDefault;
          const candidates = candidateTypeSpecsForLength(rowLen || 0);
          const selectedType = rowType || (candidates[0] || null);

          const tr = document.createElement("tr");

          const td0 = document.createElement("td");
          td0.className = "offset-cell";
          const label = document.createElement("div");
          label.className = "offset-label";
          label.textContent = rrKey;
          td0.appendChild(label);

          const hasNames = rowMyvaillantName || ebusdNameList.length;
          if (hasNames) {
            if (rowMyvaillantName) {
              const nameEl = document.createElement("div");
              nameEl.className = "offset-name";
              nameEl.textContent = rowMyvaillantName;
              td0.appendChild(nameEl);
            }

            if (ebusdNameList.length) {
              const ebusdEl = document.createElement("div");
              ebusdEl.className = rowMyvaillantName ? "offset-name-secondary" : "offset-name";

              let txt = ebusdNameList[0];
              if (ebusdNameList.length > 1) {
                const head = ebusdNameList.slice(0, 3).join(", ");
                txt = head + (ebusdNameList.length > 3 ? ", …" : "");
                ebusdEl.title = ebusdNameList.join(", ");
              }
              if (rowMyvaillantName) txt = "ebusd: " + txt;
              ebusdEl.textContent = txt;
              td0.appendChild(ebusdEl);
            }
          }

          if (candidates.length) {
            const sel = document.createElement("select");
            sel.className = "type-select";
            for (const t of candidates) {
              const opt = document.createElement("option");
              opt.value = t;
              opt.textContent = t;
              sel.appendChild(opt);
            }
            if (selectedType) sel.value = selectedType;
            sel.addEventListener("change", () => {
              setRowOverride(groupKey, rrKey, sel.value);
              renderActiveGroup();
            });
            td0.appendChild(sel);
          }

          tr.appendChild(td0);

          for (const iiKey of instanceKeys) {
            const td = document.createElement("td");
            const inst = getInstanceObject(instancesObj[iiKey]);
            const regs = inst.registers || {};
            const entry = regs && typeof regs === "object" ? regs[rrKey] : null;

            if (!entry) {
              td.innerHTML = "<div class='cell-missing'>—</div>";
              tr.appendChild(td);
              continue;
            }

            const rawHex = typeof entry.raw_hex === "string" ? entry.raw_hex : "";
            const valueBytes = rawHex ? bytesFromHex(rawHex) : null;
            const displayValue = (typeof entry.value_display === "string" && entry.value_display.length)
              ? entry.value_display
              : entry.value;
            const decoded = selectedType && valueBytes
              ? parseTypedValue(selectedType, valueBytes)
              : { value: displayValue, error: null };

            const valueTxt = formatValue(decoded.value);
            const valueEl = document.createElement("div");
            valueEl.className = "cell-value";
            valueEl.textContent = valueTxt;

            td.appendChild(valueEl);

            if (rawHex) {
              const rawEl = document.createElement("div");
              rawEl.className = "cell-raw";
              rawEl.textContent = rawHex;
              td.appendChild(rawEl);
            }

            const errTxt = typeof entry.error === "string" ? entry.error : decoded.error;
            if (errTxt) {
              td.classList.add("cell-bad");
              const errEl = document.createElement("div");
              errEl.className = "cell-error";
              errEl.textContent = errTxt;
              td.appendChild(errEl);
            }

            const tipParts = [];
            if (typeof entry.flags !== "undefined" && entry.flags !== null) tipParts.push(`flags=${entry.flags}`);
            if (entry.flags_access) tipParts.push(`flags_access=${entry.flags_access}`);
            if (entry.reply_hex) tipParts.push(`reply_hex=${entry.reply_hex}`);
            if (entry.type) tipParts.push(`original_type=${entry.type}`);
            if (typeof entry.value !== "undefined") tipParts.push(`original_value=${formatValue(entry.value)}`);
            if (entry.enum_raw_name) tipParts.push(`enum_raw_name=${entry.enum_raw_name}`);
            if (entry.enum_resolved_name) tipParts.push(`enum_resolved_name=${entry.enum_resolved_name}`);
            if (entry.constraint_type) tipParts.push(`constraint_type=${entry.constraint_type}`);
            if (typeof entry.constraint_min !== "undefined") tipParts.push(`constraint_min=${formatValue(entry.constraint_min)}`);
            if (typeof entry.constraint_max !== "undefined") tipParts.push(`constraint_max=${formatValue(entry.constraint_max)}`);
            if (typeof entry.constraint_step !== "undefined") tipParts.push(`constraint_step=${formatValue(entry.constraint_step)}`);
            if (entry.constraint_tt) tipParts.push(`constraint_tt=${entry.constraint_tt}`);
            if (tipParts.length) td.title = tipParts.join("\\n");

            tr.appendChild(td);
          }

          tbody.appendChild(tr);
        }

        table.appendChild(tbody);
        wrap.appendChild(table);

        sheetArea.innerHTML = "";
        sheetArea.appendChild(wrap);
      }

      function renderActiveTab() {
        if (_isB509Tab(state.activeTab)) {
          renderB509Tab();
          return;
        }
        const groupKey = _groupKeyFromTab(state.activeTab);
        renderActiveGroup(groupKey);
      }

      const groupsRoot = artifact && typeof artifact === "object" ? artifact.groups || {} : {};
      const groupKeys = sortedHexKeys(Object.keys(groupsRoot));
      const hasB509 = !!(artifact && typeof artifact === "object" && artifact.b509_dump && typeof artifact.b509_dump === "object");
      buildTabs(groupKeys, hasB509);
      renderActiveTab();
    </script>
  </body>
</html>
"""


def render_html_report(artifact: dict[str, Any], *, title: str | None = None) -> str:
    page_title = title or "helianthus-vrc-explorer scan report"
    return (
        _TEMPLATE.replace("__TITLE__", _escape_html(page_title))
        .replace("__ARTIFACT_JSON__", _json_for_html(artifact))
        .rstrip()
        + "\n"
    )
