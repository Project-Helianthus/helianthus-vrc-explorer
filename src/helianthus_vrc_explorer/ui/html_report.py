# ruff: noqa: E501

from __future__ import annotations

import json
from html import escape as _escape_html
from typing import Any

from .emphasis import html_star_bold


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

      .cell-status {
        margin-top: 5px;
      }

      .status-chip {
        display: inline-flex;
        align-items: center;
        padding: 2px 7px;
        border-radius: 999px;
        font-size: 11px;
        font-family: var(--mono);
        border: 1px solid transparent;
      }

      .status-absent {
        color: #ffe1a3;
        background: rgba(255, 207, 110, 0.14);
        border-color: rgba(255, 207, 110, 0.28);
      }

      .status-dormant {
        color: #bfe9ff;
        background: rgba(122, 196, 255, 0.16);
        border-color: rgba(122, 196, 255, 0.32);
      }

      .status-transport {
        color: #ffb3b3;
        background: rgba(255, 122, 122, 0.16);
        border-color: rgba(255, 122, 122, 0.32);
      }

      .status-decode {
        color: #ffd8b1;
        background: rgba(255, 166, 77, 0.16);
        border-color: rgba(255, 166, 77, 0.32);
      }

      .status-error {
        color: var(--muted);
        background: rgba(255, 255, 255, 0.05);
        border-color: rgba(255, 255, 255, 0.08);
      }

      .cell-value-muted {
        color: var(--muted);
        font-weight: 500;
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

      .subtabs {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-bottom: 4px;
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

      .section-title {
        font-size: 16px;
        font-weight: 650;
      }

      .summary-grid {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }

      .summary-chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 10px;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.04);
        border: 1px solid rgba(255, 255, 255, 0.08);
        font-size: 12px;
      }

      .summary-chip strong {
        color: var(--ink);
      }

      .identity-card {
        display: grid;
        gap: 10px;
      }

      .identity-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 10px;
      }

      .identity-row {
        display: grid;
        gap: 4px;
        padding: 10px 12px;
        border-radius: 12px;
        background: rgba(255, 255, 255, 0.035);
        border: 1px solid rgba(255, 255, 255, 0.06);
      }

      .identity-label {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--muted);
      }

      .identity-value {
        font-size: 14px;
        line-height: 1.4;
        color: var(--ink);
        word-break: break-word;
      }

      .table-title {
        margin: 8px 0 6px;
        font-size: 14px;
        font-weight: 650;
        color: var(--ink);
      }

      .access-chip {
        display: inline-flex;
        align-items: center;
        padding: 2px 7px;
        border-radius: 999px;
        font-size: 11px;
        font-family: var(--mono);
        border: 1px solid transparent;
      }

      .access-ro {
        color: #c7ffd9;
        background: rgba(78, 194, 116, 0.18);
        border-color: rgba(78, 194, 116, 0.32);
      }

      .access-rw {
        color: #ffd9a6;
        background: rgba(255, 166, 77, 0.18);
        border-color: rgba(255, 166, 77, 0.32);
      }

      .access-other {
        color: var(--muted);
        background: rgba(255, 255, 255, 0.05);
        border-color: rgba(255, 255, 255, 0.08);
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

__IDENTITY_CARD__

      <section class="sheet-card">
        <div class="section-title">Namespace Totals</div>
        <div class="summary-grid" id="summaryChips"></div>
      </section>

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
        // Artifact v2: groups may be single-namespace via `instances` or dual-namespace via `namespaces`.
        if (
          (groupObj.instances && typeof groupObj.instances === "object") ||
          (groupObj.namespaces && typeof groupObj.namespaces === "object")
        ) {
          return groupObj;
        }
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
        if (n === 3) return ["HDA:3", "HTI", "FW", "HEX:3"];
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
              const dd = bytes[0];
              const mm = bytes[1];
              const yy = bytes[2];
              if (dd < 1 || dd > 31) throw new Error("day out of range");
              if (mm < 1 || mm > 12) throw new Error("month out of range");
              if (yy < 0 || yy > 99) throw new Error("year out of range");
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
            case "FW": {
              expectLen(3);
              const major = decodeBcdByte(bytes[0]);
              const minor = decodeBcdByte(bytes[1]);
              const patch = decodeBcdByte(bytes[2]);
              if (major === null || minor === null || patch === null) {
                throw new Error("invalid FW version");
              }
              return {
                value: `${major.toString().padStart(2, "0")}.${minor
                  .toString()
                  .padStart(2, "0")}.${patch.toString().padStart(2, "0")}`,
                error: null,
              };
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
        activeNamespaceByGroup: {},
        overrides: (meta && typeof meta === "object" && meta.type_overrides) || {},
        b524Filters: {
          hideAbsent: false,
        },
        b509Filters: {
          search: "",
          hideTimeout: false,
          hideEmpty: false,
          hideDecodeErrors: false,
        },
      };

      const tabsEl = document.getElementById("tabs");
      const sheetArea = document.getElementById("sheetArea");
      const summaryChips = document.getElementById("summaryChips");

      function getRowOverride(groupKey, rrKey, namespaceKey = null) {
        const g = state.overrides && state.overrides[groupKey];
        if (!g || typeof g !== "object") return null;
        if (namespaceKey) {
          if (g.namespaces && typeof g.namespaces === "object") {
            const ns = g.namespaces[namespaceKey];
            if (ns && typeof ns === "object" && typeof ns[rrKey] === "string") return ns[rrKey];
          }
          return null;
        }
        return typeof g[rrKey] === "string" ? g[rrKey] : null;
      }

      function setRowOverride(groupKey, rrKey, typeSpec, namespaceKey = null) {
        if (!state.overrides || typeof state.overrides !== "object") state.overrides = {};
        if (!state.overrides[groupKey] || typeof state.overrides[groupKey] !== "object") state.overrides[groupKey] = {};
        if (namespaceKey) {
          if (!state.overrides[groupKey].namespaces || typeof state.overrides[groupKey].namespaces !== "object") {
            state.overrides[groupKey].namespaces = {};
          }
          if (!state.overrides[groupKey].namespaces[namespaceKey] || typeof state.overrides[groupKey].namespaces[namespaceKey] !== "object") {
            state.overrides[groupKey].namespaces[namespaceKey] = {};
          }
          state.overrides[groupKey].namespaces[namespaceKey][rrKey] = typeSpec;
          return;
        }
        state.overrides[groupKey][rrKey] = typeSpec;
      }

      function normalizeOpcodeKey(opcodeRaw) {
        if (typeof opcodeRaw !== "string") return null;
        const trimmed = opcodeRaw.trim().toLowerCase();
        if (!trimmed) return null;
        if (trimmed === "local") return "0x02";
        if (trimmed === "remote") return "0x06";
        const parsed = Number(trimmed);
        if (!Number.isInteger(parsed) || parsed < 0 || parsed > 0xff) return null;
        return `0x${parsed.toString(16).padStart(2, "0")}`;
      }

      function canonicalNamespaceLabel(namespaceKey) {
        if (namespaceKey === "0x02") return "local";
        if (namespaceKey === "0x06") return "remote";
        return null;
      }

      function namespaceLabel(namespaceKey, label) {
        const raw = typeof label === "string" && label ? label : namespaceKey;
        if (!raw) return "";
        if (!namespaceKey) return raw;
        const canonical = canonicalNamespaceLabel(namespaceKey);
        if (canonical) {
          return `${canonical.charAt(0).toUpperCase()}${canonical.slice(1)} (${namespaceKey})`;
        }
        if (raw.startsWith("0x")) return namespaceKey;
        return `${raw.charAt(0).toUpperCase()}${raw.slice(1)} (${namespaceKey})`;
      }

      function namespaceKeyFromEntry(entry, fallbackNamespaceKey = null) {
        if (!entry || typeof entry !== "object") return fallbackNamespaceKey;
        return (
          normalizeOpcodeKey(entry.read_opcode)
          || normalizeOpcodeKey(fallbackNamespaceKey)
          || normalizeOpcodeKey(entry.read_opcode_label)
        );
      }

      function splitInstancesByNamespace(instancesObj, fallbackNamespaceKey = null) {
        const split = {};
        if (!instancesObj || typeof instancesObj !== "object") return split;
        for (const iiKey of sortedHexKeys(Object.keys(instancesObj))) {
          const inst = getInstanceObject(instancesObj[iiKey]);
          const regs = inst.registers && typeof inst.registers === "object" ? inst.registers : {};
          for (const rrKey of sortedHexKeys(Object.keys(regs))) {
            const entry = regs[rrKey];
            if (!entry || typeof entry !== "object") continue;
            const namespaceKey = namespaceKeyFromEntry(entry, fallbackNamespaceKey);
            if (!namespaceKey) continue; // Keep namespace views isolated; do not force-assign unknown rows.
            if (!split[namespaceKey] || typeof split[namespaceKey] !== "object") {
              split[namespaceKey] = {};
            }
            if (!split[namespaceKey][iiKey] || typeof split[namespaceKey][iiKey] !== "object") {
              split[namespaceKey][iiKey] = {
                present: inst.present,
                registers: {},
              };
            }
            split[namespaceKey][iiKey].registers[rrKey] = entry;
          }
        }
        return split;
      }

      function entryStatusKind(entry) {
        if (!entry || typeof entry !== "object") return "error";
        const errTxt = typeof entry.error === "string" ? entry.error.trim() : "";
        if (errTxt) {
          const lower = errTxt.toLowerCase();
          if (lower.startsWith("parse_error:") || lower.startsWith("decode_error:")) return "decode_error";
          if (lower === "timeout" || lower.startsWith("transport_error:") || lower.startsWith("mcp_error:")) {
            return "transport_failure";
          }
          return "error";
        }
        const access = typeof entry.flags_access === "string" ? entry.flags_access.trim().toLowerCase() : "";
        if (access === "absent") return "absent";
        if (access === "dormant") return "dormant";
        const replyHex = typeof entry.reply_hex === "string" ? entry.reply_hex.trim().toLowerCase() : "";
        if (replyHex === "00") return "absent";
        return "ok";
      }

      function entryStatusLabel(entry) {
        const kind = entryStatusKind(entry);
        if (kind === "absent") return "Absent / no data";
        if (kind === "dormant") return "Dormant (feature inactive)";
        if (kind === "transport_failure") return "Transport failure";
        if (kind === "decode_error") return "Decode error";
        if (kind === "error") return "Error";
        return "OK";
      }

      function statusChipClass(kind) {
        if (kind === "absent") return "status-chip status-absent";
        if (kind === "dormant") return "status-chip status-dormant";
        if (kind === "transport_failure") return "status-chip status-transport";
        if (kind === "decode_error") return "status-chip status-decode";
        return "status-chip status-error";
      }

      function rowHasExplicitName(instancesObj, rrKey) {
        if (!instancesObj || typeof instancesObj !== "object") return false;
        for (const instanceObj of Object.values(instancesObj)) {
          if (!instanceObj || typeof instanceObj !== "object") continue;
          const registers = instanceObj.registers;
          if (!registers || typeof registers !== "object") continue;
          const entry = registers[rrKey];
          if (!entry || typeof entry !== "object") continue;
          for (const field of ["myvaillant_name", "ebusd_name"]) {
            const value = entry[field];
            if (typeof value === "string" && value.trim()) return true;
          }
        }
        return false;
      }

      function rowIsAbsent(instancesObj, rrKey) {
        if (!instancesObj || typeof instancesObj !== "object") return false;
        let sawEntry = false;
        for (const instanceObj of Object.values(instancesObj)) {
          if (!instanceObj || typeof instanceObj !== "object") continue;
          const registers = instanceObj.registers;
          if (!registers || typeof registers !== "object") continue;
          const entry = registers[rrKey];
          if (!entry || typeof entry !== "object") continue;
          sawEntry = true;
          if (entryStatusKind(entry) !== "absent") return false;
        }
        return sawEntry;
      }

      function visibleRegisterKeys(instancesObj) {
        const rrSet = new Set();
        if (!instancesObj || typeof instancesObj !== "object") return [];
        for (const instanceObj of Object.values(instancesObj)) {
          if (!instanceObj || typeof instanceObj !== "object") continue;
          const registers = instanceObj.registers;
          if (!registers || typeof registers !== "object") continue;
          for (const rrKey of Object.keys(registers)) rrSet.add(rrKey);
        }
        const rrKeys = sortedHexKeys(Array.from(rrSet)).filter((rrKey) => rrKey !== "0x0000");
        let lastKeep = -1;
        for (let idx = 0; idx < rrKeys.length; idx += 1) {
          const rrKey = rrKeys[idx];
          if (rowHasExplicitName(instancesObj, rrKey) || !rowIsAbsent(instancesObj, rrKey)) {
            lastKeep = idx;
          }
        }
        if (lastKeep < 0) return [];
        return rrKeys.slice(0, lastKeep + 1);
      }

      function accessChipClass(accessValue) {
        const text = String(accessValue || "").trim();
        if (text === "stable_ro" || text === "volatile_ro") return "access-chip access-ro";
        if (text === "technical_rw" || text === "user_rw") return "access-chip access-rw";
        return "access-chip access-other";
      }

      function appendAccessBadges(cell, accessValues) {
        if (!accessValues.length) {
          cell.innerHTML = "<div class='cell-missing'>—</div>";
          return;
        }
        for (const accessValue of accessValues) {
          const badge = document.createElement("span");
          badge.className = accessChipClass(accessValue);
          badge.textContent = accessValue;
          cell.appendChild(badge);
        }
      }

      function countRegisters(instancesObj) {
        let count = 0;
        if (!instancesObj || typeof instancesObj !== "object") return 0;
        for (const instanceObj of Object.values(instancesObj)) {
          if (!instanceObj || typeof instanceObj !== "object") continue;
          const registers = instanceObj.registers;
          if (!registers || typeof registers !== "object") continue;
          count += Object.keys(registers).length;
        }
        return count;
      }

      function renderSummaryChips(groupsRoot) {
        summaryChips.innerHTML = "";
        const totals = new Map();
        let totalRegisters = 0;

        for (const groupKey of sortedHexKeys(Object.keys(groupsRoot || {}))) {
          const groupObj = getGroupObject(groupsRoot[groupKey]);
          if (groupObj.dual_namespace && groupObj.namespaces && typeof groupObj.namespaces === "object") {
            for (const namespaceKey of sortedHexKeys(Object.keys(groupObj.namespaces))) {
              const namespaceObj = groupObj.namespaces[namespaceKey];
              if (!namespaceObj || typeof namespaceObj !== "object") continue;
              const normalizedKey = normalizeOpcodeKey(namespaceKey) || namespaceKey;
              const label = namespaceLabel(normalizedKey, namespaceObj.label);
              const count = countRegisters(namespaceObj.instances);
              totalRegisters += count;
              totals.set(label, (totals.get(label) || 0) + count);
            }
            continue;
          }

          const instances = groupObj.instances && typeof groupObj.instances === "object" ? groupObj.instances : {};
            for (const instanceObj of Object.values(instances)) {
              if (!instanceObj || typeof instanceObj !== "object") continue;
              const registers = instanceObj.registers && typeof instanceObj.registers === "object" ? instanceObj.registers : {};
              for (const entry of Object.values(registers)) {
                if (!entry || typeof entry !== "object") continue;
                const namespaceKey = namespaceKeyFromEntry(entry);
                if (!namespaceKey) continue;
                const label = namespaceLabel(namespaceKey, entry.read_opcode_label);
                totalRegisters += 1;
                totals.set(label, (totals.get(label) || 0) + 1);
              }
            }
          }

        const chips = [["total", totalRegisters], ...Array.from(totals.entries())];
        for (const [label, count] of chips) {
          const chip = document.createElement("div");
          chip.className = "summary-chip";
          const strong = document.createElement("strong");
          strong.textContent = label;
          chip.appendChild(strong);
          chip.appendChild(document.createTextNode(` ${count}`));
          summaryChips.appendChild(chip);
        }
      }

      function _isB509Tab(tabId) {
        return tabId === "b509";
      }

      function _isB555Tab(tabId) {
        return tabId === "b555";
      }

      function _isB516Tab(tabId) {
        return tabId === "b516";
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

      function buildTabs(groupKeys, hasB555, hasB516, hasB509) {
        tabsEl.innerHTML = "";
        const groupsRoot = artifact && typeof artifact === "object" ? artifact.groups || {} : {};
        const orderedTabIds = [];

        if (hasB555) {
          const btn = document.createElement("div");
          btn.className = "tab";
          btn.textContent = "B555 Dump";
          btn.dataset.tabId = "b555";
          btn.addEventListener("click", () => {
            state.activeTab = "b555";
            _syncActiveTabClasses();
            renderActiveTab();
          });
          tabsEl.appendChild(btn);
          orderedTabIds.push("b555");
        }

        if (hasB516) {
          const btn = document.createElement("div");
          btn.className = "tab";
          btn.textContent = "B516 Dump";
          btn.dataset.tabId = "b516";
          btn.addEventListener("click", () => {
            state.activeTab = "b516";
            _syncActiveTabClasses();
            renderActiveTab();
          });
          tabsEl.appendChild(btn);
          orderedTabIds.push("b516");
        }

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

      function renderB555Tab() {
        const b555 = artifact && typeof artifact === "object" ? artifact.b555_dump : null;
        if (!b555 || typeof b555 !== "object") {
          sheetArea.innerHTML = "<div class='subtitle'>No B555 dump in artifact.</div>";
          return;
        }

        const programs = b555.programs && typeof b555.programs === "object" ? b555.programs : {};
        const rows = [];

        for (const programKey of Object.keys(programs).sort()) {
          const program = programs[programKey];
          if (!program || typeof program !== "object") continue;
          const label = typeof program.label === "string" && program.label ? program.label : programKey;
          const selector = program.selector && typeof program.selector === "object" ? program.selector : {};
          const zone = typeof selector.zone === "string" ? selector.zone : "n/a";
          const hc = typeof selector.hc === "string" ? selector.hc : "n/a";

          function pushRow(kind, key, entry, valueText) {
            if (!entry || typeof entry !== "object") return;
            rows.push({
              programKey,
              label,
              selector: `zone=${zone} hc=${hc}`,
              kind,
              key,
              valueText,
              requestHex: typeof entry.request_hex === "string" ? entry.request_hex : "",
              replyHex: typeof entry.reply_hex === "string" ? entry.reply_hex : "",
              error: typeof entry.error === "string" ? entry.error : "",
              status: typeof entry.status_label === "string" ? entry.status_label : (typeof entry.status === "string" ? entry.status : ""),
            });
          }

          const config = program.config;
          if (config && typeof config === "object") {
            const parts = [];
            if (typeof config.max_slots === "number") parts.push(`max_slots=${config.max_slots}`);
            if (typeof config.temp_slots === "number") parts.push(`temp_slots=${config.temp_slots}`);
            if (typeof config.time_resolution_min === "number") parts.push(`resolution=${config.time_resolution_min}m`);
            pushRow("A3", "config", config, parts.join(", ") || "config");
          }

          const slots = program.slots_per_weekday;
          if (slots && typeof slots === "object") {
            const dayMap = slots.days && typeof slots.days === "object" ? slots.days : {};
            const valueText = Object.entries(dayMap).map(([day, count]) => `${day.slice(0, 3)}=${count}`).join(", ") || "slots/weekday";
            pushRow("A4", "slots_per_weekday", slots, valueText);
          }

          const weekdays = program.weekdays && typeof program.weekdays === "object" ? program.weekdays : {};
          for (const dayName of Object.keys(weekdays).sort()) {
            const dayObj = weekdays[dayName];
            if (!dayObj || typeof dayObj !== "object") continue;
            const slotMap = dayObj.slots && typeof dayObj.slots === "object" ? dayObj.slots : {};
            for (const slotKey of sortedHexKeys(Object.keys(slotMap))) {
              const entry = slotMap[slotKey];
              if (!entry || typeof entry !== "object") continue;
              let valueText = typeof entry.status_label === "string" && entry.status_label && entry.status_label !== "available"
                ? entry.status_label
                : "entry";
              if (typeof entry.start_text === "string" && typeof entry.end_text === "string") {
                valueText = `${entry.start_text}-${entry.end_text}`;
                if (typeof entry.temperature_c === "number") valueText += ` @ ${formatValue(entry.temperature_c)}C`;
              }
              pushRow("A5", `${dayName}:${slotKey}`, entry, valueText);
            }
          }
        }

        const card = document.createElement("div");
        if (!rows.length) {
          const msg = document.createElement("div");
          msg.className = "subtitle";
          msg.textContent = "No B555 rows in artifact.";
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
        for (const col of ["Program", "Selector", "Entry", "Value", "Reply", "Error"]) {
          const th = document.createElement("th");
          th.textContent = col;
          trHead.appendChild(th);
        }
        thead.appendChild(trHead);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        for (const row of rows) {
          const tr = document.createElement("tr");
          for (const value of [
            row.label,
            row.selector,
            `${row.kind} ${row.key}`,
            row.status ? `${row.valueText} (${row.status})` : row.valueText,
            row.replyHex || "—",
            row.error || "—",
          ]) {
            const td = document.createElement("td");
            td.textContent = value;
            tr.appendChild(td);
          }
          if (row.requestHex) {
            tr.title = `request_hex=${row.requestHex}${row.replyHex ? `\\nreply_hex=${row.replyHex}` : ""}`;
          }
          tbody.appendChild(tr);
        }

        table.appendChild(tbody);
        wrap.appendChild(table);
        card.appendChild(wrap);
        sheetArea.innerHTML = "";
        sheetArea.appendChild(card);
      }

      function renderB516Tab() {
        const b516 = artifact && typeof artifact === "object" ? artifact.b516_dump : null;
        if (!b516 || typeof b516 !== "object") {
          sheetArea.innerHTML = "<div class='subtitle'>No B516 dump in artifact.</div>";
          return;
        }

        const entries = b516.entries && typeof b516.entries === "object" ? b516.entries : {};
        const rows = [];
        for (const entryKey of Object.keys(entries).sort()) {
          const entry = entries[entryKey];
          if (!entry || typeof entry !== "object") continue;
          rows.push({ entryKey, entry });
        }

        const card = document.createElement("div");
        if (!rows.length) {
          const msg = document.createElement("div");
          msg.className = "subtitle";
          msg.textContent = "No B516 entries in artifact.";
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
        for (const col of ["Label", "Selector", "kWh", "Wh", "Request", "Reply", "Error"]) {
          const th = document.createElement("th");
          th.textContent = col;
          trHead.appendChild(th);
        }
        thead.appendChild(trHead);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        for (const row of rows) {
          const tr = document.createElement("tr");
          const entry = row.entry;
          const label = typeof entry.label === "string" && entry.label ? entry.label : row.entryKey;
          const period = typeof entry.period === "string" ? entry.period : "n/a";
          const source = typeof entry.source === "string" ? entry.source : "n/a";
          const usage = typeof entry.usage === "string" ? entry.usage : "n/a";
          const requestHex = typeof entry.request_hex === "string" ? entry.request_hex : "";
          const replyHex = typeof entry.reply_hex === "string" ? entry.reply_hex : "";
          const error = typeof entry.error === "string" ? entry.error : "";
          const valueKwh = typeof entry.value_kwh === "number" ? formatValue(entry.value_kwh) : "—";
          const valueWh = typeof entry.value_wh === "number" ? formatValue(entry.value_wh) : "—";

          const labelTd = document.createElement("td");
          const nameEl = document.createElement("div");
          nameEl.className = "offset-name";
          nameEl.textContent = label;
          labelTd.appendChild(nameEl);
          const keyEl = document.createElement("div");
          keyEl.className = "offset-name-secondary";
          keyEl.textContent = row.entryKey;
          labelTd.appendChild(keyEl);
          tr.appendChild(labelTd);

          const selectorTd = document.createElement("td");
          selectorTd.textContent = `${period} / ${source} / ${usage}`;
          const echoParts = [];
          if (typeof entry.echo_period === "string") echoParts.push(`p=${entry.echo_period}`);
          if (typeof entry.echo_source === "string") echoParts.push(`s=${entry.echo_source}`);
          if (typeof entry.echo_usage === "string") echoParts.push(`u=${entry.echo_usage}`);
          if (typeof entry.echo_window === "string") echoParts.push(`w=${entry.echo_window}`);
          if (typeof entry.echo_qualifier === "string") echoParts.push(`q=${entry.echo_qualifier}`);
          if (echoParts.length) {
            const echoEl = document.createElement("div");
            echoEl.className = "offset-name-secondary";
            echoEl.textContent = `echo ${echoParts.join(" ")}`;
            selectorTd.appendChild(echoEl);
          }
          tr.appendChild(selectorTd);

          for (const value of [valueKwh, valueWh, requestHex || "—", replyHex || "—", error || "—"]) {
            const td = document.createElement("td");
            td.textContent = value;
            if (value === requestHex || value === replyHex) td.className = "cell-raw";
            if (value === error && error) td.className = "cell-error";
            tr.appendChild(td);
          }

          tbody.appendChild(tr);
        }

        table.appendChild(tbody);
        wrap.appendChild(table);
        card.appendChild(wrap);
        sheetArea.innerHTML = "";
        sheetArea.appendChild(card);
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
        const groupName = typeof groupObj.name === "string" && groupObj.name ? groupObj.name : "Unknown";

        function buildGroupTable(title, instancesObj, namespaceKey = null) {
          const instanceKeys = sortedHexKeys(Object.keys(instancesObj || {}));
          let rrKeys = visibleRegisterKeys(instancesObj);
          if (state.b524Filters.hideAbsent) {
            rrKeys = rrKeys.filter((rrKey) => !rowIsAbsent(instancesObj, rrKey));
          }

          const fragment = document.createElement("div");
          const heading = document.createElement("div");
          heading.className = "table-title";
          heading.textContent = title;
          fragment.appendChild(heading);

          if (!rrKeys.length) {
            const empty = document.createElement("div");
            empty.className = "subtitle";
            empty.textContent = "No visible registers.";
            fragment.appendChild(empty);
            return fragment;
          }

          const wrap = document.createElement("div");
          wrap.className = "table-wrap";

          const table = document.createElement("table");
          const thead = document.createElement("thead");
          const trHead = document.createElement("tr");
          const th0 = document.createElement("th");
          th0.className = "offset-cell";
          th0.innerHTML = `Register <span style="opacity:.7;font-weight:500">(${groupKey} · ${groupName})</span>`;
          trHead.appendChild(th0);

          const flagsTh = document.createElement("th");
          flagsTh.textContent = "FLAGS Access";
          trHead.appendChild(flagsTh);

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
            let rowMyvaillantName = "";
            let rowEbusdNames = new Set();
            let rowTypeDefault = null;
            let rowLen = null;
            let rowFlagsAccess = new Set();

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
              if (typeof entry.flags_access === "string" && entry.flags_access) {
                rowFlagsAccess.add(entry.flags_access);
              }
            }

            const ebusdNameList = Array.from(rowEbusdNames).sort();
            const accessValues = Array.from(rowFlagsAccess).sort();
            const override = getRowOverride(groupKey, rrKey, namespaceKey);
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
                setRowOverride(groupKey, rrKey, sel.value, namespaceKey);
                renderActiveGroup(groupKey);
              });
              td0.appendChild(sel);
            }
            tr.appendChild(td0);

            const flagsTd = document.createElement("td");
            appendAccessBadges(flagsTd, accessValues);
            tr.appendChild(flagsTd);

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
              const statusKind = entryStatusKind(entry);
              const statusLabel = entryStatusLabel(entry);
              const decoded = selectedType && valueBytes
                ? parseTypedValue(selectedType, valueBytes)
                : { value: displayValue, error: null };

              const valueTxt = (statusKind === "absent" || statusKind === "dormant")
                ? statusKind
                : formatValue(decoded.value);
              const valueEl = document.createElement("div");
              valueEl.className = "cell-value";
              if (statusKind === "absent" || statusKind === "dormant") valueEl.classList.add("cell-value-muted");
              valueEl.textContent = valueTxt;
              td.appendChild(valueEl);

              if (rawHex) {
                const rawEl = document.createElement("div");
                rawEl.className = "cell-raw";
                rawEl.textContent = rawHex;
                td.appendChild(rawEl);
              }

              const errTxt = typeof entry.error === "string" ? entry.error : decoded.error;
              if (statusKind !== "ok") {
                const statusEl = document.createElement("div");
                statusEl.className = "cell-status";
                const badge = document.createElement("span");
                badge.className = statusChipClass(statusKind);
                badge.textContent = statusLabel;
                statusEl.appendChild(badge);
                td.appendChild(statusEl);
              }
              if (errTxt && statusKind !== "absent") {
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
              if (entry.constraint_scope) tipParts.push(`constraint_scope=${entry.constraint_scope}`);
              if (entry.constraint_provenance) tipParts.push(`constraint_provenance=${entry.constraint_provenance}`);
              if (tipParts.length) td.title = tipParts.join("\\n");

              tr.appendChild(td);
            }

            tbody.appendChild(tr);
          }

          table.appendChild(tbody);
          wrap.appendChild(table);
          fragment.appendChild(wrap);
          return fragment;
        }

        const container = document.createElement("div");
        const title = document.createElement("div");
        title.className = "section-title";
        title.textContent = `${groupKey} · ${groupName}`;
        container.appendChild(title);

        const filters = document.createElement("div");
        filters.className = "filters";
        const hideAbsentLabel = document.createElement("label");
        hideAbsentLabel.className = "filter-chip";
        const hideAbsentCb = document.createElement("input");
        hideAbsentCb.type = "checkbox";
        hideAbsentCb.checked = !!state.b524Filters.hideAbsent;
        hideAbsentCb.addEventListener("change", () => {
          state.b524Filters.hideAbsent = !!hideAbsentCb.checked;
          renderActiveGroup(groupKey);
        });
        hideAbsentLabel.appendChild(hideAbsentCb);
        hideAbsentLabel.appendChild(document.createTextNode("Hide absent"));
        filters.appendChild(hideAbsentLabel);
        container.appendChild(filters);

        if (groupObj.dual_namespace && groupObj.namespaces && typeof groupObj.namespaces === "object") {
          const namespaceKeys = sortedHexKeys(Object.keys(groupObj.namespaces));
          if (!namespaceKeys.length) {
            const empty = document.createElement("div");
            empty.className = "subtitle";
            empty.textContent = "No namespaces scanned.";
            container.appendChild(empty);
          } else {
            const subtabs = document.createElement("div");
            subtabs.className = "subtabs";
            let activeNamespace = state.activeNamespaceByGroup[groupKey];
            if (!namespaceKeys.includes(activeNamespace)) activeNamespace = namespaceKeys[0];
            state.activeNamespaceByGroup[groupKey] = activeNamespace;

            for (const namespaceKey of namespaceKeys) {
              const namespaceObj = groupObj.namespaces[namespaceKey];
              if (!namespaceObj || typeof namespaceObj !== "object") continue;
              const normalizedKey = normalizeOpcodeKey(namespaceKey) || namespaceKey;
              const btn = document.createElement("div");
              btn.className = "tab";
              if (namespaceKey === activeNamespace) btn.classList.add("active");
              btn.textContent = namespaceLabel(normalizedKey, namespaceObj.label);
              btn.addEventListener("click", () => {
                state.activeNamespaceByGroup[groupKey] = namespaceKey;
                renderActiveGroup(groupKey);
              });
              subtabs.appendChild(btn);
            }
            container.appendChild(subtabs);

            const namespaceObj = groupObj.namespaces[activeNamespace];
            if (namespaceObj && typeof namespaceObj === "object") {
              const normalizedKey = normalizeOpcodeKey(activeNamespace) || activeNamespace;
              const tableTitle = `${namespaceLabel(normalizedKey, namespaceObj.label)} Registers`;
              container.appendChild(buildGroupTable(tableTitle, namespaceObj.instances || {}, activeNamespace));
            }
          }
        } else {
          const splitNamespaces = splitInstancesByNamespace(groupObj.instances || {}, null);
          const namespaceKeys = sortedHexKeys(Object.keys(splitNamespaces));
          if (namespaceKeys.length > 1) {
            const subtabs = document.createElement("div");
            subtabs.className = "subtabs";
            let activeNamespace = state.activeNamespaceByGroup[groupKey];
            if (!namespaceKeys.includes(activeNamespace)) activeNamespace = namespaceKeys[0];
            state.activeNamespaceByGroup[groupKey] = activeNamespace;

            for (const namespaceKey of namespaceKeys) {
              const btn = document.createElement("div");
              btn.className = "tab";
              if (namespaceKey === activeNamespace) btn.classList.add("active");
              btn.textContent = namespaceLabel(namespaceKey, namespaceKey);
              btn.addEventListener("click", () => {
                state.activeNamespaceByGroup[groupKey] = namespaceKey;
                renderActiveGroup(groupKey);
              });
              subtabs.appendChild(btn);
            }
            container.appendChild(subtabs);
            container.appendChild(
              buildGroupTable(
                `${namespaceLabel(activeNamespace, activeNamespace)} Registers`,
                splitNamespaces[activeNamespace] || {},
                activeNamespace,
              ),
            );
          } else if (namespaceKeys.length === 1) {
            const namespaceKey = namespaceKeys[0];
            container.appendChild(
              buildGroupTable(
                `${namespaceLabel(namespaceKey, namespaceKey)} Registers`,
                splitNamespaces[namespaceKey] || {},
                namespaceKey,
              ),
            );
          } else {
            container.appendChild(buildGroupTable("Registers", groupObj.instances || {}, null));
          }
        }

        sheetArea.innerHTML = "";
        sheetArea.appendChild(container);
      }

      function renderActiveTab() {
        if (_isB555Tab(state.activeTab)) {
          renderB555Tab();
          return;
        }
        if (_isB516Tab(state.activeTab)) {
          renderB516Tab();
          return;
        }
        if (_isB509Tab(state.activeTab)) {
          renderB509Tab();
          return;
        }
        const groupKey = _groupKeyFromTab(state.activeTab);
        renderActiveGroup(groupKey);
      }

      const groupsRoot = artifact && typeof artifact === "object" ? artifact.groups || {} : {};
      const groupKeys = sortedHexKeys(Object.keys(groupsRoot));
      const hasB555 = !!(artifact && typeof artifact === "object" && artifact.b555_dump && typeof artifact.b555_dump === "object");
      const hasB516 = !!(artifact && typeof artifact === "object" && artifact.b516_dump && typeof artifact.b516_dump === "object");
      const hasB509 = !!(artifact && typeof artifact === "object" && artifact.b509_dump && typeof artifact.b509_dump === "object");
      renderSummaryChips(groupsRoot);
      buildTabs(groupKeys, hasB555, hasB516, hasB509);
      renderActiveTab();
    </script>
  </body>
</html>
"""


def render_html_report(artifact: dict[str, Any], *, title: str | None = None) -> str:
    meta = artifact.get("meta")
    identity_html = ""
    if isinstance(meta, dict):
        identity_obj = meta.get("identity")
        if not isinstance(identity_obj, dict):
            identity_obj = meta.get("resolved_identity")
        if isinstance(identity_obj, dict):
            rows: list[tuple[str, str]] = []
            for label, key in (
                ("Device", "device"),
                ("Model", "model"),
                ("Serial", "serial"),
                ("Firmware", "firmware"),
            ):
                value = identity_obj.get(key)
                if not isinstance(value, str):
                    continue
                text = value.strip()
                if not text or text == "n/a":
                    continue
                rows.append((label, text))
            if rows:
                cards = "".join(
                    (
                        '<div class="identity-row">'
                        f'<div class="identity-label">{_escape_html(label)}</div>'
                        f'<div class="identity-value">{html_star_bold(value)}</div>'
                        "</div>"
                    )
                    for label, value in rows
                )
                identity_html = (
                    '<section class="sheet-card identity-card">'
                    '<div class="section-title">Scan Identity</div>'
                    f'<div class="identity-grid">{cards}</div>'
                    "</section>"
                )
    page_title = title or "helianthus-vrc-explorer scan report"
    return (
        _TEMPLATE.replace("__TITLE__", _escape_html(page_title))
        .replace("__IDENTITY_CARD__", identity_html)
        .replace("__ARTIFACT_JSON__", _json_for_html(artifact))
        .rstrip()
        + "\n"
    )
