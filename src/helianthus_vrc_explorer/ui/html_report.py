# ruff: noqa: E501

from __future__ import annotations

import json
import re
from html import escape as _escape_html
from typing import Any

from ..artifact_schema import migrate_artifact_schema
from ..scanner.director import group_name_for_opcode
from ..schema.b524_register_names import apply_b524_canonical_register_names
from ..schema.b524_value_labels import apply_b524_value_labels
from ..schema.parameter_descriptions import attach_bundled_descriptions
from .emphasis import html_star_bold


def _json_for_html(obj: Any) -> str:
    """Dump JSON in a form that is safe to embed inside an HTML <script> tag."""

    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    # Prevent `</script>` breaks and avoid HTML parser surprises.
    return (
        raw.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("'", "\\u0027")
    )


_PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")


def _substitute_template(template: str, substitutions: dict[str, str]) -> str:
    """Single-pass placeholder substitution (VE26-R3: prevents collision)."""
    return _PLACEHOLDER_RE.sub(
        lambda m: substitutions.get(m.group(0), m.group(0)),
        template,
    )


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

      body {
        margin: 0;
        padding: 28px 18px 60px;
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

      .tabs, .subtabs {
        display: flex;
        flex-wrap: nowrap;
        border: 1px solid rgba(255, 255, 255, 0.10);
        border-radius: 8px;
        overflow: hidden;
        width: fit-content;
      }

      .tab {
        padding: 7px 10px;
        border-right: 1px solid rgba(255, 255, 255, 0.08);
        background: rgba(255, 255, 255, 0.03);
        color: var(--muted);
        cursor: pointer;
        user-select: none;
        font-size: 12px;
        font-family: var(--mono);
        white-space: nowrap;
        transition: background 0.15s ease, color 0.15s ease;
      }

      .tab:last-child { border-right: none; }

      .tab:hover {
        background: rgba(255, 255, 255, 0.06);
        color: var(--ink);
      }

      .tab.active {
        background: rgba(102, 227, 196, 0.13);
        color: var(--ink);
      }

      table {
        overflow-x: auto;
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

      .cell-flags {
        margin-top: 3px;
        display: flex;
        gap: 3px;
        flex-wrap: wrap;
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

      .operation-editor {
        margin-top: 12px;
        padding: 12px;
        display: grid;
        gap: 10px;
        border: 1px solid rgba(122, 162, 255, 0.25);
        border-radius: 10px;
        background: rgba(122, 162, 255, 0.06);
      }

      .operation-editor-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        gap: 8px;
      }

      .operation-editor-field {
        display: grid;
        gap: 4px;
        color: var(--muted);
        font-size: 11px;
      }

      .operation-editor-field input {
        width: 100%;
        background: #0c111a;
        color: var(--ink);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        font-family: var(--mono);
        padding: 6px 8px;
      }

      .operation-editor-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }

      .operation-editor button, table button {
        padding: 6px 9px;
        border: 1px solid rgba(122, 162, 255, 0.35);
        border-radius: 8px;
        background: rgba(122, 162, 255, 0.12);
        color: var(--ink);
        cursor: pointer;
      }

      .operation-editor button:disabled, table button:disabled {
        opacity: 0.45;
        cursor: not-allowed;
      }

      .operation-preview {
        margin: 0;
        padding: 10px;
        overflow-x: auto;
        white-space: pre-wrap;
        background: #0c111a;
        border-radius: 8px;
        font-family: var(--mono);
        font-size: 11px;
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

      .flag-state     { color: #c7ffd9; background: rgba(78,194,116,0.18);  border-color: rgba(78,194,116,0.32); }
      .flag-volatile  { color: var(--muted); background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.08); }
      .flag-stable    { color: #a6d4ff; background: rgba(77,148,255,0.15);  border-color: rgba(77,148,255,0.28); }
      .flag-config    { color: #ffd9a6; background: rgba(255,166,77,0.18);  border-color: rgba(255,166,77,0.32); }
      .flag-installer { color: #e0c4ff; background: rgba(180,130,255,0.15); border-color: rgba(180,130,255,0.28); }
      .flag-user      { color: #c7ffd9; background: rgba(78,194,116,0.12);  border-color: rgba(78,194,116,0.25); }
      .flag-valid     { color: #a6d4ff; background: rgba(77,148,255,0.15);  border-color: rgba(77,148,255,0.28); }
      .flag-invalid   { color: #ff9e9e; background: rgba(255,100,100,0.12); border-color: rgba(255,100,100,0.25); }
      .flag-sentinel  { color: var(--muted); background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.08); }
      .flag-other     { color: var(--muted); background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.08); }

      @media (max-width: 860px) {
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
    <header>
      <div class="title">Regulator Scan Browser</div>
      <div class="subtitle">
        This report is generated from the scan artifact.
        <span class="pill" id="metaDst"></span>
        <span class="pill" id="metaTs"></span>
        <span class="pill" id="metaIncomplete" style="display: none"></span>
      </div>
    </header>

__IDENTITY_CARD__

    <section class="sheet-card">
      <div class="tabs" id="tabs"></div>
      <div id="sheetArea"></div>
    </section>

    <script id="artifact-data" type="application/json">
__ARTIFACT_JSON__
    </script>

    <script>
      const artifact = JSON.parse(document.getElementById("artifact-data").textContent || "{}");
      const B524_GROUP_NAMES = __B524_GROUP_NAMES__;

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

      // Look up a group directly from artifact.operations[opKey].groups[groupKey].
      // Returns the group object or null.
      function getOperationGroup(opKey, groupKey) {
        const ops = artifact && typeof artifact === "object" ? artifact.operations : null;
        const opObj = ops && typeof ops === "object" ? ops[opKey] : null;
        const opGroups = opObj && typeof opObj === "object" ? opObj.groups : null;
        const g = opGroups && typeof opGroups === "object" ? opGroups[groupKey] : null;
        if (g && typeof g === "object") return g;
        const plan = finalPlanForRoute(groupKey, opKey);
        if (!plan || typeof plan !== "object") return null;
        const instances = {};
        for (const iiKey of (Array.isArray(plan.instances) ? plan.instances : [])) {
          if (typeof iiKey === "string") instances[iiKey] = { present: false, registers: {} };
        }
        return { name: "Planned group", instances };
      }

      // Collect all unique group keys across all operations.
      function allGroupKeys() {
        const ops = artifact && typeof artifact === "object" ? artifact.operations : null;
        if (!ops || typeof ops !== "object") return [];
        const keys = new Set();
        for (const opObj of Object.values(ops)) {
          if (!opObj || typeof opObj !== "object") continue;
          const opGroups = opObj.groups;
          if (!opGroups || typeof opGroups !== "object") continue;
          for (const k of Object.keys(opGroups)) keys.add(k);
        }
        return sortedHexKeys(Array.from(keys));
      }

      // Collect group keys that exist in a specific operation.
      function groupKeysForOp(opKey) {
        const ops = artifact && typeof artifact === "object" ? artifact.operations : null;
        if (!ops || typeof ops !== "object") return [];
        const opObj = ops[opKey];
        if (!opObj || typeof opObj !== "object") return [];
        const opGroups = opObj.groups;
        if (!opGroups || typeof opGroups !== "object") return [];
        return sortedHexKeys(Object.keys(opGroups));
      }

      function getGroupObject(groupObj) {
        if (!groupObj || typeof groupObj !== "object") return { name: "Unknown", instances: {} };
        // Operations-first: groups always have flat instances.
        if (groupObj.instances && typeof groupObj.instances === "object") {
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
        if (n === 3) return ["HDA:3", "HTI", "FWU", "FW", "HEX:3"];
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
              const hh = bytes[0];
              const mi = bytes[1];
              const ss = bytes[2];
              if (hh > 23 || mi > 59 || ss > 59) throw new Error("time out of range");
              const txt = `${hh.toString().padStart(2, "0")}:${mi.toString().padStart(2, "0")}:${ss
                .toString()
                .padStart(2, "0")}`;
              return { value: txt, error: null };
            }
            case "FWU": {
              expectLen(3);
              if (bytes.every((value) => value === 255)) throw new Error("firmware unavailable");
              return {value: bytes.map((value) => value.toString().padStart(2, "0")).join("."), error: null};
            }
            case "FW": {
              expectLen(3);
              const decodeFwComponent = (value) => {
                const bcd = decodeBcdByte(value);
                if (bcd !== null) return bcd;
                if (Number.isInteger(value) && value >= 0 && value <= 99) return value;
                return null;
              };
              const major = decodeFwComponent(bytes[0]);
              const minor = decodeFwComponent(bytes[1]);
              const patch = decodeFwComponent(bytes[2]);
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

      const B524_SECTIONS = [
        { key: "scan_coverage", label: "Scan coverage and descriptions" },
        { key: "system_information", label: "OP00 ReadSystemInformation" },
        { key: "controller_registers", label: "OP02 GetParameter" },
        { key: "operation_03", label: "OP03 ReadTimer" },
        { key: "operation_08", label: "OP08 ReadVR91" },
        { key: "operation_09", label: "OP09 GetEvent" },
        { key: "operation_0b", label: "OP0B GetEventSetPoint" },
        { key: "device_slots", label: "OP06 GetDeviceParameter" },
        { key: "register_tables", label: "OP0B GetEventSetPoint" },
        { key: "group_directory", label: "Legacy unqualified group-directory artifacts" },
        { key: "register_constraints", label: "Legacy unqualified constraint artifacts" },
      ];

      const state = {
        activeTab: null,
        activeB524Section: "controller_registers",
        activeB524GroupBySection: {},
        activeNamespaceByGroup: {},
        overrides: (meta && typeof meta === "object" && meta.type_overrides) || {},
        b524Filters: {
          hideAbsent: true,
          hideDormant: true,
          hideMissingInstances: true,
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
        if (typeof opcodeRaw === "number" && Number.isInteger(opcodeRaw) && opcodeRaw >= 0 && opcodeRaw <= 0xff) {
          return `0x${opcodeRaw.toString(16).padStart(2, "0")}`;
        }
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
          return "";
        }
        if (raw.startsWith("0x")) return namespaceKey;
        return `${raw.charAt(0).toUpperCase()}${raw.slice(1)} (${namespaceKey})`;
      }

      function groupLabelForSection(groupKey, sectionKey, fallbackName) {
        const opcode = requiredNamespaceForSection(sectionKey);
        if (!opcode) return fallbackName;
        const entry = B524_GROUP_NAMES && typeof B524_GROUP_NAMES === "object" ? B524_GROUP_NAMES[groupKey] : null;
        if (!entry || typeof entry !== "object") return fallbackName;
        const scoped = entry[opcode];
        if (typeof scoped === "string" && scoped) return scoped;
        if (scoped && typeof scoped === "object" && typeof scoped.name === "string" && scoped.name) {
          return scoped.name;
        }
        return fallbackName;
      }

      function groupPresentationForSection(groupKey, sectionKey) {
        const opcode = requiredNamespaceForSection(sectionKey);
        if (!opcode) return null;
        const entry = B524_GROUP_NAMES && typeof B524_GROUP_NAMES === "object" ? B524_GROUP_NAMES[groupKey] : null;
        if (!entry || typeof entry !== "object") return null;
        const scoped = entry[opcode];
        return scoped && typeof scoped === "object" ? scoped : null;
      }

      function operationLabelForOpcode(namespaceKey) {
        if (namespaceKey === "0x00") return "ReadSystemInformation";
        if (namespaceKey === "0x01") return "DescribeParameter";
        if (namespaceKey === "0x02") return "GetParameter";
        if (namespaceKey === "0x03") return "ReadTimer";
        if (namespaceKey === "0x04") return "WriteTimer";
        if (namespaceKey === "0x06") return "GetDeviceParameter";
        if (namespaceKey === "0x0b") return "GetEventSetPoint";
        return namespaceKey || "UnknownOperation";
      }

      function sectionLabel(sectionKey) {
        for (const section of B524_SECTIONS) {
          if (section.key === sectionKey) return section.label;
        }
        return sectionKey;
      }

      function requiredNamespaceForSection(sectionKey) {
        if (sectionKey === "controller_registers") return "0x02";
        if (sectionKey === "device_slots") return "0x06";
        return null;
      }



      function entryStatusKind(entry) {
        if (!entry || typeof entry !== "object") return "error";
        const responseState = typeof entry.response_state === "string"
          ? entry.response_state.trim().toLowerCase()
          : "";
        if (responseState === "empty_reply") return "dormant";
        if (responseState === "timeout" || responseState === "nack") return "transport_failure";
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

      function rowIsDormant(instancesObj, rrKey) {
        if (!instancesObj || typeof instancesObj !== "object") return false;
        let sawEntry = false;
        for (const instanceObj of Object.values(instancesObj)) {
          if (!instanceObj || typeof instanceObj !== "object") continue;
          const registers = instanceObj.registers;
          if (!registers || typeof registers !== "object") continue;
          const entry = registers[rrKey];
          if (!entry || typeof entry !== "object") continue;
          sawEntry = true;
          const kind = entryStatusKind(entry);
          if (kind !== "dormant" && kind !== "absent") return false;
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

      // Raw attributes provide profile-scoped annotations, not privilege or storage.
      function flagBadges(accessValue) {
        switch (accessValue) {
          case "read_only_not_visible": return [{text:"read-only",cls:"flag-state"},{text:"not-visible",cls:"flag-other"}];
          case "read_only_visible": return [{text:"read-only",cls:"flag-state"},{text:"visible",cls:"flag-other"}];
          case "writable_not_visible": return [{text:"writable",cls:"flag-config"},{text:"not-visible",cls:"flag-other"}];
          case "writable_visible": return [{text:"writable",cls:"flag-config"},{text:"visible",cls:"flag-other"}];
          case "state_volatile": case "state_stable": case "config_installer": case "config_user":
          case "valid": case "invalid": case "config_valid": case "config_sentinel":
            return [{text:"legacy attribute interpretation (unqualified)",cls:"flag-other"}];
          default:                  return [{text: accessValue, cls: "flag-other"}];
        }
      }

      function appendAccessBadges(cell, accessValues) {
        if (!accessValues.length) {
          cell.innerHTML = "<div class='cell-missing'>—</div>";
          return;
        }
        // Collect unique individual badges across all instances
        const seen = new Set();
        const badges = [];
        for (const av of accessValues) {
          for (const b of flagBadges(av)) {
            if (!seen.has(b.text)) { seen.add(b.text); badges.push(b); }
          }
        }
        for (const b of badges) {
          const el = document.createElement("span");
          el.className = "access-chip " + b.cls;
          el.textContent = b.text;
          cell.appendChild(el);
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
        return tabId === "b524";
      }

      function _syncActiveTabClasses() {
        for (const el of tabsEl.querySelectorAll(".tab")) {
          if (el.dataset && el.dataset.tabId === state.activeTab) el.classList.add("active");
          else el.classList.remove("active");
        }
      }

      function buildTabs(hasB524, hasB555, hasB516, hasB509) {
        tabsEl.innerHTML = "";
        const orderedTabIds = [];

        const pbsbTabs = [
          { id: "b524", has: hasB524, label: "PB=B5 SB=24 - Vaillant Regulator Params" },
          { id: "b509", has: hasB509, label: "PB=B5 SB=09 - Vaillant BAI Identity" },
          { id: "b555", has: hasB555, label: "PB=B5 SB=55 - Vaillant Timer Programs" },
          { id: "b516", has: hasB516, label: "PB=B5 SB=16 - Vaillant Energy Counters" },
        ];
        for (const def of pbsbTabs) {
          if (!def.has) continue;
          const btn = document.createElement("div");
          btn.className = "tab";
          btn.textContent = def.label;
          btn.dataset.tabId = def.id;
          btn.addEventListener("click", () => {
            state.activeTab = def.id;
            _syncActiveTabClasses();
            renderActiveTab();
          });
          tabsEl.appendChild(btn);
          orderedTabIds.push(def.id);
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

      function b524GroupKeysForSection(sectionKey) {
        const required = requiredNamespaceForSection(sectionKey);
        if (!required) return [];
        const all = groupKeysForOp(required);
        const groups = finalPlanGroups();
        if (groups === null) return all;
        return Object.keys(groups)
          .filter((groupKey) => finalPlanForRoute(groupKey, required) !== null)
          .sort((a, b) => Number(a) - Number(b));
      }

      function finalPlanGroups() {
        const scanPlan = meta && typeof meta === "object" ? meta.scan_plan : null;
        if (!scanPlan || typeof scanPlan !== "object" || !("groups" in scanPlan)) return null;
        return scanPlan.groups && typeof scanPlan.groups === "object" ? scanPlan.groups : null;
      }

      function finalPlanForRoute(groupKey, opcode) {
        const groups = finalPlanGroups();
        if (groups === null) return undefined;
        const groupPlan = groups[groupKey];
        if (!groupPlan || typeof groupPlan !== "object") return null;
        const operations = groupPlan.operations;
        if (operations && typeof operations === "object") {
          const operationPlan = operations[opcode];
          return operationPlan && typeof operationPlan === "object" ? operationPlan : null;
        }
        return normalizeOpcodeKey(groupPlan.opcode) === opcode ? groupPlan : null;
      }

      const B524_TIMER_CHANNELS = {
        "ventilation": [0x00, 0x01],
        "noise-reduction": [0x00, 0x02],
        "tariff": [0x00, 0x03],
        "dhw": [0x01, 0x01],
        "circulation": [0x01, 0x02],
        "zone-cooling": [0x03, 0x01],
        "zone-heating": [0x03, 0x02],
      };
      const B524_EVENT_SYSTEM_TYPES = {system: 0x00, dhw: 0x01, zone: 0x03};

      function b524HexBytes(raw, expectedLength) {
        if (typeof raw !== "string" || !new RegExp(`^[0-9a-fA-F]{${expectedLength * 2}}$`).test(raw)) return null;
        return raw.match(/../g).map((value) => parseInt(value, 16));
      }

      function b524BytesHex(values) {
        return values.map((value) => value.toString(16).padStart(2, "0")).join("");
      }

      function b524SelectorKey(selector) {
        if (!selector || typeof selector !== "object" || Array.isArray(selector)) return null;
        return JSON.stringify(Object.keys(selector).sort().map((key) => [key, typeof selector[key], selector[key]]));
      }

      function b524CanonicalSelector(selector, operation) {
        if (!selector || typeof selector !== "object" || Array.isArray(selector)) return null;
        const byte = (value) => Number.isInteger(value) && value >= 0 && value <= 0xff;
        if (operation === "WriteTimer") {
          if (Object.keys(selector).sort().join(",") !== "channel,instance,weekday") return null;
          if (!(selector.channel in B524_TIMER_CHANNELS) || !byte(selector.instance)
              || !Number.isInteger(selector.weekday) || selector.weekday < 0 || selector.weekday > 6) return null;
          if (!selector.channel.startsWith("zone-") && selector.instance !== 0) return null;
          return {channel: selector.channel, instance: selector.instance, weekday: selector.weekday};
        }
        if (Object.keys(selector).sort().join(",") !== "address,instance,profile,weekday_code") return null;
        if (!(selector.profile in B524_EVENT_SYSTEM_TYPES) || !byte(selector.instance)
            || !byte(selector.address) || !byte(selector.weekday_code)) return null;
        const addresses = selector.profile === "system" ? [1, 2, 3] : [1, 2];
        if (!addresses.includes(selector.address)) return null;
        return {
          profile: selector.profile,
          instance: selector.instance,
          address: selector.address,
          weekday_code: selector.weekday_code,
        };
      }

      function b524OperationForSection(sectionKey) {
        return {operation_03: "WriteTimer", operation_09: "SetEvent", operation_0b: "SetEventSetPoint"}[sectionKey] || null;
      }

      function b524BaselineReason(row, opcode, operation) {
        if (!row || typeof row !== "object") return "record is missing";
        if (row.response_state !== "value") return `response state is ${String(row.response_state || "unknown")}`;
        if (!row.decoded || typeof row.decoded !== "object" || Array.isArray(row.decoded)) {
          return "a decoded canonical baseline is required";
        }
        if (!b524CanonicalSelector(row.selector, operation)) return "selector is not canonical for this operation";
        const expectedLength = opcode === "0x03" ? 7 : 8;
        if (!b524HexBytes(row.response_raw_hex, expectedLength)) return `raw baseline must contain ${expectedLength} bytes`;
        return null;
      }

      function b524EditAvailability(row, operation, reads) {
        const sourceOpcode = operation === "WriteTimer" ? "0x03" : operation === "SetEvent" ? "0x09" : "0x0b";
        const sourceReason = b524BaselineReason(row, sourceOpcode, operation);
        if (sourceReason) return {available: false, reason: sourceReason};
        if (operation === "WriteTimer") return {available: true, reason: "complete decoded timer baseline"};
        const key = b524SelectorKey(row.selector);
        const matching = (opcode) => reads.filter((candidate) => candidate && typeof candidate === "object"
          && normalizeOpcodeKey(candidate.opcode_hex || candidate.opcode) === opcode
          && b524SelectorKey(candidate.selector) === key);
        const events = matching("0x09");
        const setpoints = matching("0x0b");
        if (events.length !== 1 || setpoints.length !== 1) {
          return {available: false, reason: "exactly one OP09 and one OP0B baseline are required for this selector"};
        }
        const eventReason = b524BaselineReason(events[0], "0x09", operation);
        const setpointReason = b524BaselineReason(setpoints[0], "0x0b", operation);
        if (eventReason || setpointReason) {
          return {available: false, reason: `paired baseline is incomplete: ${eventReason || setpointReason}`};
        }
        return {available: true, reason: "complete decoded OP09/OP0B pair"};
      }

      function b524EditDocumentForRow(row, operation, reads, metaObj) {
        const availability = b524EditAvailability(row, operation, reads);
        if (!availability.available) throw new Error(availability.reason);
        const destinationAddress = b524DestinationAddress(metaObj);
        const selector = b524CanonicalSelector(row.selector, operation);
        if (operation === "WriteTimer") {
          const raw = b524HexBytes(row.response_raw_hex, 7);
          const values = [];
          for (const offset of [1, 3, 5]) {
            values.push(raw[offset] === 0x90 && raw[offset + 1] === 0x90 ? null : [raw[offset], raw[offset + 1]]);
          }
          return {schema_version: 1, destination_address: destinationAddress, operation, selector, values, expected_before_raw_hex: [row.response_raw_hex.toLowerCase()]};
        }
        const key = b524SelectorKey(row.selector);
        const event = reads.find((candidate) => normalizeOpcodeKey(candidate && (candidate.opcode_hex || candidate.opcode)) === "0x09"
          && b524SelectorKey(candidate.selector) === key);
        const setpoint = reads.find((candidate) => normalizeOpcodeKey(candidate && (candidate.opcode_hex || candidate.opcode)) === "0x0b"
          && b524SelectorKey(candidate.selector) === key);
        const eventRaw = b524HexBytes(event.response_raw_hex, 8);
        const setpointRaw = b524HexBytes(setpoint.response_raw_hex, 8);
        const values = (operation === "SetEvent" ? eventRaw : setpointRaw).slice(1);
        return {
          schema_version: 1,
          destination_address: destinationAddress,
          operation,
          selector,
          values,
          expected_before_raw_hex: [event.response_raw_hex.toLowerCase(), setpoint.response_raw_hex.toLowerCase()],
        };
      }

      function b524ReadUint8(input, label) {
        const text = String(input.value || "").trim();
        const value = text ? Number(text) : NaN;
        if (!Number.isInteger(value) || value < 0 || value > 0xff) throw new Error(`${label} must be an integer from 0 to 255 (decimal or 0xNN)`);
        return value;
      }

      function b524DestinationAddress(metaObj) {
        const raw = metaObj && (metaObj.destination_address ?? metaObj.dest ?? metaObj.dst);
        const parsed = typeof raw === "number" ? raw : typeof raw === "string" && raw.trim() ? Number(raw) : NaN;
        return Number.isInteger(parsed) && parsed >= 0 && parsed <= 0xff ? parsed : null;
      }

      function b524Destination(metaObj) {
        const parsed = b524DestinationAddress(metaObj);
        return parsed === null ? "unknown" : `0x${parsed.toString(16).padStart(2, "0")}`;
      }

      function b524BuildPreview(documentValue, metaObj) {
        const destination = b524Destination(metaObj);
        if (destination === "unknown") throw new Error("artifact destination is missing or invalid");
        const destinationAddress = b524DestinationAddress(metaObj);
        if (documentValue.destination_address !== destinationAddress) throw new Error("edit document destination does not match artifact target");
        const operation = documentValue.operation;
        const selector = b524CanonicalSelector(documentValue.selector, operation);
        if (!selector) throw new Error("selector is not canonical for this operation");
        const before = documentValue.expected_before_raw_hex.map((raw, index) => {
          const length = operation === "WriteTimer" ? 7 : 8;
          const parsed = b524HexBytes(raw, length);
          if (!parsed) throw new Error(`baseline ${index + 1} is not a complete ${length}-byte value`);
          return parsed;
        });
        let opcode;
        let payload;
        let after;
        if (operation === "WriteTimer") {
          if (!Array.isArray(documentValue.values) || documentValue.values.length !== 3) throw new Error("exactly three timer slots are required");
          const channel = B524_TIMER_CHANNELS[selector.channel];
          const slots = [];
          for (let index = 0; index < 3; index += 1) {
            const slot = documentValue.values[index];
            if (slot === null) { slots.push(0x90, 0x90); continue; }
            if (!Array.isArray(slot) || slot.length !== 2) throw new Error(`slot ${index + 1} must be a pair or unused`);
            const [start, stop] = slot;
            if (!Number.isInteger(start) || !Number.isInteger(stop) || start < 0 || start > 0x8f || stop < 0 || stop > 0x90 || start >= stop) {
              throw new Error(`slot ${index + 1} must satisfy 0 <= start < stop <= 0x90`);
            }
            slots.push(start, stop);
          }
          opcode = 0x04;
          payload = [opcode, channel[0], selector.instance, channel[1], selector.weekday, ...slots];
          after = [[before[0][0], ...slots]];
        } else {
          if (!Array.isArray(documentValue.values) || documentValue.values.length !== 7
              || documentValue.values.some((value) => !Number.isInteger(value) || value < 0 || value > 0xff)) {
            throw new Error("exactly seven uint8 raw values are required");
          }
          opcode = operation === "SetEvent" ? 0x0a : 0x0c;
          payload = [opcode, B524_EVENT_SYSTEM_TYPES[selector.profile], selector.instance, selector.address, selector.weekday_code, ...documentValue.values];
          after = operation === "SetEvent"
            ? [[before[0][0], ...documentValue.values], before[1].slice()]
            : [before[0].slice(), [before[1][0], ...documentValue.values]];
        }
        const beforeHex = before.map(b524BytesHex);
        const afterHex = after.map(b524BytesHex);
        return {
          schema_version: 1,
          operation,
          opcode_hex: `0x${opcode.toString(16).toUpperCase().padStart(2, "0")}`,
          destination,
          selector,
          payload_hex: b524BytesHex(payload),
          expected_before_raw_hex: beforeHex,
          expected_after_raw_hex: afterHex,
          diff: beforeHex.map((raw, index) => ({before_raw_hex: raw, after_raw_hex: afterHex[index], changed: raw !== afterHex[index]})),
          live_send: false,
          live_write: false,
          native_write_available: false,
        };
      }

      function b524DownloadEditDocument(documentValue) {
        const blob = new Blob([JSON.stringify(documentValue, null, 2) + "\\n"], {type: "application/json"});
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = "b524-operation-edit.json";
        link.click();
        URL.revokeObjectURL(link.href);
      }

      function b524AppendValueField(parent, labelText, value, onChange, index) {
        const label = document.createElement("label");
        label.className = "operation-editor-field";
        label.textContent = labelText;
        const input = document.createElement("input");
        input.type = "text";
        input.value = String(value);
        input.dataset.role = "operation-value";
        input.dataset.valueIndex = String(index);
        input.addEventListener("input", onChange);
        label.appendChild(input);
        parent.appendChild(label);
        return input;
      }

      function renderB524OperationEditor(sectionKey, rows, reads, container, metaObj) {
        const operation = b524OperationForSection(sectionKey);
        const table = document.createElement("table");
        table.innerHTML = "<thead><tr><th>Selector</th><th>State</th><th>Raw response</th><th>Decoded</th><th>Qualification</th><th>Correlation</th><th>Attempts</th><th>Offline edit</th></tr></thead>";
        const tbody = document.createElement("tbody");
        const editorHost = document.createElement("div");

        const openEditor = (row) => {
          editorHost.innerHTML = "";
          const documentValue = b524EditDocumentForRow(row, operation, reads, metaObj);
          const editor = document.createElement("div"); editor.className = "operation-editor";
          const heading = document.createElement("div"); heading.className = "table-title";
          heading.textContent = `${operation} offline editor — ${Object.entries(documentValue.selector).map(([key, value]) => `${key}=${String(value)}`).join(", ")}`;
          editor.appendChild(heading);
          const boundary = document.createElement("div"); boundary.className = "subtitle";
          boundary.textContent = `Recorded qualification: ${String(row.decode_qualification || "unknown")}. Candidate labels remain offline hints. No native write or network action is available.`;
          editor.appendChild(boundary);
          const grid = document.createElement("div"); grid.className = "operation-editor-grid";
          const inputs = [];
          const invalidate = () => { exportButton.disabled = true; previewBox.textContent = "Change pending. Preview again before export."; };
          let timerSlots = null;
          if (operation === "WriteTimer") {
            timerSlots = documentValue.values.map((slot, index) => {
              const cell = document.createElement("div"); cell.className = "operation-editor-field";
              const unusedLabel = document.createElement("label"); unusedLabel.textContent = `Slot ${index + 1} unused (0x90/0x90)`;
              const unused = document.createElement("input"); unused.type = "checkbox"; unused.checked = slot === null;
              unused.dataset.role = "timer-slot-unused"; unused.dataset.slotIndex = String(index);
              unused.addEventListener("change", invalidate); unusedLabel.appendChild(unused); cell.appendChild(unusedLabel);
              const start = b524AppendValueField(cell, `Slot ${index + 1} start raw`, slot === null ? 0x90 : slot[0], invalidate, index * 2);
              const stop = b524AppendValueField(cell, `Slot ${index + 1} stop raw`, slot === null ? 0x90 : slot[1], invalidate, index * 2 + 1);
              grid.appendChild(cell);
              return {unused, start, stop};
            });
          } else {
            for (let index = 0; index < 7; index += 1) {
              let label;
              if (operation === "SetEvent") {
                label = index === 0 ? "Event value 1 raw (meaning unknown; edit explicitly)" : `Event start ${index + 1} raw (candidate 10-minute code)`;
              } else if (documentValue.selector.profile === "dhw") {
                label = `Setpoint ${index + 1} raw (candidate states: 253 enable, 254 disable, 255 replacement)`;
              } else {
                label = `Setpoint ${index + 1} raw (candidate temperature = raw / 2 °C)`;
              }
              inputs.push(b524AppendValueField(grid, label, documentValue.values[index], invalidate, index));
            }
          }
          editor.appendChild(grid);
          const status = document.createElement("div"); status.className = "subtitle"; status.dataset.role = "operation-validation";
          const previewBox = document.createElement("pre"); previewBox.className = "operation-preview"; previewBox.dataset.role = "operation-preview";
          previewBox.textContent = "Preview has not been built.";
          const actions = document.createElement("div"); actions.className = "operation-editor-actions";
          const previewButton = document.createElement("button"); previewButton.type = "button"; previewButton.dataset.role = "operation-preview-button"; previewButton.textContent = "Preview encoded payload";
          const exportButton = document.createElement("button"); exportButton.type = "button"; exportButton.dataset.role = "operation-export-button"; exportButton.textContent = "Export offline edit document"; exportButton.disabled = true;
          let lastDocument = null;
          previewButton.addEventListener("click", () => {
            try {
              const next = {...documentValue, values: []};
              if (operation === "WriteTimer") {
                next.values = timerSlots.map((slot, index) => slot.unused.checked ? null : [
                  b524ReadUint8(slot.start, `slot ${index + 1} start`),
                  b524ReadUint8(slot.stop, `slot ${index + 1} stop`),
                ]);
              } else {
                next.values = inputs.map((input, index) => b524ReadUint8(input, `value ${index + 1}`));
              }
              const preview = b524BuildPreview(next, metaObj);
              lastDocument = next;
              previewBox.textContent = JSON.stringify(preview, null, 2);
              status.textContent = "Offline preview validated. Export contains values and recorded baselines only; it cannot write to a device.";
              exportButton.disabled = false;
            } catch (error) {
              lastDocument = null; exportButton.disabled = true;
              status.textContent = String(error && error.message ? error.message : error);
              previewBox.textContent = "Preview rejected.";
            }
          });
          exportButton.addEventListener("click", () => { if (lastDocument) b524DownloadEditDocument(lastDocument); });
          actions.appendChild(previewButton); actions.appendChild(exportButton);
          editor.appendChild(actions); editor.appendChild(status); editor.appendChild(previewBox);
          editorHost.appendChild(editor);
        };

        rows.forEach((row, index) => {
          const selector = row.selector && typeof row.selector === "object" ? Object.entries(row.selector).map(([key, value]) => `${key}=${String(value)}`).join(", ") : "unqualified selector";
          const decoded = row.decoded === null || typeof row.decoded === "undefined" ? "—" : JSON.stringify(row.decoded);
          const values = [selector, row.response_state || "unknown", row.response_raw_hex || "—", decoded, row.decode_qualification || "unknown", row.selector_correlation || "unknown", row.request_attempts ?? "—"];
          const tr = document.createElement("tr");
          for (const value of values) { const td = document.createElement("td"); td.textContent = String(value); tr.appendChild(td); }
          const action = document.createElement("td");
          if (operation) {
            const availability = b524EditAvailability(row, operation, reads);
            const button = document.createElement("button"); button.type = "button"; button.textContent = "Edit offline";
            button.dataset.role = "operation-edit-select"; button.dataset.operationEditIndex = String(index);
            button.disabled = !availability.available; button.title = availability.reason;
            button.addEventListener("click", () => openEditor(row)); action.appendChild(button);
          } else {
            action.textContent = "Read-only";
          }
          tr.appendChild(action); tbody.appendChild(tr);
        });
        table.appendChild(tbody); container.appendChild(table);
        const note = document.createElement("div"); note.className = "subtitle";
        note.textContent = "Offline editors require complete decoded canonical baselines. Event edits require one exact-selector OP09/OP0B pair in this artifact. This report cannot send a native write; no fetch, network call, or native writer is present.";
        container.appendChild(note); container.appendChild(editorHost);
      }

      function b524SectionHasContent(sectionKey, operations, metaObj) {
        if (sectionKey.startsWith("operation_")) {
          const opcode = `0x${sectionKey.slice("operation_".length)}`;
          const reads = artifact && Array.isArray(artifact.b524_operation_reads) ? artifact.b524_operation_reads : [];
          return reads.some((row) => normalizeOpcodeKey(row && (row.opcode_hex || row.opcode)) === opcode);
        }
        if (sectionKey === "scan_coverage") {
          return !!(metaObj && (metaObj.scan_coverage || metaObj.parameter_description_coverage));
        }
        if (sectionKey === "controller_registers" || sectionKey === "device_slots") {
          return b524GroupKeysForSection(sectionKey).length > 0;
        }
        if (sectionKey === "system_information") {
          return !!(metaObj && typeof metaObj === "object" && Array.isArray(metaObj.system_information) && metaObj.system_information.length);
        }
        if (sectionKey === "group_directory") {
          return !!(operations && typeof operations === "object" && Array.isArray(operations.group_directory) && operations.group_directory.length);
        }
        if (sectionKey === "register_constraints") {
          return !!(metaObj && typeof metaObj === "object" && metaObj.constraint_dictionary && Object.keys(metaObj.constraint_dictionary).length)
            || !!(operations && typeof operations === "object" && Array.isArray(operations.register_constraints) && operations.register_constraints.length);
        }
        if (sectionKey === "register_tables") {
          const reads = artifact && Array.isArray(artifact.b524_operation_reads) ? artifact.b524_operation_reads : [];
          if (reads.some((row) => normalizeOpcodeKey(row && (row.opcode_hex || row.opcode)) === "0x0b")) return false;
        }
        return !!(operations && typeof operations === "object" && Array.isArray(operations[sectionKey]) && operations[sectionKey].length);
      }

      function visibleB524Sections(operations, metaObj) {
        return B524_SECTIONS.filter((section) => b524SectionHasContent(section.key, operations, metaObj));
      }

      function renderB524OperationRows(sectionKey, mountTarget) {
        const operations = artifact && typeof artifact === "object" ? artifact.b524_operations : null;
        const metaObj = artifact && typeof artifact === "object" ? artifact.meta : null;
        const container = document.createElement("div");
        const title = document.createElement("div");
        title.className = "section-title";
        title.textContent = sectionLabel(sectionKey);
        container.appendChild(title);

        if (sectionKey.startsWith("operation_")) {
          const opcode = `0x${sectionKey.slice("operation_".length)}`;
          const reads = artifact && Array.isArray(artifact.b524_operation_reads) ? artifact.b524_operation_reads : [];
          const rows = reads.filter((row) => row && typeof row === "object" && normalizeOpcodeKey(row.opcode_hex || row.opcode) === opcode);
          renderB524OperationEditor(sectionKey, rows, reads, container, metaObj);
          mountTarget.innerHTML = ""; mountTarget.appendChild(container); return;
        }

        if (sectionKey === "scan_coverage") {
          const scan = metaObj && metaObj.scan_coverage || {};
          const descriptions = metaObj && metaObj.parameter_description_coverage || {};
          const rows = [
            ["Preset", scan.preset], ["Configured scope", scan.scope],
            ["Request budget", scan.request_budget], ["Actual requests", scan.actual_requests],
            ["Scan completed", scan.completed], ["Unknown groups", Array.isArray(scan.unknown_groups) ? scan.unknown_groups.join(", ") : "unknown"],
            ["Device discovery qualified", scan.device_discovery_complete], ["Qualification incomplete", scan.qualification_incomplete],
            ["Description request budget", descriptions.request_budget], ["Effective description budget", descriptions.effective_request_budget],
            ["Description candidates", descriptions.eligible], ["Descriptions scheduled", descriptions.scheduled], ["Descriptions attempted", descriptions.attempted],
            ["Descriptions received", descriptions.received], ["Descriptions interpreted", descriptions.interpreted], ["Descriptions omitted", descriptions.omitted],
            ["Descriptions matched", descriptions.matched], ["Descriptions unavailable", descriptions.unavailable],
            ["Descriptions unqualified", descriptions.unqualified], ["Descriptions skipped by budget", descriptions.budget_skipped],
            ["Descriptions not attempted", descriptions.not_attempted],
            ["Description request attempts", descriptions.request_attempts], ["Description retries", descriptions.retries],
          ];
          const families = descriptions.by_read_operation || {};
          for (const opcode of Object.keys(families).sort()) {
            const stats = families[opcode];
            if (!stats || typeof stats !== "object") continue;
            for (const name of ["eligible", "planned", "scheduled", "attempted", "received", "interpreted", "matched", "unavailable", "unqualified", "budget_skipped", "omitted", "not_attempted", "request_attempts", "retries"]) {
              rows.push([`${opcode} ${name}`, stats[name]]);
            }
          }
          const table = document.createElement("table");
          table.innerHTML = "<thead><tr><th>Coverage</th><th>Observation</th></tr></thead>";
          const tbody = document.createElement("tbody");
          for (const [label, value] of rows) {
            const tr = document.createElement("tr");
            for (const cellValue of [label, value]) {
              const td = document.createElement("td");
              td.textContent = typeof cellValue === "undefined" || cellValue === null ? "unknown" : String(cellValue);
              tr.appendChild(td);
            }
            tbody.appendChild(tr);
          }
          table.appendChild(tbody);
          container.appendChild(table);
          mountTarget.innerHTML = "";
          mountTarget.appendChild(container);
          return;
        }

        if (sectionKey === "system_information") {
          const rows = metaObj && typeof metaObj === "object" && Array.isArray(metaObj.system_information)
            ? metaObj.system_information
            : [];
          if (!rows.length) {
            container.innerHTML += "<div class='subtitle'>No ReadSystemInformation entries in artifact.</div>";
            mountTarget.innerHTML = "";
            mountTarget.appendChild(container);
            return;
          }
          const wrap = document.createElement("div");
          wrap.className = "table-wrap";
          const table = document.createElement("table");
          table.innerHTML = "<thead><tr><th>Identifier</th><th>Name</th><th>Value</th><th>Raw reply</th><th>State</th></tr></thead>";
          const tbody = document.createElement("tbody");
          for (const row of rows) {
            if (!row || typeof row !== "object") continue;
            const tr = document.createElement("tr");
            for (const value of [
              typeof row.identifier === "string" ? row.identifier : "n/a",
              typeof row.name === "string" ? row.name : "unknown",
              typeof row.value === "number" ? formatValue(row.value) : "—",
              typeof row.raw_hex === "string" && row.raw_hex ? row.raw_hex : "—",
              typeof row.state === "string" ? row.state : "unknown",
            ]) {
              const td = document.createElement("td");
              td.textContent = value;
              tr.appendChild(td);
            }
            tbody.appendChild(tr);
          }
          table.appendChild(tbody);
          wrap.appendChild(table);
          container.appendChild(wrap);
          mountTarget.innerHTML = "";
          mountTarget.appendChild(container);
          return;
        }

        if (sectionKey === "group_directory") {
          const rows = [];
          if (operations && typeof operations === "object" && Array.isArray(operations.group_directory)) {
            for (const row of operations.group_directory) rows.push(row);
          } else {
            // Derive from operations-first structure: each unique group key
            // gets one directory row, picking the first operation that has it.
            for (const groupKey of allGroupKeys()) {
              let groupObj = null;
              const artOps = artifact && typeof artifact === "object" ? artifact.operations : null;
              if (artOps && typeof artOps === "object") {
                for (const opObj of Object.values(artOps)) {
                  if (!opObj || typeof opObj !== "object") continue;
                  const g = opObj.groups && typeof opObj.groups === "object" ? opObj.groups[groupKey] : null;
                  if (g && typeof g === "object") { groupObj = getGroupObject(g); break; }
                }
              }
              if (!groupObj) continue;
              rows.push({
                group: groupKey,
                descriptor: groupObj.descriptor_observed,
                reply_hex: null,
              });
            }
          }
          if (!rows.length) {
            container.innerHTML += "<div class='subtitle'>No legacy group-directory entries in artifact.</div>";
            mountTarget.innerHTML = "";
            mountTarget.appendChild(container);
            return;
          }
          const wrap = document.createElement("div");
          wrap.className = "table-wrap";
          const table = document.createElement("table");
          table.innerHTML =
            "<thead><tr><th>Group</th><th>Descriptor</th><th>Reply</th></tr></thead>";
          const tbody = document.createElement("tbody");
          for (const row of rows) {
            const tr = document.createElement("tr");
            for (const value of [
              String(row.group || "n/a"),
              typeof row.descriptor === "number" ? formatValue(row.descriptor) : "n/a",
              typeof row.reply_hex === "string" && row.reply_hex ? row.reply_hex : "—",
            ]) {
              const td = document.createElement("td");
              td.textContent = value;
              tr.appendChild(td);
            }
            tbody.appendChild(tr);
          }
          table.appendChild(tbody);
          wrap.appendChild(table);
          container.appendChild(wrap);
          mountTarget.innerHTML = "";
          mountTarget.appendChild(container);
          return;
        }

        if (sectionKey === "register_constraints") {
          const dict = metaObj && typeof metaObj === "object" ? metaObj.constraint_dictionary : null;
          const rows = [];
          if (dict && typeof dict === "object") {
            for (const groupKey of sortedHexKeys(Object.keys(dict))) {
              const groupObj = dict[groupKey];
              if (!groupObj || typeof groupObj !== "object") continue;
              for (const rrKey of sortedHexKeys(Object.keys(groupObj))) {
                const constraint = groupObj[rrKey];
                if (!constraint || typeof constraint !== "object") continue;
                rows.push({
                  group: groupKey,
                  register: rrKey,
                  type: constraint.type || "n/a",
                  min: typeof constraint.min !== "undefined" ? formatValue(constraint.min) : "n/a",
                  max: typeof constraint.max !== "undefined" ? formatValue(constraint.max) : "n/a",
                  step: typeof constraint.step !== "undefined" ? formatValue(constraint.step) : "n/a",
                });
              }
            }
          } else if (
            operations
            && typeof operations === "object"
            && Array.isArray(operations.register_constraints)
          ) {
            for (const row of operations.register_constraints) {
              if (!row || typeof row !== "object") continue;
              rows.push({
                group: typeof row.group === "string" ? row.group : "n/a",
                register: typeof row.register_selector === "string" ? row.register_selector : "n/a",
                type: typeof row.kind === "string" ? row.kind : (typeof row.reply_hex === "string" && row.reply_hex ? "raw" : "—"),
                min: (typeof row.min_value === "number" || typeof row.min_value === "string") ? String(row.min_value) : "—",
                max: (typeof row.max_value === "number" || typeof row.max_value === "string") ? String(row.max_value) : "—",
                step: (typeof row.step_value === "number" || typeof row.step_value === "string") ? String(row.step_value) : "—",
              });
            }
          }
          if (!rows.length) {
            container.innerHTML += "<div class='subtitle'>No legacy constraint rows in artifact.</div>";
            mountTarget.innerHTML = "";
            mountTarget.appendChild(container);
            return;
          }
          const wrap = document.createElement("div");
          wrap.className = "table-wrap";
          const table = document.createElement("table");
          table.innerHTML =
            "<thead><tr><th>Group</th><th>Register</th><th>Type</th><th>Min</th><th>Max</th><th>Step</th></tr></thead>";
          const tbody = document.createElement("tbody");
          for (const row of rows) {
            const tr = document.createElement("tr");
            for (const value of [row.group, row.register, row.type, row.min, row.max, row.step]) {
              const td = document.createElement("td");
              td.textContent = String(value);
              tr.appendChild(td);
            }
            tbody.appendChild(tr);
          }
          table.appendChild(tbody);
          wrap.appendChild(table);
          container.appendChild(wrap);
          mountTarget.innerHTML = "";
          mountTarget.appendChild(container);
          return;
        }

        const opRows = operations && typeof operations === "object" ? operations[sectionKey] : null;
        if (!Array.isArray(opRows) || !opRows.length) {
          container.innerHTML += `<div class='subtitle'>No ${sectionLabel(sectionKey)} entries in artifact.</div>`;
          mountTarget.innerHTML = "";
          mountTarget.appendChild(container);
          return;
        }
        const pre = document.createElement("pre");
        pre.className = "cell-raw";
        pre.textContent = JSON.stringify(opRows, null, 2);
        container.appendChild(pre);
        mountTarget.innerHTML = "";
        mountTarget.appendChild(container);
      }

      function renderActiveGroup(groupKey, opKey, mountTarget = sheetArea) {
        const rawGroup = getOperationGroup(opKey, groupKey);
        if (!groupKey || !rawGroup) {
          mountTarget.innerHTML = "<div class='subtitle'>No groups.</div>";
          return;
        }

        const groupObj = getGroupObject(rawGroup);
        const groupName = typeof groupObj.name === "string" && groupObj.name ? groupObj.name : "Unknown";
        const resolvedGroupName = opKey === "0x02"
          ? groupLabelForSection(groupKey, "controller_registers", groupName)
          : opKey === "0x06"
            ? groupLabelForSection(groupKey, "device_slots", groupName)
            : groupName;

        function instanceIsConnected(instancesObj, iiKey, namespaceKey) {
          const inst = instancesObj[iiKey];
          if (!inst || typeof inst !== "object") return false;
          if (Object.prototype.hasOwnProperty.call(inst, "present")) return inst.present === true;
          const regs = inst.registers;
          if (!regs || typeof regs !== "object") return false;
          if (namespaceKey === "0x06" || opKey === "0x06") {
            // OP=0x06: RR=0x0001 (device_connected) is the universal indicator
            const r1 = regs["0x0001"];
            if (!r1 || typeof r1 !== "object") return false;
            const kind = entryStatusKind(r1);
            if (kind === "absent" || kind === "transport_failure") return false;
            return !!r1.value;
          }
          // OP=0x02: group-specific presence heuristics
          if (groupKey === "0x02") {
            // GG=0x02 Heating Circuits: RR=0x0002 (circuit_type) != 0
            const circuitType = regs["0x0002"];
            if (circuitType && typeof circuitType === "object" && entryStatusKind(circuitType) === "ok") {
              return !!circuitType.value;
            }
          }
          if (groupKey === "0x03") {
            // GG=0x03 Zones: RR=0x001C (zone_index) == 0xFF means absent
            const zoneIdx = regs["0x001c"];
            if (zoneIdx && typeof zoneIdx === "object" && entryStatusKind(zoneIdx) === "ok") {
              return zoneIdx.value !== 255 && zoneIdx.value !== 0xFF;
            }
          }
          // Generic: instance is connected if present=true and has non-dormant data
          if (inst.present === false) return false;
          for (const entry of Object.values(regs)) {
            if (!entry || typeof entry !== "object") continue;
            if (entryStatusKind(entry) === "ok") return true;
          }
          return false;
        }

        function buildGroupTable(instancesObj, namespaceKey = null) {
          let instanceKeys = sortedHexKeys(Object.keys(instancesObj || {})).filter((iiKey) => {
            const ii = parseInt(iiKey, 16);
            if (namespaceKey === "0x06" || opKey === "0x06") return ii >= 1 && ii <= 8;
            if (groupKey === "0x02") return ii >= 1 && ii <= 9;
            return true;
          });
          if (state.b524Filters.hideMissingInstances) {
            instanceKeys = instanceKeys.filter((iiKey) => instanceIsConnected(instancesObj, iiKey, namespaceKey));
          }
          // Build a filtered view with only visible instances for row filtering
          const visibleInstances = {};
          for (const iiKey of instanceKeys) {
            if (instancesObj[iiKey]) visibleInstances[iiKey] = instancesObj[iiKey];
          }
          let rrKeys = visibleRegisterKeys(visibleInstances);
          if (groupKey === "0x00") {
            rrKeys = rrKeys.filter((rrKey) => parseHexKey(rrKey) <= 0x00FF);
          }
          if (state.b524Filters.hideAbsent) {
            rrKeys = rrKeys.filter((rrKey) => !rowIsAbsent(visibleInstances, rrKey));
          }
          if (state.b524Filters.hideDormant) {
            rrKeys = rrKeys.filter((rrKey) => !rowIsDormant(visibleInstances, rrKey));
          }

          if (!rrKeys.length) {
            const empty = document.createElement("div");
            empty.className = "subtitle";
            empty.textContent = "No visible registers.";
            return empty;
          }

          const table = document.createElement("table");
          const thead = document.createElement("thead");
          const trHead = document.createElement("tr");
          const th0 = document.createElement("th");
          th0.className = "offset-cell";
          const ggNum = parseInt(groupKey, 16);
          const ggHex = ggNum.toString(16).toUpperCase().padStart(2, "0") + "h";
          const nameStr = resolvedGroupName !== "Unknown" ? ` ${resolvedGroupName}` : "";
          const presentation = groupPresentationForSection(
            groupKey,
            opKey === "0x02" ? "controller_registers" : "device_slots",
          );
          const rrMax = presentation && typeof presentation.rr_max === "string"
            ? `; declared RR_max ${presentation.rr_max}`
            : "";
          th0.innerHTML = `Register <span style="opacity:.7;font-weight:500">(${ggHex}${nameStr}${rrMax})</span>`;
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

            const ebusdNameList = Array.from(rowEbusdNames).sort();
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
                setRowOverride(groupKey, rrKey, sel.value, opKey);
                renderActiveGroup(groupKey, opKey, mountTarget);
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

              if (typeof entry.candidate_name === "string" && entry.candidate_name) {
                const candidateEl = document.createElement("div");
                candidateEl.className = "cell-raw";
                const evidence = typeof entry.candidate_evidence === "string"
                  ? ` (${entry.candidate_evidence})`
                  : "";
                candidateEl.textContent = `Candidate annotation: ${entry.candidate_name}${evidence}`;
                td.appendChild(candidateEl);
              }

              const description = entry.parameter_description;
              const bundled = entry.bundled_parameter_description;
              if (bundled && typeof bundled === "object" && bundled.verification !== "matches") {
                const bundledEl = document.createElement("div");
                bundledEl.className = "cell-raw";
                const verification = typeof bundled.verification === "string"
                  ? bundled.verification
                  : "not_verified";
                const isMismatch = verification === "differs" || verification === "profile_mismatch";
                const comparison = isMismatch
                  ? "Description mismatch"
                  : `Cached description ${verification}`;
                bundledEl.textContent = `${comparison}: ${bundled.type || "unknown"} · min=${formatValue(bundled.min)} · max=${formatValue(bundled.max)} · step=${formatValue(bundled.step)}.`;
                td.appendChild(bundledEl);
              }
              if (description && typeof description === "object") {
                const descriptionEl = document.createElement("div");
                descriptionEl.className = "cell-raw";
                if (description.qualification === "matched") {
                  const step = description.step_qualification === "unknown"
                    ? "unknown"
                    : formatValue(description.step);
                  const codec = typeof description.type === "string" && description.type
                    ? description.type
                    : "unknown";
                  descriptionEl.textContent = `Describe: min=${formatValue(description.min)}, max=${formatValue(description.max)}, step=${step}, ${codec}`;
                } else {
                  if (!(selectedType && selectedType.startsWith("STR:"))) {
                    const reason = typeof description.reason === "string" ? `: ${description.reason}` : "";
                    descriptionEl.textContent = `Parameter description unavailable${reason}; offline edit confirmation remains unvalidated.`;
                  }
                }
                if (descriptionEl.textContent) td.appendChild(descriptionEl);
              }

              if (typeof entry.flags_access === "string" && entry.flags_access && statusKind === "ok") {
                const flagsEl = document.createElement("div");
                flagsEl.className = "cell-flags";
                appendAccessBadges(flagsEl, [entry.flags_access]);
                td.appendChild(flagsEl);
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
              if (statusKind !== "transport_failure" && errTxt && statusKind !== "absent") {
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
              if (entry.value_label_qualification) tipParts.push(`value_label_qualification=${entry.value_label_qualification} (presentation only; no write authority)`);
              if (entry.constraint_type) tipParts.push(`constraint_type=${entry.constraint_type}`);
              if (typeof entry.constraint_min !== "undefined") tipParts.push(`constraint_min=${formatValue(entry.constraint_min)}`);
              if (typeof entry.constraint_max !== "undefined") tipParts.push(`constraint_max=${formatValue(entry.constraint_max)}`);
              if (typeof entry.constraint_step !== "undefined") tipParts.push(`constraint_step=${formatValue(entry.constraint_step)}`);
              if (entry.constraint_tt) tipParts.push(`constraint_tt=${entry.constraint_tt}`);
              if (entry.constraint_scope) tipParts.push(`constraint_scope=${entry.constraint_scope}`);
              if (entry.constraint_provenance) tipParts.push(`constraint_provenance=${entry.constraint_provenance}`);
              if (entry.candidate_name) tipParts.push(`candidate_name=${entry.candidate_name}`);
              if (description && typeof description === "object") tipParts.push(`parameter_description_qualification=${description.qualification || "unknown"}`);
              if (tipParts.length) td.title = tipParts.join("\\n");

              tr.appendChild(td);
            }

            tbody.appendChild(tr);
          }

          table.appendChild(tbody);
          return table;
        }

        mountTarget.innerHTML = "";

        const filters = document.createElement("div");
        filters.className = "filters";
        const hideAbsentLabel = document.createElement("label");
        hideAbsentLabel.className = "filter-chip";
        const hideAbsentCb = document.createElement("input");
        hideAbsentCb.type = "checkbox";
        hideAbsentCb.checked = !!state.b524Filters.hideAbsent;
        hideAbsentCb.addEventListener("change", () => {
          state.b524Filters.hideAbsent = !!hideAbsentCb.checked;
          renderActiveGroup(groupKey, opKey, mountTarget);
        });
        hideAbsentLabel.appendChild(hideAbsentCb);
        hideAbsentLabel.appendChild(document.createTextNode("Hide absent"));
        filters.appendChild(hideAbsentLabel);

        const hideDormantLabel = document.createElement("label");
        hideDormantLabel.className = "filter-chip";
        const hideDormantCb = document.createElement("input");
        hideDormantCb.type = "checkbox";
        hideDormantCb.checked = !!state.b524Filters.hideDormant;
        hideDormantCb.addEventListener("change", () => {
          state.b524Filters.hideDormant = !!hideDormantCb.checked;
          renderActiveGroup(groupKey, opKey, mountTarget);
        });
        hideDormantLabel.appendChild(hideDormantCb);
        hideDormantLabel.appendChild(document.createTextNode("Hide dormant"));
        filters.appendChild(hideDormantLabel);

        const hideMissingLabel = document.createElement("label");
        hideMissingLabel.className = "filter-chip";
        const hideMissingCb = document.createElement("input");
        hideMissingCb.type = "checkbox";
        hideMissingCb.checked = !!state.b524Filters.hideMissingInstances;
        hideMissingCb.addEventListener("change", () => {
          state.b524Filters.hideMissingInstances = !!hideMissingCb.checked;
          renderActiveGroup(groupKey, opKey, mountTarget);
        });
        hideMissingLabel.appendChild(hideMissingCb);
        hideMissingLabel.appendChild(document.createTextNode("Hide missing instances"));
        filters.appendChild(hideMissingLabel);

        mountTarget.appendChild(filters);

        // Operations-first: instances come directly from the operation's group.
        // No merging or namespace splitting needed.
        const finalPlan = finalPlanForRoute(groupKey, opKey);
        const sourceInstances = groupObj.instances || {};
        const activeInstances = finalPlan && Array.isArray(finalPlan.instances)
          ? Object.fromEntries(finalPlan.instances.map((key) => [key, sourceInstances[key]]).filter(([, value]) => value && typeof value === "object"))
          : sourceInstances;
        mountTarget.appendChild(buildGroupTable(activeInstances, opKey));
      }

      function renderB524Tab() {
        const operations = artifact && typeof artifact === "object" ? artifact.b524_operations : null;
        const metaObj = artifact && typeof artifact === "object" ? artifact.meta : null;
        const host = document.createElement("div");
        const sectionTabs = document.createElement("div");
        sectionTabs.className = "subtabs";
        sectionTabs.id = "b524-section-tabs";

        const renderedSections = visibleB524Sections(operations, metaObj);
        const allowedSections = renderedSections.map((item) => item.key);
        if (!allowedSections.length) {
          host.innerHTML = "<div class='subtitle'>No B524 sections with scanned content in artifact.</div>";
          sheetArea.innerHTML = "";
          sheetArea.appendChild(host);
          return;
        }
        if (!allowedSections.includes(state.activeB524Section)) {
          state.activeB524Section = allowedSections[0];
        }

        for (const section of renderedSections) {
          const btn = document.createElement("div");
          btn.className = "tab";
          if (state.activeB524Section === section.key) btn.classList.add("active");
          btn.textContent = section.label;
          btn.addEventListener("click", () => {
            state.activeB524Section = section.key;
            renderB524Tab();
          });
          sectionTabs.appendChild(btn);
        }

        host.appendChild(sectionTabs);
        const sectionBody = document.createElement("div");
        host.appendChild(sectionBody);
        sheetArea.innerHTML = "";
        sheetArea.appendChild(host);

        const sectionKey = state.activeB524Section;
        const requiredOp = requiredNamespaceForSection(sectionKey);
        if (requiredOp) {
          const groupKeys = b524GroupKeysForSection(sectionKey);
          if (!groupKeys.length) {
            sectionBody.innerHTML = `<div class='subtitle'>No ${sectionLabel(sectionKey)} groups in artifact.</div>`;
            return;
          }

          let activeGroup = state.activeB524GroupBySection[sectionKey];
          if (!groupKeys.includes(activeGroup)) activeGroup = groupKeys[0];
          state.activeB524GroupBySection[sectionKey] = activeGroup;

          const groupTabs = document.createElement("div");
          groupTabs.className = "subtabs";
          groupTabs.id = "b524-group-tabs";
          for (const groupKey of groupKeys) {
            const btn = document.createElement("div");
            btn.className = "tab";
            if (groupKey === activeGroup) btn.classList.add("active");
            const rawGroup = getOperationGroup(requiredOp, groupKey);
            const groupObj = rawGroup ? getGroupObject(rawGroup) : { name: "Unknown", instances: {} };
            const groupName = typeof groupObj.name === "string" && groupObj.name ? groupObj.name : "Unknown";
            const friendlyName = groupLabelForSection(groupKey, sectionKey, groupName);
            const ggNum = parseInt(groupKey, 16);
            const ggHex = ggNum.toString(16).toUpperCase().padStart(2, "0") + "h";
            btn.textContent = friendlyName !== "Unknown" ? `${ggHex} ${friendlyName}` : ggHex;
            btn.addEventListener("click", () => {
              state.activeB524GroupBySection[sectionKey] = groupKey;
              renderB524Tab();
            });
            groupTabs.appendChild(btn);
          }
          sectionBody.appendChild(groupTabs);

          const groupMount = document.createElement("div");
          sectionBody.appendChild(groupMount);
          renderActiveGroup(activeGroup, requiredOp, groupMount);
          return;
        }

        renderB524OperationRows(sectionKey, sectionBody);
      }

      function renderActiveTab() {
        if (_isB524Tab(state.activeTab)) {
          renderB524Tab();
          return;
        }
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
        sheetArea.innerHTML = "<div class='subtitle'>No tab selected.</div>";
      }

      const hasB524 = !!(
        allGroupKeys().length > 0
        || (artifact && typeof artifact === "object" && artifact.b524_operations && typeof artifact.b524_operations === "object")
        || (artifact && typeof artifact === "object" && Array.isArray(artifact.b524_operation_reads) && artifact.b524_operation_reads.length)
        || (meta && typeof meta === "object" && meta.constraint_dictionary && typeof meta.constraint_dictionary === "object")
      );
      const hasB555 = !!(artifact && typeof artifact === "object" && artifact.b555_dump && typeof artifact.b555_dump === "object");
      const hasB516 = !!(artifact && typeof artifact === "object" && artifact.b516_dump && typeof artifact.b516_dump === "object");
      const hasB509 = !!(artifact && typeof artifact === "object" && artifact.b509_dump && typeof artifact.b509_dump === "object");
      buildTabs(hasB524, hasB555, hasB516, hasB509);
      renderActiveTab();
    </script>
  </body>
</html>
"""


def render_html_report(artifact: dict[str, Any], *, title: str | None = None) -> str:
    # Ensure operations-first structure for consistent JS traversal.
    artifact, _migration = migrate_artifact_schema(artifact)
    apply_b524_value_labels(artifact)
    operations = artifact.get("operations")
    if isinstance(operations, dict):
        apply_b524_canonical_register_names(operations)
    attach_bundled_descriptions(artifact)
    meta = artifact.get("meta")
    # Build group_name_map from operations-first structure
    group_name_map: dict[str, dict[str, dict[str, str]]] = {}
    operations = artifact.get("operations")
    if isinstance(operations, dict):
        seen_groups: set[str] = set()
        for op_obj in operations.values():
            if not isinstance(op_obj, dict):
                continue
            op_groups = op_obj.get("groups")
            if isinstance(op_groups, dict):
                seen_groups.update(k for k in op_groups if isinstance(k, str))
        for group_key in seen_groups:
            try:
                group = int(group_key, 0)
            except ValueError:
                continue
            local_name = group_name_for_opcode(group, 0x02)
            local_presentation: dict[str, str] = {"name": local_name}
            if group == 0x00:
                # Presentation-only correction: scanner policy keeps its own
                # declared profile bounds and is intentionally not changed here.
                local_presentation["rr_max"] = "0x00FF"
            group_name_map[group_key] = {
                "0x02": local_presentation,
                "0x06": {"name": group_name_for_opcode(group, 0x06)},
            }
    identity_html = ""
    if isinstance(meta, dict):
        identity_obj = meta.get("identity")
        if not isinstance(identity_obj, dict):
            identity_obj = meta.get("resolved_identity")
        if isinstance(identity_obj, dict):
            rows: list[tuple[str, str]] = []
            from .regulator_identity import regulator_profile_label

            profile = regulator_profile_label(identity_obj)
            if profile:
                rows.append(("Profile", profile))
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
    page_title = title or "Regulator Scan Browser"
    return (
        _substitute_template(
            _TEMPLATE,
            {
                "__TITLE__": _escape_html(page_title),
                "__IDENTITY_CARD__": identity_html,
                "__ARTIFACT_JSON__": _json_for_html(artifact),
                "__B524_GROUP_NAMES__": _json_for_html(group_name_map),
            },
        ).rstrip()
        + "\n"
    )
