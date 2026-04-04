from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ..scanner.director import GROUP_CONFIG
from .browse_models import BrowseTab, RegisterAddress, RegisterRow, TreeNodeRef
from .register_semantics import entry_display_value_text, visible_rr_keys


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _safe_int_hex(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        return 0


def _fmt_value(entry: dict[str, Any]) -> str:
    return entry_display_value_text(entry)


def _parse_timestamp(meta: dict[str, Any]) -> datetime | None:
    ts = meta.get("scan_timestamp")
    if not isinstance(ts, str):
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _tab_from_entry(entry: dict[str, Any]) -> BrowseTab:
    register_class = str(entry.get("register_class") or "").strip().lower()
    if register_class == "config":
        return "config"
    if register_class in {"config_limits", "limits"}:
        return "config_limits"
    if register_class == "state":
        return "state"

    flags_access = entry.get("flags_access")
    if flags_access == "user_rw":
        return "config"
    if flags_access == "technical_rw":
        return "config_limits"
    return "state"


def _fmt_group_label(group_key: str, group_name: str) -> str:
    return f"{group_name} ({group_key})"


def _instance_display_base(*, group_key: str, group_name: str) -> str:
    mapping: dict[int, str] = {
        0x02: "Heating Circuit",
        0x03: "Zone",
        0x05: "Cylinder",
    }
    gg = _safe_int_hex(group_key)
    if gg in mapping:
        return mapping[gg]
    # Best-effort singularization for unknown groups.
    text = group_name.strip()
    if text.endswith("s") and len(text) > 1:
        text = text[:-1]
    return text or "Instance"


def _instance_label(
    *,
    group_key: str,
    group_name: str,
    instance_key: str,
    instance_obj: dict[str, Any],
) -> str:
    # Prefer a user-visible name if present (e.g. Zones: RR=0x0016 name).
    registers = instance_obj.get("registers")
    if isinstance(registers, dict):
        for wanted in ("name", "name_prefix", "name_suffix"):
            for entry in registers.values():
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("myvaillant_name") or "").strip() != wanted:
                    continue
                value = entry.get("value")
                if isinstance(value, str) and value.strip():
                    return f"{value.strip()} ({instance_key})"

    base = _instance_display_base(group_key=group_key, group_name=group_name)
    # Human-friendly numbering: show 1-based index, but always keep the instance ID too.
    ii = _safe_int_hex(instance_key)
    return f"{base} {ii + 1} ({instance_key})"


def _row_sort_key(row: RegisterRow) -> tuple[int, int, int, int, int]:
    proto_weight_map = {"b524": 0, "b555": 1, "b516": 2, "b509": 3}
    proto_weight = proto_weight_map.get(row.protocol, 99)
    if row.protocol == "b524":
        return (
            proto_weight,
            _safe_int_hex(row.group_key or "0"),
            _safe_int_hex(row.namespace_key or "0"),
            _safe_int_hex(row.instance_key or "0"),
            _safe_int_hex(row.register_key),
        )
    if row.protocol == "b555":
        return (
            proto_weight,
            _safe_int_hex(row.group_key or "0"),
            0,
            0,
            _safe_int_hex(row.register_key.split(":", 1)[-1] if ":" in row.register_key else "0"),
        )
    if row.protocol == "b516":
        period_weight_map = {
            "system": 0,
            "year_current": 1,
            "year_previous": 2,
        }
        source_weight_map = {"gas": 0, "electricity": 1}
        usage_weight_map = {"heating": 0, "hot_water": 1}
        return (
            proto_weight,
            period_weight_map.get(row.group_key or "", 99),
            source_weight_map.get(row.namespace_key or "", 99),
            usage_weight_map.get(row.namespace_label or "", 99),
            0,
        )
    return (proto_weight, 0, 0, 0, _safe_int_hex(row.register_key))


def _namespace_display_label(namespace_key: str | None, namespace_label: str | None) -> str | None:
    if namespace_key is None:
        return None
    label = (namespace_label or namespace_key).strip()
    if not label:
        label = namespace_key
    if label.startswith("0x"):
        return label
    return f"{label[:1].upper()}{label[1:]} ({namespace_key})"


def _normalize_opcode_hex(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        opcode = int(raw, 0)
    except ValueError:
        return None
    if opcode < 0x00 or opcode > 0xFF:
        return None
    return _hex_u8(opcode)


def _namespace_label_for_key(namespace_key: str | None) -> str | None:
    if namespace_key is None:
        return None
    opcode = _safe_int_hex(namespace_key)
    if opcode == 0x02:
        return "local"
    if opcode == 0x06:
        return "remote"
    return namespace_key


def _single_namespace_key(group_key: str, group_obj: dict[str, Any]) -> str | None:
    discovery_advisory = group_obj.get("discovery_advisory")
    if isinstance(discovery_advisory, dict):
        proven = discovery_advisory.get("proven_register_opcodes")
        if isinstance(proven, list):
            for opcode in proven:
                normalized = _normalize_opcode_hex(opcode)
                if normalized is not None:
                    return normalized

    instances = group_obj.get("instances")
    if isinstance(instances, dict):
        for instance_key in sorted(
            (k for k in instances if isinstance(k, str)),
            key=_safe_int_hex,
        ):
            instance_obj = instances.get(instance_key)
            if not isinstance(instance_obj, dict):
                continue
            registers = instance_obj.get("registers")
            if not isinstance(registers, dict):
                continue
            for register_key in sorted(
                (k for k in registers if isinstance(k, str)),
                key=_safe_int_hex,
            ):
                entry = registers.get(register_key)
                if not isinstance(entry, dict):
                    continue
                normalized = _normalize_opcode_hex(entry.get("read_opcode"))
                if normalized is not None:
                    return normalized

    gg = _safe_int_hex(group_key)
    config = GROUP_CONFIG.get(gg)
    if config is not None:
        opcodes = config.get("opcodes")
        if isinstance(opcodes, list):
            for opcode in opcodes:
                if isinstance(opcode, int):
                    return _hex_u8(opcode)
    return None


def _build_b524_instance_node_id(
    *, group_key: str, namespace_key: str | None, instance_key: str
) -> str:
    parts = ["b524", "inst", group_key]
    if namespace_key is not None:
        parts.append(namespace_key)
    parts.append(instance_key)
    return ":".join(parts)


def _build_b524_row_id(
    *, group_key: str, namespace_key: str | None, instance_key: str, register_key: str
) -> str:
    parts = [group_key]
    if namespace_key is not None:
        parts.append(namespace_key)
    parts.extend([instance_key, register_key])
    return ":".join(parts)


def _group_namespace_views(
    group_obj: dict[str, Any],
) -> list[tuple[str | None, str | None, dict[str, Any]]]:
    if bool(group_obj.get("dual_namespace")):
        namespaces = group_obj.get("namespaces")
        if not isinstance(namespaces, dict):
            return []
        views: list[tuple[str | None, str | None, dict[str, Any]]] = []
        for namespace_key in sorted(
            (k for k in namespaces if isinstance(k, str)), key=_safe_int_hex
        ):
            namespace_obj = namespaces.get(namespace_key)
            if not isinstance(namespace_obj, dict):
                continue
            label_obj = namespace_obj.get("label")
            namespace_label = label_obj if isinstance(label_obj, str) else namespace_key
            instances = namespace_obj.get("instances")
            views.append(
                (
                    namespace_key,
                    namespace_label,
                    instances if isinstance(instances, dict) else {},
                )
            )
        return views

    instances = group_obj.get("instances")
    return [(None, None, instances if isinstance(instances, dict) else {})]


def _parse_range_key(range_key: str) -> tuple[int, int] | None:
    raw = range_key.strip()
    if ".." not in raw:
        return None
    start_s, end_s = raw.split("..", 1)
    try:
        start = int(start_s.strip(), 0)
        end = int(end_s.strip(), 0)
    except ValueError:
        return None
    if start > end:
        start, end = end, start
    return (start, end)


def _format_b555_value(entry: dict[str, Any]) -> str:
    error = entry.get("error")
    if isinstance(error, str) and error:
        return error
    status_label = str(entry.get("status_label") or "").strip()
    if status_label and status_label != "available":
        return status_label
    op = str(entry.get("op") or "").strip().lower()
    if op == "0xa3":
        parts: list[str] = []
        if isinstance(entry.get("max_slots"), int):
            parts.append(f"max_slots={entry['max_slots']}")
        if isinstance(entry.get("temp_slots"), int):
            parts.append(f"temp_slots={entry['temp_slots']}")
        if isinstance(entry.get("time_resolution_min"), int):
            parts.append(f"resolution={entry['time_resolution_min']}m")
        return ", ".join(parts) or "config"
    if op == "0xa4":
        days = entry.get("days")
        if isinstance(days, dict):
            return ", ".join(f"{day[:3]}={value}" for day, value in days.items())
        return "slots/weekday"
    start_text = entry.get("start_text")
    end_text = entry.get("end_text")
    temp = entry.get("temperature_c")
    if isinstance(start_text, str) and isinstance(end_text, str):
        if isinstance(temp, (int, float)) and not isinstance(temp, bool):
            return f"{start_text}-{end_text} @ {float(temp):g}C"
        return f"{start_text}-{end_text}"
    return "entry"


def _format_b516_value(entry: dict[str, Any]) -> str:
    error = entry.get("error")
    if isinstance(error, str) and error:
        return error
    value_kwh = entry.get("value_kwh")
    value_wh = entry.get("value_wh")
    if isinstance(value_kwh, (int, float)) and not isinstance(value_kwh, bool):
        value_txt = f"{float(value_kwh):g} kWh"
        if isinstance(value_wh, (int, float)) and not isinstance(value_wh, bool):
            value_txt += f" ({float(value_wh):g} Wh)"
        return value_txt
    if isinstance(value_wh, (int, float)) and not isinstance(value_wh, bool):
        return f"{float(value_wh):g} Wh"
    return "entry"


@dataclass(slots=True)
class BrowseStore:
    device_label: str
    rows: list[RegisterRow]
    tree_nodes: list[TreeNodeRef]
    _row_by_id: dict[str, RegisterRow]

    @classmethod
    def from_artifact(cls, artifact: dict[str, Any]) -> BrowseStore:
        meta = artifact.get("meta")
        if not isinstance(meta, dict):
            meta = {}
        dst = meta.get("destination_address")
        dst_txt = dst if isinstance(dst, str) else "0x??"
        device_label = f"Device {dst_txt}"

        last_update_dt = _parse_timestamp(meta)
        last_update_text = (
            last_update_dt.strftime("%Y-%m-%d %H:%M:%SZ") if last_update_dt else "n/a"
        )
        age_text = "n/a"
        if last_update_dt is not None:
            age_s = max(0.0, (datetime.now(UTC) - last_update_dt).total_seconds())
            age_text = f"{age_s:.1f}s"

        rows: list[RegisterRow] = []
        tree_nodes: list[TreeNodeRef] = [
            TreeNodeRef(node_id="root", label=device_label, level="root")
        ]
        row_by_id: dict[str, RegisterRow] = {}
        groups = artifact.get("groups")
        if not isinstance(groups, dict):
            groups = {}

        group_keys = sorted((k for k in groups if isinstance(k, str)), key=_safe_int_hex)
        if group_keys:
            tree_nodes.append(
                TreeNodeRef(
                    node_id="proto:b524",
                    label="B524",
                    level="protocol",
                    protocol="b524",
                )
            )

        for group_key in group_keys:
            group_obj = groups.get(group_key)
            if not isinstance(group_obj, dict):
                continue
            group_name = str(group_obj.get("name") or "Unknown")
            gg = _safe_int_hex(group_key)
            group_single_namespace_key = _single_namespace_key(group_key, group_obj)
            group_single_namespace_label = _namespace_label_for_key(group_single_namespace_key)
            namespace_views = _group_namespace_views(group_obj)
            if not namespace_views:
                continue
            all_instance_keys = sorted(
                {
                    instance_key
                    for (_namespace_key, _namespace_label, instances) in namespace_views
                    for instance_key in instances
                    if isinstance(instance_key, str)
                },
                key=_safe_int_hex,
            )
            config = GROUP_CONFIG.get(gg)
            is_instanced = (config is not None and int(config["ii_max"]) > 0) or any(
                instance_key != "0x00" for instance_key in all_instance_keys
            )

            tree_nodes.append(
                TreeNodeRef(
                    node_id=f"b524:group:{group_key}",
                    label=_fmt_group_label(group_key, group_name),
                    level="group",
                    protocol="b524",
                    group_key=group_key,
                )
            )

            for namespace_key, namespace_label, instances in namespace_views:
                effective_namespace_key = (
                    namespace_key if namespace_key is not None else group_single_namespace_key
                )
                effective_namespace_label = (
                    namespace_label if namespace_key is not None else group_single_namespace_label
                )
                namespace_display = _namespace_display_label(
                    effective_namespace_key, effective_namespace_label
                )
                if namespace_key is not None and namespace_display is not None:
                    tree_nodes.append(
                        TreeNodeRef(
                            node_id=f"b524:ns:{group_key}:{namespace_key}",
                            label=namespace_display,
                            level="namespace",
                            protocol="b524",
                            group_key=group_key,
                            namespace_key=namespace_key,
                            namespace_label=namespace_label,
                        )
                    )

                instance_keys = sorted(
                    (k for k in instances if isinstance(k, str)),
                    key=_safe_int_hex,
                )
                visible_registers = set(visible_rr_keys(instances))
                for instance_key in instance_keys:
                    instance_obj = instances.get(instance_key)
                    if not isinstance(instance_obj, dict):
                        continue
                    # For instanced groups, list instances as the leaf nodes (do not expand to RR).
                    if is_instanced:
                        node_id = _build_b524_instance_node_id(
                            group_key=group_key,
                            namespace_key=effective_namespace_key,
                            instance_key=instance_key,
                        )
                        tree_nodes.append(
                            TreeNodeRef(
                                node_id=node_id,
                                label=_instance_label(
                                    group_key=group_key,
                                    group_name=group_name,
                                    instance_key=instance_key,
                                    instance_obj=instance_obj,
                                ),
                                level="instance",
                                protocol="b524",
                                group_key=group_key,
                                namespace_key=effective_namespace_key,
                                namespace_label=effective_namespace_label,
                                instance_key=instance_key,
                            )
                        )

                    registers = instance_obj.get("registers")
                    if not isinstance(registers, dict):
                        continue
                    for register_key in sorted(
                        (k for k in registers if isinstance(k, str)),
                        key=_safe_int_hex,
                    ):
                        if register_key not in visible_registers:
                            continue
                        entry = registers.get(register_key)
                        if not isinstance(entry, dict):
                            continue

                        myvaillant_name = str(entry.get("myvaillant_name") or "").strip()
                        ebusd_name = str(entry.get("ebusd_name") or "").strip()
                        name = myvaillant_name or register_key
                        tab = _tab_from_entry(entry)
                        entry_namespace_key = effective_namespace_key
                        read_opcode = _normalize_opcode_hex(entry.get("read_opcode"))
                        if read_opcode is not None:
                            entry_namespace_key = read_opcode
                        read_opcode_label = (
                            entry.get("read_opcode_label")
                            if isinstance(entry.get("read_opcode_label"), str)
                            else None
                        )
                        if read_opcode_label:
                            entry_namespace_label = read_opcode_label
                        elif (
                            namespace_key is not None
                            and entry_namespace_key == effective_namespace_key
                        ):
                            entry_namespace_label = effective_namespace_label
                        else:
                            entry_namespace_label = _namespace_label_for_key(entry_namespace_key)
                        address = RegisterAddress(
                            protocol="b524",
                            group_key=group_key,
                            namespace_key=entry_namespace_key,
                            namespace_label=entry_namespace_label,
                            instance_key=instance_key,
                            register_key=register_key,
                            read_opcode=entry.get("read_opcode")
                            if isinstance(entry.get("read_opcode"), str)
                            else None,
                        )
                        value_text = _fmt_value(entry)
                        raw_hex = str(entry.get("raw_hex") or "")
                        entry_namespace_display = _namespace_display_label(
                            entry_namespace_key, entry_namespace_label
                        )
                        path_parts = ["B524", group_name]
                        if entry_namespace_display is not None:
                            path_parts.append(entry_namespace_display)
                        path_parts.extend([instance_key, name])
                        path = "/".join(path_parts)
                        row_id = _build_b524_row_id(
                            group_key=group_key,
                            namespace_key=entry_namespace_key,
                            instance_key=instance_key,
                            register_key=register_key,
                        )
                        access_flags = str(entry.get("flags_access") or "—")
                        row = RegisterRow(
                            row_id=row_id,
                            protocol="b524",
                            group_key=group_key,
                            namespace_key=entry_namespace_key,
                            namespace_label=entry_namespace_label,
                            group_name=group_name,
                            instance_key=instance_key,
                            register_key=register_key,
                            name=name,
                            myvaillant_name=myvaillant_name,
                            ebusd_name=ebusd_name,
                            path=path,
                            tab=tab,
                            address=address,
                            value_text=value_text,
                            raw_hex=raw_hex,
                            unit="n/a",
                            access_flags=access_flags,
                            last_update_text=last_update_text,
                            age_text=age_text,
                            change_indicator="-",
                            search_blob=" ".join(
                                [
                                    path.lower(),
                                    myvaillant_name.lower(),
                                    ebusd_name.lower(),
                                    address.label.lower(),
                                    (entry_namespace_label or "").lower(),
                                    value_text.lower(),
                                    raw_hex.lower(),
                                    access_flags.lower(),
                                    tab.lower(),
                                ]
                            ),
                        )
                        rows.append(row)
                        row_by_id[row_id] = row

        b509_dump = artifact.get("b509_dump")
        if isinstance(b509_dump, dict):
            proto_node = TreeNodeRef(
                node_id="proto:b509",
                label="B509",
                level="protocol",
                protocol="b509",
            )
            tree_nodes.append(proto_node)

            # Tree: B509 -> ranges (leaf nodes, no per-register expansion).
            meta_obj = b509_dump.get("meta")
            ranges = meta_obj.get("ranges") if isinstance(meta_obj, dict) else None
            if isinstance(ranges, list):
                for range_key in ranges:
                    if not isinstance(range_key, str) or not range_key.strip():
                        continue
                    tree_nodes.append(
                        TreeNodeRef(
                            node_id=f"b509:range:{range_key.strip()}",
                            label=range_key.strip(),
                            level="range",
                            protocol="b509",
                            range_key=range_key.strip(),
                        )
                    )

            # Rows: include all dumped B509 registers (default in State tab).
            devices = b509_dump.get("devices")
            dst_key = dst_txt.lower()
            if isinstance(devices, dict):
                device_obj = devices.get(dst_key) or devices.get(dst_txt)
                if isinstance(device_obj, dict):
                    registers_obj = device_obj.get("registers")
                    if isinstance(registers_obj, dict):
                        for addr_key in sorted(
                            (k for k in registers_obj if isinstance(k, str)),
                            key=_safe_int_hex,
                        ):
                            entry = registers_obj.get(addr_key)
                            if not isinstance(entry, dict):
                                continue
                            ebusd_name = str(entry.get("ebusd_name") or "").strip()
                            myvaillant_name = str(entry.get("myvaillant_name") or "").strip()
                            name = ebusd_name or addr_key
                            op = entry.get("op") if isinstance(entry.get("op"), str) else None
                            address = RegisterAddress(
                                protocol="b509",
                                group_key=None,
                                namespace_key=None,
                                namespace_label=None,
                                instance_key=None,
                                register_key=addr_key,
                                read_opcode=op,
                            )
                            value_text = _fmt_value(entry)
                            raw_hex = str(entry.get("raw_hex") or "")
                            path = f"B509/{addr_key}/{name}"
                            row_id = f"b509:{addr_key}"
                            row = RegisterRow(
                                row_id=row_id,
                                protocol="b509",
                                group_key=None,
                                namespace_key=None,
                                namespace_label=None,
                                group_name="B509",
                                instance_key=None,
                                register_key=addr_key,
                                name=name,
                                myvaillant_name=myvaillant_name,
                                ebusd_name=ebusd_name,
                                path=path,
                                tab="state",
                                address=address,
                                value_text=value_text,
                                raw_hex=raw_hex,
                                unit="n/a",
                                access_flags="—",
                                last_update_text=last_update_text,
                                age_text=age_text,
                                change_indicator="-",
                                search_blob=" ".join(
                                    [
                                        path.lower(),
                                        myvaillant_name.lower(),
                                        ebusd_name.lower(),
                                        address.label.lower(),
                                        value_text.lower(),
                                        raw_hex.lower(),
                                        "state",
                                    ]
                                ),
                            )
                            rows.append(row)
                            row_by_id[row_id] = row

        b555_dump = artifact.get("b555_dump")
        if isinstance(b555_dump, dict):
            tree_nodes.append(
                TreeNodeRef(
                    node_id="proto:b555",
                    label="B555",
                    level="protocol",
                    protocol="b555",
                )
            )
            programs = b555_dump.get("programs")
            if isinstance(programs, dict):
                for program_key in sorted(
                    (key for key in programs if isinstance(key, str)),
                    key=str,
                ):
                    program_obj = programs.get(program_key)
                    if not isinstance(program_obj, dict):
                        continue
                    label = str(program_obj.get("label") or program_key)
                    tree_nodes.append(
                        TreeNodeRef(
                            node_id=f"b555:program:{program_key}",
                            label=label,
                            level="group",
                            protocol="b555",
                            group_key=program_key,
                        )
                    )

                    selector_obj = program_obj.get("selector")
                    selector_text = ""
                    if isinstance(selector_obj, dict):
                        zone = selector_obj.get("zone")
                        hc = selector_obj.get("hc")
                        if isinstance(zone, str) and isinstance(hc, str):
                            selector_text = f"zone={zone} hc={hc}"

                    for entry_key, tab in (("config", "config"), ("slots_per_weekday", "config")):
                        entry = program_obj.get(entry_key)
                        if not isinstance(entry, dict):
                            continue
                        register_key = "0xa3" if entry_key == "config" else "0xa4"
                        name = f"{label} {entry_key.replace('_', ' ')}"
                        value_text = _format_b555_value(entry)
                        raw_hex = str(entry.get("reply_hex") or "")
                        access_flags = str(entry.get("status_label") or "—")
                        path = f"B555/{label}/{entry_key}"
                        row_id = f"b555:{program_key}:{entry_key}"
                        address = RegisterAddress(
                            protocol="b555",
                            group_key=program_key,
                            namespace_key=None,
                            namespace_label=None,
                            instance_key=None,
                            register_key=register_key,
                            read_opcode=register_key,
                        )
                        search_blob = " ".join(
                            [
                                path.lower(),
                                name.lower(),
                                selector_text.lower(),
                                value_text.lower(),
                                raw_hex.lower(),
                                access_flags.lower(),
                            ]
                        )
                        row = RegisterRow(
                            row_id=row_id,
                            protocol="b555",
                            group_key=program_key,
                            namespace_key=None,
                            namespace_label=None,
                            group_name=label,
                            instance_key=None,
                            register_key=register_key,
                            name=name,
                            myvaillant_name="",
                            ebusd_name="",
                            path=path,
                            tab=tab,
                            address=address,
                            value_text=value_text,
                            raw_hex=raw_hex,
                            unit="n/a",
                            access_flags=access_flags,
                            last_update_text=last_update_text,
                            age_text=age_text,
                            change_indicator="-",
                            search_blob=search_blob,
                        )
                        rows.append(row)
                        row_by_id[row_id] = row

                    weekdays = program_obj.get("weekdays")
                    if not isinstance(weekdays, dict):
                        continue
                    for day_name in sorted(
                        (key for key in weekdays if isinstance(key, str)),
                        key=str,
                    ):
                        day_obj = weekdays.get(day_name)
                        if not isinstance(day_obj, dict):
                            continue
                        slots = day_obj.get("slots")
                        if not isinstance(slots, dict):
                            continue
                        for slot_key in sorted(
                            (key for key in slots if isinstance(key, str)),
                            key=_safe_int_hex,
                        ):
                            entry = slots.get(slot_key)
                            if not isinstance(entry, dict):
                                continue
                            register_key = f"{day_name}:{slot_key}"
                            name = f"{label} {day_name} slot {slot_key}"
                            value_text = _format_b555_value(entry)
                            raw_hex = str(entry.get("reply_hex") or "")
                            access_flags = str(entry.get("status_label") or "—")
                            path = f"B555/{label}/{day_name}/{slot_key}"
                            row_id = f"b555:{program_key}:{day_name}:{slot_key}"
                            address = RegisterAddress(
                                protocol="b555",
                                group_key=program_key,
                                namespace_key=None,
                                namespace_label=None,
                                instance_key=None,
                                register_key=register_key,
                                read_opcode=str(entry.get("op") or "0xa5"),
                            )
                            search_blob = " ".join(
                                [
                                    path.lower(),
                                    name.lower(),
                                    selector_text.lower(),
                                    value_text.lower(),
                                    raw_hex.lower(),
                                    access_flags.lower(),
                                ]
                            )
                            row = RegisterRow(
                                row_id=row_id,
                                protocol="b555",
                                group_key=program_key,
                                namespace_key=None,
                                namespace_label=None,
                                group_name=label,
                                instance_key=None,
                                register_key=register_key,
                                name=name,
                                myvaillant_name="",
                                ebusd_name="",
                                path=path,
                                tab="state",
                                address=address,
                                value_text=value_text,
                                raw_hex=raw_hex,
                                unit="n/a",
                                access_flags=access_flags,
                                last_update_text=last_update_text,
                                age_text=age_text,
                                change_indicator="-",
                                search_blob=search_blob,
                            )
                            rows.append(row)
                            row_by_id[row_id] = row

        b516_dump = artifact.get("b516_dump")
        if isinstance(b516_dump, dict):
            tree_nodes.append(
                TreeNodeRef(
                    node_id="proto:b516",
                    label="B516",
                    level="protocol",
                    protocol="b516",
                )
            )
            entries = b516_dump.get("entries")
            if isinstance(entries, dict):
                period_labels = {
                    "system": "System",
                    "year_current": "Current Year",
                    "year_previous": "Previous Year",
                }
                seen_periods: set[str] = set()
                for entry_key in sorted(
                    (key for key in entries if isinstance(key, str)),
                    key=str,
                ):
                    entry = entries.get(entry_key)
                    if not isinstance(entry, dict):
                        continue
                    period = str(entry.get("period") or "").strip()
                    source = str(entry.get("source") or "").strip()
                    usage = str(entry.get("usage") or "").strip()
                    label = str(entry.get("label") or entry_key).strip() or entry_key
                    if period and period not in seen_periods:
                        tree_nodes.append(
                            TreeNodeRef(
                                node_id=f"b516:group:{period}",
                                label=period_labels.get(period, period),
                                level="group",
                                protocol="b516",
                                group_key=period,
                            )
                        )
                        seen_periods.add(period)
                    request_hex = str(entry.get("request_hex") or "")
                    reply_hex = str(entry.get("reply_hex") or "")
                    error = str(entry.get("error") or "")
                    value_text = _format_b516_value(entry)
                    path_parts = ["B516"]
                    if period:
                        path_parts.append(period_labels.get(period, period))
                    if source:
                        path_parts.append(source)
                    if usage:
                        path_parts.append(usage)
                    path = "/".join(path_parts + [label])
                    address = RegisterAddress(
                        protocol="b516",
                        group_key=period or None,
                        namespace_key=source or None,
                        namespace_label=usage or None,
                        instance_key=None,
                        register_key=entry_key,
                        read_opcode=None,
                    )
                    search_blob = " ".join(
                        [
                            path.lower(),
                            label.lower(),
                            entry_key.lower(),
                            period.lower(),
                            source.lower(),
                            usage.lower(),
                            value_text.lower(),
                            request_hex.lower(),
                            reply_hex.lower(),
                            error.lower(),
                            str(entry.get("echo_period") or "").lower(),
                            str(entry.get("echo_source") or "").lower(),
                            str(entry.get("echo_usage") or "").lower(),
                            str(entry.get("echo_window") or "").lower(),
                            str(entry.get("echo_qualifier") or "").lower(),
                            "state",
                        ]
                    )
                    row_id = f"b516:{entry_key}"
                    row = RegisterRow(
                        row_id=row_id,
                        protocol="b516",
                        group_key=period or None,
                        namespace_key=source or None,
                        namespace_label=usage or None,
                        group_name="B516",
                        instance_key=None,
                        register_key=entry_key,
                        name=label,
                        myvaillant_name="",
                        ebusd_name="",
                        path=path,
                        tab="state",
                        address=address,
                        value_text=value_text,
                        raw_hex=reply_hex,
                        unit="kWh",
                        access_flags="read-only",
                        last_update_text=last_update_text,
                        age_text=age_text,
                        change_indicator="-",
                        search_blob=search_blob,
                    )
                    rows.append(row)
                    row_by_id[row_id] = row

        rows.sort(key=_row_sort_key)
        return cls(
            device_label=device_label,
            rows=rows,
            tree_nodes=tree_nodes,
            _row_by_id=row_by_id,
        )

    def row_by_id(self, row_id: str) -> RegisterRow | None:
        return self._row_by_id.get(row_id)

    def rows_for_selection(self, node: TreeNodeRef | None, *, tab: BrowseTab) -> list[RegisterRow]:
        selected = [row for row in self.rows if row.tab == tab]
        if node is None or node.level == "root":
            return selected
        if node.level == "protocol" and node.protocol is not None:
            return [row for row in selected if row.protocol == node.protocol]
        if (
            node.level == "group"
            and node.protocol in {"b524", "b555", "b516"}
            and node.group_key is not None
        ):
            return [
                row
                for row in selected
                if row.protocol == node.protocol and row.group_key == node.group_key
            ]
        if (
            node.level == "namespace"
            and node.protocol == "b524"
            and node.group_key is not None
            and node.namespace_key is not None
        ):
            return [
                row
                for row in selected
                if row.protocol == "b524"
                and row.group_key == node.group_key
                and row.namespace_key == node.namespace_key
            ]
        if (
            node.level == "instance"
            and node.protocol == "b524"
            and node.group_key is not None
            and node.instance_key is not None
        ):
            by_group_instance = [
                row
                for row in selected
                if row.protocol == "b524"
                and row.group_key == node.group_key
                and row.instance_key == node.instance_key
            ]
            has_namespace_nodes = any(
                tree.level == "namespace"
                and tree.protocol == "b524"
                and tree.group_key == node.group_key
                for tree in self.tree_nodes
            )
            if node.namespace_key is None or not has_namespace_nodes:
                return by_group_instance
            return [row for row in by_group_instance if row.namespace_key == node.namespace_key]
        if node.level == "range" and node.protocol == "b509" and node.range_key is not None:
            parsed = _parse_range_key(node.range_key)
            if parsed is None:
                return [row for row in selected if row.protocol == "b509"]
            start, end = parsed
            return [
                row
                for row in selected
                if row.protocol == "b509" and start <= _safe_int_hex(row.register_key) <= end
            ]
        return selected
