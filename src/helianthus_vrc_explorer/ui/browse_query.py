"""Private BrowseStore selection queries."""

from __future__ import annotations

from .browse_models import BrowseTab, RegisterRow, TreeNodeRef


def _safe_int_hex(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        return 0


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
    return start, end


def rows_for_selection(
    rows: list[RegisterRow],
    tree_nodes: list[TreeNodeRef],
    node: TreeNodeRef | None,
    *,
    tab: BrowseTab,
) -> list[RegisterRow]:
    """Return the same ordered rows selected by the compatible tree node."""

    selected = [row for row in rows if row.tab == tab]
    if node is None or node.level == "root":
        return selected
    if node.level == "protocol" and node.protocol is not None:
        return [row for row in selected if row.protocol == node.protocol]
    if node.level == "section" and node.protocol == "b524" and isinstance(node.section_key, str):
        return [
            row
            for row in selected
            if row.protocol == "b524" and row.section_key == node.section_key
        ]
    if (
        node.level == "group"
        and node.protocol in {"b524", "b555", "b516"}
        and node.group_key is not None
    ):
        filtered = [
            row
            for row in selected
            if row.protocol == node.protocol and row.group_key == node.group_key
        ]
        if node.protocol == "b524" and isinstance(node.section_key, str):
            return [row for row in filtered if row.section_key == node.section_key]
        return filtered
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
            and (node.section_key is None or row.section_key == node.section_key)
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
            and (node.section_key is None or row.section_key == node.section_key)
        ]
        has_namespace_nodes = any(
            tree.level == "namespace"
            and tree.protocol == "b524"
            and tree.group_key == node.group_key
            and (node.section_key is None or tree.section_key == node.section_key)
            for tree in tree_nodes
        )
        if node.namespace_key is None or not has_namespace_nodes:
            return by_group_instance
        return [row for row in by_group_instance if row.namespace_key == node.namespace_key]
    if (
        node.level == "register"
        and node.protocol == "b524"
        and node.group_key is not None
        and node.instance_key is not None
        and node.register_key is not None
    ):
        return [
            row
            for row in selected
            if row.protocol == "b524"
            and row.group_key == node.group_key
            and row.instance_key == node.instance_key
            and row.register_key == node.register_key
            and (node.namespace_key is None or row.namespace_key == node.namespace_key)
            and (node.section_key is None or row.section_key == node.section_key)
        ]
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
