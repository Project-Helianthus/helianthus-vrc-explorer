"""Compatible BrowseStore facade over private hydration, index, and query phases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .browse_hydration import hydrate_browse_store
from .browse_index import build_row_index
from .browse_models import BrowseTab, RegisterRow, TreeNodeRef
from .browse_query import rows_for_selection


@dataclass(slots=True)
class BrowseStore:
    """Browse artifact facade kept stable for CLI and Textual consumers."""

    device_label: str
    rows: list[RegisterRow]
    tree_nodes: list[TreeNodeRef]
    _row_by_id: dict[str, RegisterRow]

    @classmethod
    def from_artifact(cls, artifact: dict[str, Any]) -> BrowseStore:
        device_label, rows, tree_nodes = hydrate_browse_store(artifact)
        return cls(
            device_label=device_label,
            rows=rows,
            tree_nodes=tree_nodes,
            _row_by_id=build_row_index(rows),
        )

    def row_by_id(self, row_id: str) -> RegisterRow | None:
        return self._row_by_id.get(row_id)

    def rows_for_selection(self, node: TreeNodeRef | None, *, tab: BrowseTab) -> list[RegisterRow]:
        return rows_for_selection(self.rows, self.tree_nodes, node, tab=tab)
