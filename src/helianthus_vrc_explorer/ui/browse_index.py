"""Private BrowseStore row-index construction."""

from __future__ import annotations

from .browse_models import RegisterRow


def build_row_index(rows: list[RegisterRow]) -> dict[str, RegisterRow]:
    """Build the compatible row-id lookup without exposing mutable aliases."""

    return {row.row_id: row for row in rows}
