"""Tests for VE17-R2, VE18-R3, VE26-R3 -- protocol and UI fixes."""

from __future__ import annotations

import pytest

from helianthus_vrc_explorer.protocol.b555 import parse_b555_timer_read_response
from helianthus_vrc_explorer.ui.html_report import (
    _json_for_html,
    _substitute_template,
)

# ---------------------------------------------------------------------------
# VE17-R2: B555 timer must reject impossible time values
# ---------------------------------------------------------------------------


def _timer_payload(status: int, sh: int, sm: int, eh: int, em: int, temp: int = 0xFFFF) -> bytes:
    """Build a 7-byte B555 A5 response payload."""
    return bytes((status, sh, sm, eh, em)) + temp.to_bytes(2, "little")


class TestVE17R2TimerValidation:
    """VE17-R2: B555 timer must reject impossible time values."""

    def test_hour_25_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid start hour"):
            parse_b555_timer_read_response(_timer_payload(0x00, 25, 0, 22, 0))

    def test_end_hour_25_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid end hour"):
            parse_b555_timer_read_response(_timer_payload(0x00, 6, 0, 25, 0))

    def test_minute_60_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid start minute"):
            parse_b555_timer_read_response(_timer_payload(0x00, 6, 60, 22, 0))

    def test_end_minute_60_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid end minute"):
            parse_b555_timer_read_response(_timer_payload(0x00, 6, 0, 22, 60))

    def test_hour_0xff_sentinel_accepted(self) -> None:
        result = parse_b555_timer_read_response(_timer_payload(0x00, 0xFF, 0xFF, 0xFF, 0xFF))
        assert result.start_hour == 0xFF
        assert result.end_hour == 0xFF

    def test_valid_time_accepted(self) -> None:
        result = parse_b555_timer_read_response(_timer_payload(0x00, 6, 30, 22, 45))
        assert result.start_hour == 6
        assert result.start_minute == 30
        assert result.end_hour == 22
        assert result.end_minute == 45

    def test_boundary_23_59_accepted(self) -> None:
        result = parse_b555_timer_read_response(_timer_payload(0x00, 23, 59, 0, 0))
        assert result.start_hour == 23
        assert result.start_minute == 59

    def test_hour_24_minute_0_accepted(self) -> None:
        """24:00 is a valid eBUS encoding for end-of-day."""
        result = parse_b555_timer_read_response(_timer_payload(0x00, 0, 0, 24, 0))
        assert result.end_hour == 24
        assert result.end_minute == 0

    def test_hour_24_minute_30_rejected(self) -> None:
        """24:30 is not valid -- only 24:00 is allowed."""
        with pytest.raises(ValueError, match="24:30"):
            parse_b555_timer_read_response(_timer_payload(0x00, 0, 0, 24, 30))

    def test_half_sentinel_hour_0xff_minute_normal_rejected(self) -> None:
        """R6-Codex-Cross-03: hour=0xFF + minute=30 is an invalid half-sentinel."""
        with pytest.raises(ValueError, match="half-sentinel"):
            parse_b555_timer_read_response(_timer_payload(0x00, 0xFF, 30, 0, 0))

    def test_half_sentinel_hour_normal_minute_0xff_rejected(self) -> None:
        """R6-Codex-Cross-03: hour=12 + minute=0xFF is an invalid half-sentinel."""
        with pytest.raises(ValueError, match="half-sentinel"):
            parse_b555_timer_read_response(_timer_payload(0x00, 12, 0xFF, 0, 0))

    def test_half_sentinel_end_time_rejected(self) -> None:
        """R6-Codex-Cross-03: end time with half-sentinel rejected too."""
        with pytest.raises(ValueError, match="half-sentinel"):
            parse_b555_timer_read_response(_timer_payload(0x00, 6, 0, 0xFF, 15))


# ---------------------------------------------------------------------------
# VE18-R3: _json_for_html must escape single quotes
# ---------------------------------------------------------------------------


class TestVE18R3SingleQuoteEscape:
    """VE18-R3: _json_for_html must escape single quotes."""

    def test_single_quote_escaped(self) -> None:
        result = _json_for_html({"key": "it's a test"})
        assert "'" not in result
        assert "\\u0027" in result

    def test_angle_brackets_still_escaped(self) -> None:
        result = _json_for_html({"x": "</script>"})
        assert "<" not in result
        assert ">" not in result

    def test_ampersand_still_escaped(self) -> None:
        result = _json_for_html({"x": "a&b"})
        assert "&" not in result


# ---------------------------------------------------------------------------
# VE26-R3: Template substitution must not allow placeholder collision
# ---------------------------------------------------------------------------


class TestVE26R3PlaceholderCollision:
    """VE26-R3: Template substitution must not allow placeholder collision."""

    def test_title_containing_placeholder_is_safe(self) -> None:
        template = "<title>__TITLE__</title><data>__ARTIFACT_JSON__</data>"
        result = _substitute_template(
            template,
            {
                "__TITLE__": "__ARTIFACT_JSON__",
                "__ARTIFACT_JSON__": "real-json-data",
            },
        )
        # Title should contain the literal string "__ARTIFACT_JSON__",
        # NOT "real-json-data".
        assert "<title>__ARTIFACT_JSON__</title>" in result
        assert "<data>real-json-data</data>" in result

    def test_unknown_placeholder_preserved(self) -> None:
        result = _substitute_template("Hello __UNKNOWN__", {"__TITLE__": "x"})
        assert result == "Hello __UNKNOWN__"

    def test_all_placeholders_substituted(self) -> None:
        result = _substitute_template("__A__ and __B__", {"__A__": "1", "__B__": "2"})
        assert result == "1 and 2"


# ---------------------------------------------------------------------------
# Adversarial tests added by angry-tester audit
# ---------------------------------------------------------------------------


class TestAdvXssInTitle:
    """ADV: HTML title containing XSS payload and placeholder collision."""

    def test_script_tag_in_title_escaped(self) -> None:
        """Title with <script>alert(1)</script> must be HTML-escaped."""
        xss_title = "<script>alert(1)</script>"
        result = _json_for_html({"title": xss_title})
        # _json_for_html escapes angle brackets
        assert "<script>" not in result
        assert "<" not in result
        assert ">" not in result

    def test_artifact_json_placeholder_in_title_no_collision(self) -> None:
        """Title containing __ARTIFACT_JSON__ must not collide with real data."""
        template = "<title>__TITLE__</title><data>__ARTIFACT_JSON__</data>"
        result = _substitute_template(
            template,
            {
                "__TITLE__": "__ARTIFACT_JSON__",
                "__ARTIFACT_JSON__": '{"real":"data"}',
            },
        )
        assert "<title>__ARTIFACT_JSON__</title>" in result
        assert '<data>{"real":"data"}</data>' in result
        # The title must NOT get replaced in a second pass
        assert "__ARTIFACT_JSON__" in result.split("</title>")[0]

    def test_script_in_artifact_json_escaped(self) -> None:
        """Artifact data containing script tag must be escaped by _json_for_html."""
        result = _json_for_html({"payload": "<script>alert(1)</script>"})
        assert "<script>" not in result

    def test_title_with_nested_placeholders(self) -> None:
        """Title value itself contains __TITLE__ -- must not recurse."""
        template = "<h1>__TITLE__</h1>"
        result = _substitute_template(
            template,
            {"__TITLE__": "Hello __TITLE__ World"},
        )
        # Single-pass substitution: the inner __TITLE__ is literal, not expanded again
        assert result == "<h1>Hello __TITLE__ World</h1>"
