from __future__ import annotations

from helianthus_vrc_explorer.ui.emphasis import (
    html_star_bold,
    rich_star_bold_text,
    strip_star_bold_markers,
)


def test_strip_star_bold_markers_removes_balanced_markers() -> None:
    assert (
        strip_star_bold_markers(
            "Wireless 720-series Regulator *BA*se *S*tation *V*aillant-branded Revision *2*"
        )
        == "Wireless 720-series Regulator BAse Station Vaillant-branded Revision 2"
    )


def test_rich_star_bold_text_strips_markers_and_marks_bold_spans() -> None:
    text = rich_star_bold_text("Device *BA*SV*2*")

    assert text.plain == "Device BASV2"
    assert len(text.spans) == 2
    assert all(span.style == "bold" for span in text.spans)


def test_html_star_bold_wraps_balanced_markers_in_strong_tags() -> None:
    html = html_star_bold("Device *BA*SV*2*")

    assert html == "Device <strong>BA</strong>SV<strong>2</strong>"
