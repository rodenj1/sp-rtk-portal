"""Reading what a Portal page shows, by its ``data-field`` markers.

``base_card(html, base_id)`` -> ``{field: [text, ...]}`` for the base's
``<li data-base="<id>">`` in the list; ``fields(html)`` does the same for a
whole page. Attributes of the base's ``<li>`` come as ``@name``; a field's
``datetime``, ``href`` and ``disabled`` as ``<field>@datetime`` /
``<field>@href`` / ``<field>@disabled``. Fields
come in the order the page first shows them.
"""

from __future__ import annotations

from html.parser import HTMLParser

VOID = ("input", "br", "img", "meta", "link", "hr")


class _Fields(HTMLParser):
    def __init__(self, base_id: str | None) -> None:
        super().__init__()
        self._base_id = base_id
        self._depth = 0 if base_id is not None else 1  # >0: inside the scope
        self._open: list[tuple[str, int]] = []  # (field, depth)
        self._level = 0
        self.found: dict[str, list[str]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag in VOID:  # never closed, holds no text
            return
        self._level += 1
        if (
            self._base_id is not None
            and tag == "li"
            and a.get("data-base") == self._base_id
        ):
            self._depth = self._level
            for name, value in attrs:
                self.found.setdefault("@" + name, []).append(value or "")
        if self._depth and "data-field" in a:
            field = a["data-field"] or ""
            self.found.setdefault(field, []).append("")
            self._open.append((field, self._level))
            for attr in ("datetime", "href", "disabled"):
                if attr in a:
                    self.found.setdefault(f"{field}@{attr}", []).append(a[attr] or "")

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID:
            return
        while self._open and self._open[-1][1] >= self._level:
            self._open.pop()
        if self._base_id is not None and self._depth == self._level:
            self._depth = 0
        self._level -= 1

    def handle_data(self, data: str) -> None:
        for field, _ in self._open:
            self.found[field][-1] += data

    def result(self) -> dict[str, list[str]]:
        return {k: [" ".join(v.split()) for v in vs] for k, vs in self.found.items()}


def _parse(html: str, base_id: str | None) -> dict[str, list[str]]:
    parser = _Fields(base_id)
    parser.feed(html)
    return parser.result()


def base_card(html: str, base_id: str) -> dict[str, list[str]]:
    return _parse(html, base_id)


def fields(html: str) -> dict[str, list[str]]:
    return _parse(html, None)


class _Rows(HTMLParser):
    """Each element carrying ``data-entry`` is one row of ``data-field``s."""

    def __init__(self) -> None:
        super().__init__()
        self._level = 0
        self._row_level = 0
        self._open: list[tuple[str, int]] = []
        self.rows: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in VOID:
            return
        a = dict(attrs)
        self._level += 1
        if "data-entry" in a:
            self._row_level = self._level
            self.rows.append({"@" + k: v or "" for k, v in attrs if k != "data-entry"})
        elif self._row_level and "data-field" in a:
            field = a["data-field"] or ""
            self.rows[-1][field] = ""
            self._open.append((field, self._level))
            if "datetime" in a:
                self.rows[-1][f"{field}@datetime"] = a["datetime"] or ""

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID:
            return
        while self._open and self._open[-1][1] >= self._level:
            self._open.pop()
        if self._row_level == self._level:
            self._row_level = 0
        self._level -= 1

    def handle_data(self, data: str) -> None:
        for field, _ in self._open:
            self.rows[-1][field] += data


def entries(html: str) -> list[dict[str, str]]:
    """The rows of a list page (the audit log): one dict per ``data-entry``
    element, ``{field: text}`` plus its other attributes as ``@name``."""
    parser = _Rows()
    parser.feed(html)
    return [{k: " ".join(v.split()) for k, v in row.items()} for row in parser.rows]
