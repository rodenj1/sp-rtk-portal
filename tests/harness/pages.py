"""Reading what a Portal page shows, by its ``data-field`` markers.

``base_card(html, base_id)`` -> ``{field: [text, ...]}`` for the base's
``<li data-base="<id>">`` in the list; ``fields(html)`` does the same for a
whole page. Attributes of the base's ``<li>`` come as ``@name``.
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
            if "datetime" in a:
                self.found.setdefault(field + "@datetime", []).append(
                    a["datetime"] or ""
                )

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
