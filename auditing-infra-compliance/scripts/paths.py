"""Mini path language used by inventory.json and for_each: extract(data, path) -> list.

Segments are separated by '.'. 'key' reads a key of every dict node; '[]' (or '[*]') flattens
every list node one level. A missing key, or a null value, drops the node, so a path that does
not exist returns []. '.' alone is the node itself; '' matches nothing (an unused optional path).
"""

import re

_SEGMENT = re.compile(r"^([^\[\]]*)((?:\[\*?\])*)$")


def _parse(path: str) -> list[tuple[str, int]]:
    segments = []
    for raw in path.split("."):
        if not raw:
            continue
        match = _SEGMENT.match(raw)
        if not match:
            raise ValueError(f"ruta inválida: {path!r} (segmento {raw!r})")
        key, brackets = match.groups()
        segments.append((key, brackets.count("[")))
    return segments


def _flatten(nodes: list) -> list:
    return [item for node in nodes if isinstance(node, list) for item in node if item is not None]


def extract(data: object, path: str) -> list:
    if not path:
        return []
    nodes = [data]
    for key, flattens in _parse(path):
        if key:
            nodes = [n[key] for n in nodes if isinstance(n, dict) and n.get(key) is not None]
        for _ in range(flattens):
            nodes = _flatten(nodes)
    return nodes
