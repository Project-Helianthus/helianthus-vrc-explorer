"""Statically enforce package layers, exact import debt and cycle-edge counts.

Only parse source: never import the scanned package. Baseline reductions pass;
stale records are reported so reviewers can remove them. Baseline additions
require review, and there is deliberately no baseline regeneration command.
"""

import argparse
import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

PACKAGE = "helianthus_vrc_explorer"
ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = {
    "protocol": "protocol",
    "schema": "schema",
    "transport": "transport",
    "scanner": "scanner",
    "ui": "ui",
    "commands": "cli",
    "data": "protocol",
    "fixtures": "protocol",
}
# Shared parsing/limits are foundational; artifact and evidence helpers are schema.
# Replay orchestrates scanner decoding. New root modules require an explicit choice.
ROOT_MODULES = {
    "__init__": "protocol",
    "__main__": "cli",
    "cli": "cli",
    "artifact_schema": "schema",
    "evidence_compat": "schema",
    "evidence_export": "schema",
    "ebusd": "protocol",
    "input_limits": "protocol",
    "replay_trace": "scanner",
}
RANK = {"protocol": 0, "schema": 1, "transport": 1, "scanner": 2, "ui": 3, "cli": 4}


def layer(module):
    parts = module.split(".")[1:]
    if not parts:
        return ROOT_MODULES["__init__"]
    if len(parts) == 1 and parts[0] in ROOT_MODULES:
        return ROOT_MODULES[parts[0]]
    if parts[0] in DIRECTORIES:
        return DIRECTORIES[parts[0]]
    raise ValueError(f"unclassified in-repository module: {module}")


def declared_names(tree):
    """Collect possible module bindings without evaluating control flow."""
    names = set()
    pending = list(tree.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.TypeAlias):
            names.add(node.name.id)
        elif isinstance(node, ast.AnnAssign) and node.value is None:
            continue  # a bare annotation binds nothing at runtime
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar, ast.MatchMapping)):
            capture = node.rest if isinstance(node, ast.MatchMapping) else node.name
            if capture is not None:
                names.add(capture)
            pending.extend(ast.iter_child_nodes(node))
        elif isinstance(node, ast.Lambda):
            continue
        elif isinstance(node, ast.comprehension):
            # Iteration targets belong to the comprehension's scope. Assignment
            # expressions in its iterable/filters can still bind module names.
            pending.extend([node.iter, *node.ifs])
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(a.asname or a.name.split(".")[0] for a in node.names)
        else:
            pending.extend(ast.iter_child_nodes(node))
    return names


def inventory(package_root):
    modules, packages = {}, set()
    for path in sorted(package_root.rglob("*.py")):
        relative = path.relative_to(package_root).with_suffix("")
        parts = list(relative.parts)
        initializer = parts[-1] == "__init__"
        if initializer:
            parts.pop()
        module = ".".join([PACKAGE, *parts])
        if module in modules:
            raise ValueError(f"ambiguous module/package: {module}")
        layer(module)
        modules[module] = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative))
        if initializer:
            packages.add(module)
        for length in range(len(parts)):
            packages.add(".".join([PACKAGE, *parts[:length]]))
    if PACKAGE not in modules:
        raise ValueError("missing package initializer")
    return modules, packages


def import_base(node, parent):
    if not node.level:
        return node.module or ""
    parts = parent.split(".")
    if node.level > len(parts):
        raise ValueError(f"relative import escapes repository package: {parent}")
    base = ".".join(parts[: len(parts) - node.level + 1])
    return base + "." + node.module if node.module else base


def internal(module):
    return module == PACKAGE or module.startswith(PACKAGE + ".")


def from_targets(node, parent, known, symbols):
    base = import_base(node, parent)
    if not internal(base):
        return set()
    if base not in known:
        raise ValueError(f"unresolved in-repository import: {parent} -> {base}")
    targets = set()
    for alias in node.names:
        candidate = base + "." + alias.name
        if alias.name == "*":
            raise ValueError(f"unresolved star import: {parent} -> {base}")
        if candidate in known:
            targets.add(candidate)
        elif alias.name in symbols.get(base, set()):
            targets.add(base)
        else:
            raise ValueError(f"unresolved in-repository import: {parent} -> {candidate}")
    return targets


def module_edges(module, tree, modules, packages, symbols):
    edges = Counter()
    known = modules.keys() | packages
    parent = module if module in packages else module.rpartition(".")[0]
    for node in ast.walk(tree):
        targets = set()
        if isinstance(node, ast.Import):
            targets = {alias.name for alias in node.names if internal(alias.name)}
        elif isinstance(node, ast.ImportFrom):
            targets = from_targets(node, parent, known, symbols)
        for target in targets:
            if target not in known:
                raise ValueError(f"unresolved in-repository import: {module} -> {target}")
            layer(target)
            edges[module, target] += 1
    return edges


def collect(package_root):
    modules, packages = inventory(package_root)
    symbols = {module: declared_names(tree) for module, tree in modules.items()}
    edges = Counter()
    for module, tree in modules.items():
        edges.update(module_edges(module, tree, modules, packages, symbols))
    return edges


def violations(edges):
    return {
        edge: count
        for edge, count in edges.items()
        if layer(edge[0]) != layer(edge[1]) and RANK[layer(edge[0])] <= RANK[layer(edge[1])]
    }


def cycle_edges(edges):
    adjacency = {}
    for source, target in edges:
        adjacency.setdefault(source, set()).add(target)
    result = {}
    for edge, count in edges.items():
        source, target = edge
        pending, seen = [target], set()
        while pending:
            current = pending.pop()
            if current == source:
                result[edge] = count
                break
            if current not in seen:
                seen.add(current)
                pending.extend(adjacency.get(current, ()))
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(source):
    return json.loads(source, object_pairs_hook=unique_object)


def index(records):
    if not isinstance(records, list):
        raise ValueError("baseline records must be an array")
    result = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"importer", "imported", "count"}:
            raise ValueError("malformed baseline record")
        edge = (record["importer"], record["imported"])
        if (
            any(
                not isinstance(v, str) or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", v)
                for v in edge
            )
            or type(record["count"]) is not int
            or record["count"] < 1
        ):
            raise ValueError("invalid baseline edge/count")
        if edge in result:
            raise ValueError("duplicate baseline edge")
        result[edge] = record["count"]
    return result


def compare(observed, baseline):
    errors = [
        f"new or grown edge: {a} -> {b} ({count})"
        for (a, b), count in observed.items()
        if count > baseline.get((a, b), 0)
    ]
    if errors:
        raise ValueError("\n".join(sorted(errors)))
    return [
        f"stale baseline edge: {a} -> {b}" for a, b in sorted(baseline.keys() - observed.keys())
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", required=True, action="store_true")
    parser.parse_args()
    try:
        payload = read_json((ROOT / "scripts/layer-import-baseline.json").read_text())
        if (
            not isinstance(payload, dict)
            or set(payload) != {"version", "violations", "cycle_edges"}
            or type(payload["version"]) is not int
            or payload["version"] != 1
        ):
            raise ValueError("unsupported baseline schema")
        edges = collect(ROOT / "src" / PACKAGE)
        for category, current in (
            ("violations", violations(edges)),
            ("cycle_edges", cycle_edges(edges)),
        ):
            stale = compare(current, index(payload[category]))
            for message in stale:
                print(f"{category}: {message}")
        print(
            f"Import layers passed: {len(edges)} edges; "
            f"{sum(violations(edges).values())} baselined import occurrences; "
            f"{len(cycle_edges(edges))} existing cycle edges"
        )
    except (OSError, ValueError, SyntaxError) as exc:
        print(f"Import layers failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
