"""Synthetic checks for static import boundaries and their exact-edge ratchet."""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "layer_gate", Path(__file__).resolve().parents[1] / "check_layer_imports.py"
)


class LayerGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.gate)

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name) / self.gate.PACKAGE
        self.root.mkdir()
        self.write("__init__", "")

    def write(self, module, source=""):
        path = self.root / (module.replace(".", "/") + ".py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)

    def collect(self):
        return self.gate.collect(self.root)

    def test_every_layer_direction(self):
        layers = ["protocol", "schema", "transport", "scanner", "ui", "commands"]
        allowed = {
            "protocol": {"protocol"},
            "schema": {"protocol", "schema"},
            "transport": {"protocol", "transport"},
            "scanner": {"protocol", "schema", "transport", "scanner"},
            "ui": {"protocol", "schema", "transport", "scanner", "ui"},
            "commands": set(layers),
        }
        for source in layers:
            for target in layers:
                with self.subTest(source=source, target=target):
                    self.write(f"{target}.target")
                    self.write(f"{source}.source", f"import {self.gate.PACKAGE}.{target}.target")
                    edges = self.collect()
                    edge = (
                        f"{self.gate.PACKAGE}.{source}.source",
                        f"{self.gate.PACKAGE}.{target}.target",
                    )
                    self.assertEqual(
                        edge not in self.gate.violations(edges), target in allowed[source]
                    )
                    (self.root / source / "source.py").unlink()

    def test_aliases_relative_package_submodules_and_type_checking(self):
        self.write("ui.__init__", "")
        self.write("ui.panel", "raise RuntimeError('must never execute')")
        self.write("transport.__init__", "")
        self.write(
            "transport.link",
            """from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..ui import panel as display
from .. import ui as screens
import helianthus_vrc_explorer.ui.panel as alias
from helianthus_vrc_explorer.ui.panel import missing
""",
        )
        with self.assertRaisesRegex(ValueError, "unresolved.*missing"):
            self.collect()
        self.write(
            "transport.link",
            """from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..ui import panel as display
import helianthus_vrc_explorer.ui.panel as alias
from ..ui.panel import value as renamed, other
from .. import ui as screens
""",
        )
        self.write("ui.panel", "value = 1\nother = 2\nraise RuntimeError('never execute')")
        edges = self.collect()
        edge = (f"{self.gate.PACKAGE}.transport.link", f"{self.gate.PACKAGE}.ui.panel")
        self.assertEqual(edges[edge], 3)
        self.assertIn(edge, self.gate.violations(edges))
        self.assertIn((f"{self.gate.PACKAGE}.transport.link", f"{self.gate.PACKAGE}.ui"), edges)

    def test_cli_roots_and_explicit_helpers(self):
        helpers = {
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
        self.assertEqual(self.gate.ROOT_MODULES, helpers)
        for name, layer in helpers.items():
            self.assertEqual(self.gate.layer(f"{self.gate.PACKAGE}.{name}"), layer)
        self.assertEqual(self.gate.layer(f"{self.gate.PACKAGE}.cli"), "cli")
        self.assertEqual(self.gate.layer(f"{self.gate.PACKAGE}.__main__"), "cli")
        self.write("new_helper")
        with self.assertRaisesRegex(ValueError, "unclassified"):
            self.collect()

    def test_unknown_directory_and_missing_module(self):
        self.write("unknown.module")
        with self.assertRaisesRegex(ValueError, "unclassified"):
            self.collect()
        (self.root / "unknown/module.py").unlink()
        self.write("protocol.item", "import helianthus_vrc_explorer.ui.absent")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.collect()

    def test_relative_escape_and_package_star_fail_closed(self):
        self.write("protocol.item", "from ...ui import panel")
        with self.assertRaisesRegex(ValueError, "relative"):
            self.collect()
        self.write("protocol.item", "from helianthus_vrc_explorer import *")
        with self.assertRaisesRegex(ValueError, "star"):
            self.collect()

    def test_exact_identity_counts_reductions_and_stale_entries(self):
        edge = ("pkg.transport.link", "pkg.ui.panel")
        baseline = {edge: 2}
        self.assertEqual(self.gate.compare({edge: 1}, baseline), [])
        self.assertTrue(self.gate.compare({}, baseline))
        for changed in [("pkg.transport.other", edge[1]), (edge[0], "pkg.ui.other")]:
            with self.subTest(identity=changed), self.assertRaisesRegex(ValueError, "new|grown"):
                self.gate.compare({changed: 1}, baseline)
        with self.assertRaisesRegex(ValueError, "grown"):
            self.gate.compare({edge: 3}, baseline)

    def test_cycles_in_same_layer_and_baseline_growth(self):
        self.write("ui.first", "from .second import value\nvalue = 1")
        self.write("ui.second", "from .first import value\nvalue = 2")
        cycles = self.gate.cycle_edges(self.collect())
        self.assertEqual(len(cycles), 2)
        with self.assertRaisesRegex(ValueError, "new|grown"):
            self.gate.compare(cycles, {})
        self.assertEqual(self.gate.compare(cycles, cycles), [])
        self.write("ui.third", "from .first import value")
        self.write("ui.second", "from .third import value\nvalue = 2")
        with self.assertRaisesRegex(ValueError, "new|grown"):
            self.gate.compare(self.gate.cycle_edges(self.collect()), cycles)

    def test_cycle_count_growth_and_self_cycle(self):
        self.write("ui.first", "from .second import value\nvalue = 1")
        self.write("ui.second", "from .first import value\nvalue = 2")
        baseline = self.gate.cycle_edges(self.collect())
        self.write("ui.second", "from .first import value\nfrom .first import value as alias")
        with self.assertRaisesRegex(ValueError, "grown"):
            self.gate.compare(self.gate.cycle_edges(self.collect()), baseline)
        self.write("ui.self_import", "value = 1\nfrom .self_import import value")
        cycle = (f"{self.gate.PACKAGE}.ui.self_import",) * 2
        self.assertIn(cycle, self.gate.cycle_edges(self.collect()))

    def test_missing_initializer_and_ambiguous_module_fail_closed(self):
        (self.root / "__init__.py").unlink()
        with self.assertRaisesRegex(ValueError, "missing package"):
            self.collect()
        self.write("__init__")
        self.write("ui")
        self.write("ui.__init__")
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.collect()

    def test_cli_fails_new_upward_edge_and_passes_reduction(self):
        repository = Path(self.scratch.name) / "repository"
        (repository / "src").mkdir(parents=True)
        self.root.rename(repository / "src" / self.gate.PACKAGE)
        self.root = repository / "src" / self.gate.PACKAGE
        (repository / "scripts").mkdir()
        baseline = repository / "scripts/layer-import-baseline.json"
        baseline.write_text(json.dumps({"version": 1, "violations": [], "cycle_edges": []}))
        self.write("ui.panel", "value = 1")
        self.write("transport.link", "from ..ui.panel import value")
        with patch.object(self.gate, "ROOT", repository), patch("sys.argv", ["gate", "--check"]):
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(self.gate.main(), 1)
            self.assertIn("new or grown", errors.getvalue())
            baseline.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "cycle_edges": [],
                        "violations": [
                            {
                                "importer": f"{self.gate.PACKAGE}.transport.link",
                                "imported": f"{self.gate.PACKAGE}.ui.panel",
                                "count": 1,
                            }
                        ],
                    }
                )
            )
            self.write("transport.link", "")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(self.gate.main(), 0)
            self.assertIn("stale baseline edge", output.getvalue())
            baseline.write_text('{"version": true, "violations": [], "cycle_edges": []}')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(self.gate.main(), 1)

    def test_aliases_type_aliases_and_conditional_exports(self):
        self.write(
            "schema.item",
            """type Choice = str
if True:
    value = 1
from typing import Any as Exported
""",
        )
        self.write("scanner.item", "from ..schema.item import Choice, value, Exported")
        edges = self.collect()
        self.assertEqual(
            edges[(f"{self.gate.PACKAGE}.scanner.item", f"{self.gate.PACKAGE}.schema.item")], 1
        )

    def test_baseline_validation(self):
        valid = {"importer": "pkg.a", "imported": "pkg.b", "count": 1}
        self.assertEqual(len(self.gate.index([valid])), 1)
        for records in [
            [valid, valid],
            [{**valid, "count": True}],
            [{**valid, "count": 0}],
            [{**valid, "extra": 1}],
        ]:
            with self.subTest(records=records), self.assertRaises(ValueError):
                self.gate.index(records)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.gate.read_json('{"version": 1, "version": 1}')


if __name__ == "__main__":
    unittest.main()
