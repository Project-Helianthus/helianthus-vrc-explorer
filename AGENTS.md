# Contributor and Agent Guide

## Project status

`helianthus-vrc-explorer` is an active, community-facing project. It is **not
deprecated**. It provides a safe, read-first CLI for exploring Vaillant VRC
regulators through eBUS and for producing reviewable scan artifacts.

This guide is self-contained. Use it together with the repository code, tests,
and public documentation linked below.

## Purpose and community commitment

- Keep raw protocol evidence and semantic annotations distinguishable.
- Make offline fixtures and deterministic replay useful to contributors without
  access to heating hardware.
- Prefer small, reviewable data and code changes over opaque generated payloads.
- Treat incomplete or uncertain observations as evidence, not as confirmed
  protocol facts.

## Safety and privacy

- `scan` is read-only. New device-affecting behavior needs an explicit opt-in,
  a clear confirmation path, focused tests, and reviewer attention.
- Preserve partial-scan data and last-known observations; do not replace useful
  evidence wholesale after a failed read.
- Keep fixtures sanitized. Never commit credentials, private network details,
  serial numbers, personal data, or unredacted captures.
- Do not contact live hardware for ordinary development or CI. Use fixtures,
  replay, dry-run behavior, and unit tests first.
- Changes to transport, framing, decoded semantics, or safety behavior require
  public documentation and proportionate regression coverage.

## Technical sources of truth

- Runtime behavior is defined by implementation and tests.
- `data/models.csv` is the canonical editable VRC model table.
- `src/helianthus_vrc_explorer/data/models.csv` is its packaged copy. Refresh
  it with `python3 scripts/generate_models_csv.py` after changing the canonical
  file.
- `docs/cli-reference.md` is the generated CLI help reference. Refresh it with
  `python3 scripts/docs_sync_help.py`; do not hand-edit command help blocks.
- `fixtures/` contains offline inputs. Keep replay compatibility when evolving
  artifact schemas.

## Public technical references

- [B524 protocol overview](https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-B524.md)
- [B524 register map](https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/vaillant/ebus-vaillant-B524-register-map.md)
- [B524 namespace invariants](https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/architecture/b524-namespace-invariants.md)

These references are evidence and design context. Do not claim an inferred
mapping is confirmed without reproducible support.

## Engineering expectations

- Support Python 3.12 as declared in `pyproject.toml`.
- Keep protocol parsing explicit about opcode, namespace, selectors, byte order,
  and response state.
- Maintain namespace-aware artifact identities and retain raw response details
  needed for reverse engineering.
- Keep CLI output scriptable in non-TTY mode and user-friendly in interactive
  mode.
- Prefer CSV or JSON data files for reviewable mappings rather than embedding
  mutable tables in Python.
- When command behavior changes, refresh the CLI reference in the same change.

## Change process

- Create one focused issue and branch for each repository change; use
  `issue/<number>-<slug>` branch names.
- Start behavioral or regression-prone work with a failing focused test, then
  implement the smallest change that makes it pass.
- Keep commits purposeful and describe validation in the pull request.
- Use the repository issue and pull-request templates. Do not include private
  infrastructure or secrets in their text.
- Do not merge unless the maintainer explicitly requests it.

## Validation

Run the applicable checks before opening a pull request:

```bash
ruff check .
python3 scripts/check_protocol_terminology.py
python3 scripts/check_b524_namespace_guardrails.py
python3 scripts/check_docs_sync.py
ruff format --check .
mypy src
pytest
```

For focused iterations, run the relevant test module first, then the full suite
before handoff. Record exact commands and results in the pull request.

## Documentation and review boundaries

- Keep README content user-facing; place detailed protocol rationale in the
  public documentation above.
- Update public documentation alongside a protocol or semantic change, not as a
  substitute for tests.
- Flag any proposed write path, destructive operation, credential handling, or
  live-device action for explicit maintainer confirmation before it runs.
- Keep the final handoff concrete: issue, branch, commit, pull request, changed
  files, and validation results.
