# Data Directory

This directory is for non-code assets (JSON, CSV, fixtures, captured payloads, etc).

Guidelines:
- Do not embed large tables or mappings into Python source. Keep them here as data files.
- Prefer human-editable formats and clear filenames.
- Do not commit secrets (tokens, credentials, hostnames, private identifiers).

The runtime myVaillant register map is packaged at
`src/helianthus_vrc_explorer/data/myvaillant_register_map.csv`. It carries optional,
opcode-scoped leaf-name annotations only; it does not establish a value codec or a
wire-qualified semantic contract.
