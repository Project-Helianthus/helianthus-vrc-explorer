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

`src/helianthus_vrc_explorer/data/b524_parameter_descriptions.json` is the
profile-qualified, read-only description baseline. Each entry is keyed by native
read opcode, group, instance and register, so same-numbered OP02 and OP06 groups
remain distinct. It stores only decoded type, width and limits plus the identity
needed to qualify that prior observation; it never stores endpoints, serials or
raw request/reply captures. Remote entries require their observed device class
and firmware identity before they can be reused.

`src/helianthus_vrc_explorer/data/b524_register_name_correspondence.csv` is a
purely presentational cross-reference, keyed by `(opcode, group, register)`,
between the canonical Explorer name (`name`, matching
`b524_register_names.csv`) and the observed Vaillant and eBUSd names for the
same register: `vaillant_friendly_name`, `vaillant_name_vrc720`,
`vaillant_name_vrc700`, `myvaillant_name_vrc720`, `myvaillant_name_vrc700` and
`ebusd_name`. A cell may hold several values separated by ` | `; `ebusd_name`
may contain `{hc}`/`{zone}` placeholders. It carries no codec, class or write
authority, never changes the canonical Explorer name, and is resolved by the
Browser and HTML report at render time -- it is never written into scan
artifacts. There is no separate canonical/packaged split for catalog CSVs in
this project: they are packaged directly under
`src/helianthus_vrc_explorer/data/`, and this file follows that same
convention.
