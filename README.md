# yu-server

The Rust backend of [YU AI Manager](https://github.com/eauesque/yu_ai_manager) —
an on-device WebUI for managing AI-generated image metadata.

This repository exists so the server can be read and reviewed on its own,
separately from the application it serves. Nothing here is new: every file is
already published inside `eauesque/yu_ai_manager`. Development happens in a
private repository and is mirrored here.

## What is in here

A single Cargo workspace under `crates/`:

| Crate | What it does |
|---|---|
| `yu-server` | The HTTP server binary: routes, auth, MCP, analysis engines |
| `lan-cowork` | LAN peer discovery, pairing, transport, fleet operations |
| `auth-core` | Shared authentication primitives |
| `tagdb-core` | Tag database access and migrations |
| `scan-core` | Filesystem scanning |
| `meta-extract` | Metadata extraction (A1111, NovelAI, ComfyUI) |
| `xmp-core` | XMP packet read/merge/write for JPEG, PNG and WebP |
| `yu-infer-shim` | Emits a `yu-infer` binary beside `yu-server`; the sidecar it stands in for lives in [yu-hailo-infer](https://github.com/eauesque/yu-hailo-infer) |

Two files sit outside `crates/`:

```
config/settings_schema.json
extensions/builtin_wd_tagger/extension.json
```

They are here because `crates/yu-server/src/routes/misc_admin.rs` pulls them in
with `include_str!` at their original relative depth. Keeping the paths intact
means the mirror needs no source changes. It is worth stating why they are easy
to forget: Cargo's dependency graph never sees `include_str!`, so a tree whose
`cargo metadata` resolves cleanly can still fail to compile once those two files
are missing. The only way to settle it is to build the tree somewhere else.

## Build

```sh
cd crates
cargo build --release -p yu-server
```

`crates/.cargo/config.toml` pins `jobs = 1`: this workspace is also built on a
Raspberry Pi 5, where parallel compilation crashes the machine. Remove it or
override `CARGO_BUILD_JOBS` on a larger host.

The Hailo inference sidecar is pulled from the public
[yu-hailo-infer](https://github.com/eauesque/yu-hailo-infer) repository by git
revision, so a fresh clone needs no credentials or registry setup.

## Running

`yu-server` is a backend, not a self-contained application. At startup it
resolves a **project root** and reads the UI, templates and extensions from it:

```
<project root>/ui/default/templates
<project root>/ui/default/static
<project root>/extensions
```

Point it at a YU AI Manager checkout. Without one the server starts but has
nothing to serve.

## Known state

- `cargo clippy --workspace --all-targets -- -D warnings` reports 4 lints in
  `meta-extract` (`type_complexity`, `manual_strip`, and two map-values
  iterations). CI therefore gates on `cargo check` and `cargo fmt`, not on
  clippy — a gate that is red on arrival tells you nothing.
- The test suite is not run in CI: it carries pre-existing failures inherited
  from the upstream repository.

## License

MIT. See [LICENSE](LICENSE).
