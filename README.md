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
| `auth-core` | Shared authentication primitives |
| `tagdb-core` | Tag database access and migrations |
| `scan-core` | Filesystem scanning |
| `meta-extract` | Metadata extraction (A1111, NovelAI, ComfyUI) |
| `xmp-core` | XMP packet read/merge/write for JPEG, PNG and WebP |
| `yu-infer-shim` | Emits a `yu-infer` binary beside `yu-server`; the sidecar it stands in for lives in [yu-hailo-infer](https://github.com/eauesque/yu-hailo-infer) |

Two crates that used to live here are now their own repositories and are pinned
by git revision:

- [yu-lan-cowork](https://github.com/eauesque/yu-lan-cowork) — LAN peer
  discovery, pairing, transport, fleet operations
- [yu-hailo-infer](https://github.com/eauesque/yu-hailo-infer) — the Hailo
  inference sidecar

Both pins point at the **public** repositories on purpose, so a fresh clone or a
CI runner resolves them with no credentials and no registry setup.

## Self-contained

Nothing outside `crates/` is needed to build or test this workspace. That is
worth stating because it was not always true, and because the two ways of
breaking it fail differently:

- **At compile time.** `include_str!` used to reach up to `config/` and
  `extensions/` at the repository root. Cargo's dependency graph never sees
  `include_str!`, so a tree whose `cargo metadata` resolves cleanly could still
  fail to compile once those files were missing. Those reads are now done at
  runtime from the project root instead.
- **At test time.** `meta-extract`'s conformance test used to climb two
  directories up to read its goldens and image fixtures. Compiling and even
  `cargo check` succeeded; only `cargo test` in an extracted tree failed. The
  goldens and fixtures now live under `crates/meta-extract/tests/`.

The upstream repository gates the first with a check over `include_str!` /
`include_bytes!` paths. The second is not something a static check catches — the
only way to settle it is to build and test the tree somewhere else, which is
what the mirror sync does before publishing.

## Build

```sh
cd crates
cargo build --release -p yu-server
```

`crates/.cargo/config.toml` pins `jobs = 1`: this workspace is also built on a
Raspberry Pi 5, where parallel compilation crashes the machine. Remove it or
override `CARGO_BUILD_JOBS` on a larger host.

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

Measured on the extracted tree, not on the upstream checkout:

- `cargo clippy --workspace --all-targets -- -D warnings` passes with no
  warnings.
- `cargo test --workspace` runs 1361 passing tests and 5 failing ones. All five
  invoke the Python implementation to check cross-language agreement — the
  prompt-engine golden outputs, the encrypted-secret format, the YOLO stream
  config reader, and the ComfyUI model-registry guard. They shell out to files
  under `extensions/` in `yu_ai_manager`, which is not part of this repository.
  They are not failures of the Rust code; they are comparisons with no
  counterpart present. CI therefore runs `cargo check`, `cargo fmt --check` and
  clippy.

## License

MIT. See [LICENSE](LICENSE).
