# Flybrain node

Authority and service APIs for [Flybrain](https://flybrain.work/).

## Scope

Durable goal competition, commit/reveal processing, full replay coordination, private artifacts, scientific publication, customer tickets and accounting APIs. The Marketplace catalog and checked financial domain are under development; production payments are not enabled.

## Source map

- `src/target_authority.rs`
- `src/product.rs`
- `src/economic_ledger.rs`
- `src/market/`
- `config/`

Each imported file has one owning repository. `component.json` maps maintained
files into the shared build layout. Dependencies are pinned by commit in the
[infrastructure release manifest](https://github.com/flybrainwork/infra/blob/main/release-manifest.json).

## Build and test

Use Rust 1.90 or newer (the source uses edition 2024), Node 22 or newer and Python
3.11 or newer. Optional scientific Python dependencies are in
`tools/requirements-research.txt` in the assembled workspace. SBF builds require
the compatible Solana/Agave build tools.

First assemble the exact source revisions:

```sh
git clone https://github.com/flybrainwork/infra.git flybrain/infra
python3 flybrain/infra/tools/workspace.py checkout --repos flybrain
python3 flybrain/infra/tools/workspace.py assemble --repos flybrain --output flybrain-workspace
cd flybrain-workspace
npm ci
```

Run the applicable checks from the assembled workspace:

```sh
cargo test -p flypow --lib --test target_authority --test product_api --test market_catalog
cargo build --locked --release --bin target_authority
```

This transition keeps the existing cross-component import paths intact. Cloning
this repository alone does not supply its external components. The assembler
creates a disposable build layout; all maintained edits belong to the owning
repositories. Use `workspace.py sync` for intentional changes made in that layout,
then review the component diffs and validate them before publication.

Full-model and browser integration checks require existing, verified local
resources and explicit arguments. They do not download a model or reset a
browser profile by default. Isolated chain checks require their own local bank;
production funds and addresses are never substituted.

## Development policy

- All maintained documentation, commit messages, issues, PRs and release notes
  are written in English. Product interfaces may remain bilingual.
- Completed, verified updates are committed and pushed automatically to
  `flybrainwork/node` using normal fast forwards.
- Keys, wallets, customer inputs, node databases, private artifacts, browser
  profiles and model caches stay outside Git and website exports.
- Production payment and reward configuration remains disabled until its actual
  asset identities, authorities, funds and operating gates are satisfied.

See [AGENTS.md](AGENTS.md), the
[development guide](https://github.com/flybrainwork/docs/blob/main/docs/DEVELOPMENT.md),
[architecture](https://github.com/flybrainwork/docs/blob/main/docs/ARCHITECTURE.md)
and [status](https://github.com/flybrainwork/docs/blob/main/docs/STATUS.md).

## License and provenance

Project code retains the declared `MIT OR Apache-2.0` license. Data descriptors
and third-party assets retain their own source attribution and licenses; this
code license does not relicense MaleCNS data or third-party libraries. The
import preserves numerical/identity fixtures and does not reinterpret existing
scientific or financial records. See [NOTICE](NOTICE).
