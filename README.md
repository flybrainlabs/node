# flybrainlabs node

Authority and service APIs for [flybrainlabs](https://flybrain.work/).

## Scope

Durable goal competition, commit/reveal processing, full replay coordination, private artifacts, scientific publication, customer tickets and accounting APIs. The Marketplace catalog and checked financial domain are under development; production payments are not enabled.

## Source map

- `src/target_authority.rs`
- `src/product.rs`
- `src/economic_ledger.rs`
- `src/market/`
- `config/`

Each maintained file has one owning repository. `component.json` maps maintained
files into the shared build layout. Dependencies are pinned by commit in the
[infrastructure release manifest](https://github.com/flybrainlabs/infra/blob/main/release-manifest.json).

## Build and test

Use Rust 1.90 or newer (the source uses edition 2024), Node 22 or newer and Python
3.11 or newer. Optional scientific Python dependencies are in
`tools/requirements-research.txt` in the assembled workspace. SBF builds require
the compatible Solana/Agave build tools.

First assemble the exact source revisions:

```sh
git clone https://github.com/flybrainlabs/infra.git flybrainlabs/infra
python3 flybrainlabs/infra/tools/workspace.py checkout --repos flybrainlabs
python3 flybrainlabs/infra/tools/workspace.py assemble --repos flybrainlabs --output flybrainlabs-workspace
cd flybrainlabs-workspace
npm ci
```

Run the applicable checks from the assembled workspace:

```sh
cargo test -p flypow --lib --test target_authority --test product_api --test market_catalog
cargo build --locked --release --bin target_authority
```

The assembled layout keeps cross-component import paths intact. Cloning
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
  `flybrainlabs/node` using normal fast forwards.
- Keys, wallets, customer inputs, node databases, private artifacts, browser
  profiles and model caches stay outside Git and website exports.
- Production payment and reward configuration remains disabled until its actual
  asset identities, authorities, funds and operating gates are satisfied.

See [AGENTS.md](AGENTS.md), the
[development guide](https://github.com/flybrainlabs/docs/blob/main/docs/DEVELOPMENT.md),
[architecture](https://github.com/flybrainlabs/docs/blob/main/docs/ARCHITECTURE.md)
and [status](https://github.com/flybrainlabs/docs/blob/main/docs/STATUS.md).

## License and provenance

Project code retains the declared `MIT OR Apache-2.0` license. Data descriptors
and third-party assets retain their own source attribution and licenses; this
code license does not relicense MaleCNS data or third-party libraries. The
maintained sources preserve numerical/identity fixtures and the meaning of
existing scientific and financial records. See [NOTICE](NOTICE).

## Wallet mining V3

The finite Solana Devnet wallet-mining extension is described in the
[execution and acceptance record](https://github.com/flybrainlabs/docs/blob/main/docs/WALLET_MINING_V3_EXECUTION.md)
and [canonical Result layout](https://github.com/flybrainlabs/docs/blob/main/docs/WALLET_MINING_V3_RESULT_LAYOUT.md).
Use the assembled workspace for cross-component imports and pinned release
verification. Public receipts are in the contracts repository under
`deploy/wallet-mining-v3/`; private signers, signed journals and full response
archives remain outside source repositories. The two-unit acceptance budget is
complete. Future paid work requires a new prospectively frozen finite plan.
Actual extension-wallet and physical-device confirmation remain separate gates.


## Community contributions

The Social service (`tools/social_server.mjs`) shares existing wallet sessions and SQLite/WAL while running separately on loopback 8791. `config/social-community-v1.sql` is an additive checksummed migration. Run `npm run test:community`, `npm run typecheck:community` and `npm run lint:community` in the assembled workspace. The new API/provider/client modules opt into JavaScript type checking; legacy financial modules retain their existing validation suites. No relayer or asset execution is started by the Social service. See `docs/social-community-system.md`.

## Contract task factory V4

The opt-in V4 lifecycle freezes a predefined catalog on chain, accepts full replay
attestations and advances tasks without a privileged relayer or minimum successful-
task interval. Existing V3 records and grants are retained. Public activation is
pending an approved calibrated catalog and finite funding. See
[the lifecycle specification](https://github.com/flybrainlabs/docs/blob/feat/contract-task-factory-v4-20261015/docs/CONTRACT_TASK_FACTORY_V4.md).

## Scientific mining V5

`tools/scientific_service_v5.mjs --config PRIVATE_CONFIG` runs configured, already
funded rounds with one resident complete-model verifier, authenticated evidence
uploads, durable leases and a signed transaction journal. It does not allocate a
new reward budget. The finite signer fee allowances and private key/configuration
paths must be supplied through the approved operator route. Two verifier keys of
one operator are disclosed as one operator. Public V5 activation is pending.
See the [operations guide](https://github.com/flybrainlabs/infra/blob/feat/scientific-mining-20261020/docs/SCIENTIFIC_MINING_V5_OPERATIONS.md).

## Continuous V4 mining candidate

Independent keeper/supply/replay/payment lanes, reentrant schema, historical recovery and storage lifecycle. The feature branch is `feat/continuous-mining-20261021`.

Run from the assembled workspace with the existing pinned dependencies:

```sh
node tests/factory_gateway_v4.mjs
node tests/factory_pool_capacity_v4.mjs
node tests/factory_validator_fleet_v4.mjs
node tests/factory_validator_quorum_v4.mjs
FLYBRAIN_POOL_TEST_SOCKET=/path/to/isolated/socket node tests/factory_pool_recovery_v4.mjs
FLYBRAIN_POOL_TEST_SOCKET=/path/to/isolated/socket node tests/factory_pool_sbf_v4.mjs
```

See `docs/CONTINUOUS_MINING_V4_20261021.md` and the infrastructure
`docs/CONTINUOUS_MINING_V4_20261021_ACCEPTANCE.json` for evidence boundaries.
Source publication does not establish live acceptance or activate the service.

The quorum suite uses actual loopback HTTP with fixture signed scientific reports.
It exercises a held fourth request, bounded collection time, conflicting groups,
tampering, a busy member during the next candidate, stable returned evidence and
the finalized-chain time budget. It creates no public chain transaction. Full
model replay, real miner rewards and long-duration operation need separate live
evidence. See the infrastructure validation participant operations guide.
