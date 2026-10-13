# flybrainlabs development agreement

## Project identity and repository ownership

On 2026-10-12 the owner selected `flybrainlabs` as the project name and GitHub
account and authorized recreating and publishing the component repositories.
Use `flybrainlabs` in current project titles, repository descriptions, product
branding, documentation, release notes and new technical explanations.

- Maintained repositories: `web`, `node`, `miner`, `explorer`, `protocol`,
  `contracts`, `sdk`, `infra`, `research`, and `docs`, all under `flybrainlabs`.
- Use the dedicated `github-flybrainlabs` SSH identity and pinned official GitHub
  host keys. Verify the SSH login and the CLI/API login separately; both must
  identify `flybrainlabs` before account mutations or publication.
- The former GitHub accounts are retired publication targets. Do not push to
  `mars99` or `flybrainwork`, use their connectors, transfer/delete their
  repositories, or merge the historical draft pull request.
- Honor actual platform access errors. Report failed or incomplete publication
  accurately; do not retry using a retired identity.
- After each completed and verified update, commit and push automatically to its
  owning repository. Inspect remote changes first, preserve them and use normal
  fast forwards. No force pushes, empty commits or history deletion.
- Keep verified dependency pins and the infrastructure release manifest current.
  A release is available only after every pinned component and the containing
  infrastructure commit have been verified on the authorized remote.
- All new or updated documentation, commit messages, PR text, issues, release
  notes, repository descriptions and technical comments must be in English.
  Product interfaces may remain bilingual; conversation may remain Chinese.
- Each repository must contain actual component code, ownership metadata and
  correct build/test instructions. Never describe unfinished features as live.

## Token identity and public labels

Use **flybrainwork** as the token name and **FBW** as its current public symbol.
Current website labels, translations, guides and release explanations use FBW.
The existing asset is on Solana Devnet; a display rename does not change its mint,
authorities, supply, pools, program or cluster and does not issue another token.
Keep frozen receipt bytes, policy objects, signature domains and historical
contracts unchanged. Explain compatibility separately instead of rewriting them.
On compact/mobile navigation, place the language switch inside the menu and keep
reading panels in normal document flow, with no overlays over the prose.

## Compatibility, retained state and secrets

- Preserve scientific identity bytes, frozen vectors, signatures, addresses,
  existing schema identifiers and persisted storage keys. Historical internal
  identifiers are compatibility inputs, not the current project name. Migrate
  them only under an explicit versioned compatibility plan.
- Preserve model caches, OPFS results, browser profiles, signed identities,
  databases/WAL, private archives and backups. Never clear or redownload them
  for a repository or branding migration.
- Wallet secrets, SSH private keys, passwords, tokens, session credentials and
  customer data stay outside repositories and public builds. Never print them.
- Scan staged files and publication history before pushing or deploying.
- Do not delegate to sub-agents unless explicitly requested by the owner or an
  applicable project instruction.

## Product priorities and activation boundaries

Preserve the deployed Explorer, three-stage mining workflow and recoverable
archives. Continue the FLY Marketplace with real complete-model computation,
immutable versions, finite authorization, checked atom amounts, durable
settlement and cumulative historical entitlements. Physical-device, independent
operator and external scientific acceptance require their actual evidence.

Repository publication does not activate mainnet, formal FBW issuance, production
payments or unconfigured asset routes. Those operations retain their own identity,
funding and authorization gates. The existing official website and the separately
authorized X account are not changed by selecting the GitHub project name.
