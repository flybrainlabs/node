# Flybrain development agreement

## Ownership and automatic publication

On 2026-10-12 the owner moved future development to `flybrainwork` on GitHub.
The former `mars99/flypow` repository is historical source only. Do not push
commits, documentation, branches, tags, issues or pull requests to that account.
Do not transfer or delete the old repository or merge its existing draft PR.

- Use the dedicated `github-flybrainwork` SSH identity, verify its login and pin
  official GitHub host keys.
- Maintained repositories: `web`, `node`, `miner`, `explorer`, `protocol`,
  `contracts`, `sdk`, `infra`, `research`, and `docs`, all under `flybrainwork`.
- After each completed and verified update, commit and push to the relevant
  repository automatically. Keep release pins consistent, inspect remote changes
  first and use normal fast forwards. No force pushes, empty commits or history
  deletion. Report the actual remote commits and unsynchronized work accurately.
- All new or updated documentation, commit messages, PR text, issues, release
  notes, repository descriptions and newly introduced technical comments must be
  in English. Product interfaces may remain bilingual.
- Each repository contains actual component code, ownership, build/test commands
  and dependency pins. Never claim unfinished features are operational.
- Repository creation and publication are authorized. Formal payments, mainnet
  issuance and production asset configuration require their actual identities,
  funding and authorization; this migration does not activate them.

## Retain state and protect secrets

- Preserve model caches, OPFS results, browser profiles, signed identities,
  databases/WAL, private archives and backups. Do not redownload or clear data
  for a repository migration.
- Wallet secrets, SSH private keys, passwords, tokens, session credentials and
  customer data stay outside repositories and public builds. Do not print them.
- Scan staged files and publication bundles before pushing or deploying.
- Do not delegate to sub-agents unless explicitly requested by the owner or an
  applicable project instruction.

## Current priorities

Preserve the deployed Explorer, three-stage mining UI and recoverable archives.
Continue FLY Marketplace development with real complete-model computation,
immutable versions, finite authorization, checked atom amounts, durable
settlement and cumulative historical entitlements. Production assets and
payment routes remain unconfigured until supplied and verified.
