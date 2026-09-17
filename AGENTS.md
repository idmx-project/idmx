#IDMX-Project
## Conventions

- Name: IDMX = Inter-Domain Mail Exchange. Org: `idmx-project`. Project domain: `idmx-project.org`
  (use for schema `$id`s and problem `type` URIs). DNS labels: `_idmx.<domain>`,
  `<selector>._idmxkey.<domain>`.
- Spec is implementation-independent; the Rust code demonstrates it, never defines it.
- Keep v1 minimal. Prefer std and well-known crates (hickory-dns for SVCB); no speculative abstractions.
- Do not publish crates, push, or create public anything without asking. Repo is private for now.
- Commits: Conventional Commits (`type(scope): subject`, e.g. `feat(core): ...`, `docs(spec): ...`,
  `chore: ...`). Sign off every commit (`git commit -s`, DCO).
