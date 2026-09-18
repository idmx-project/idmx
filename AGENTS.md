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
- Rust: follow `.claude/skills/rust-strict` when writing, reviewing, or refactoring code (it
  wins on conflict). `.claude/skills/rust-best-practices` (Apollo handbook, MIT, vendored via
  `skills-lock.json`) is background reference for the why and for topics rust-strict omits.
- Quality gates before every commit: `cargo fmt --all -- --check`,
  `cargo clippy --all-targets --all-features --locked -- -D warnings`, `cargo test`,
  `cargo deny check`.
- Containers: use rootless podman (`podman`, `podman compose`), not docker, unless told otherwise.
  The devnet scripts default to it (`CONTAINER_ENGINE` overrides). Verify devnet changes by
  running `./devnet/up.sh` and the flow scripts, not only by reading them.
- Workflow: commit locally in small commits; the maintainer reviews and pushes. Check
  `git status -sb` before claiming anything about what is or is not pushed.
- Ask before deciding anything listed under "Open Questions" in `docs/IDMX_IDEAS.md` or marked
  TODO in `spec/`; give a recommendation first.
