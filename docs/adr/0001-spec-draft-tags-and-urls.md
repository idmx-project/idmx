# Spec drafts are `spec/*` tags with permanent, section-numbered URLs

Each Draft of the specification is an immutable git tag in this repo named `spec/v<major>-draft-<NN>`
(e.g. `spec/v1-draft-00`); the `spec/` prefix keeps Draft tags apart from crate release tags, which
share this repo. idmx-project.org builds one page set per Draft tag at
`/spec/<draft>/<page>#section-<N.N>`, plus the Editor's draft (`main`) at `/spec/latest/`. Section
anchors come from section numbers, not heading text, because reviewers cite "§2.1 of v1-draft-00"
and those links must never break. Once a Draft URL is published it is never moved or removed.

## Consequences

- `v1-draft-00` was tagged before this scheme, without the prefix; the website accepts it as is rather
  than retagging a published tag.
- Section numbers within a tagged Draft are frozen; renumbering happens only in the next Draft.
- The spec stays in this repo as the single source of truth; the website fetches it at build time
  and never holds a copy.
