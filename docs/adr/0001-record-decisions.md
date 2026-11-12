# 0001 Record decisions as ADRs

**Status:** Accepted (phase 1)

**Context.** The build spec is the source of truth, but it has gaps and a few
contradictions that need explicit, reviewable resolutions.

**Decision.** Every deviation from or clarification of the spec gets a short
ADR in `docs/adr/`, listed in `docs/adr/README.md`.

**Consequences.** Reviewers can see why the code differs from the spec without
reading commit history.
