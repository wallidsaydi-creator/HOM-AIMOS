# AIMOS agent compatibility entry point

This file is a public-tool compatibility entry point. It is not a second
guidance authority.

Use the LLM-agnostic canonical guide in this order:

1. `Guide/AGENTS.md`
2. `Guide/connect-to-aimos-cert-envelope.md`
3. `Guide/aimos-guide-tier1-boot.md`
4. `Guide/aimos-guide-tier2-recall.md`
5. `Guide/aimos-guide-tier3-save.md`
6. `Guide/aimos-guide-tier4-debug.md`
7. `ARCHITECTURE-MAP.md`

Truth hierarchy:

1. Live AIMOS endpoints and retained memories.
2. Generated `architecture-authority.json`.
3. `hom-architecture-manifest.json`.
4. The manifest-bound `Guide/` corpus.
5. Session context.

Do not modify AIMOS internals without explicit operator authorization.
Mathematical services require their cited paper and service-header review before
implementation changes. No wrappers, hooks, placeholders, stubs, selective
deletion, decay, suppression, or environment-owned authority are permitted.
