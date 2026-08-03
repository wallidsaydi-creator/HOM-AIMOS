# Aimos LLM Guidance Index

This file teaches you how to USE Aimos, not how to modify it.

## Boot Order

1. Read this file first.
2. Read `Guide/connect-to-aimos-cert-envelope.md` before any protected Aimos API call.
3. Read `Guide/aimos-guide-tier1-boot.md` before any Aimos API use.
4. Read `Guide/aimos-guide-tier2-recall.md` before the first recall.
5. Read `Guide/aimos-guide-tier3-save.md` before the first save.
6. Read `Guide/aimos-guide-tier4-debug.md` before debugging internals.
7. Read `ARCHITECTURE-MAP.md` before making architecture claims.
8. `CAPABILITY-MANIFEST.md` has been retired. Use this entire Guide folder, live Aimos, `architecture-authority.json`, `hom-architecture-manifest.json`, and `ARCHITECTURE-MAP.md` instead.
9. Use Aimos as the memory source of truth before any implementation claims.

## Truth Hierarchy

1. Live Aimos endpoints and memories.
2. `architecture-authority.json`.
3. `hom-architecture-manifest.json`.
4. Files under `Guide/`.
5. Session context.

If sources disagree, verify live Aimos first. If live Aimos is unavailable, say that clearly and use the mirrors as provisional context.

## Write Boundary

Do not write to Aimos unless the operator explicitly authorizes the save.

When a save is authorized, use the real `/aimos/save` path, preserve truth metadata, and report the save result without exposing bearer tokens or secrets.

## Modification Boundary

Do not modify Aimos internals without explicit user authorization.

For paper-backed implementation work, follow the required order:

1. Paper authority.
2. Target service read.
3. Implementation.
4. Dry run.
5. Header annotation only after proof.
6. Next service.

## Validation

Use these checks when relevant:

```bash
npm run test:syntax
npm run test:priority-tem
npm run test:architecture-authority
```

For local health:

```bash
curl -s -m 8 http://127.0.0.1:9100/health
```

## Safety Rules

- No placeholder services, fake stubs, fake-green tests, or misleading "wired" claims.
- If a service is not implemented, say `not implemented`. If a test only proves scaffolding, say that.
- For paper-backed services, recall the paper technique from Aimos before implementing or claiming faithfulness.
- Unknown is acceptable. Invented certainty is not.
- No delete, soft delete, TTL forgetting, or canonical memory removal.
- Security gates and quarantine are protective boundaries, not UX decorations.
- Unlearning papers must be reframed as supersession, counter-evidence, repair overlays, ranking-frequency changes, or quarantine labels with canonical evidence preserved and recallable.
- Never expose hidden chain-of-thought; use concise evidence-backed reasoning cards instead.
- MCP is an integration surface, not the whole Aimos architecture.
