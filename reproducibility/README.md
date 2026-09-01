# MutMem V2 verification and reproduction

The two reviewer-facing entry points are:

```bash
npm run verify
```

Regenerate the publication tables, claim map, attempt ledger, and disclosure
boundary deterministically from the retained public evidence, then verify them:

```bash
npm run evidence:regenerate
npm run verify
```

Evidence regeneration is offline and does not run a benchmark, open a database,
call a provider, or touch a live AIMOS brain.

The evidence-bound MutMem V2 manuscript is rendered and audited separately:

```bash
npm run paper:render
npm run paper:build
npm run paper:verify
```

The PDF is a separately bound publication artifact and is intentionally excluded
from the executable npm source package.

This is offline and read-only. It does not open AIMOS, PostgreSQL, Keychain,
provider, or network authority.

```bash
./install-macos.sh
npm run reproduce -- --installed-instance canonical --agent-id <enrolled-agent-id> --full --benchmark both --protocol canonical-blind-v1
```

The installer creates the Housekeeper and enrolls the reviewer-selected agent.
Reproduction then uses that same installed service and its native signed SAVE
and RECALL surfaces. It refuses a canonical installation containing ordinary
user memories; this protects a lived-in brain and makes the clean-install claim
explicit.

PoisonedRAG N=100 uses the same `reproduce` entry point and the same enrolled
agent with `--benchmark poisonedrag --protocol poisonedrag-n100-v1`. Its restricted source
bytes remain downloader-and-hash governed. The existing native ablation
executor is exposed as `npm run reproduce:ablation` and consumes the completed
PoisonedRAG run identity.

Every new benchmark run retains `environment.json` and a terminal projection.
`complete` is valid only when all intended, selected, completed, evaluated,
failed, and incomplete denominators reconcile and the exact immutable selected
aggregate path and hash are bound.
