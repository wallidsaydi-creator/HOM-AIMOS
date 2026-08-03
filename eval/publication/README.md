# Verified benchmark evidence

`mutation-integrity-verification.json`,
`poisonedrag-epistemic-verification.json`,
`poisonedrag-human-agreement.json`, and
`poisonedrag-epistemic-ablation.json`, and
`verified-benchmark-results.json` are the public, sanitized aggregates generated
in this order:

```bash
npm run benchmark:export:mutation-integrity -- --run-id <completed-mutation-run-id>
npm run benchmark:export:poisonedrag-epistemic -- --run-id <completed-poisonedrag-run-id>
npm run benchmark:export:publication
```

The mutation-integrity exporter verifies the retained live-fire artifact
manifest and emits authorization, bidirectional-trajectory, tamper-detection,
SQL/portable-verifier parity, native-transaction latency, and PostgreSQL logical
row-storage measurements without exposing scratch identifiers or retained
content.

The epistemic exporter opens the completed scratch brain read-only, executes the
native classification-chain verifier for every retained PoisonedRAG memory, and
emits aggregate label counts, false-positive accounting, and a deterministic
record root. The publication exporter reads the promoted local evidence packs, verifies each run is
complete, rehashes every entry declared by each run's artifact manifest,
recomputes statistical intervals from row-level records, and validates the
PoisonedRAG save, recall, target-outcome, epistemic-verification, and N=100
causal-ablation proofs. It then emits aggregate
metrics, counts, protocol identities, model identities, and cryptographic
hashes only. The standalone ablation evidence and unified publication aggregate
use canonical-JSON SHA-256 self-hashes so verification does not depend on object
insertion order.

The public file deliberately excludes benchmark questions, answers,
conversations, passages, provider payloads, credentials, certificates, memory
identifiers, and machine-specific paths. Dataset bytes remain downloader- and
hash-based under their upstream terms.

Interpret the records separately:

- LongMemEval reports LLM-judged answer accuracy and retrieval at `k=20`.
- LoCoMo reports both LLM-judged answer accuracy and an upstream-compatible
  category-aware token-F1 result. They are different protocols and must not be
  averaged or substituted for one another.
- PoisonedRAG reports a declared N=100 adaptation. All poison passages were
  canonically retained and finished with signed `poison_likely` projections.
  The observed result is signed classification plus retrieval isolation, not
  save-time rejection, quarantine, deletion, or semantic proof of falsity.
- The N=100 ablation identifies signed stored epistemic labels as the observed
  causal retrieval mechanism. Query-local detection produced no measurable
  incremental change in this fixed corpus, and active-context withholding was
  not exercised. A2/A3 output differences therefore cannot be attributed to
  withholding because their selected evidence, active contexts, and prompts
  were identical for all 200 clean and attacked pairs.

The 200-answer human agreement audit is integrated into the unified publication
aggregate. Its labels were collected with arm identity and judge verdict hidden,
but the reviewer was the system author; the aggregate discloses that limitation
and does not claim independent assessment. The mutation-integrity suite is
complete. The aggregate also contains sanitized evidence for 39/39 verified
signed scratch-brain purge receipts; raw identity-bearing receipts remain
private.
