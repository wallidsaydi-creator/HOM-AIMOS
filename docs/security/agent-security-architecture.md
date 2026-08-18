# Agent-security architecture

HOM-AIMOS is a persistent-memory system whose security controls are part of
the save, recall, mutation, tool, and evidence paths. They are not a separate
filter placed around a vector store.

## Control planes

| Plane | Native responsibility | Evidence | Boundary |
|---|---|---|---|
| Identity and authority | Binds protected operations to certificate, method, path, body, nonce, and time | Signed request and authorization events | A valid signature proves attribution, not truth |
| Save | Validates, embeds, persists canonical content, and appends signed epistemic state | Immutable memory/version/provenance records and classification events | Suspicious content is retained; it is not selectively deleted |
| Recall | Admits principal-scoped evidence, ranks it, applies trust and calibration, and signs disclosure order | Signed recall receipt and RFC 6962-style Merkle evidence | A recalled item can still be false |
| Cognitive mutation | Changes bounded retrieval weight after signed outcome evidence | Housekeeper-authorized, predecessor-linked transition | Canonical memory content is not rewritten |
| Canary traversal | Tracks generated markers at persistence, model relay, tool input, and tool output | Stage decisions at `PERSISTED`, `RELAYED`, `EXECUTED`, and `EXPOSED` | Detects its explicit marker family, not arbitrary poison |
| Governed graph-family selection | Reconstructed Graph G2 contributes one bounded structural vote over admitted evidence; MAGMA is retained dormant | Graph-family decision and final recall receipt | Graph evidence owns neither candidate admission nor final disclosure |
| Operational red team | Exercises fixed attack and benign-control manifests | Signed campaign start, per-case decision, terminal outcome, and portable hash-only evidence | Evaluation only; no runtime authority and no certification claim |

## Retention and quarantine

HOM-AIMOS separates retention from disclosure. Potentially poisoned content is
kept as canonical evidence and receives a signed, reversible epistemic label.
The label can lower its retrieval treatment or keep it outside active context
without erasing the observation. Later counter-evidence can revise the label.

Canary decisions are a distinct mechanism. A marked save remains retained under
quarantine semantics. A marked relay, tool input, or tool result is prevented
from entering the next execution context. Canary evidence must not be described
as universal poison detection.

## Governed retrieval

Reconstructed Graph G2 is the sole live subgear in one bounded graph-family
channel. It operates after principal and provenance admission and before
epistemic, Canary, retention, and signed-disclosure controls. It owns no
candidate admission, persistence, mutation, or final-disclosure authority.

MAGMA is retained as dormant research. Its paper adaptation, tests, historical
positive proof, later current-stack utility and latency failures, and signed
policy history remain reviewable, but canonical recall does not call it,
accept its discoveries, or assign it a rank vote. Its signed configuration head
is `dormant`. A future version requires a new preregistered utility, latency,
scale, security-composition, and operator-authorization sequence.

Other graph candidates are evaluated one at a time against the complete native
gearbox and are not claimed as active merely because dormant source or isolated
tests exist.

## Operational self-red-team evidence

The SABER-inspired harness evaluates fixed, hash-bound attack and benign
manifests. Each case is decided by the native security owner and receives a
signed event. A signed terminal event binds the campaign aggregate. Validation,
reports, and score reconstruction accept verified event identifiers rather
than caller-generated aggregates.

The canonical 2026-08-11 campaign recorded:

- 27/27 attack cases blocked or retained-quarantined;
- 0 bypasses and 0 indeterminate attack observations;
- 28/28 benign controls allowed and 0 false positives;
- 55/55 native signed case receipts; and
- four signed terminal campaign outcomes.

These values are operational conformance for the declared vectors. They are not
DARPA equivalence, ARTE, a universal defense rate, an independent penetration
test, or formal robustness certification. See
[SABER operational evidence](saber-operational-evidence.md).

## Non-claims

HOM-AIMOS does not claim that cryptographic integrity makes remembered content
true. It does not claim universal prompt-injection or poisoning prevention. It
does not claim certified robustness outside a separately specified and proved
perturbation model. The present supported deployment is a local, single-machine
macOS backend, not a certified internet-facing multi-tenant security product.
