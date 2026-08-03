# Certified Cognitive-Weight Trajectory — Formal Specification (v3)

**Status:** normative through migration 091. Migration 091 is the forward-only
v3 correction for exact signer epochs, exact derived displays, honest retained
initial-weight baselines, and non-vacuous whole-corpus verification. The live
mathematical doctrine is age-neutral and bounded by `[0.1,3.0]`; see
`docs/security/cognitive-weight-doctrine-v3.md`.
**Scope:** the retrieval weight of a memory `m` and how it changes. It says nothing about `m`'s content, existence, or eligibility — those are governed separately and are **invariant** under everything here.

---

## 1. Purpose and the one distinction that governs the design

The retrieval weight is **dynamic and bidirectional**: a memory may move good → bad → good as evidence changes. The database does **not** guarantee monotonicity (that was the wrong guarantee). It guarantees four things and no more:

- **E — Existence.** `m` is never deleted, deactivated, or made ineligible by any weight change. (Aladdin law; enforced elsewhere by `REVOKE DELETE` and by recall ranking-not-filtering.)
- **B — Bounds.** weight ∈ `[0.1, 3.0]`, floored at `0.1` so "bad" ≠ "gone".
- **S — Signed.** every change carries a housekeeper Ed25519 `REWEIGHT` attestation (the "who/why").
- **C — Chained.** every change is a link in an append-only, tamper-evident hash chain (the "in what order, from what"), replayable to reconstruct the entire trajectory.

Monotonicity is explicitly **absent**. The only monotone quantity is chain *length* (append-only).

---

## 2. Notation

| Symbol | Meaning | Domain / type |
|---|---|---|
| $m$ | memory id | UUID, 16 bytes |
| $c$ | company id | text |
| $k$ | index of the current (terminal) transition | $\mathbb{N}_0$ |
| $q_i$ | **quantized** weight after transition $i$ | $q_i \in \{100,\dots,3000\}\subset\mathbb{Z}$ |
| $w_i$ | real weight, $w_i = q_i/1000$ | $[0.1,3.0]$ |
| $\sigma_i$ | provenance mutation hash of the signed `REWEIGHT` node for transition $i$ | 32 bytes |
| $h_i$ | projection (chain) hash of transition $i$ | 32 bytes |
| $t_i$ | domain-separated transition commitment binding $(c,m,q_{i-1},q_i,\sigma_i)$ | 32 bytes |
| $s_i$ | housekeeper Ed25519 signature over $t_i$ | 64 bytes |
| $h_{-1}$ | genesis predecessor sentinel | $\mathbf{0}^{32}$ (32 zero bytes) |
| $\tau_i$ | transition $i$: the tuple $(m,\,q_{i-1},\,q_i,\,\sigma_i,\,h_{i-1},\,h_i)$ | — |
| $\mathrm{be64}(x)$ | 8-byte big-endian two's-complement encoding (`int8send`) | bytea, 8 bytes |
| $\mathrm{u16}(m)$ | 16-byte UUID encoding (`uuid_send`) | bytea, 16 bytes |
| $\mathrm{H}(\cdot)$ | SHA-256 (`pgcrypto digest(·,'sha256')`) | bytea, 32 bytes |
| $P$ | domain-separation prefix, the 12 ASCII bytes `aimos.cwc/v1` followed by one `0x00` | bytea, 13 bytes |
| $T$ | domain-separation prefix `aimos.cognitive-transition/v2` followed by `0x00` | bytea, 30 bytes |
| $b_m$ | optional signed observation of a retained non-default pre-chain weight | baseline row |

---

## 3. Data model (schema, Phase 1)

Extends `public.aimos_cognitive_weight_projections` (created in migration 080):

```
projection_id            uuid   PK
company_id               text   NOT NULL
memory_id                uuid   NOT NULL
provenance_mutation_hash bytea  NOT NULL          -- σ_i  (FK → aimos_memory_provenance, ON DELETE RESTRICT)
old_weight               real   NOT NULL          -- derived display of w_{i-1}
new_weight               real   NOT NULL          -- derived display of w_i
old_weight_milli         int    NOT NULL          -- q_{i-1}  (canonical; CHECK 100..3000)   [NEW]
new_weight_milli         int    NOT NULL          -- q_i      (canonical; CHECK 100..3000)   [NEW]
prev_projection_hash     bytea                     -- h_{i-1}; NULL ⇔ genesis (i=0)           [NEW]
projection_hash          bytea  NOT NULL UNIQUE    -- h_i                                     [NEW]
transition_hash          bytea  NOT NULL UNIQUE    -- t_i                                     [v2]
transition_sig           bytea  NOT NULL           -- s_i, exactly 64 bytes                   [v2]
applied_at               timestamptz NOT NULL
```

Chain-shape constraints (reuse the proven provenance pattern):

- **one genesis per memory:** `UNIQUE (memory_id) WHERE prev_projection_hash IS NULL`.
- **no fork:** `UNIQUE (memory_id, prev_projection_hash)` — no two transitions share a parent ⇒ the chain is a simple path, not a DAG.
- **append-only at the DB:** `REVOKE UPDATE, DELETE, TRUNCATE ON aimos_cognitive_weight_projections FROM agent_runtime, aimos_app, PUBLIC`. Only INSERT, only via the signed function.
- **no direct runtime append:** migration 085 also revokes `INSERT` from
  `agent_runtime`; the SECURITY DEFINER writer is the only projection owner.
- RLS company isolation (already present in 080) retained.

The **canonical** weight is `*_milli` (integer). `old_weight`/`new_weight` (real) are a convenience projection $w=q/1000$ and are **never** on the hash path.
Migration 091 constrains both display columns to the exact float4 bytes produced
from `*_milli / 1000`; callers cannot store an alternative rounded display.

### 3.1 Honest retained baseline

A memory whose non-default weight predates the certified transition chain has
no reconstructable original trajectory. Migration 091 records one append-only
housekeeper-signed baseline containing the exact observed float4 bytes, its
canonical milli, current memory content hash, signed event mutation hash, exact
housekeeper epoch, and certificate fingerprint. It asserts only observation at
ceremony time and sets `historical_origin_claimed=false`; it never fabricates a
`REWEIGHT` or original author.

---

## 4. Canonical byte layout (LOAD-BEARING — ambiguity here is a forgery surface)

$$
\text{preimage}(\tau_i) \;=\; P \,\Vert\, \mathrm{u16}(m) \,\Vert\, \mathrm{be64}(q_{i-1}) \,\Vert\, \mathrm{be64}(q_i) \,\Vert\, \sigma_i \,\Vert\, h_{i-1}
\tag{4.1}
$$

Exactly $13 + 16 + 8 + 8 + 32 + 32 = 109$ bytes. Every field is fixed-width, so no separator is needed and no concatenation is ambiguous. Here $\mathrm{be64}(q_{i-1})$ encodes $\text{old}(\tau_i)$ and $\mathrm{be64}(q_i)$ encodes $\text{new}(\tau_i)$. For the genesis transition ($i=0$): $\text{old}(\tau_0)$ is the memory's weight immediately before its first signed reweight, $\text{new}(\tau_0)$ is the weight after it, and $h_{-1}=\mathbf{0}^{32}$ (see §6 genesis rule). There is no self-equal transition.

SQL realization (inside the SECURITY DEFINER function, so the caller cannot influence it):

```sql
digest(
  '\x61696d6f732e6377632f7631'::bytea   -- 'aimos.cwc/v1'
  || '\x00'::bytea
  || uuid_send(p_memory_id)
  || int8send(v_old_milli::int8)
  || int8send(v_new_milli::int8)
  || p_provenance_mutation_hash
  || v_prev_hash,                        -- 32 bytes, or '\x00…00' (32) for genesis
  'sha256'
)
```

An external verifier in any language reproduces (4.1) byte-for-byte from public
columns; no secret is required to verify either hash layer or signature. Only
the housekeeper private key can create $s_i$.

The v2 signature does not sign $h_i$ or an ambiguous JSON serialization. It
signs a second fixed-width commitment:

$$
t_i = \mathrm H\!\left(T\,\Vert\,\mathrm{be32}(|\mathrm{utf8}(c)|)\,\Vert\,
\mathrm{utf8}(c)\,\Vert\,\mathrm{u16}(m)\,\Vert\,
\mathrm{be64}(q_{i-1})\,\Vert\,\mathrm{be64}(q_i)\,\Vert\,\sigma_i\right),
\qquad s_i=\mathrm{Ed25519Sign}_{HK}(t_i).
\tag{4.2}
$$

All fields after the explicit company-length prefix are fixed-width. For the
canonical company `hom`, the preimage is 101 bytes. An external verifier needs
only the retained projection/provenance columns and the enrolled housekeeper
public key.

---

## 5. The recurrence

$$
h_i \;=\; \mathrm{H}\big(\text{preimage}(\tau_i)\big), \qquad h_{-1} = \mathbf{0}^{32}
\tag{5.1}
$$

---

## 6. Invariants

- **I1 (bounds).** $\forall i:\; q_i \in [100,3000]$.
- **I2 (continuity).** $\forall i\ge 1:\; \text{old}(\tau_i) = \text{new}(\tau_{i-1})$, i.e. $q_{i-1}^{(\tau_i)} = q_i^{(\tau_{i-1})}$. Checked as **integer equality**, never float.
- **I3 (terminal fidelity).** For a non-empty chain, the exact float4 bytes of
  `retrieval_weight(m)` equal the float4 bytes derived from $q_k/1000$.
- **I4 (signature).** each $\tau_i$ references exactly one terminal
  `REWEIGHT` provenance node ($\sigma_i$), with
  `binding_schema_version = 2`, `agent_id='housekeeper'`, and a 64-byte
  provenance signature. Independently, $s_i$ must verify against (4.2), which
  cryptographically binds the exact company, memory, quantized old/new state,
  and provenance mutation hash. The SQL verifier checks the provenance tuple
  fields and mutation commitment; a portable full verifier additionally checks
  the retained canonical body/content hash and its provenance signature.
- **I5 (single chain).** exactly one genesis per $m$; no fork ⇒ total order on transitions.
- **I6 (append-only).** the projection row set is insert-only; `UPDATE`/`DELETE` are revoked at the DB.

**Genesis rule (i=0).** A memory enters the chain on its **first** reweight. Its
old state must be anchored either to exact default float4 `1.000`, or to a
verified signed retained baseline. An unattested non-default initial state is
rejected. A no-transition memory is classified as `default_empty_chain`,
`signed_initial_weight`, or `unattested_initial_weight`; it is never silently
omitted from corpus verification.

---

## 7. Operations

### 7.1 `apply_signed_cognitive_reweight(m, w_old, w_new, σ, s)` — the sole writer

**Interface (migration 091):** the sole function is
`(p_memory_id uuid, p_old_weight double precision, p_new_weight double
precision, p_provenance_mutation_hash bytea, p_transition_sig bytea)`. It
quantizes to millis internally ($q=\mathrm{round}(w\times1000)$). The unsigned
four-argument form is absent.

**Pre:** company+housekeeper scope set; I1 for $w_{old},w_{new}$ and their
millis; $q_{new}\ne q_{old}$ (no-op rejected); a terminal signed `REWEIGHT`
node $\sigma$ binding $(c,m,w_{old},w_{new})$ exists; $s$ verifies over the
exact (4.2) bytes; the signer is a non-null, active, unrevoked exact housekeeper
epoch whose certificate fingerprint matches the provenance row; the memory's
current chain head satisfies I2, or no head exists and the old state matches a
verified baseline or exact default.
**Effect (one transaction):** the native caller and stored writer acquire the
same transaction-scoped advisory key `cognitive-reweight:c:m`; the caller reads
and signs under that serialization without receiving direct table UPDATE
privilege. The writer takes its owner-level row lock, derives the integer
millis, verifies $s$, computes $h$ in-DB, appends the projection, and updates
only `retrieval_weight` to $q_{new}/1000$.
**No monotone check.** $q_{new}$ may be `<` or `>` $q_{old}$ (bidirectional); `=` is rejected.
**Post:** I1–I6 hold; chain length $k\!\to\!k{+}1$.
**Verified end-to-end (082):** good→bad→good (1.0→1.3→0.9→1.5) produced in-DB hashes byte-identical to the external Python verifier; no-op, discontinuity, and out-of-bounds each rejected without mutating the chain.

### 7.2 Per-memory and corpus verification

**Implemented (migration 083), pure SQL, LIVE.** Streams transitions in chain order from genesis; recomputes each $h_i$ by (5.1) via pgcrypto; asserts I2 (continuity), hash match, reachability (no orphan rows, I5), and I3 (terminal fidelity). Returns the first violating $h$ in `break_at` with a `reason`, else `ok=true`. $O(k)$ time. Companion `verify_all_cognitive_weight_chains()` for the ceremony/CI. Tap any moment: `SELECT * FROM verify_cognitive_weight_chain('<id>')`.
**Verified (083):** intact good→bad→good ⇒ ok; DB-attacker tamper of a mid transition ⇒ `hash_mismatch` localized; tamper of the live weight only ⇒ `terminal_weight_mismatch`; empty chain ⇒ ok/len 0.

**Layer 2 (Ed25519 signature) — corrected by migration 085, in-DB.** Migration
084's content-hash signature did not bind the projected tuple and recreated the
writer with default PUBLIC execution. Migration 085 replaces it with (4.2),
requires a 64-byte transition signature on every v2 row, verifies it with
`pgsodium.crypto_sign_verify_detached`, scopes every verifier by current
company, revokes PUBLIC/`aimos_app`, revokes direct runtime INSERT, and grants
only the certified writer/verifiers to `agent_runtime`.
- Return: `verify_cognitive_weight_chain(m) → (ok, chain_length, terminal_weight, sigs_verified, break_at, reason)`. Both layers, one call, any moment.
- **Verified (085 disposable live fire):** a real signed negative outcome moved
  a retained Guide memory from `1.000` to `0.859`; verification returned
  `ok=true`, `chain_length=1`, `sigs_verified=1`; reuse of a valid signature
  against a different transition returned `cognitive_transition_sig_invalid`
  and rolled back its provisional provenance atomically.
- **Deployment note:** requires the pgsodium extension (`scripts/db/build-pgsodium.sh`). 084 installs it and **disables pgsodium's `pgsodium_trg_mask_update` DDL event trigger** — its column-masking KMS feature (unused) otherwise aborts all subsequent DDL without `shared_preload_libraries`. Signature functions are unaffected.
- **`reason` values:** `provenance_binding_invalid`, `provenance_hash_invalid`,
  `continuity_break`, `hash_mismatch`, `signature_missing`,
  `transition_hash_invalid`, `signature_invalid`, `unreachable_rows`,
  `terminal_weight_mismatch`.

Migration 091 makes `verify_all_cognitive_weight_chains()` enumerate every
memory in the current company, not only memories already having a projection.
It returns one of four structural classifications: `certified_chain`,
`default_empty_chain`, `signed_initial_weight`, or
`unattested_initial_weight`. Classification describes evidence shape; `ok`
reports whether that evidence verifies.

The native portable verifier in
`services/security/cognitive-weight-verifier.js` independently verifies exact
baseline/event/epoch bindings, canonical provenance bodies and signatures,
projection and transition hashes, continuity, terminal state, and SQL parity.
It emits a deterministic company corpus proof root.

---

## 8. Theorems

**Theorem 1 (tamper-evidence).** *Any post-hoc modification of a stored $q_i$ or $\sigma_i$ for $i<k$ is detected by `verify` in $O(k)$.*
**Proof (telescoping).** Suppose an adversary alters $q_j\!\to\!q_j'$ (or $\sigma_j\!\to\!\sigma_j'$), $j\le k$. `verify` recomputes $h_j' = \mathrm H(\text{preimage}'(\tau_j))$. Since SHA-256 is collision-resistant, $h_j'\ne h_j$ except with negligible probability, so either $h_j'$ mismatches the stored $h_j$ (detected at $j$) or the adversary also rewrote the stored $h_j$; but then by (5.1) $h_{j+1}=\mathrm H(\dots\Vert h_j)$ no longer matches unless $h_{j+1}$ is also rewritten, and so on to $h_k$. Rewriting $h_k$ changes the terminal hash, and I3 ties the terminal to `retrieval_weight`; a consistent forgery therefore requires rewriting the entire suffix **and** the live weight **and** forging a housekeeper Ed25519 signature for the altered $\sigma$ (I4) — the last being infeasible without the key. The DB also forbids the rewrite outright (I6). $\square$

**Theorem 2 (reversibility / bidirectional reachability).** *From terminal
$q_k$, every different quantized target
$q'\in\{100,\ldots,3000\}\setminus\{q_k\}$ is reachable by one valid append;
the identical target requires no transition.*
**Proof (construction).** Sign a `REWEIGHT` provenance node and (4.2)
transition binding $(c,m,q_k,q')$. I1 holds and the head satisfies I2. Apply.
good→bad→good is two appends on one immutable chain; reversal never edits
history. $\square$

**Proposition 3 (total order).** *I5 ⇒ the transitions of $m$ form a total order.* By I5 there is one genesis and each non-genesis transition has a unique parent (no fork) and each parent has at most one child (`UNIQUE(memory_id, prev_projection_hash)`); a rooted tree with out-degree ≤1 and one root is a path. $\square$

**Proposition 4 (existence-decoupling).** *No weight change alters E.* `apply_signed_cognitive_reweight` writes only `retrieval_weight` and the projection row; it never touches `is_active`, never deletes, and $q_{new}\ge 100 \Rightarrow w\ge 0.1>0$. Recall ranks by weight and applies no `retrieval_weight`-threshold filter, so eligibility is independent of $w$. $\square$

---

## 9. Numerical justification `[/mathematician]`

- **Why quantize.** SHA-256 needs exact byte equality; float32 equality is unsafe (mig 080 itself uses a $10^{-6}$ epsilon). Hashing integers $q$ removes floats from the hash and continuity paths entirely.
- **Resolution.** $\Delta = 10^{-3}$ ⇒ $2901$ levels on $[0.1,3.0]$; retrieval ranking needs ≪ that. No information loss of consequence.
- **Round-trip stability.** For $q\in[100,3000]$, storing $w=(q/1000)$ as float32 incurs error $\le w\cdot 2^{-24}\le 3.0\cdot2^{-24}\approx1.8\times10^{-7}$; times $1000$ is $\le1.8\times10^{-4}\ll 0.5$, so $\mathrm{round}(w\times1000)=q$ exactly across the whole range — I3 is safe. Nonetheless the **critical path uses `*_milli` integers**; the real column is belt-and-suspenders only.
- **Complexity.** reweight $O(1)$ (indexed head lookup + insert + update); per-memory verify $O(k)$/$O(1)$-space; corpus verify $O(\sum_m k_m)$.

---

## 10. Governance

- **H9:** this is **not** a new trust tier or deletion authority — it strengthens an existing signed mutation with an ordering chain. **No amendment required.** Recorded doctrine refinement: *"cognitive weight is a certified, bidirectional, append-only chain; the database guarantees existence, bounds, signature, and chained order — never monotonicity."*
- **H10 (schema forward-only):** migration 081 is additive; no legacy alias removed.
- **Paper dividend:** external verifiability (§4) + Theorems 1–2 = *certified cognitive trajectory under an append-only store*, reusing the memory hash-chain machinery. For Paper 1/2.

---

## 11. External verification recipe (for reviewers / the ceremony)

Given the public columns of a memory's projection rows, ordered from genesis:
1. set $h_{-1} = \texttt{00…00}$ (32 bytes);
2. for each row: assert `old_weight_milli == prev row's new_weight_milli` (genesis exempt); recompute $h$ by (4.1)/(5.1) with `pgcrypto`-equivalent SHA-256; assert it equals the stored `projection_hash`;
3. assert the final `new_weight_milli` equals `round(1000 × retrieval_weight)` of the live memory;
4. recompute `transition_hash` by (4.2) and verify `transition_sig` against the
   housekeeper key from the referenced signing epoch;
5. for full portable provenance verification, recompute the canonical
   `body_json` content hash and mutation hash, then verify the retained
   provenance signature over its canonical body/nonce/timestamp.
Any mismatch localizes the tamper to a specific transition. No secret needed for steps 1–3.
```
```
