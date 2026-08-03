# Cognitive Weight Doctrine v3 — Retention-Preserving, Age-Neutral Mutation

**Status:** forward normative doctrine for the live AIMOS implementation from
migration 091 onward.

The historical derivation in `Book batches /Cogpaper/DERIVATION-dynamic-mutation-governors.md`
is retained as academic and architectural history. Its `W_MIN=0.01`, finite
lookback, and exponential age-decay terms are not live AIMOS authority.

## Constitutional invariants

1. A memory persists. Cognitive mutation changes retrieval frequency, never
   content, existence, eligibility, or cryptographic history.
2. The live weight is bidirectional and bounded:
   \(w \in [0.1,3.0]\). A low frequency is not suppression.
3. Signed positive and negative outcome evidence remains influential regardless
   of age. No TTL, lookback cutoff, or time coefficient removes its influence.
4. Every changed quantized weight appends signed `REWEIGHT` provenance and one
   certified projection. An unchanged quantized target retains its signed
   `VALENCE` evidence and a signed `cognitive_weight_unchanged` event, but does
   not invent a transition.
5. Purge Brain is the sole deletion mechanism and is an offline whole-brain
   operation governed separately.

## Age-neutral judge and update

For retained signed outcomes \(r_\ell\in\{-1,+1\}\), the live judge is

\[
j=\tanh\!\left(\sum_{\ell=1}^{L} r_\ell\right).
\]

There is no age term. The reference-point update is

\[
q'=\operatorname{round}\!\left(1000\cdot
\operatorname{clamp}_{[0.1,3.0]}(w\,e^{\eta j})\right),
\qquad w'=q'/1000.
\]

If \(q'=q\), the outcome is still retained and ledgered; the projection chain
does not grow because the state did not change. This permits a sequence such as
negative, balancing positive, then positive to cross from bad to good without
rolling back the balancing evidence.

## Paper mappings

- HeLa-Mem Eq. 2 is authority for accumulated associative edge strength. The
  AIMOS consensus service is an explicit semantic-kNN adaptation; cosine edges
  and neighbor retrieval frequencies are not claimed to be the paper's exact
  learned edge state.
- SPICED Eq. 5 is authority for multiplicative strengthening of connection
  state. AIMOS explicitly adapts that operation to a retrieval-frequency
  projection while retaining canonical memory content.
- DA-SSDP governs the STDP co-activation/lag lane. The signed-outcome weight
  path retains those signals as context but uses the age-neutral equation above.

These mappings preserve academic provenance without claiming equation fidelity
where the AIMOS state variable differs from the paper's state variable.
