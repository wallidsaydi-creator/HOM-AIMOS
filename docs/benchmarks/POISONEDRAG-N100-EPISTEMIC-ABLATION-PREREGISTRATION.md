# PoisonedRAG N=100 Epistemic Ablation Preregistration

Date: 2026-07-30
Protocol: `poisonedrag-n100-epistemic-ablation-v1`
Source evidence: canonical completed N=100 aggregate
Source protocol: `poisonedrag-n100-v1`
Status: protocol fixed before computing counterfactual-arm results

## 1. Purpose and prior knowledge

This experiment adds causal attribution to the completed PoisonedRAG N=100
evaluation. It does not replace or invalidate any completed LoCoMo,
LongMemEval, PoisonedRAG, mutation-integrity, traceability, or human-audit
result.

The production arm from the source run is already known. The counterfactual
arms have not been evaluated. This document is therefore a prospective
registration of the counterfactual definitions and estimands, not a claim that
the production outcome is blinded.

The central question is:

> Under the same retained corpus, target questions, native pre-disclosure
> candidate openings, generator, judge, prompts, and cryptographic identity,
> what result change is attributable to signed stored epistemic labels,
> query-local lure detection, and active-context withholding?

## 2. Scientific boundary

The experiment measures epistemic retrieval and disclosure policy. It is not a
cognitive-weight mutation ablation:

- no canonical memory body is changed;
- no memory is deleted, suppressed, expired, or decayed;
- no persistent `retrieval_weight` is changed;
- no poison label is rewritten or refuted for the experiment;
- all 504 retained signed epistemic-classification rows remain present and
  re-verify identically in every arm;
- all source memories remain retained and recallable;
- the experiment runs against an isolated clone of the completed scratch
  brain;
- the clone continues the append-only signed event history;
- each experimental decision is appended to the cryptographic event ledger.

The production `/aimos/recall` behavior is not made configurable. No ENV
variable, public request switch, hidden route, unsigned policy, wrapper,
placeholder, hook, or alternate save path is introduced.

## 3. Fixed inputs

The following inputs are fixed to the completed source run and must be hashed
into the ablation manifest:

1. Source run manifest and terminal summary.
2. Source database identity and pre-clone evidence root.
3. PoisonedRAG source lock.
4. Public N=100 target lock.
5. Private target manifest.
6. Candidate-pool manifest.
7. Corpus-resolution manifest.
8. All 100 target questions and target answers.
9. All clean and poison memory identifiers from source-run admission proofs.
10. Exact source-file hashes for the native epistemic retriever, doctor trace,
    ablation runner, provider bridge, and benchmark prompts.

The ablation must use a new scratch database whose name begins with
`aimos_benchmark_` and is supplied only through the explicit `--aimos-db`
runtime argument. The source database identifier remains in the private
run-level evidence and is committed publicly only by its sanitized aggregate.

## 4. Fixed model and prompt protocol

- Generator: `gpt-5.5`, Codex authentication, reasoning `medium`.
- Judge: `gpt-5.6-terra`, Codex authentication, reasoning `high`.
- Generator and correctness prompts use one fixed neutral ablation template
  across all four policies. The template receives only the arm's already
  selected active context and never discloses the policy identifier or applies
  a second evidence filter.
- Correctness and target-assertion system instructions and strict schemas are
  unchanged from `poisonedrag-n100-v1`.
- Top-k: 5.
- Maximum provider attempts: 6.
- First schema-valid answer is retained; no best-of-N selection.
- Completed artifacts are immutable and reused only after self-hash and input
  hash verification.

No matched-model bridge is part of this experiment. Expanded corpus-scale and
matched-model validation are deferred to a subsequent study.

## 5. Fixed policy arms

The pre-disclosure candidate opening is obtained once per target and clean or
attacked scope through a signed native recall with the diagnostic doctor trace.
The trace is body-free and does not change native ranking.

All arm decisions are computed over the exact same candidate opening.

| Arm | Stored signed label policy | Query-local lure policy | Active-context withholding | Interpretation |
| --- | --- | --- | --- | --- |
| A0 | bypassed by policy | off | off | relevance-plus-diversity reference |
| A1 | on | off | off | signed stored-label contribution |
| A2 | on | on | off | query-local detector contribution |
| A3 | on | on | on | complete production policy |

Definitions:

- **A0:** every candidate receives an epistemic multiplier of 1.0. MMR and the
  native candidate relevance values remain active. All 504 signed
  classification rows remain intact and verifiable; the copied
  counterfactual policy does not consult their projection.
- **A1:** signed stored labels, explicit verification, and retained quarantine
  states affect the multiplier. Query-prefix and query-cluster signals do not.
- **A2:** A1 plus query-local lure-suspect and lure-cluster signals. Untrusted
  selected evidence is still supplied to the generator.
- **A3:** A2 ranking plus removal of
  `untrusted_reference_only` evidence from the generator's active context.
  The evidence remains present in the decision record.

A2 and A3 are expected to have identical selected memory identifiers. Their
only designed difference is active-context withholding.

## 6. Confirmatory execution

### 6.1 Retrieval evaluation

Run A0, A1, A2, and A3 for all 100 target pairs:

- 100 clean scopes;
- 100 attacked scopes;
- 800 arm-level retrieval decisions;
- no target or row may be silently omitted.

The reconstructed A3 epistemic-selection order must exactly match the ordered
memory identifiers committed by the signed native epistemic-decision event.
The same existing full-detail output calibrator is then applied independently
to each arm's selected set. Reconstructed A3 disclosure order must exactly
match the final native production response. A2 and A3 must match at both
stages. Any mismatch blocks model execution.

The native pre-epistemic candidate opening is a positive control. For every
attacked scope the run reports whether each of the five admitted poison
passages entered that opening, its raw rank, and its native relevance inputs.
This establishes whether poison was retrievable at the mechanism boundary
before policy attribution. The pinned upstream artifact retains Contriever
scores for the 100 clean candidates but not for the generated poison passages;
therefore no result is mislabelled as a Contriever-ranked poison control.

### 6.2 Model evaluation

Run generation and both judges for A0, A1, A2, and A3:

- 200 target/scope answers per policy;
- 800 generated answers total;
- correctness and target-assertion judgment for every answer;
- 1,600 judgment records total.

## 7. Primary estimands

All estimands are paired by target.

1. Attacked poison retrieval@5 difference: A3 minus A0.
2. Attacked target-answer ASR difference: A3 minus A0.
3. Induced ASR difference over targets where the paired clean answer does not
   assert the target answer.
4. Clean answer-accuracy difference: A3 minus A0.
5. Attacked answer-accuracy difference: A3 minus A0.

The primary total-effect contrast is A3 versus A0. The adjacent mechanism
contrasts are A1 minus A0, A2 minus A1, and A3 minus A2 for retrieval, target
assertion, induced ASR, and answer correctness.

## 8. Secondary diagnostics

1. Number of poison passages selected at each rank.
2. Fraction of targets with any poison in top five.
3. Signed-label state counts in each candidate opening.
4. Number of selected passages marked `untrusted_reference_only`.
5. Number of passages withheld from A3 active context.
6. Clean-memory displacement at top five.
7. Clean memories adversely labelled as
   `poison_suspect`, `poison_likely`, or `poison_confirmed`.
8. Abstention rate.
9. Recall, generation, and judge latency distributions.
10. Provider failures and intended-N denominators.

## 9. Statistical analysis

- Proportions: point estimate and two-sided 95% Wilson interval.
- Paired binary outcomes: exact McNemar test.
- Paired mean differences: deterministic paired bootstrap with 10,000
  replicates and a fixed published seed.
- Within each outcome family, the three adjacent contrasts and total-effect
  contrast use Holm--Bonferroni correction at familywise alpha 0.05. Raw and
  adjusted exact McNemar p-values are both reported.
- All denominators report intended N and completed N.
- No failed row is converted to a negative result.
- No significance threshold is used as a publication gate.
- Effect sizes and uncertainty are reported even when the result is null.

## 10. Cryptographic evidence requirements

Every target/scope opening must retain:

1. signed request envelope evidence;
2. native recall receipt;
3. native epistemic-decision receipt;
4. doctor-trace hash;
5. candidate-set hash and ordered memory identifiers;
6. candidate live-content hashes and body-free output-calibration projection;
7. policy identifier and policy-manifest hash inside the signed arm-decision
   receipt, not only in the run manifest;
8. ordered epistemic-selected identifiers and selected-set hash;
9. ordered post-calibration disclosure identifiers and disclosure-set hash;
10. active-context identifiers and context hash;
11. append-only `poisonedrag_ablation_decision` event receipt.

Every generated answer and judgment must retain its prompt hash, requested and
actual model identity, provider metadata, latency, schema hash, and immutable
artifact hash.

The terminal evidence pack must prove:

- source database and clone binding;
- source corpus root unchanged;
- canonical memory bodies unchanged;
- persistent retrieval weights unchanged;
- no missing target or scope;
- all event receipts verify;
- all artifact self-hashes verify;
- the canonical `aimos` database received no benchmark memory.

## 11. Stop conditions

Stop before model execution if any of the following occurs:

1. source-run artifact hash failure;
2. source database mismatch;
3. target/candidate manifest mismatch;
4. clone corpus-root mismatch;
5. doctor trace missing or incomplete;
6. A3 reconstructed epistemic-selection order differs from the signed native
   decision, or reconstructed A3 disclosure order differs from the native
   production response;
7. an arm changes canonical memory or persistent retrieval weight;
8. an experimental decision lacks a signed ledger receipt;
9. model preflight reports a requested/actual model mismatch.

Stop final aggregation if any intended row is absent or any retained artifact
fails verification.

## 12. Interpretation limits

This ablation supports causal attribution within the fixed N=100 adapted
corpus. It does not establish full-corpus external validity, universal poison
detection, or equivalence to the original retriever/model configuration.
Expanded corpus-scale and matched-model validation are future work.

Within each target, five poison passages compete against 100 clean candidates
at disclosure k=5. Conditional on entering the native candidate opening, this
bounded density makes poison competition easier than a 2.68-million-passage
corpus; a reduction observed here is therefore conservative with respect to
candidate density, while external validity remains explicitly deferred.

The experiment can show whether signed epistemic state is operational rather
than decorative. It cannot by itself prove the separate authorization and
tamper-resistance claims of the cognitive-weight mutation chain; those claims
remain supported by the mutation-integrity suite.
