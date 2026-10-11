# mcp-authscan: Detector Quality Scorecard

**The badges above are proof.** They are generated on every commit against a pinned, labeled corpus of known-vulnerable and human-cleared repositories. The same methodology used by security research institutions — frozen test data, immutable results, on-chain anchoring.

## What the Badges Mean

- **Precision** — Of all the findings we reported, what fraction were real? A false positive here means we flagged something that isn't actually vulnerable.
- **Recall** — Of all the real vulnerabilities in the corpus, what fraction did we catch? A false negative means we missed something.
- **F1** — Harmonic mean of the two. The single score that matters.

**Perfect 1.0 means:**
- Every detector finding we emit is correct (zero false positives).
- Every seed vulnerability still fires (zero false negatives).
- Regressions are caught in CI.

## The Corpus

The benchmark runs against:

- **Positives** (8 known-vulnerable repos): repositories where VATA discovered and live-reproduced security findings. Detectors are expected to fire on their seed vulnerabilities.
- **Negatives** (4 human-cleared repos): repositories audited by hand and cleared. Detectors must not fire.
- **Latent** (1 repo): pattern present but unreachable. Flagged but not counted as a false positive.

All repositories are pinned at specific commits, so results are reproducible and survive upstream patching.

## The Proof Chain

1. **Reproducible** — Run `python3 tests/benchmark.py` locally; you get the same scores.
2. **Immutable** — Benchmark manifest frozen; each repo pinned to a commit SHA.
3. **Auditable** — Full results in `vata-authscan-bench.json` (fetched, scanned, scored, reported).
4. **Anchored** — Report SHA256 enables blockchain anchoring (VATA chain-of-custody workflow).

## Honest Limitations

- **Recall floor for review-list rules** — A4 (SSRF surface) and B2 (code replay) require dataflow analysis; they're review-lists, not detectors, and excluded from scoring.
- **Latent case tolerated** — One repo has a vulnerable pattern but no reachable sink. We flag it, don't count it as FP.
- **Coverage gaps** — Two confirmed findings remain uncaught (empires-unauth-dcr-scope, unla-middleware-ordering). They're in the roadmap; the missed cases are published, not hidden.

## Why This Matters for Your Organization

A security tool with perfect scores on **someone else's test data** is marketing. Perfect scores on your **own frozen corpus** is accountability. mcp-authscan's benchmarks are the latter:

- Independent researchers can audit the corpus and the scanner against it.
- The scores are enforced in CI — a regression fails the build.
- The tool does not hide its limitations (coverage gaps, latent cases, review-lists are published).

**Every commit is a proof. No promises, just receipts.**

---

## Accessing Full Results

- **JSON Report** — `vata-authscan-bench.json` (fetch on each commit, compare histories)
- **Test Manifest** — `tests/benchmark_manifest.json` (corpus definitions, expected findings)
- **Methodology** — `METHODOLOGY.md` (validation pillars, ground truth, differential coverage)
- **External Probe** — `tests/external_probe.py` (catches third-party advisories; current: 2/3)

---

## Continuous Improvement

The gap between 2/3 external advisories caught is known and published. VATA maintains a public roadmap of missed cases, not a list of future features. Each gap corresponds to a real CVE/GHSA, and the tool gets better by closing those gaps with evidence, not by making broader claims.
