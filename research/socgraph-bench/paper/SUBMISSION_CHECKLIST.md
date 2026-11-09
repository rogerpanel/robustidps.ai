# IEEE S&P 2027 submission checklist

Derived from the S&P 2027 call for papers (sp2027.ieee-security.org/cfpapers.html).
Re-check the CFP before submitting; this list reflects it as of October 2026.

## Dates (cycle 2, all 23:59:59 AoE)

| Step | Date |
|---|---|
| Abstract registration: title, abstract, **all authors with ORCIDs**, conflicts | November 10, 2026 |
| Paper submission (have a draft uploaded 24 h earlier) | November 17, 2026 |
| Early-reject notification | January 18, 2027 |
| Reviews released / rebuttal due | February 11 / February 16, 2027 |
| Acceptance notification | March 5, 2027 |

Title, abstract and author list cannot change after November 10.
Current title: "Right for the Wrong Names: Mimicry Evasion of LLM Agents in Provenance-Graph Alert
Triage" (`\TitleText` in `preamble.tex`; also in `../README.md` and `../CITATION.cff`).

## Format (desk-reject risks)

- [x] `\documentclass[conference,compsoc]{IEEEtran}` (`main-conference.tex`), US letter.
- [x] At most 13 pages of text; references and appendices at most 5 more; 18 in total.
  Current build (after the Nov 2026 review fixes **and the landed RQ7 runs**): text ends on page 13 and
  references start on page 13 (within the hard limit), **17 pages in total** (within the 18-page soft limit).
  Room was made by moving the RQ6 two-model figure (Fig. 3; Table 4 keeps the numbers) and three discussion
  paragraphs to the journal build only (`\ifconf\else`), the task list to the artifact in the conference build,
  and by tightening the RQ7, discussion, limitations and conclusion prose.
  Re-check after every edit: `latexmk -pdf main-conference.tex`, then `pdfinfo`.
- [x] Everything after page 13 is references or a labelled appendix.
- [x] No margin, font or spacing changes; no packages that override compsoc.
- [ ] IEEEtran.cls version 1.8b: Overleaf's "IEEE Demo Template for Computer Society
  Conferences" ships it; compile there once before submitting.

## November 2026 readiness-review response

- [x] Anonymity: Appendix engineering/ethics "the author" -> "the authors" (singular revealed a single author).
- [x] Statistics: added an exact task-clustered paired permutation test alongside Fisher, in
  `results_to_tex.py` and `model_compare.py`. Reported honestly -- the first model's mimicry effect is
  suggestive but not significant clustered ($p=0.125$, 4 tasks); the second model's survives ($p=0.031$) and
  the difference-in-differences interval excludes zero. The exact Fisher *and* clustered $p$ are both given.
- [x] Per-platform split: Windows/Linux miss counts show the effect is entirely on Linux for both models.
- [x] Related work: added code-model renaming attacks (Yefet et al. 2020; Risse \& Bohme 2024), positioning
  this as the first such study for LLM triage over provenance.
- [x] **Experiment C (remedy)**: built `scripts/make_variants.py` `canon` pack (name-blind canonicalisation;
  the build verifies canon(v1.1)==canon(mimicry)), the `--name-rule` agent flag, `scripts/remedy.py`, and the
  RQ7 paper section (pending until the server runs land; see README "Testing the remedy").
- [x] **Ran experiment C on the server** (both models, three repeats each of `canon` and
  `name-rule-on-mimicry`); summaries under `results/remedy/<model>-<condition>/`. RQ7 is filled with the real
  numbers (Table 4 `tab:remedy`, `remedy_macros.tex`) and the honest finding: **neither lightweight defence
  restores accuracy** -- canonicalisation recovers little (Claude slightly worse without the real names; GPT
  partly recovers, not significant), the prompt name rule changes almost nothing, FPR stays 0, and no condition
  reaches clean-name recall. RQ7, abstract, discussion, limitations and conclusion rewritten to match.
- [x] **Regenerated the RQ7 `recovered` column** with the fixed `scripts/remedy.py` (task-level numerator and
  denominator): Claude recovers 0/3 of its mimicry-missed tasks under both defences, GPT 2/8 under
  canonicalisation and 0/8 under the name rule. Recall, FPR, quality and clustered $p$ were unaffected.
- [x] **Experiment D (open-weight model, RQ6)**: ran **DeepSeek-V3.2** (open-weight, via an OpenAI-compatible
  endpoint, same agent), v1.1 + mimicry, three repeats, under `scripts/run_openmodel.sh`. It is a weaker detector
  (v1.1 recall 0.600, misses 18/45) and, like GPT, clears attacks as authorised testing (17/18 of its base misses
  cite test cues); its mimicry reward drop is small and **not significant** ($-0.030$, CI $[-0.128,+0.051]$), but
  the **Linux-localised** miss pattern recurs (Linux 7/21$\to$13/21, Windows does not rise). Table~1 is now three
  models and RQ6 has an honest paragraph; the shortcut recurs across all three families, clear (GPT) $\to$
  suggestive (Claude) $\to$ small (DeepSeek). `model_compare.py` three-model output verified; DiD stays on the
  Claude/GPT pair. A first run with Llama 3.3 70B was discarded -- it could not drive the tools (3 aborts,
  ~4 calls/task), so its scores measured tool-use failure, not the shortcut. (Llama runs remain on disk.)
- [ ] Experiments A (telemetry prompt injection) and B (adaptive renaming) are **deliberately not built**. Both
  would require authoring working injection payloads and an automated evasion-string search -- offensive tooling
  that does not belong in this defensive research repo. Mimicry (RQ5) is already reported as a *lower bound* on
  evasion and §9 names A/B as future work; if a reviewer presses for an adaptive attack, that is a follow-up
  study with its own ethics/disclosure section, not a deadline add-on. The rebuttal should argue that a
  lower-bound attack *strengthens* the shortcut-reliance claim rather than weakening it.
- [x] Re-ran `latexmk` locally after experiment C: conference 17 pages (text ends p.13), journal 21 pages, both
  clean (no undefined/multiply-defined). Still compile once on Overleaf with IEEEtran 1.8b before submitting.

## Anonymity

- [x] No author names or affiliations in the PDF (`main-conference.tex`).
- [x] Platform name replaced by a neutral phrase (`\ReviewUI`); the only link to code is the anonymous artifact.
- [x] Artifact: anonymised export (`scripts/make_anonymous_artifact.py`) published at
  https://anonymous.4open.science/r/SOC-Graph-LLM-Agents/ and cited in the conference build
  (introduction, Ethics / Availability, Artifact appendix via `\ArtifactURL`).
  Do not update the underlying repository after the paper deadline.
- [ ] Do not post the paper on the RobustIDPS website or advertise results widely while
  under review (an arXiv preprint is allowed).

## HotCRP fields

- [ ] **Ethics considerations**: paste and adapt Appendix "Ethics Considerations"
  (public lab data, no human subjects, no live systems, the agent is defensive, the evasion
  result and why publishing it is justified, no vulnerability disclosure needed).
- [ ] **Generative AI usage considerations**: paste and adapt Appendix "Generative AI Usage".
  The paragraph "In preparing this work" is a draft. **Edit it to describe exactly how you
  used AI assistance** (the policy requires accurate disclosure; misstatement is grounds for
  desk rejection and submission bans).
- [ ] Conflicts of interest with PC members, by the CFP's definitions (co-author, co-worker,
  institution, collaborator, advisor, personal). Read the full PC list.
- [ ] ORCID for every author, with the same email as on HotCRP.

## Reviewer expectations (from the CFP and the PC)

The PC includes provenance-graph and ML-security researchers whose work the paper builds on
(e.g. authors of NoDoze/RapSheet, of the provenance mimicry attack, of the PIDS evaluation
study, and of problem-space attacks). Expect scrutiny of:

- **Model generality.** Addressed: three model families -- Claude Opus 5.5 (Anthropic API), GPT-6 astra
  (OpenAI Responses API), and DeepSeek-V3.2 (open-weight, OpenAI-compatible endpoint) -- on v1.1 and `mimicry`
  (RQ6, Table 1). The shortcut recurs in all three, concentrated on dual-use Linux. The ablation itself is
  single-model.
- **Benchmark size.** 21 tasks, 15 attacks. The paper reports paired intervals and limits;
  more tasks would strengthen RQ5 in particular.
- **Adversary strength.** Mimicry is lexical only; structural mimicry and prompt injection
  are stated as out of scope. Be ready to discuss in the rebuttal.
- **Label ambiguity under mimicry.** Addressed in §7.2 ("Two readings") and §9; the traces
  give the agent's reasons per case.

Public meta-reviews list the PC's remaining concerns for accepted papers; addressing the
points above in the submission keeps that list short.
