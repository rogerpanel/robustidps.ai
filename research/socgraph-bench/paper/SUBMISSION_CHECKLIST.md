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
- [ ] **Regenerate the RQ7 `recovered` column** with the fixed `scripts/remedy.py` (now task-level numerator
  *and* denominator; the committed `remedy_macros.tex`/`tables/remedy.tex` still carry the old cell-denominator
  `recovered` values, e.g. 0/9, 2/24). Pull, `python3 scripts/remedy.py --out paper ...`, recompile. Everything
  else (recall, FPR, quality, clustered $p$) is final and unaffected.
- [ ] Experiments A (telemetry prompt injection) and B (adaptive renaming) from the review are **not built**:
  they construct injected instructions and search for evasive names. If a reviewer insists, discuss scope;
  the limitations section already frames mimicry as a lower bound and names A/B as the next step.
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

- **Model generality.** Addressed: Claude Opus 5.5 (Anthropic API) and GPT-6 astra (OpenAI
  Responses API) on v1.1 and `mimicry` (RQ6, Table 4, Fig. 3). The ablation itself is single-model;
  an open-weight model would strengthen this further.
- **Benchmark size.** 21 tasks, 15 attacks. The paper reports paired intervals and limits;
  more tasks would strengthen RQ5 in particular.
- **Adversary strength.** Mimicry is lexical only; structural mimicry and prompt injection
  are stated as out of scope. Be ready to discuss in the rebuttal.
- **Label ambiguity under mimicry.** Addressed in §7.2 ("Two readings") and §9; the traces
  give the agent's reasons per case.

Public meta-reviews list the PC's remaining concerns for accepted papers; addressing the
points above in the submission keeps that list short.
