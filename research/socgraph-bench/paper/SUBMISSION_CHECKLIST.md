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
  Current build: body ends on page 13, references start on page 14, 18 pages in total.
  Re-check after every edit: `latexmk -pdf main-conference.tex`, then `pdfinfo`.
- [x] Everything after page 13 is references or a labelled appendix.
- [x] No margin, font or spacing changes; no packages that override compsoc.
- [ ] IEEEtran.cls version 1.8b: Overleaf's "IEEE Demo Template for Computer Society
  Conferences" ships it; compile there once before submitting.

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
