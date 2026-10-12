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
- [x] Platform name replaced by a neutral phrase (`\ReviewUI`); no repository link in the text.
- [ ] Artifact: run `python scripts/make_anonymous_artifact.py --out ../socgraph-artifact`
  (removes names from text files and benchmark zips and fails if any remain), upload the
  output with Anonymous GitHub from a non-identifying account, and put that link in the
  paper (Ethics / Availability and the Artifact appendix). Do not update it after the deadline.
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

- **Single model.** All results use one closed model. Strongest single improvement before
  submission: run the full agent on v1.1 and on `mimicry` with one other model (for example an
  open-weight model through the OpenAI-compatible driver, `--provider openai --label ...`).
- **Benchmark size.** 21 tasks, 15 attacks. The paper reports paired intervals and limits;
  more tasks would strengthen RQ5 in particular.
- **Adversary strength.** Mimicry is lexical only; structural mimicry and prompt injection
  are stated as out of scope. Be ready to discuss in the rebuttal.
- **Label ambiguity under mimicry.** Addressed in Limitations ("two readings"); the traces
  give the agent's reasons per case.

Public meta-reviews list the PC's remaining concerns for accepted papers; addressing the
points above in the submission keeps that list short.
