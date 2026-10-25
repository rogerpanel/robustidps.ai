# Submission checklist (IEEE S&P, anonymous build)

Re-check the current call for papers before submitting; venue rules change.

## Open items

- [ ] Decide the venue and cycle. The SOCGraph checklist lists S&P 2027 cycle 2 (abstract
  registration November 10, 2026; paper November 17, 2026); confirm against the CFP.
- [ ] Create an anonymised artifact repository for this paper and set `\ArtifactURL` in
  `main-conference.tex` (currently a placeholder). Do not update it after the deadline.
- [ ] Re-check the references flagged in `references_verification.md` (fides venue, agentharm
  author count, greshake pages/DOI, wabersich volume/DOI, orangetsai title punctuation,
  clopper issue, inspect authorship) on the primary pages; the automated check could only
  use search results that point to them.
- [ ] Choose the MCP specification revision the filter targets and cite it by date.
- [ ] Page budget: body at most 13 pages, references and appendices at most 5 more (current
  conference build: 11 pages in total, references from page 10). Room exists for a live-model
  evaluation or an adaptive-attack section.
- [ ] Compile once with the official IEEEtran class version the venue requires.

## Done

- [x] Every number in the text comes from `generated/results_macros.tex` (no hand-typed results).
- [x] No platform, product or author names in `main-conference.tex` output (checked with pdftotext).
- [x] Claims checked against code and results: host contracts (OpenHands SDK 1.58.2 source,
  Claude Agent SDK 0.2.174 documentation, Claude Code hooks reference), AgentDojo exclusions,
  intervals (cluster bootstrap by attack goal), deferral simulation.
