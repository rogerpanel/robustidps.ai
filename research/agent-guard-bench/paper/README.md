# Manuscript

- `main.tex`: journal format (IEEEtran journal), with author and affiliation.
- `main-conference.tex`: anonymous IEEE S&P format (IEEEtran conference, compsoc); the system is
  called "the filter" and the artifact link is a placeholder until an anonymous repository exists.
- `preamble.tex`, `content.tex`, `sections/`, `figures/`: shared sources.
- `generated/`: numbers and tables written by `../harness/make_tables.py`. Do not edit by hand.
- `references.bib`: every entry checked against a primary source; see
  `references_verification.md` for the source URL per entry and the items still to re-check.

Build: `latexmk -pdf main.tex main-conference.tex` (or pdflatex, bibtex, pdflatex, pdflatex).
