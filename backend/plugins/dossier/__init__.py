"""Assurance-dossier generator.

Produces a canonical JSON dossier from any vertical's certificate set.
The dossier is rendered to paper-ready HTML by the React /dossier route
using the existing Print theme (zero new PDF dependency); users print to
PDF from the browser. Server-side PDF rendering (weasyprint / headless
Chromium) is an optional production add-on.

Sections (matches EU AI Act Art. 15, NIST AI RMF, DO-326A airworthiness,
ISO/IEC 42001 SoA, MITRE ATLAS coverage matrix, OWASP Top 10 attestation):
  identity              who/what/when
  certificates          quantitative robustness evidence
  attack_coverage       reference attacks evaluated
  industry_position     comparison vs incumbents
  regulatory_mapping    instrument -> satisfying method -> evidence type
  reproducibility       commit / seed / runner instructions
"""
from plugins.dossier.assemble import (
    DossierVertical, assemble_dossier, list_verticals,
)

__all__ = ["DossierVertical", "assemble_dossier", "list_verticals"]
