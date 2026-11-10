#!/usr/bin/env python3
"""Generate a redacted source listing for software registration.

    python3 scripts/make-deposit-listing.py --pages 70 -o deposit-listing.txt

Registration deposits establish authorship, so the listing must be the
project's own code. This script does not write code — it selects real
files, strips anything unsafe to disclose, and paginates the result.

What it removes, and why:

  secrets          API keys, tokens, passwords, private keys. Never
                   disclosable, and a deposit copy can be requested by
                   third parties.
  tuned constants  Detection thresholds and score weights. Publishing the
                   exact values an attacker must stay under is the one
                   category that measurably weakens the running system;
                   the surrounding logic discloses the method without
                   handing over the calibration.
  hosts and IPs    Internal addresses and origin server IPs.

What it keeps, because it is what identifies the work: module headers,
class and function signatures, docstrings, type definitions, API route
declarations, Rust trait and struct definitions, and the CLI surface.
These demonstrate architecture and authorship while disclosing nothing
that is not already visible to any user of the deployed service.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Ordered so the listing opens with architecture, not incidental files.
SELECTION: list[tuple[str, list[str]]] = [
    ("Backend — application entry point and API surface", [
        "backend/main.py",
    ]),
    ("Backend — detection models (dissertation methods M1-M7)", [
        "backend/models/neural_ode.py",
        "backend/models/sde_tgnn.py",
        "backend/models/optimal_transport.py",
        "backend/models/federated_graph.py",
        "backend/models/heterogeneous_graph.py",
        "backend/models/bayesian_inference.py",
        "backend/models/encrypted_traffic.py",
    ]),
    ("Backend — LLM agent security plane", [
        "backend/plugins/agent_studio/api.py",
        "backend/plugins/agent_studio/orchestrator.py",
    ]),
    ("Backend — UAV / electronic-warfare plane", [
        "backend/plugins/uav/api.py",
        "backend/plugins/uav/uav_defense/ew_bench/simulator.py",
    ]),
    ("Edge agent (Rust) — capture, features, inference, enforcement", [
        "agent/agent-edge/src/lib.rs",
        "agent/agent-features/src/lib.rs",
        "agent/agent-inference/src/lib.rs",
        "agent/agent-netfilter/src/lib.rs",
        "agent/agent-xdp/src/lib.rs",
    ]),
    ("Frontend — application shell and routing", [
        "frontend/src/App.tsx",
    ]),
]

SECRET_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key|secret|token|password|passwd|credential)'
                r'(\s*[:=]\s*)(["\'])(?!<)[^"\']{4,}\3'), r'\1\2\3<REDACTED>\3'),
    (re.compile(r'(?i)\b(sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{8,}|'
                r'dsk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,})\b'), '<REDACTED-KEY>'),
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
                re.S), '<REDACTED-PRIVATE-KEY>'),
    # Public IPv4 literals. Loopback, RFC1918 and 0.0.0.0 are left alone:
    # they carry no information about the deployment.
    (re.compile(r'\b(?!127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0)'
                r'(?:\d{1,3}\.){3}\d{1,3}\b'), '<REDACTED-IP>'),
]

# Numeric constants whose exact value is operationally sensitive.
THRESHOLD_ASSIGN = re.compile(
    r'(?i)^(\s*(?:pub\s+)?(?:const\s+|let\s+|static\s+)?'
    r'[A-Za-z_][A-Za-z0-9_]*(?:threshold|cutoff|limit|weight|score|epsilon|sigma|alpha)'
    r'[A-Za-z0-9_]*\s*(?::\s*[A-Za-z0-9_<>:\[\] ]+)?\s*[:=]\s*)'
    r'([0-9][0-9_.eE+-]*)(.*)$')


SKELETON_KEEP = re.compile(
    r'^\s*('
    r'#|//|"""|\'\'\'|/\*|\*|'                       # comments and docstrings
    r'from\s|import\s|use\s|mod\s|pub\s+use\s|'      # imports
    r'@\w|'                                          # decorators (FastAPI routes)
    r'(async\s+)?def\s|class\s|'                     # Python
    r'(pub\s+)?(async\s+)?fn\s|(pub\s+)?struct\s|'   # Rust
    r'(pub\s+)?trait\s|(pub\s+)?enum\s|impl\s|'
    r'(export\s+)?(default\s+)?function\s|'          # TS/JS
    r'(export\s+)?(interface|type|const)\s'
    r')')


def skeletonise(text: str, ext: str) -> str:
    """Reduce a large file to its interface: imports, declarations,
    decorators and documentation, with bodies elided.

    Preferred over truncation for big files. Truncating keeps the first N
    lines — usually imports and one class — which misrepresents the file
    and wastes the page budget. A skeleton shows the whole module's
    surface, which is what demonstrates architecture, and it discloses
    strictly less than the full body.
    """
    kept, elided = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        if SKELETON_KEEP.match(line):
            if elided:
                indent = " " * (len(line) - len(line.lstrip()))
                kept.append(f"{indent}    ... [{elided} lines of implementation] ...")
                elided = 0
            kept.append(line)
        else:
            elided += 1
    if elided:
        kept.append(f"    ... [{elided} lines of implementation] ...")
    return "\n".join(kept)


def redact(text: str) -> tuple[str, int]:
    """Strip secrets and blunt tuned constants. Returns text and a count."""
    n = 0
    for pattern, repl in SECRET_PATTERNS:
        text, k = pattern.subn(repl, text)
        n += k
    out = []
    for line in text.splitlines():
        m = THRESHOLD_ASSIGN.match(line)
        if m:
            out.append(f"{m.group(1)}<CALIBRATED>{m.group(3)}")
            n += 1
        else:
            out.append(line)
    return "\n".join(out), n


def verify_clean(text: str) -> list[str]:
    """Second pass over the redacted output. A redactor that silently
    misses something is worse than none, so failures are reported rather
    than assumed away."""
    problems = []
    for pattern, _ in SECRET_PATTERNS[:3]:
        for hit in pattern.findall(text):
            s = hit if isinstance(hit, str) else "".join(str(x) for x in hit)
            if "REDACTED" not in s:
                problems.append(s[:60])
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", default="deposit-listing.txt")
    ap.add_argument("--pages", type=int, default=70,
                    help="page budget (default 70)")
    ap.add_argument("--lines-per-page", type=int, default=50)
    ap.add_argument("--max-file-lines", type=int, default=200,
                    help="files longer than this are reduced to their interface")
    args = ap.parse_args()

    budget = args.pages * args.lines_per_page
    parts: list[str] = []
    used = 0
    redactions = 0
    included: list[str] = []
    missing: list[str] = []

    for section, files in SELECTION:
        section_added = False
        for rel in files:
            path = ROOT / rel
            if not path.is_file():
                missing.append(rel)
                continue
            if used >= budget:
                break
            raw = path.read_text(errors="replace")
            note = ""
            # Skeletonise anything that would crowd out the rest of the
            # system. Without this a single large module consumes the
            # whole budget and the listing shows one file, not an
            # architecture.
            if len(raw.splitlines()) > args.max_file_lines:
                raw = skeletonise(raw, path.suffix)
                note = ", interface only"
            body, k = redact(raw)
            redactions += k
            lines = body.splitlines()
            room = budget - used
            truncated = len(lines) > room
            if truncated:
                lines = lines[:room]
                note += ", truncated"
            if not section_added:
                parts.append(f"\n{'=' * 72}\n{section}\n{'=' * 72}")
                section_added = True
            parts.append(f"\n--- {rel} ({len(lines)} lines{note}) ---\n")
            parts.append("\n".join(lines))
            used += len(lines)
            included.append(rel)

    listing = "\n".join(parts)
    problems = verify_clean(listing)

    header = (
        "RobustIDPS.ai — source listing for software registration\n"
        "Copyright (c) 2026 Roger Nick Anaedevha\n"
        f"Files included: {len(included)}   Lines: {used}   "
        f"Pages (at {args.lines_per_page}/page): {used // args.lines_per_page + 1}\n"
        f"Redactions applied: {redactions}\n"
        "Secrets, credentials, private keys, public IP literals and\n"
        "calibrated detection constants have been removed. Structure,\n"
        "interfaces and documentation are unmodified.\n"
    )
    Path(args.out).write_text(header + listing)

    print(header)
    if missing:
        print(f"NOT FOUND ({len(missing)}) — check SELECTION paths:")
        for m in missing:
            print(f"  {m}")
    if problems:
        print(f"\n!! {len(problems)} possible secret(s) survived redaction — "
              f"review before filing:")
        for p in problems[:10]:
            print(f"  {p}")
        return 1
    print(f"Wrote {args.out} — verification pass found no surviving secrets.")
    print("Read it before filing. This tool reduces risk; it does not replace review.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
