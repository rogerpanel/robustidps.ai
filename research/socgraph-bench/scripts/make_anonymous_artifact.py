#!/usr/bin/env python3
"""Export an anonymised copy of this repository for double-blind review.

    python scripts/make_anonymous_artifact.py --out ../socgraph-artifact

IEEE S&P (and SaTML) ask that artifact repositories reveal nothing about the
authors. This copies the repository without the manuscript sources and the
citation file, replaces author, institution and platform names in every text
file and inside the benchmark zips, rewrites the licence holder, regenerates
the checksums, and fails if any identifying string remains. Upload the output
with an anonymising service (for example Anonymous GitHub) from an account
whose name does not identify the authors.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP = {"paper", "CITATION.cff", ".git", "__pycache__", "make_anonymous_artifact.py"}
# Ordered: longer, more specific strings first.
REPLACE = [
    # The manuscript is submitted separately and is not part of the artifact.
    ("| [`paper/`](paper/) | The manuscript as an Overleaf-ready LaTeX project (IEEEtran). |\n", ""),
    ("Then upload `paper/` to Overleaf (or run `latexmk -pdf main.tex` in `paper/`).",
     "These commands write every table, figure input and number quoted in the paper to `paper/` "
     "(the manuscript itself is submitted separately)."),
    ("~/robustidps.ai/research/socgraph-bench", "~/socgraph-bench"),
    ("~/robustidps.ai/bluesec/install.sh", "~/socgraph-bench/agent/install.sh"),
    ("Then import the run folder on robustidps.ai > BlueSec Runs.",
     "Run folders can be inspected with any JSON viewer."),
    ("robustidps-bluesec-pack", "socgraph-pack"),
    ("RobustIDPS BlueSec practice pack", "SOCGraph practice pack"),
    ("robustidps-hypothesis-agent", "socgraph-hypothesis-agent"),
    ("robustidps-agent", "socgraph-agent"),
    ("Scoring (RobustIDPS, not the competition's)", "Scoring (ours, not the competition's)"),
    ("RobustIDPS", "SOCGraph"),
    ("robustidps.ai", "the authors' platform"),
    ("robustidps", "socgraph"),
    ("2026 (manuscript in `paper/`)", "2026 (manuscript under review)"),
    ("Roger Nick Anaedevha", "Anonymous Authors"),
    ("National Research Nuclear University MEPhI", "Anonymous Institution"),
]
FORBIDDEN = re.compile(r"robustidps|anaedevha|mephi|rogerpanel|torchroger|37\.27\.31\.70", re.I)
TEXT_SUFFIXES = {".py", ".md", ".txt", ".json", ".csv", ".sh", ".cff", ".example", ".log", ".toml", ".tex"}


def scrub(text: str) -> str:
    for old, new in REPLACE:
        text = text.replace(old, new)
    return text


def is_text(path: Path) -> bool:
    return path.suffix in TEXT_SUFFIXES or path.name in {"LICENSE", "SHA256SUMS", ".gitignore"}


def rewrite_zip(src: Path, dst: Path) -> None:
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename.endswith((".json", ".md", ".txt")):
                data = scrub(data.decode("utf-8")).encode("utf-8")
            zout.writestr(item.filename, data)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    out: Path = args.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    for path in sorted(ROOT.rglob("*")):
        rel = path.relative_to(ROOT)
        if any(part in SKIP for part in rel.parts) or path.is_dir():
            continue
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".zip":
            rewrite_zip(path, target)
        elif is_text(path):
            target.write_text(scrub(path.read_text(encoding="utf-8")), encoding="utf-8")
        else:
            shutil.copy2(path, target)
    lic = out / "LICENSE"
    if lic.exists():
        lic.write_text(re.sub(r"Copyright \(c\) (\d{4}) .*", r"Copyright (c) \1 Anonymous Authors",
                              lic.read_text()))
    sums = out / "benchmark" / "SHA256SUMS"
    if sums.exists():
        lines = [f"{hashlib.sha256(z.read_bytes()).hexdigest()}  {z.name}"
                 for z in sorted((out / "benchmark").glob("*.zip"))]
        sums.write_text("\n".join(lines) + "\n")
    # Verify: no identifying string in any file, including inside zips.
    leaks = []
    for path in out.rglob("*"):
        if path.is_dir():
            continue
        if path.suffix == ".zip":
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    if FORBIDDEN.search(zf.read(name).decode("utf-8", "ignore")):
                        leaks.append(f"{path.relative_to(out)}:{name}")
        elif FORBIDDEN.search(path.read_bytes().decode("utf-8", "ignore")):
            leaks.append(str(path.relative_to(out)))
    if leaks:
        raise SystemExit("identifying strings remain in:\n  " + "\n  ".join(leaks))
    n = sum(1 for p in out.rglob("*") if p.is_file())
    size = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    print(f"anonymised artifact: {out} ({n} files, {size / 1e6:.1f} MB); no identifying strings found")


if __name__ == "__main__":
    main()
