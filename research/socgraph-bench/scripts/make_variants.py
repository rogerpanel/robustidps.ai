#!/usr/bin/env python3
"""Build cue-controlled variants of a SOCGraph pack for robustness experiments.

    python scripts/make_variants.py --pack benchmark/socgraph-21-v1.1.zip --out benchmark

Two variants, each with the same graphs, identifiers and answers as the input
(so they score identically and results are directly comparable):

  blind     removes lab artefacts an agent could use as a label shortcut:
            the alert's `source` field (dataset name and ATT&CK technique),
            and lab host and domain names (`*-attack-range-*`, `mordor.local`)
            replaced with neutral ones.
  mimicry   blind, plus a semantics-preserving renaming of names the operator
            chose (`rootkit.ko`, `evil_user`, `atomic_user1`, the Atomic Red
            Team download URL, the "atomic testing" firewall rule name, ATT&CK
            ids written into file names and echoed strings). The
            behaviour is unchanged: the same module is loaded, the same
            sudoers rule written, the same accounts created. Only the words
            that announce an attack are gone, as an evasive operator would do.

Substitutions are applied to every string value in the task files (never to
keys or identifiers) and are listed in each variant's manifest.
"""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path
from typing import Any

BLIND = [
    ("sysmonlinux-ctus-attack-range-6628", "web-01"),
    ("sysmonlinux-tcontreras-attack-range-643", "app-01"),
    ("mordordc", "dc01"),
    ("MORDORDC", "DC01"),
    ("mordor.local", "corp.local"),
    ("MORDOR.LOCAL", "CORP.LOCAL"),
    ("mordor", "corp"),
    ("MORDOR", "CORP"),
    ("Mordor", "Corp"),
]
MIMICRY = [
    ("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md",
     "https://files.example-cdn.net/it-tools/main/docs/transfer.md"),
    ("bitsadmin1_flag.ps1", "update_check.ps1"),
    ("T1543.003 Test", "Service check"),
    ("T1218.005.hta", "welcome.hta"),
    ("atomic testing", "remote support"),
    ("atomic_user1", "jsmith"),
    ("atomic_user2", "svc_backup"),
    ("rootkit_test", "kmod_build"),
    ("rootkit.ko", "hidmon.ko"),
    ("rootkit", "hidmon"),
    ("evil_preload.c", "preload_fix.c"),
    ("evil_user", "deploy"),
]
CUE = re.compile(r"attack-range|mordor|attack_data|atomic|rootkit|evil|\bT1\d{3}", re.I)

# Name-blind canonicalisation (defence, RQ7). Every operator-chosen artefact, in BOTH its v1.1 and its mimicry
# spelling, maps to one stable neutral token, and residual ATT&CK technique ids are replaced. System paths and
# OS binaries (/etc/shadow, lsass.exe, comsvcs.dll, insmod, useradd, ...) are not attacker-controllable and are
# left intact, so behaviour is preserved. The point: applied to v1.1 and to mimicry, canonicalisation yields the
# same input, so the agent cannot read intent from a name and must decide from behaviour. `make_canon` below
# verifies that identity on every task.
CANON_TOKENS: list[tuple[tuple[str, str], str]] = [
    (("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md",
      "https://files.example-cdn.net/it-tools/main/docs/transfer.md"), "https://host.example/doc.md"),
    (("bitsadmin1_flag.ps1", "update_check.ps1"), "script-a.ps1"),
    (("T1543.003 Test", "Service check"), "note-a"),
    (("T1218.005.hta", "welcome.hta"), "page-a.hta"),
    (("atomic testing", "remote support"), "note-b"),
    (("atomic_user1", "jsmith"), "user-a"),
    (("atomic_user2", "svc_backup"), "user-b"),
    (("rootkit_test", "kmod_build"), "proj-a"),
    (("rootkit.ko", "hidmon.ko"), "mod-a.ko"),
    (("rootkit", "hidmon"), "mod-a"),
    (("evil_preload.c", "preload_fix.c"), "lib-a.c"),
    (("evil_user", "deploy"), "user-c"),
]
TECH = re.compile(r"\bT1\d{3}(\.\d{3})?\b")


def substitute(obj: Any, table: list[tuple[str, str]]) -> Any:
    if isinstance(obj, dict):
        return {k: substitute(v, table) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute(v, table) for v in obj]
    if isinstance(obj, str):
        for old, new in table:
            obj = obj.replace(old, new)
        return obj
    return obj


def ids(rec: dict[str, Any]) -> set[str]:
    return set(rec["graph"]["entities"]) | set(rec["graph"]["relations"])


def build(src: Path, out: Path, name: str, table: list[tuple[str, str]], forbid: re.Pattern | None) -> None:
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zout:
        manifest = json.loads(zin.read("manifest.json"))
        manifest["variant"] = name
        manifest["variant_of"] = manifest.get("version")
        manifest["substitutions"] = [{"from": a, "to": b} for a, b in table]
        manifest["alert_fields_removed"] = ["source"]
        for item in zin.namelist():
            data = zin.read(item)
            if item.startswith("tasks/"):
                rec = json.loads(data)
                before = ids(rec)
                rec["alert"].pop("source", None)
                rec = substitute(rec, table)
                if ids(rec) != before:
                    raise SystemExit(f"{item}: identifiers changed")
                text = json.dumps(rec)
                if forbid and (m := forbid.search(text)):
                    raise SystemExit(f"{item}: cue left after substitution: {m.group(0)!r}")
                zout.writestr(item, text)
            elif item == "manifest.json":
                continue
            elif item == "README.md":
                zout.writestr(item, data.decode() + f"\n## Variant: {name}\n\nSee `manifest.json` "
                              "(`substitutions`, `alert_fields_removed`). Graphs, identifiers and "
                              "answers are those of the base version.\n")
            else:
                zout.writestr(item, data)
        zout.writestr("manifest.json", json.dumps(manifest, indent=2))
    print(f"{name}: {out} ({out.stat().st_size / 1e6:.2f} MB)")


def make_canon(src: Path, mim: Path, out: Path) -> None:
    """Name-blind canonicalisation of the base pack, and a check that it coincides with the canonicalisation
    of the mimicry pack (so names, in either spelling, no longer distinguish the inputs)."""
    base_table = BLIND + [(v11, tok) for (v11, _), tok in CANON_TOKENS]
    mim_table = [(mm, tok) for (_, mm), tok in CANON_TOKENS]

    def canon(rec: dict[str, Any], table: list[tuple[str, str]]) -> dict[str, Any]:
        rec = substitute(rec, table)
        return json.loads(TECH.sub("TECH", json.dumps(rec)))

    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(mim) as zmim, \
            zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zout:
        manifest = json.loads(zin.read("manifest.json"))
        manifest["variant"] = "canon"
        manifest["variant_of"] = manifest.get("version")
        manifest["defence"] = "name-blind canonicalisation"
        manifest["substitutions"] = [{"from": a, "to": b} for a, b in base_table] + [{"from": "T1###", "to": "TECH"}]
        manifest["alert_fields_removed"] = ["source"]
        for item in zin.namelist():
            data = zin.read(item)
            if item.startswith("tasks/"):
                rec = json.loads(data)
                before = ids(rec)
                rec["alert"].pop("source", None)
                rec = canon(rec, base_table)
                if ids(rec) != before:
                    raise SystemExit(f"{item}: identifiers changed under canonicalisation")
                rmim = json.loads(zmim.read(item))
                if json.dumps(rec, sort_keys=True) != json.dumps(canon(rmim, mim_table), sort_keys=True):
                    raise SystemExit(f"{item}: canon(v1.1) != canon(mimicry); a name was not neutralised")
                if (m := CUE.search(json.dumps(rec))):
                    raise SystemExit(f"{item}: cue left after canonicalisation: {m.group(0)!r}")
                zout.writestr(item, json.dumps(rec))
            elif item == "manifest.json":
                continue
            elif item == "README.md":
                zout.writestr(item, data.decode() + "\n## Variant: canon\n\nName-blind canonicalisation "
                              "(defence): operator-chosen artefacts, in either spelling, map to stable tokens; "
                              "system paths and OS binaries are untouched. canon(v1.1) equals canon(mimicry) on "
                              "every task. See `manifest.json`.\n")
            else:
                zout.writestr(item, data)
        zout.writestr("manifest.json", json.dumps(manifest, indent=2))
    print(f"canon: {out} ({out.stat().st_size / 1e6:.2f} MB; canon(v1.1)==canon(mimicry) on all tasks)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pack", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    stem = args.pack.stem
    build(args.pack, args.out / f"{stem}-blind.zip", "blind", BLIND,
          re.compile(r"attack-range|mordor|attack_data|Security-Datasets", re.I))
    build(args.pack, args.out / f"{stem}-mimicry.zip", "mimicry", BLIND + MIMICRY, CUE)
    make_canon(args.pack, args.out / f"{stem}-mimicry.zip", args.out / f"{stem}-canon.zip")


if __name__ == "__main__":
    main()
