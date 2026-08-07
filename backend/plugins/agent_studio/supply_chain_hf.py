"""HuggingFace Hub live API client for the Supply Chain Scanner.

Fetches real model metadata (downloads, likes, licence, tags,
siblings/files, model architecture) from huggingface.co/api/models/{id}.
Falls back to the user-supplied spec when:
  - the model isn't on HF (private / local / URL)
  - network is blocked (air-gapped deploy)
  - the HF API rate-limits us

The fetched metadata is merged into the spec before passing to the
existing scan_model() so risk scoring + SBOM stay schema-stable.
"""
from __future__ import annotations

import os
from typing import Any

import httpx

HF_API_BASE = "https://huggingface.co/api"
HF_TIMEOUT_S = 4.0   # short — air-gap-friendly


def looks_like_hf_id(model_id: str) -> bool:
    """Heuristic: HF model IDs are 'org/name' with no path-traversal
    or URL/file scheme."""
    if "/" not in model_id:
        return False
    if model_id.startswith(("http", "ftp", "/", "file:")):
        return False
    if "\\" in model_id or model_id.count("/") > 1:
        return False
    return True


def fetch_hf_metadata(model_id: str, token: str | None = None) -> dict | None:
    """Return a dict matching the supply_chain.scan_model() spec shape,
    or None when the HF API can't help."""
    if not looks_like_hf_id(model_id):
        return None
    token = token or os.getenv("HF_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        with httpx.Client(timeout=HF_TIMEOUT_S) as client:
            r = client.get(f"{HF_API_BASE}/models/{model_id}", headers=headers)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            data = r.json()
    except Exception:
        return None

    files = [s.get("rfilename") for s in (data.get("siblings") or []) if s.get("rfilename")]
    tags = data.get("tags") or []
    licence = _extract_licence(tags, data.get("cardData") or {})

    return {
        "licence": licence,
        "files": files[:50],         # cap so the SBOM stays compact
        "size_gb": _estimate_size_gb(data),
        "downloads": data.get("downloads"),
        "likes": data.get("likes"),
        "parent_models": _extract_parents(data),
        "framework": _detect_framework(tags, files),
        "dependencies": _extract_dependencies(data),
        "hf_metadata": {
            "id": data.get("id"),
            "pipeline_tag": data.get("pipeline_tag"),
            "library_name": data.get("library_name"),
            "private": data.get("private", False),
            "gated": data.get("gated", False),
            "last_modified": data.get("lastModified"),
            "tag_count": len(tags),
        },
    }


def _extract_licence(tags: list[str], card_data: dict) -> str:
    explicit = card_data.get("license") or card_data.get("licence")
    if explicit:
        return str(explicit).lower()
    for tag in tags:
        if tag.startswith("license:"):
            return tag.split(":", 1)[1].lower()
    return "unknown"


def _extract_parents(data: dict) -> list[str]:
    card_data = data.get("cardData") or {}
    base = card_data.get("base_model")
    if base is None:
        return []
    if isinstance(base, str):
        return [base]
    if isinstance(base, list):
        return [str(b) for b in base[:5]]
    return []


def _detect_framework(tags: list[str], files: list[str]) -> str:
    if "library:transformers" in tags or any("config.json" in f for f in files):
        return "transformers"
    if any(f.endswith(".gguf") for f in files):
        return "llama.cpp"
    if any(f.endswith(".onnx") for f in files):
        return "onnx"
    if any(f.endswith(".safetensors") for f in files):
        return "transformers/safetensors"
    if any(f.endswith(".bin") or f.endswith(".pt") or f.endswith(".pth") for f in files):
        return "pytorch"
    return "unknown"


def _estimate_size_gb(data: dict) -> float | None:
    """HF doesn't ship a clean total-size field; best-effort from
    the disk usage when available, else None."""
    usage = data.get("usedStorage") or data.get("storage")
    if isinstance(usage, (int, float)) and usage > 0:
        return round(usage / (1024 ** 3), 2)
    return None


def _extract_dependencies(data: dict) -> list[str]:
    """Hint dependencies from the tags + library_name. Used by the
    CVE matcher in supply_chain.scan_model()."""
    deps = []
    lib = data.get("library_name")
    if lib == "transformers":
        deps.append("transformers")
    elif lib == "diffusers":
        deps.append("diffusers")
    if any("library:peft" in t for t in (data.get("tags") or [])):
        deps.append("peft")
    if any("library:bitsandbytes" in t for t in (data.get("tags") or [])):
        deps.append("bitsandbytes")
    return deps


def runner_info() -> dict:
    return {
        "client": "huggingface_hub_live",
        "version": "0.1.0",
        "base_url": HF_API_BASE,
        "timeout_s": HF_TIMEOUT_S,
        "has_token": bool(os.getenv("HF_TOKEN")),
        "fallback": "user-supplied spec when HF API unreachable",
    }
