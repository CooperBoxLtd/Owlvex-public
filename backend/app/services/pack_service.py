from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from app.services.knowledge_base import _data_root


PACK_DEFINITIONS = {
    "owlvex.issue-pack.v1": {
        "pack_type": "issue-pack",
        "relative_path": Path("issues/owlvex-issue-pack.v1.json"),
        "frameworks": [],
    },
    "owlvex.issue-mapping-pack.v1": {
        "pack_type": "issue-mapping-pack",
        "relative_path": Path("issues/owlvex-issue-mappings.v1.json"),
        "frameworks": [],
    },
    "owlvex.stride.2026.1": {
        "pack_type": "reasoning-profile",
        "relative_path": Path("stride/owlvex.stride.2026.1.json"),
        "frameworks": ["STRIDE"],
    },
}


def _load_pack_json(relative_path: Path) -> dict[str, Any]:
    return json.loads((_data_root() / relative_path).read_text(encoding="utf-8"))


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _build_manifest_entry(pack_id: str, definition: dict[str, Any]) -> dict[str, Any]:
    relative_path = definition["relative_path"]
    absolute_path = _data_root() / relative_path
    payload = _load_pack_json(relative_path)
    canonical_payload = _canonical_json_bytes(payload)

    return {
        "schema_version": "owlvex.rulepack.manifest.v1",
        "pack_id": pack_id,
        "pack_type": definition["pack_type"],
        "pack_version": absolute_path.stat().st_mtime_ns,
        "sha256": hashlib.sha256(canonical_payload).hexdigest(),
        "size_bytes": len(canonical_payload),
        "frameworks": definition["frameworks"],
        "download_path": f"/v1/packs/{pack_id}",
    }


def list_available_packs(allowed_frameworks: list[str]) -> list[dict[str, Any]]:
    allowed = {framework.upper() for framework in allowed_frameworks}
    manifests: list[dict[str, Any]] = []

    for pack_id, definition in PACK_DEFINITIONS.items():
        pack_frameworks = {framework.upper() for framework in definition.get("frameworks", [])}
        if pack_frameworks and not pack_frameworks.issubset(allowed):
            continue
        manifests.append(_build_manifest_entry(pack_id, definition))

    return manifests


def get_pack_artifact(pack_id: str, allowed_frameworks: list[str]) -> dict[str, Any] | None:
    manifests = {manifest["pack_id"]: manifest for manifest in list_available_packs(allowed_frameworks)}
    manifest = manifests.get(pack_id)
    if not manifest:
        return None

    definition = PACK_DEFINITIONS[pack_id]
    artifact = _load_pack_json(definition["relative_path"])
    return {
        "schema_version": "owlvex.rulepack.artifact.v1",
        **manifest,
        "artifact": artifact,
    }
