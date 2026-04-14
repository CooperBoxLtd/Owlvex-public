from __future__ import annotations

import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import get_settings
from app.services.knowledge_base import _data_root

logger = logging.getLogger(__name__)

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
    "owlvex.remediation-pack.v1": {
        "pack_type": "remediation-pack",
        "relative_path": Path("remediation/owlvex-remediation-pack.v1.json"),
        "frameworks": [],
    },
    "owlvex.stride.2026.1": {
        "pack_type": "reasoning-profile",
        "relative_path": Path("stride/owlvex.stride.2026.1.json"),
        "frameworks": ["STRIDE"],
    },
}


def _normalize_frameworks(frameworks: list[str]) -> list[str]:
    return sorted({framework.upper() for framework in frameworks})

DEV_PACK_SIGNING_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPdEILhBPJPbXD/zvw5DvKx47+DNVrNmDJWYbKLfFTze
-----END PRIVATE KEY-----"""
DEFAULT_SIGNING_KEY_ID = "owlvex-dev-ed25519-2026-04"


def _load_pack_json(relative_path: Path) -> dict[str, Any]:
    return json.loads((_data_root() / relative_path).read_text(encoding="utf-8"))


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _get_signing_private_key_pem() -> str:
    settings = get_settings()
    configured = settings.owlvex_pack_signing_private_key_pem.strip()
    if configured:
        return configured
    if settings.is_development:
        return DEV_PACK_SIGNING_PRIVATE_KEY_PEM
    raise RuntimeError("OWLVEX pack signing private key is required outside development")


def _get_signing_key_id() -> str:
    settings = get_settings()
    configured = settings.owlvex_pack_signing_key_id.strip()
    if configured:
        return configured
    if settings.is_development:
        return DEFAULT_SIGNING_KEY_ID
    raise RuntimeError("OWLVEX pack signing key id is required outside development")


def _sign_manifest_payload(payload: dict[str, Any]) -> str:
    private_key = serialization.load_pem_private_key(
        _get_signing_private_key_pem().encode("utf-8"),
        password=None,
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Owlvex pack signing key must be an Ed25519 private key")

    signature = private_key.sign(_canonical_json_bytes(payload))
    return base64.b64encode(signature).decode("ascii")


def _build_manifest_entry(pack_id: str, definition: dict[str, Any], licence_scope: dict[str, Any]) -> dict[str, Any]:
    relative_path = definition["relative_path"]
    absolute_path = _data_root() / relative_path
    payload = _load_pack_json(relative_path)
    canonical_payload = _canonical_json_bytes(payload)

    unsigned_entry = {
        "schema_version": "owlvex.rulepack.manifest.v1",
        "pack_id": pack_id,
        "pack_type": definition["pack_type"],
        "pack_version": absolute_path.stat().st_mtime_ns,
        "issued_at": definition.get("issued_at", "2026-04-14T00:00:00Z"),
        "expires_at": definition.get("expires_at", "2026-05-14T00:00:00Z"),
        "sha256": hashlib.sha256(canonical_payload).hexdigest(),
        "size_bytes": len(canonical_payload),
        "frameworks": definition["frameworks"],
        "licence_scope": licence_scope,
        "download_path": f"/v1/packs/{pack_id}",
        "signature_algorithm": "ed25519",
        "key_id": _get_signing_key_id(),
    }
    return {
        **unsigned_entry,
        "signature": _sign_manifest_payload(unsigned_entry),
    }


def list_available_packs(plan: str, allowed_frameworks: list[str]) -> list[dict[str, Any]]:
    allowed = {framework.upper() for framework in allowed_frameworks}
    manifests: list[dict[str, Any]] = []
    licence_scope = {
        "plan": plan,
        "frameworks": _normalize_frameworks(allowed_frameworks),
    }

    for pack_id, definition in PACK_DEFINITIONS.items():
        pack_frameworks = {framework.upper() for framework in definition.get("frameworks", [])}
        if pack_frameworks and not pack_frameworks.issubset(allowed):
            continue
        manifests.append(_build_manifest_entry(pack_id, definition, licence_scope))

    return manifests


def get_pack_artifact(pack_id: str, plan: str, allowed_frameworks: list[str]) -> dict[str, Any] | None:
    manifests = {manifest["pack_id"]: manifest for manifest in list_available_packs(plan, allowed_frameworks)}
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


def get_pack_signing_posture() -> dict[str, Any]:
    settings = get_settings()
    key_id = _get_signing_key_id()
    return {
        "environment": settings.environment,
        "key_id": key_id,
        "using_dev_fallback": settings.is_development and key_id == DEFAULT_SIGNING_KEY_ID,
    }
