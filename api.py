"""HTTP API blueprint for user metadata and public key directory.

Specification: docs/PROJECT_MAIN.md section 10 and docs/STEP_05_keys.md.

Routes:
- GET  /api/me                  — {username, has_keys}
- POST /api/keys                — upload first public keys (409 if already set)
- PUT  /api/keys                — replace public keys (explicit key reset)
- GET  /api/users/<username>/keys — {username, ecdh_jwk, ecdsa_jwk} (404 if missing)

Security:
- All routes require authentication (@login_required).
- State-changing requests (POST, PUT) require X-CSRFToken header.
- Uploaded JWKs are strictly validated: exactly {kty, crv, x, y}.
- Rejects any JWK containing 'd' or extraneous members with 400.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from audit import audit_event
from extensions import db, limiter
from models import User

api_bp = Blueprint("api", __name__, url_prefix="/api")

_ALLOWED_JWK_KEYS = frozenset({"kty", "crv", "x", "y"})


def _write_audit_log(event: str, username: str) -> None:
    """Use the shared allowlisted audit trail for key management."""
    audit_event(event, username)


def _validate_ec_public_jwk(jwk: Any) -> dict[str, str]:
    """Validate that `jwk` is a clean EC P-256 public key JWK.

    SECURITY (Rule 2 & Step 5):
    - Must contain exactly {kty, crv, x, y}.
    - Any extra member (notably 'd', the private key) is strictly rejected.
    - 'x' and 'y' must decode to exactly 32 bytes from base64url.
    """
    if not isinstance(jwk, dict):
        raise ValueError("JWK must be a JSON object")

    keys = set(jwk.keys())
    if "d" in keys:
        raise ValueError("Private key member 'd' must never be uploaded")

    if keys != _ALLOWED_JWK_KEYS:
        raise ValueError("JWK must contain exactly kty, crv, x, y")

    if jwk.get("kty") != "EC":
        raise ValueError("Expected kty='EC'")

    if jwk.get("crv") != "P-256":
        raise ValueError("Expected crv='P-256'")

    for coord in ("x", "y"):
        val = jwk.get(coord)
        if not isinstance(val, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", val):
            raise ValueError(f"Coordinate '{coord}' is not valid base64url")
        try:
            padded = val + "=" * (-len(val) % 4)
            decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"Coordinate '{coord}' is not valid base64url") from exc
        if len(decoded) != 32:
            raise ValueError(f"Coordinate '{coord}' must be 32 bytes, got {len(decoded)}")
        # SECURITY: reject alternate encodings with nonzero unused padding bits.
        if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != val.rstrip("="):
            raise ValueError(f"Coordinate '{coord}' is not canonical base64url")

    return {
        "kty": str(jwk["kty"]),
        "crv": str(jwk["crv"]),
        "x": str(jwk["x"]),
        "y": str(jwk["y"]),
    }


@api_bp.get("/me")
@login_required
def get_me() -> Any:
    """Return the current user's profile and key status."""
    has_keys = bool(current_user.ecdh_public_jwk and current_user.ecdsa_public_jwk)
    return jsonify({
        "username": current_user.username,
        "has_keys": has_keys,
    })


@api_bp.post("/keys")
@limiter.shared_limit("10 per hour", scope="key_management", methods=["POST", "PUT"])
@login_required
def post_keys() -> Any:
    """Upload initial public keys.

    Returns 409 Conflict if keys already exist.
    """
    if current_user.ecdh_public_jwk or current_user.ecdsa_public_jwk:
        return jsonify({"error": "keys already exist; use PUT /api/keys to reset"}), 409

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid JSON payload"}), 400

    raw_ecdh = data.get("ecdh_jwk")
    raw_ecdsa = data.get("ecdsa_jwk")

    try:
        ecdh_clean = _validate_ec_public_jwk(raw_ecdh)
        ecdsa_clean = _validate_ec_public_jwk(raw_ecdsa)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    current_user.ecdh_public_jwk = json.dumps(ecdh_clean, separators=(",", ":"))
    current_user.ecdsa_public_jwk = json.dumps(ecdsa_clean, separators=(",", ":"))
    db.session.commit()
    _write_audit_log("keys_uploaded", current_user.username)

    return jsonify({"ok": True}), 201


@api_bp.put("/keys")
@limiter.shared_limit("10 per hour", scope="key_management", methods=["POST", "PUT"])
@login_required
def put_keys() -> Any:
    """Replace public keys (explicit key reset)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid JSON payload"}), 400

    raw_ecdh = data.get("ecdh_jwk")
    raw_ecdsa = data.get("ecdsa_jwk")

    try:
        ecdh_clean = _validate_ec_public_jwk(raw_ecdh)
        ecdsa_clean = _validate_ec_public_jwk(raw_ecdsa)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    current_user.ecdh_public_jwk = json.dumps(ecdh_clean, separators=(",", ":"))
    current_user.ecdsa_public_jwk = json.dumps(ecdsa_clean, separators=(",", ":"))
    db.session.commit()
    _write_audit_log("keys_reset", current_user.username)

    return jsonify({"ok": True}), 200


@api_bp.get("/users/<username>/keys")
@limiter.limit("30 per minute")
@login_required
def get_user_keys(username: str) -> Any:
    """Fetch the public keys for a specific user.

    Returns 404 if the user is unknown or has not uploaded keys.
    """
    normalised = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9_]{3,32}", normalised):
        return jsonify({"error": "user not found"}), 404
    user = User.query.filter_by(username=normalised).first()
    if not user:
        return jsonify({"error": "user not found"}), 404

    if not user.ecdh_public_jwk or not user.ecdsa_public_jwk:
        return jsonify({"error": "user has no public keys"}), 404

    try:
        ecdh_jwk = json.loads(user.ecdh_public_jwk)
        ecdsa_jwk = json.loads(user.ecdsa_public_jwk)
    except Exception:
        return jsonify({"error": "failed to decode stored keys"}), 500

    return jsonify({
        "username": user.username,
        "ecdh_jwk": ecdh_jwk,
        "ecdsa_jwk": ecdsa_jwk,
    })
