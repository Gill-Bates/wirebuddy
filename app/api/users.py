#!/usr/bin/env python3
#
# app/api/users.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""User management API routes."""

from __future__ import annotations

import base64
import io
import logging
import sqlite3

import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response

from ..db.sqlite_auth import (
    delete_user_tokens,
)
from ..db.sqlite_runtime import transaction
from ..db.sqlite_users import (
    LastAdminError,
    UpdateResult,
    confirm_user_otp,
    create_user as db_create_user,
    decrypt_otp_secret,
    delete_user as db_delete_user,
    disable_user_otp,
    get_all_users,
    get_user_by_id,
    set_user_otp_secret,
    update_user as db_update_user,
)
from ..models.users import (
    AdminPasswordResetRequest,
    OTPConfirmRequest,
    OTPDisableRequest,
    PasswordChangeRequest,
    RequiredPasswordChangeRequest,
    UserCreate,
    UserPublic,
    UserUpdate,
)
from ..utils.coerce import coerce_db_bool
from ..utils.crypto import hash_password, verify_password
from ..utils.deps import get_conn
from ..utils.otp import (
    build_provisioning_uri,
    generate_otp_secret,
    generate_recovery_codes,
    serialize_recovery_codes,
    verify_otp,
)
from ..utils.rate_limit import RATE_LIMIT_AUTH, limiter
from .auth import get_current_user, require_admin, store_recovery_download
from .response import ok_response

logger = logging.getLogger(__name__)

router = APIRouter(tags=["users"])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _to_qr_data_url(content: str) -> str:
    """Render QR PNG as data URL."""
    img = qrcode.make(content)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _row_to_public(row: sqlite3.Row) -> UserPublic:
    """Convert a SQLite user row into the public response model."""
    return UserPublic(
        id=row["id"],
        username=row["username"],
        is_admin=bool(row["is_admin"]),
        is_active=bool(row["is_active"]),
        otp_enabled=bool(row["otp_enabled"]),
        created_at=row["created_at"],
        last_login_at=row["last_login_at"],
        last_login_ip=row["last_login_ip"],
    )


def _get_user_or_404(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row:
    """Load a user row or raise HTTP 404 when it does not exist."""
    user = get_user_by_id(conn, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def require_self_or_admin(
    user_id: int,              # Injected from path parameter /{user_id}
    current_user: sqlite3.Row = Depends(get_current_user),
) -> sqlite3.Row:
    """Allow access only to the user themself or an admin."""
    if current_user["id"] != user_id and not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    return current_user


def _is_self(user_id: int, current_user: sqlite3.Row) -> bool:
    return int(current_user["id"]) == int(user_id)


def _require_self(user_id: int, current_user: sqlite3.Row) -> None:
    if not _is_self(user_id, current_user):
        raise HTTPException(status_code=403, detail="OTP setup must be completed by the user")


def _update_password_and_revoke_tokens(
    conn: sqlite3.Connection,
    user_id: int,
    new_password: str,
    *,
    must_change_password: bool,
) -> UpdateResult:
    if not new_password:
        raise ValueError("Password must not be blank")

    cur = conn.execute(
        """
        UPDATE users
        SET password_hash = ?, must_change_password = ?
        WHERE id = ?
        """,
        (hash_password(new_password), int(must_change_password), user_id),
    )
    if cur.rowcount == 0:
        return UpdateResult.NOT_FOUND

    delete_user_tokens(conn, user_id)
    return UpdateResult.SUCCESS


# ─────────────────────────────────────────────────────────────────────────────
# User CRUD
# ─────────────────────────────────────────────────────────────────────────────


@router.get("")
@limiter.limit(RATE_LIMIT_AUTH)
def list_users(
    request: Request,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row = Depends(require_admin),
):
    """List all users (admin only)."""
    rows = get_all_users(conn)
    data = [_row_to_public(row) for row in rows]
    return ok_response(data=data)


@router.post("", status_code=201)
@limiter.limit(RATE_LIMIT_AUTH)
def create_user(
    request: Request,
    payload: UserCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(require_admin),
):
    """Create a new user (admin only)."""
    try:
        user_id = db_create_user(
            conn,
            username=payload.username,
            password=payload.password,
            is_admin=payload.is_admin,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    
    if user_id is None:
        raise HTTPException(status_code=409, detail="Username already exists")
    
    user = get_user_by_id(conn, user_id)
    if not user:
        raise HTTPException(status_code=500, detail="User creation failed")
    
    logger.info("USER_CREATED username=%s by_admin_id=%d", payload.username, current_user["id"])
    return ok_response(data=_row_to_public(user))


@router.get("/{user_id}")
def get_user(
    user_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row = Depends(require_self_or_admin),
):
    """Get a user by ID.
    
    Users can view their own profile, admins can view anyone.
    """
    user = _get_user_or_404(conn, user_id)
    
    return ok_response(data=_row_to_public(user))


@router.patch("/{user_id}")
@limiter.limit(RATE_LIMIT_AUTH)
def update_user(
    request: Request,
    user_id: int,
    payload: UserUpdate,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(require_self_or_admin),
):
    """Update a user.
    
    Users can update their own username.
    Admins can update anyone and change admin/active status.
    Note: Password updates must use the /change-password endpoint.
    """
    is_self = current_user["id"] == user_id
    is_admin = bool(current_user["is_admin"])
    
    if not is_admin:
        if payload.is_admin is not None or payload.is_active is not None:
            raise HTTPException(status_code=403, detail="Cannot change admin/active status")
    
    # Prevent admins from removing their own admin rights (safety)
    if is_self and payload.is_admin is False:
        raise HTTPException(status_code=400, detail="Cannot remove your own admin rights")
    
    # Prevent admins from deactivating themselves (safety)
    if is_self and payload.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    
    result = db_update_user(
        conn,
        user_id,
        username=payload.username,
        is_admin=payload.is_admin,
        is_active=payload.is_active,
    )
    
    if result == UpdateResult.NOT_FOUND:
        raise HTTPException(status_code=404, detail="User not found")
    if result == UpdateResult.CONFLICT:
        raise HTTPException(status_code=409, detail="Username already exists")
    if result == UpdateResult.LAST_ADMIN:
        raise HTTPException(status_code=400, detail="Cannot remove the last admin")
    
    updated = _get_user_or_404(conn, user_id)
    logger.info("USER_UPDATED user_id=%d by_user=%d", user_id, current_user["id"])
    return ok_response(data=_row_to_public(updated))


@router.delete("/{user_id}", status_code=204, response_class=Response)
@limiter.limit(RATE_LIMIT_AUTH)
def delete_user(
    request: Request,
    user_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(require_admin),
):
    """Delete a user (admin only)."""
    if current_user["id"] == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    try:
        with transaction(conn, immediate=True):
            deleted = db_delete_user(conn, user_id)
            if not deleted:
                raise HTTPException(status_code=404, detail="User not found")
            delete_user_tokens(conn, user_id)
    except LastAdminError:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin")
    
    logger.info("USER_DELETED user_id=%d by_admin=%d", user_id, current_user["id"])
    return Response(status_code=204)


# ─────────────────────────────────────────────────────────────────────────────
# Password Management
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/{user_id}/change-password")
@limiter.limit(RATE_LIMIT_AUTH)
def change_password(
    request: Request,
    user_id: int,
    payload: PasswordChangeRequest,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(get_current_user),
):
    """Change a user's own password."""
    if current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    with transaction(conn, immediate=True):
        user = _get_user_or_404(conn, user_id)
        if not verify_password(payload.current_password, user["password_hash"]):
            raise HTTPException(status_code=422, detail="Current password incorrect")
        result = _update_password_and_revoke_tokens(
            conn,
            user_id,
            payload.new_password,
            must_change_password=False,
        )
        if result == UpdateResult.NOT_FOUND:
            raise HTTPException(status_code=404, detail="User not found")

    logger.info("PASSWORD_CHANGED user_id=%d by_user=%d", user_id, current_user["id"])
    release_bootstrap_gate = getattr(request.app.state, "bootstrap_gate_release", None)
    if callable(release_bootstrap_gate) and getattr(request.app.state, "bootstrap_gate_active", False):
        release_bootstrap_gate()
    return ok_response(message="Password changed successfully")


@router.post("/me/complete-required-change")
@limiter.limit(RATE_LIMIT_AUTH)
def complete_required_password_change(
    request: Request,
    payload: RequiredPasswordChangeRequest,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(get_current_user),
):
    """Complete the mandatory first-login password change for the current user.

    Only valid while the authenticated user still has ``must_change_password``
    set (bootstrap or admin-reset flow). The session already authenticates the
    user, so the temporary password is not re-entered. Normal self-service
    changes must use ``/{user_id}/change-password`` and still require the
    current password.
    """
    if not coerce_db_bool(current_user["must_change_password"]):
        raise HTTPException(status_code=403, detail="No password change is required")

    user_id = current_user["id"]
    with transaction(conn, immediate=True):
        user = _get_user_or_404(conn, user_id)
        if verify_password(payload.new_password, user["password_hash"]):
            raise HTTPException(
                status_code=422,
                detail="New password must be different from the temporary password",
            )
        result = _update_password_and_revoke_tokens(
            conn,
            user_id,
            payload.new_password,
            must_change_password=False,
        )
        if result == UpdateResult.NOT_FOUND:
            raise HTTPException(status_code=404, detail="User not found")

    logger.info("PASSWORD_CHANGED user_id=%d (required change completed)", user_id)
    release_bootstrap_gate = getattr(request.app.state, "bootstrap_gate_release", None)
    if callable(release_bootstrap_gate) and getattr(request.app.state, "bootstrap_gate_active", False):
        release_bootstrap_gate()
    return ok_response(message="Password changed successfully")


@router.post("/{user_id}/reset-password")
@limiter.limit(RATE_LIMIT_AUTH)
def reset_password(
    request: Request,
    user_id: int,
    payload: AdminPasswordResetRequest,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(require_admin),
):
    """Reset a user's password (admin only)."""
    if current_user["id"] == user_id:
        raise HTTPException(status_code=400, detail="Use change-password for your own account")

    with transaction(conn, immediate=True):
        _get_user_or_404(conn, user_id)
        result = _update_password_and_revoke_tokens(
            conn,
            user_id,
            payload.new_password,
            must_change_password=True,
        )
        if result == UpdateResult.NOT_FOUND:
            raise HTTPException(status_code=404, detail="User not found")
    
    logger.info("PASSWORD_RESET user_id=%d by_admin=%d", user_id, current_user["id"])
    return ok_response(message="Password reset successfully")


# ─────────────────────────────────────────────────────────────────────────────
# OTP Management
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/{user_id}/otp/enable")
@limiter.limit(RATE_LIMIT_AUTH)
def enable_user_otp(
    request: Request,
    user_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(require_self_or_admin),
):
    """Prepare OTP setup for a user and return provisioning details."""
    user = _get_user_or_404(conn, user_id)
    is_self = _is_self(user_id, current_user)

    secret = generate_otp_secret()
    provisioning_uri = build_provisioning_uri(secret=secret, username=user["username"])
    if not set_user_otp_secret(conn, user_id, secret):
        raise HTTPException(status_code=500, detail="Unable to initialize OTP setup")

    if not is_self:
        logger.info("USER_OTP_SETUP_PENDING user_id=%d by_admin=%d", user_id, current_user["id"])
        return ok_response(data={"otp_setup_pending": True})

    qr_code_data_url = _to_qr_data_url(provisioning_uri)
    logger.info("USER_OTP_SETUP_STARTED user_id=%d by_user=%d", user_id, current_user["id"])
    return ok_response(
        data={
            "provisioning_uri": provisioning_uri,
            "qr_code_data_url": qr_code_data_url,
        }
    )


@router.post("/{user_id}/otp/confirm")
@limiter.limit(RATE_LIMIT_AUTH)
def confirm_user_otp_setup(
    request: Request,
    user_id: int,
    payload: OTPConfirmRequest,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(require_self_or_admin),
):
    """Confirm OTP setup using first TOTP code and enable OTP."""
    _require_self(user_id, current_user)
    user = _get_user_or_404(conn, user_id)

    # Decrypt OTP secret for verification
    encrypted_secret = str(user["otp_secret"] or "")
    if not encrypted_secret:
        raise HTTPException(status_code=400, detail="OTP setup not initialized")

    plaintext_secret = decrypt_otp_secret(encrypted_secret)
    if not plaintext_secret:
        raise HTTPException(status_code=500, detail="Unable to decrypt OTP secret")

    # verify_otp() implements a used-code window to mitigate replay attacks
    # within the 30-second TOTP validity window. See utils/otp.py for details.
    if not verify_otp(plaintext_secret, payload.code):
        raise HTTPException(status_code=401, detail="Invalid OTP code")

    recovery_codes = generate_recovery_codes()
    serialized_codes = serialize_recovery_codes(recovery_codes)
    if not confirm_user_otp(conn, user_id, serialized_codes):
        raise HTTPException(status_code=500, detail="Unable to enable OTP")

    delete_user_tokens(conn, user_id)
    logger.info("USER_OTP_ENABLED user_id=%d by_user=%d", user_id, current_user["id"])
    recovery_download_token = store_recovery_download(user_id, user["username"], recovery_codes)
    return ok_response(
        data={
            "otp_enabled": True,
            "recovery_download_token": recovery_download_token,
        }
    )


@router.post("/{user_id}/otp/disable")
@limiter.limit(RATE_LIMIT_AUTH)
def disable_user_otp_setup(
    request: Request,
    user_id: int,
    payload: OTPDisableRequest,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(require_self_or_admin),
):
    """Disable OTP for a user after re-authentication.

    Re-authentication requirements:
    - Self: current password OR valid OTP code (either suffices).
    - Admin disabling another user: the admin's OWN password is required
      (payload.current_password is verified against the admin's hash,
      not the target user's hash).
    """
    user = _get_user_or_404(conn, user_id)

    is_self = current_user["id"] == user_id
    password_ok = bool(payload.current_password) and verify_password(
        str(payload.current_password),
        str(current_user["password_hash"]),
    )

    if is_self:
        otp_ok = False
        if payload.code:
            encrypted_secret = str(user["otp_secret"] or "")
            if encrypted_secret:
                plaintext_secret = decrypt_otp_secret(encrypted_secret)
                if plaintext_secret:
                    otp_ok = verify_otp(plaintext_secret, payload.code)
        if not password_ok and not otp_ok:
            raise HTTPException(status_code=401, detail="Password or OTP code invalid")
    elif not password_ok:
        raise HTTPException(status_code=401, detail="Admin password verification required")

    if not disable_user_otp(conn, user_id):
        raise HTTPException(status_code=500, detail="Unable to disable OTP")

    delete_user_tokens(conn, user_id)

    logger.info("USER_OTP_DISABLED user_id=%d by_user=%d", user_id, current_user["id"])
    return ok_response(message="OTP disabled")
