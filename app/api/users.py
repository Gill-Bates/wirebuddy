#!/usr/bin/env python3
#
# app/api/users.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""User management API routes."""

from __future__ import annotations

from ..db.sqlite_auth import (
	delete_user_tokens,
)
from ..db.sqlite_users import (
	count_admins,
	create_user as db_create_user,
	delete_user as db_delete_user,
	get_all_users,
	get_user_by_id,
	get_user_by_username,
	update_user as db_update_user,
)

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException

from ..models.users import PasswordChangeRequest, UserCreate, UserPublic, UserUpdate
from ..utils.crypto import verify_password
from ..utils.deps import get_conn
from .auth import get_current_user, require_admin
from .response import ok_response

_log = logging.getLogger(__name__)

router = APIRouter(tags=["users"])


def _row_to_public(row: sqlite3.Row) -> UserPublic:
	"""Convert a SQLite user row into the public response model."""
	return UserPublic(
		id=row["id"],
		username=row["username"],
		is_admin=bool(row["is_admin"]),
		is_active=bool(row["is_active"]),
		created_at=row["created_at"],
		last_login_at=row["last_login_at"],
		last_login_ip=row["last_login_ip"],
	)


@router.get("")
def list_users(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""List all users (admin only)."""
	rows = get_all_users(conn)
	data = [_row_to_public(row) for row in rows]
	return ok_response(data=data)


@router.post("", status_code=201)
def create_user(
    payload: UserCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(require_admin),
):
    """Create a new user (admin only)."""
    # Check if username exists
    existing = get_user_by_username(conn, payload.username)
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")
    
    user_id = db_create_user(
        conn,
        username=payload.username,
        password=payload.password,
        is_admin=payload.is_admin,
    )
    
    user = get_user_by_id(conn, user_id)
    if not user:
        raise HTTPException(status_code=500, detail="User creation failed")
    
    _log.info("USER_CREATED username=%s by_admin_id=%d", payload.username, current_user["id"])
    return ok_response(data=_row_to_public(user))


@router.get("/{user_id}")
def get_user(
	user_id: int,
	conn: sqlite3.Connection = Depends(get_conn),
	current_user: sqlite3.Row = Depends(get_current_user),
):
	"""Get a user by ID.
	
	Users can view their own profile, admins can view anyone.
	"""
	if current_user["id"] != user_id and not current_user["is_admin"]:
		raise HTTPException(status_code=403, detail="Not authorized")
	
	user = get_user_by_id(conn, user_id)
	if not user:
		raise HTTPException(status_code=404, detail="User not found")
	
	return ok_response(data=_row_to_public(user))


@router.patch("/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(get_current_user),
):
    """Update a user.
    
    Users can update their own username.
    Admins can update anyone and change admin/active status.
    Note: Password updates must use the /change-password endpoint.
    """
    is_self = current_user["id"] == user_id
    is_admin = bool(current_user["is_admin"])
    
    if not is_self and not is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Non-admins cannot change admin/active status
    if not is_admin:
        if payload.is_admin is not None or payload.is_active is not None:
            raise HTTPException(status_code=403, detail="Cannot change admin/active status")
    
    # Prevent admins from removing their own admin rights (safety)
    if is_self and payload.is_admin is False:
        raise HTTPException(status_code=400, detail="Cannot remove your own admin rights")
    
    # Prevent admins from deactivating themselves (safety)
    if is_self and payload.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    
    user = get_user_by_id(conn, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check username uniqueness
    if payload.username and payload.username != user["username"]:
        existing = get_user_by_username(conn, payload.username)
        if existing:
            raise HTTPException(status_code=409, detail="Username already exists")
    
    # Prevent removing admin rights from the last admin
    if payload.is_admin is False and user["is_admin"]:
        if count_admins(conn) <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove the last admin")
    
    db_update_user(
        conn,
        user_id,
        username=payload.username,
        is_admin=payload.is_admin,
        is_active=payload.is_active,
    )
    
    updated = get_user_by_id(conn, user_id)
    _log.info("USER_UPDATED user_id=%d by_user=%d", user_id, current_user["id"])
    return ok_response(data=_row_to_public(updated))


@router.delete("/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(require_admin),
):
    """Delete a user (admin only)."""
    if current_user["id"] == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    user = get_user_by_id(conn, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent deleting the last admin
    if user["is_admin"] and count_admins(conn) <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin")
    
    db_delete_user(conn, user_id)
    _log.info("USER_DELETED user_id=%d by_admin=%d", user_id, current_user["id"])


@router.post("/{user_id}/change-password")
def change_password(
    user_id: int,
    payload: PasswordChangeRequest,
    conn: sqlite3.Connection = Depends(get_conn),
    current_user: sqlite3.Row = Depends(get_current_user),
):
    """Change a user's password.
    
    All users must provide their current password when changing their own.
    Admins can reset other users' passwords without knowing the current one.
    """
    is_self = current_user["id"] == user_id
    is_admin = bool(current_user["is_admin"])
    
    if not is_self and not is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    user = get_user_by_id(conn, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # All users must verify current password when changing their own (including admins)
    if is_self:
        if not payload.current_password or not verify_password(payload.current_password, user["password_hash"]):
            raise HTTPException(status_code=422, detail="Current password incorrect")
    
    db_update_user(conn, user_id, password=payload.new_password)
    
    # Invalidate all existing sessions for this user
    delete_user_tokens(conn, user_id)
    
    _log.info("PASSWORD_CHANGED user_id=%d by_user=%d", user_id, current_user["id"])
    return ok_response(message="Password changed successfully")
