#!/usr/bin/env python3
#
# app/runtime/services/__init__.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""Concrete runtime service implementations.

Each service encapsulates a domain's lifecycle management:
- SQLite: Database connection pool and WAL checkpointing
- DNS: Unbound configuration, process supervision, query ingestion
- WireGuard: Interface startup, shutdown, health monitoring
- TSDB: Time-series storage initialization and maintenance
- Scheduler: Background task scheduling and supervision
"""

from .sqlite import SQLiteService
from .wireguard import WireGuardService
from .dns import DNSService
from .tsdb import TSDBService
from .scheduler import SchedulerService

__all__ = [
    "SQLiteService",
    "WireGuardService",
    "DNSService",
    "TSDBService",
    "SchedulerService",
]
