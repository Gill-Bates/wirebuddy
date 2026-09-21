#!/usr/bin/env python3
#
# app/runtime/services/__init__.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Concrete runtime service implementations.

Each service encapsulates a domain's lifecycle management:
- SQLite: Database connection pool and WAL checkpointing
- DNS: Unbound configuration, process supervision, query ingestion
- WireGuard: Interface startup, shutdown, health monitoring
- TSDB: Time-series storage initialization and maintenance
- Scheduler: Background task scheduling and supervision
"""

from .dns import DNSService
from .scheduler import SchedulerService
from .sqlite import SQLiteService
from .tsdb import TSDBService
from .wireguard import WireGuardService

__all__ = [
    "DNSService",
    "SQLiteService",
    "SchedulerService",
    "TSDBService",
    "WireGuardService",
]
