#!/usr/bin/env python3
#
# app/runtime/__init__.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""Runtime supervision and service orchestration.

This package provides the application kernel infrastructure:
- Service container for dependency injection
- Lifecycle management (bootstrap, startup, shutdown)
- Signal handling and graceful termination
- Runtime service protocols and base classes

Architecture layers:
    Web Layer (FastAPI) → Control Plane (Services) → Data Plane (Repositories)
                              ↓
                    Runtime Supervisor (this package)
"""

from .service import RuntimeService, ServiceState
from .container import ServiceContainer
from .lifecycle import LifecycleManager
from .signals import SignalManager

__all__ = [
    "RuntimeService",
    "ServiceState",
    "ServiceContainer",
    "LifecycleManager",
    "SignalManager",
]
