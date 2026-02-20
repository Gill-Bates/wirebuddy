#!/usr/bin/env python3
#
# app/dns/ingestion.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS query log ingestion pipeline for TSDB.

This module has been refactored into smaller components:
- ingestion_parser: Parse Unbound log lines
- ingestion_retention: Log retention management
- ingestion_tailer: Log tailer with crash recovery
- ingestion_writer: TSDB batch writer
- ingestion_daemon: Pipeline orchestrator

This file provides backwards-compatible exports.
"""

from __future__ import annotations

# Re-export all public APIs
from .ingestion_daemon import run_dns_ingestion
from .ingestion_parser import DnsQueryPoint, parse_unbound_line
from .ingestion_retention import (
	DNS_LOG_RETENTION_OPTIONS,
	DEFAULT_DNS_LOG_RETENTION_DAYS,
	enforce_dns_log_retention,
	normalize_dns_log_retention_days,
)
from .ingestion_writer import read_recent_queries

__all__ = [
	"DnsQueryPoint",
	"run_dns_ingestion",
	"read_recent_queries",
	"enforce_dns_log_retention",
	"normalize_dns_log_retention_days",
	"parse_unbound_line",
	"DNS_LOG_RETENTION_OPTIONS",
	"DEFAULT_DNS_LOG_RETENTION_DAYS",
]
