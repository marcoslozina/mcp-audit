"""Fixture with an obviously hardcoded secret, used to exercise
mcp_audit's `SecretsCheck` end-to-end (via `mcp-audit scan --source-dir`).

Not a real config, not a real key — purely a test fixture. Do not model
real configuration files on this.
"""

from __future__ import annotations

API_KEY = "sk-abcdef1234567890abcdef1234567890"

DATABASE_URL = "postgres://app_user:hunter2@db.internal:5432/app"
