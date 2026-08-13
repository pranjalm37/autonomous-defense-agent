"""Build the ActionContext — wires the (simulated by default) backends + safety policy."""
from __future__ import annotations

from app.mcp_server.providers import SimulatedFirewall
from app.services.response.backends import (
    SimulatedDirectory,
    SimulatedLoggingController,
    SimulatedNotifier,
    SimulatedTicketing,
)
from app.services.response.framework import ActionContext


def build_response_context(*, dry_run: bool = False) -> ActionContext:
    protected = {"admin", "root", "breakglass"}
    allowlist: set[str] = set()
    try:
        from app.config import get_settings
        s = get_settings()
        protected |= set(getattr(s, "response_protected_accounts", []) or [])
        allowlist |= set(getattr(s, "response_ip_allowlist", []) or [])
    except Exception:
        pass

    return ActionContext(
        firewall=SimulatedFirewall(),
        notifier=SimulatedNotifier(),
        ticketing=SimulatedTicketing(),
        directory=SimulatedDirectory(),
        logging_ctrl=SimulatedLoggingController(),
        ip_allowlist=allowlist,
        protected_accounts=protected,
        dry_run=dry_run,
    )
