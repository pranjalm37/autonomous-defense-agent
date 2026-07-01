"""
Response backends — the external systems actions act on.

All defaults are SAFE in-memory simulations: they record what *would* happen
without touching real infrastructure. Production swaps in real implementations of
the same protocols (Slack/PagerDuty notifier, Jira/ServiceNow ticketing,
Okta/AD directory, SIEM logging controller) — the handlers never change.

The firewall backend is reused from the MCP server (`SimulatedFirewall`).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Notifier (Send alert) ─────────────────────────────────────────────────────
class Notifier(Protocol):
    async def send(self, channel: str, subject: str, body: str) -> dict: ...


class SimulatedNotifier:
    def __init__(self):
        self.sent: list[dict] = []

    async def send(self, channel: str, subject: str, body: str) -> dict:
        rec = {"channel": channel, "subject": subject, "body": body,
               "sent_at": _now(), "simulated": True}
        self.sent.append(rec)
        return rec


# ── Ticketing (Generate ticket) ───────────────────────────────────────────────
class TicketingSystem(Protocol):
    async def create(self, title: str, body: str, severity: str) -> dict: ...
    async def close(self, ticket_id: str) -> dict: ...


class SimulatedTicketing:
    def __init__(self):
        self.tickets: dict[str, dict] = {}
        self._counter = 0

    async def create(self, title: str, body: str, severity: str) -> dict:
        self._counter += 1
        tid = f"SOC-{self._counter:04d}"
        ticket = {"id": tid, "title": title, "body": body, "severity": severity,
                  "status": "open", "created_at": _now(), "simulated": True}
        self.tickets[tid] = ticket
        return ticket

    async def close(self, ticket_id: str) -> dict:
        t = self.tickets.get(ticket_id)
        if t:
            t["status"] = "closed"
        return {"id": ticket_id, "status": "closed", "found": t is not None}


# ── Account directory (Disable account) ───────────────────────────────────────
class AccountDirectory(Protocol):
    async def disable(self, username: str) -> dict: ...
    async def enable(self, username: str) -> dict: ...
    def is_disabled(self, username: str) -> bool: ...


class SimulatedDirectory:
    def __init__(self):
        self.disabled: set[str] = set()

    async def disable(self, username: str) -> dict:
        self.disabled.add(username)
        return {"username": username, "status": "disabled", "at": _now(), "simulated": True}

    async def enable(self, username: str) -> dict:
        self.disabled.discard(username)
        return {"username": username, "status": "enabled", "at": _now(), "simulated": True}

    def is_disabled(self, username: str) -> bool:
        return username in self.disabled


# ── Logging controller (Increase logging) ─────────────────────────────────────
class LoggingController(Protocol):
    async def get_level(self, target: str) -> str: ...
    async def set_level(self, target: str, level: str) -> str: ...


class SimulatedLoggingController:
    LEVELS = ("error", "warn", "info", "debug", "trace")   # increasing verbosity

    def __init__(self):
        self._levels: dict[str, str] = {}

    async def get_level(self, target: str) -> str:
        return self._levels.get(target, "info")

    async def set_level(self, target: str, level: str) -> str:
        previous = await self.get_level(target)
        if level not in self.LEVELS:
            level = "debug"
        self._levels[target] = level
        return previous
