"""
Action framework — the contract every response action implements.

A response action is a *reversible-where-possible* side effect on an external
system (firewall, IAM directory, ticketing, SIEM, notifier). Each one is an
`ActionHandler` with two halves:

    execute(action, ctx)   perform the side effect; return a rollback_token that
                           captures everything needed to undo it later.
    rollback(action, ctx)  reverse the side effect using that token.

Handlers are pure with respect to the database: they act on the injected backends
in `ActionContext` and mutate nothing in the ORM. The ResponseEngine owns status
transitions, logging, and persistence. This keeps every handler unit-testable
with simulated backends and no DB.

Safety lives here too: a handler raises `GuardrailError` to *refuse* an unsafe
request (blocking an internal IP, disabling a protected account). A guardrail
refusal is not a failure of the system — it is the system working.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.mcp_server.providers import FirewallBackend
from app.models.action import ActionType
from app.services.response.backends import (
    AccountDirectory,
    LoggingController,
    Notifier,
    TicketingSystem,
)


class GuardrailError(Exception):
    """A safety guardrail refused to perform the action."""


@dataclass
class ExecutionResult:
    ok: bool
    summary: str
    output: dict = field(default_factory=dict)
    rollback_token: dict | None = None     # what rollback() needs to undo this
    error: str | None = None


@dataclass
class ActionContext:
    firewall: FirewallBackend
    notifier: Notifier
    ticketing: TicketingSystem
    directory: AccountDirectory
    logging_ctrl: LoggingController
    # Safety policy
    ip_allowlist: set[str] = field(default_factory=set)
    protected_accounts: set[str] = field(default_factory=lambda: {"admin", "root", "breakglass"})
    dry_run: bool = False


class ActionHandler(ABC):
    action_type: ActionType
    reversible: bool = True
    safe_default: bool = False   # True = no human approval required by default

    @abstractmethod
    async def execute(self, action, ctx: ActionContext) -> ExecutionResult: ...

    async def rollback(self, action, ctx: ActionContext) -> ExecutionResult:
        # Default for irreversible actions (e.g. a sent notification).
        return ExecutionResult(ok=False, summary="this action cannot be rolled back",
                               error="not reversible")

    @staticmethod
    def _rollback_token(action) -> dict:
        return (action.parameters or {}).get("_rollback", {}) or {}
