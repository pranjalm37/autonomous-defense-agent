"""Handler registry — maps ActionType → its handler."""
from __future__ import annotations

from app.models.action import ActionType
from app.services.response.framework import ActionHandler
from app.services.response.handlers.block_ip import BlockIPHandler
from app.services.response.handlers.disable_account import DisableAccountHandler
from app.services.response.handlers.generate_ticket import GenerateTicketHandler
from app.services.response.handlers.increase_logging import IncreaseLoggingHandler
from app.services.response.handlers.send_alert import SendAlertHandler

_HANDLERS: list[ActionHandler] = [
    SendAlertHandler(),
    BlockIPHandler(),
    DisableAccountHandler(),
    GenerateTicketHandler(),
    IncreaseLoggingHandler(),
]


def default_handlers() -> dict[ActionType, ActionHandler]:
    return {h.action_type: h for h in _HANDLERS}


__all__ = ["default_handlers"]
