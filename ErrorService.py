"""Centralised SMTP error handling utilities.

This module defines protocol-specific exceptions and provides helper
functions for translating exceptions into SMTP responses. It is designed
so that protocol handlers can raise rich exceptions without worrying about
logging or connection cleanup logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional
import traceback


@dataclass
class SMTPError(Exception):
    """Base exception containing SMTP reply metadata."""

    code: str
    message: str
    log_message: Optional[str] = None
    close: bool = False
    count_error: bool = True

    def __post_init__(self) -> None:
        # Exception expects a string message; prefer log_message for clarity.
        super().__init__(self.log_message or f"{self.code} {self.message}")


class SMTPAuthError(SMTPError):
    """Authentication related failure (typically 535)."""


class SMTPInvalidCommand(SMTPError):
    """Raised when a command sequence or syntax is invalid."""


class SMTPTransientError(SMTPError):
    """Raised for transient delivery or storage issues (4xx codes)."""


class SMTPFatalError(SMTPError):
    """Fatal errors after which the connection should be closed."""

    def __init__(self, code: str, message: str, *, log_message: Optional[str] = None):
        super().__init__(code, message, log_message=log_message, close=True, count_error=True)


class SessionAbort(Exception):
    """Internal sentinel used to abort the current SMTP session loop."""


def handle_exception(
    exc: Exception,
    *,
    session,
    send_reply: Callable[[str], None],
    register_error: Callable[[bool], bool],
    log_exception: Callable[[str], None],
) -> None:
    """Dispatch an exception to the appropriate SMTP response.

    Parameters
    ----------
    exc:
        The exception raised inside the session loop.
    session:
        Arbitrary session state object offering a ``log`` method and ``peer``
        property. The session itself is not mutated here beyond error counting.
    send_reply:
        Callable that writes a full SMTP reply line (including CRLF) to the
        client. It should raise if writing fails.
    register_error:
        Callable taking a ``count`` flag (bool) that returns True when the
        session exceeded the error threshold and the connection should be
        closed. The callable is responsible for updating counters/blocks.
    log_exception:
        Callable used to persist textual log messages (already prefixed).

    Raises
    ------
    SessionAbort
        Raised when the session loop should terminate after the reply is sent.
    """

    if isinstance(exc, SMTPError):
        if exc.log_message:
            log_exception(exc.log_message)
        should_close = exc.close or (exc.count_error and register_error(True))
        send_reply(f"{exc.code} {exc.message}")
        if should_close:
            raise SessionAbort()
        return

    # Unexpected exception path: log full traceback, count the error, and close.
    tb = traceback.format_exc()
    log_exception(f"Unexpected exception: {exc}\n{tb}")
    threshold_hit = register_error(True)
    # Once we land here the connection is no longer trustworthy; close it.
    reply = "421 Too many bad commands, closing connection" if threshold_hit else "500 Something wrong so bye."
    send_reply(reply)
    raise SessionAbort()
