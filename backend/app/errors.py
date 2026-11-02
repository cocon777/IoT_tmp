"""Domain exceptions and FastAPI exception handlers (TV2 + TV3)."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.broker_admin import BrokerError
from app.lifecycle import Conflict, InvalidTransition, NotFound


class InvalidInput(Exception):
    """Raised when request parameters violate domain validation rules (HTTP 422)."""


class InvalidCredentials(Exception):
    """Raised when login email or password is invalid (HTTP 401)."""

    def __init__(self) -> None:
        super().__init__("Invalid email or password")


class AccountLocked(Exception):
    """Raised when an account is temporarily locked due to failed logins."""

    def __init__(self, minutes: int) -> None:
        super().__init__(
            f"Account is temporarily locked due to multiple failed login attempts ({minutes}m)"
        )
        self.minutes = minutes


class AccountDisabled(Exception):
    """Raised when a locked/disabled account attempts to authenticate (HTTP 403)."""

    def __init__(self) -> None:
        super().__init__("Account is locked or disabled")


class PublishError(Exception):
    """Raised when publishing a command or config to the MQTT broker fails (HTTP 502)."""


class SelfLockout(Exception):
    """Raised when an Admin attempts to lock or demote themselves (HTTP 400/409)."""

    def __init__(self) -> None:
        super().__init__("Cannot lock or demote the last active admin account")


def install_error_handlers(app: FastAPI) -> None:
    """Register domain exception handlers on the FastAPI application."""

    def register(exc_type: type[Exception], status_code: int, headers=None) -> None:
        async def _handler(_request: Request, exc: Exception) -> JSONResponse:
            return JSONResponse(
                status_code=status_code,
                content={"detail": str(exc)},
                headers=headers(exc) if headers else None,
            )

        app.add_exception_handler(exc_type, _handler)

    register(NotFound, 404)
    register(Conflict, 409)
    register(InvalidTransition, 409)
    register(SelfLockout, 400)
    register(InvalidInput, 422)
    register(AccountDisabled, 403)
    register(BrokerError, 502)
    register(PublishError, 502)
    register(InvalidCredentials, 401, lambda _e: {"WWW-Authenticate": "Bearer"})
    register(AccountLocked, 403, lambda e: {"Retry-After": str(e.minutes * 60)})
