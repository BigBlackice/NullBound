"""Validated process-level configuration for starting Blackwall."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Sequence


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080


def _host_argument(value: str) -> str:
    host = value.strip()
    if not host:
        raise argparse.ArgumentTypeError("host cannot be empty")
    if any(character.isspace() for character in host) or "/" in host or "\\" in host or "://" in host:
        raise argparse.ArgumentTypeError("host must be an IP address or hostname, not a URL")
    return host


def _port_argument(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Network settings validated before NiceGUI starts."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT

    def __post_init__(self) -> None:
        try:
            host = _host_argument(self.host)
            port = _port_argument(str(self.port))
        except argparse.ArgumentTypeError as error:
            raise ValueError(str(error)) from error
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)

    @classmethod
    def from_args(cls, argv: Sequence[str] | None = None) -> AppConfig:
        parser = argparse.ArgumentParser(description="Run the Blackwall operator console.")
        parser.add_argument(
            "--host",
            type=_host_argument,
            default=DEFAULT_HOST,
            help="bind address (default: 127.0.0.1; use 0.0.0.0 explicitly for LAN access)",
        )
        parser.add_argument(
            "--port",
            type=_port_argument,
            default=DEFAULT_PORT,
            help="TCP port (default: 8080)",
        )
        arguments = parser.parse_args(argv)
        return cls(host=arguments.host, port=arguments.port)

    @property
    def is_loopback(self) -> bool:
        normalized = self.host.strip("[]").casefold()
        if normalized == "localhost":
            return True
        try:
            return ip_address(normalized).is_loopback
        except ValueError:
            return False

    @property
    def remote_access_warning(self) -> str | None:
        if self.is_loopback:
            return None
        return (
            f"Blackwall is listening on {self.host}:{self.port}. "
            "Remote clients can access the host filesystem browser; use only on a trusted network "
            "until authentication is implemented."
        )
