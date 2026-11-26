"""Structured logging setup for the OSINT monitor."""

import logging
import sys
from pathlib import Path

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    log_file: str | Path = "logs/monitor.log",
    level: int = logging.INFO,
) -> logging.Logger:
    """Configure root logger with stdout and file handlers using standard format."""
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger("easm_monitor")
    root_logger.setLevel(level)

    # Clear existing handlers to ensure idempotent reconfiguration
    if root_logger.handlers:
        root_logger.handlers.clear()

    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    root_logger.propagate = False
    return root_logger


def get_logger(module_name: str) -> logging.Logger:
    """Return a child logger under the application namespace."""
    return logging.getLogger(f"easm_monitor.{module_name}")
