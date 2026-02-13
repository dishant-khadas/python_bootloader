"""
Centralized Logging Configuration for Python Bootloader Application.

This module provides a configured logger instance that all modules should use
instead of print() statements. Features:
- Rotating file handler to prevent disk fill
- Console output for development
- Environment-based log level control
- Structured formatting with timestamps
- Safe handling of sensitive data (no credential logging)

Usage:
    from utils.logger import logger
    
    logger.debug("Detailed diagnostic information")
    logger.info("Normal operation message")
    logger.warning("Warning message")
    logger.error("Error message with context", exc_info=True)
    logger.critical("Critical system failure")
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Determine log directory
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Log file paths
LOG_FILE = LOG_DIR / "bootloader.log"
ERROR_LOG_FILE = LOG_DIR / "bootloader_errors.log"

# Get log level from environment (default: INFO)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
if LOG_LEVEL not in VALID_LEVELS:
    LOG_LEVEL = "INFO"

# Create logger
logger = logging.getLogger("bootloader")
logger.setLevel(getattr(logging, LOG_LEVEL))

# Prevent duplicate handlers if module is reloaded
if not logger.handlers:
    
    # Format with timestamp, level, module, and message
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Console Handler (stdout) - for development
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)  # Show all levels in console
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Rotating File Handler - main log
    # Max 10MB per file, keep 5 backup files (50MB total)
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)  # Log everything to file
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Separate Error Log - only errors and critical
    error_handler = RotatingFileHandler(
        ERROR_LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=3,
        encoding="utf-8"
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    logger.addHandler(error_handler)

# Log startup message
logger.info(f"Logger initialized at {LOG_LEVEL} level")
logger.debug(f"Log files: {LOG_FILE}, {ERROR_LOG_FILE}")


def sanitize_log_message(message: str, sensitive_keywords: list[str] = None) -> str:
    """
    Sanitize log messages to prevent credential leakage.
    
    SECURITY: Use this function when logging data that might contain sensitive info.
    
    Args:
        message: The log message to sanitize
        sensitive_keywords: List of keywords to redact (default: common credential terms)
        
    Returns:
        Sanitized message with sensitive data replaced with [REDACTED]
        
    Example:
        >>> sanitize_log_message("Token: abc123")
        "Token: [REDACTED]"
    """
    if sensitive_keywords is None:
        sensitive_keywords = ["token", "password", "key", "secret", "credential"]
    
    sanitized = message
    for keyword in sensitive_keywords:
        # Case-insensitive replacement of pattern "keyword: value"
        import re
        pattern = rf"({keyword}\s*[:=]\s*)([^\s,]+)"
        sanitized = re.sub(pattern, r"\1[REDACTED]", sanitized, flags=re.IGNORECASE)
    
    return sanitized


# Export logger as default
__all__ = ["logger", "sanitize_log_message"]
