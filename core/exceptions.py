"""
Bootloader Custom Exceptions Module.

This module defines the custom exception hierarchy for the CZAR Bootloader application.
Using specific exceptions rather than generic `Exception` blocks improves reliability
and simplifies debugging by making failure modes explicit.
"""

class BootloaderBaseError(Exception):
    """Base class for all bootloader-specific exceptions."""
    pass

class SerialCommError(BootloaderBaseError):
    """Raised when serial communication fails (e.g., open error, timeout, read/write error)."""
    pass

class DataValidationError(BootloaderBaseError):
    """Raised when hardware handshake data validation (SOP/EOP, CRC, DU format) fails."""
    pass

class DecryptionError(BootloaderBaseError):
    """Raised when decrypting frame data or encryption keys fails."""
    pass

class APIRequestError(BootloaderBaseError):
    """Raised when backend API requests (e.g., DU_Update) fail."""
    pass

class DatabaseError(BootloaderBaseError):
    """Raised on local SQLite database operation failures."""
    pass
