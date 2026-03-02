"""
Bootloader Version Handler - Strategy Pattern for Hardware Version Support.

This module implements the Strategy Pattern to handle different packet formats
and encryption requirements for various bootloader hardware versions (1.0, 1.1, 1.2+).

Design Pattern: Strategy
- Encapsulates version-specific packet creation logic
- Makes it easy to add new versions without modifying existing code (OCP)
- Improves testability by isolating each version's logic

Usage:
    from core.bootloader_version_handler import BootloaderVersionFactory, BootloaderVersionContext
    
    # Create context with required data
    context = BootloaderVersionContext(
        file_hash="abc123...",
        phone_number="+91-1234567890",
        employee_code="CZART013",
        username="DISHANTNALWAYA"
    )
    
    # Get strategy for version
    strategy = BootloaderVersionFactory.get_strategy("1.2")
    
    # Create packet
    packet = strategy.create_packet(context)
    
    # Check if encryption needed
    if strategy.should_encrypt():
        encrypted_packet = encrypt(packet)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
from config import config


def _parse_version(version_str: str) -> tuple[int, ...]:
    """
    Parse a version string like '1.2' into a comparable tuple (1, 2).
    
    Supports any number of dot-separated numeric parts.
    
    Examples:
        _parse_version('1.2')  -> (1, 2)
        _parse_version('1.10') -> (1, 10)
        _parse_version('2.0')  -> (2, 0)
    """
    return tuple(int(p) for p in version_str.split('.'))


@dataclass
class BootloaderVersionContext:
    """
    Data context for bootloader version packet creation.
    
    Contains all necessary information to create a packet for any bootloader version.
    
    Attributes:
        file_hash (str): 64-character hex string of SHA-256 firmware hash.
        phone_number (str): Phone number from AppState (e.g., "+91-7347530726").
        employee_code (str): Employee code for v1.2+ packets. Default "CZART000".
        username (str): Username for v1.2+ packets. Default "TESTUSER".
    """
    file_hash: str
    phone_number: str = ""
    employee_code: str = "CZART000"
    username: str = "TESTUSER"


class BootloaderVersionStrategy(ABC):
    """
    Abstract base class for bootloader version strategies.
    
    Each bootloader version implements this interface to provide
    version-specific packet format and encryption requirements.
    """
    
    @abstractmethod
    def create_packet(self, context: BootloaderVersionContext) -> bytes:
        """
        Create packet for this bootloader version.
        
        Args:
            context: BootloaderVersionContext containing all required data.
            
        Returns:
            bytes: Formatted packet ready for optional encryption.
        """
        pass
    
    @abstractmethod
    def should_encrypt(self) -> bool:
        """
        Whether this version requires packet encryption.
        
        Returns:
            bool: True if encryption required, False otherwise.
        """
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """
        Version identifier for this strategy.
        
        Returns:
            str: Version string (e.g., "1.0", "1.1", "1.2").
        """
        pass
    
    @property
    def packet_size(self) -> int:
        """
        Expected packet size in bytes.
        
        Returns:
            int: Packet size (64 or 512).
        """
        # Default, can be overridden
        return 64


class V1_0VersionHandler(BootloaderVersionStrategy):
    """
    Bootloader v1.0 handler.
    
    Format: 64-byte packet, UNENCRYPTED
    - Legacy format without encryption support
    - Uses format_hash_to_64_bytes utility
    """
    
    def create_packet(self, context: BootloaderVersionContext) -> bytes:
        """Create 64-byte unencrypted packet for v1.0."""
        from core.protocol.packet_builder import format_hash_to_64_bytes
        
        packet = format_hash_to_64_bytes(context.file_hash)
        if packet is False:
            raise ValueError("Failed to format 64-byte packet for v1.0")
        
        return packet
    
    def should_encrypt(self) -> bool:
        """v1.0 does not use encryption."""
        return False
    
    @property
    def version(self) -> str:
        return "1.0"
    
    @property
    def packet_size(self) -> int:
        return 64


class V1_1VersionHandler(BootloaderVersionStrategy):
    """
    Bootloader v1.1 handler.
    
    Format: 64-byte packet, ENCRYPTED
    - Same packet format as v1.0
    - Adds encryption for security
    """
    
    def create_packet(self, context: BootloaderVersionContext) -> bytes:
        """Create 64-byte packet for v1.1 (will be encrypted later)."""
        from core.protocol.packet_builder import format_hash_to_64_bytes
        
        packet = format_hash_to_64_bytes(context.file_hash)
        if packet is False:
            raise ValueError("Failed to format 64-byte packet for v1.1")
        
        return packet
    
    def should_encrypt(self) -> bool:
        """v1.1 requires encryption."""
        return True
    
    @property
    def version(self) -> str:
        return "1.1"
    
    @property
    def packet_size(self) -> int:
        return 64


class V1_2VersionHandler(BootloaderVersionStrategy):
    """
    Bootloader v1.2+ handler.
    
    Format: 512-byte packet, ENCRYPTED
    - Expanded format with metadata
    - Includes employee code, username, phone number
    - CRC16 checksum for integrity
    """
    
    def create_packet(self, context: BootloaderVersionContext) -> bytes:
        """Create 512-byte packet for v1.2+ with metadata."""
        from core.protocol.packet_builder import create_512byte_packet_v12
        
        packet = create_512byte_packet_v12(
            original_hash=context.file_hash,
            employee_code=context.employee_code,
            username=context.username,
            phone_number=context.phone_number,
            device_id=config.DEVICE_ID
        )
        
        return packet
    
    def should_encrypt(self) -> bool:
        """v1.2+ requires encryption."""
        return True
    
    @property
    def version(self) -> str:
        return "1.2"
    
    @property
    def packet_size(self) -> int:
        return 512


class BootloaderVersionFactory:
    """
    Factory for selecting appropriate version handler based on bootloader version.
    
    Centralizes strategy selection logic and allows runtime registration
    of new version handlers.
    """
    
    # Registry of version -> handler class
    _strategies = {
        "1.0": V1_0VersionHandler,
        "1.1": V1_1VersionHandler,
        "1.2": V1_2VersionHandler,
    }
    
    @classmethod
    def get_strategy(cls, version: Optional[str]) -> BootloaderVersionStrategy:
        """
        Get appropriate version handler for bootloader version.
        
        Args:
            version: Bootloader version string (e.g., "1.0", "1.1", "1.2").
                     Can be None for unknown versions.
            
        Returns:
            BootloaderVersionStrategy: Handler instance for the version.
            
        Raises:
            ValueError: If version is None or unsupported.
            
        Examples:
            >>> strategy = BootloaderVersionFactory.get_strategy("1.2")
            >>> isinstance(strategy, V1_2VersionHandler)
            True
        """
        if not version:
            raise ValueError("Bootloader version is unknown - cannot determine version handler")
        
        # Handle >= 1.2 as v1.2 strategy (future versions use same format)
        if _parse_version(version) >= (1, 2):
            return cls._strategies["1.2"]()
        
        # Exact version match
        strategy_class = cls._strategies.get(version)
        if not strategy_class:
            raise ValueError(
                f"Unsupported bootloader version: {version}. "
                f"Supported versions: {', '.join(cls._strategies.keys())}"
            )
        
        return strategy_class()
    
    @classmethod
    def register_strategy(cls, version: str, strategy_class: type):
        """
        Register a new version handler (for future extensions).
        
        Allows dynamic registration of new bootloader version handlers
        without modifying this file.
        
        Args:
            version: Version string (e.g., "1.3").
            strategy_class: Handler class implementing BootloaderVersionStrategy.
            
        Example:
            >>> class V1_3VersionHandler(BootloaderVersionStrategy):
            ...     pass
            >>> BootloaderVersionFactory.register_strategy("1.3", V1_3VersionHandler)
        """
        if not issubclass(strategy_class, BootloaderVersionStrategy):
            raise TypeError(f"{strategy_class} must inherit from BootloaderVersionStrategy")
        
        cls._strategies[version] = strategy_class
    
    @classmethod
    def get_supported_versions(cls) -> list[str]:
        """
        Get list of all supported bootloader versions.
        
        Returns:
            list[str]: List of version strings.
        """
        return list(cls._strategies.keys())


# Public API
__all__ = [
    "BootloaderVersionContext",
    "BootloaderVersionStrategy",
    "V1_0VersionHandler",
    "V1_1VersionHandler",
    "V1_2VersionHandler",
    "BootloaderVersionFactory",
]
