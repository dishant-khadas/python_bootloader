"""
Global Application State Management Module.

This module provides a thread-safe singleton class for managing global application state.
It serves as a single source of truth for all application data including authentication,
DU information, firmware selection, and encryption keys.

Key Features:
    - Singleton pattern: Only one instance exists across the application
    - Thread-safe: All access protected by threading.Lock
    - Type validation: Ensures data integrity
    - Bootloader version extraction: Automatically parses version from 512-byte data
    - Clear API: Properties with getters/setters and type hints

Usage:
    from core.app_state import AppState
    
    # Get singleton instance
    state = AppState.get_instance()
    
    # Set authentication
    state.set_auth(phone="1234567890", token="jwt_token_here")
    
    # Set DU data after handshake
    state.set_du_data(
        du_number="99123456",
        display_number="12345678",
        raw_bytes=buffer_bytes,  # 512 bytes
        is_encrypted=True,
        encryption_key=key_bytes
    )
    
    # Access state
    print(state.bootloader_version_string)  # "11.8"
    print(state.jwt_token)
    
    # Reset on logout
    state.reset()
"""

import threading
from typing import Optional
from utils.logger import logger
from core.protocol.constants import FW_V1_OFFSET, FW_V2_OFFSET, HARDWARE_TYPE_OFFSET, VALID_HARDWARE_TYPES, HARDWARE_TYPE_NAMES


class AppState:
    """
    Singleton class for managing global application state.
    
    This class maintains all application state including authentication credentials,
    DU/Display information, bootloader version, encryption keys, and firmware selection.
    All access is thread-safe using a lock.
    
    Attributes:
        phone_number (str | None): User's phone number for authentication.
        jwt_token (str | None): JWT authentication token.
        du_number (str | None): DU serial number (8 digits, starts with 99).
        display_number (str | None): Display serial number (8 digits, starts with 12).
        raw_512_bytes (bytes | None): Complete 512-byte handshake data.
        bootloader_version (tuple[int, int] | None): Bootloader version as (v1, v2).
        bootloader_version_string (str | None): Bootloader version as string (e.g., "11.8").
        is_encryption_enabled (bool): Whether encryption is enabled for this DU.
        encryption_key (bytes | None): 32-byte AES encryption key.
        selected_file_id (str | None): Selected firmware file ID.
        selected_file_name (str | None): Selected firmware file name.
        du_options (dict | None): Response from DU_Update API.
    """
    
    _instance: Optional['AppState'] = None
    _lock_class = threading.Lock()  # Class-level lock for singleton creation
    
    def __init__(self):
        """
        Private constructor. Use get_instance() instead.
        
        Initializes all state variables to None/False and creates instance lock.
        """
        if AppState._instance is not None:
            raise RuntimeError("Use AppState.get_instance() instead of constructor")
        
        # Instance lock for thread-safe property access
        self._lock = threading.Lock()
        
        # Authentication
        self._phone_number: Optional[str] = None
        self._jwt_token: Optional[str] = None
        self._service_engineer: Optional[str] = None
        self._employee_id: Optional[str] = None
        
        # DU/Display Information (from 512-byte handshake)
        self._du_number: Optional[str] = None
        self._display_number: Optional[str] = None
        self._raw_512_bytes: Optional[bytes] = None
        
        # Bootloader/Firmware Version (extracted from bytes 392-393)
        self._bootloader_version: Optional[tuple[int, int]] = None
        self._bootloader_version_string: Optional[str] = None
        
        # Encryption
        self._is_encryption_enabled: bool = False
        self._encryption_key: Optional[bytes] = None
        
        # Hardware type (v1.2 only: 0x01=display, 0x02=slave_display)
        self._hardware_type: Optional[int] = None
        
        # Firmware Update
        self._selected_file_id: Optional[str] = None
        self._selected_file_name: Optional[str] = None
        self._du_options: Optional[dict] = None
    
    @classmethod
    def get_instance(cls) -> 'AppState':
        """
        Get the singleton instance of AppState.
        
        Thread-safe singleton implementation using double-checked locking.
        
        Returns:
            AppState: The singleton instance.
        """
        if cls._instance is None:
            with cls._lock_class:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    def reset(self):
        """
        Reset all state to initial values.
        
        Useful for logout or error recovery. Clears all authentication,
        DU data, and firmware selection.
        """
        with self._lock:
            self._phone_number = None
            self._jwt_token = None
            self._du_number = None
            self._display_number = None
            self._raw_512_bytes = None
            self._bootloader_version = None
            self._bootloader_version_string = None
            self._is_encryption_enabled = False
            self._encryption_key = None
            self._hardware_type = None
            self._selected_file_id = None
            self._selected_file_name = None
            self._du_options = None
            self._service_engineer = None
            self._employee_id = None
    
    # ========== Authentication Methods ==========
    
    def set_auth(self, phone: str, token: str):
        """
        Set authentication credentials.
        
        Automatically formats phone number to +91-XXXXXXXXXX format.
        
        Args:
            phone (str): User's phone number (will be formatted).
            token (str): JWT authentication token.
        """
        with self._lock:
            # Format phone number as +91-XXXXXXXXXX
            formatted_phone = phone.strip()
            
            if formatted_phone.startswith("+91-"):
                # Already in correct format
                pass
            elif formatted_phone.startswith("+91"):
                # Has +91 but no hyphen, add it
                formatted_phone = "+91-" + formatted_phone[3:]
            elif formatted_phone.startswith("+"):
                # Has different country code, add hyphen after country code if not present
                # For now, keep as is for non-Indian numbers
                pass
            else:
                # No country code, add +91-
                formatted_phone = "+91-" + formatted_phone
            
            self._phone_number = formatted_phone
            self._jwt_token = token
    
    @property
    def phone_number(self) -> Optional[str]:
        """Get user's phone number."""
        with self._lock:
            return self._phone_number
    
    @phone_number.setter
    def phone_number(self, value: Optional[str]):
        """Set user's phone number."""
        with self._lock:
            self._phone_number = value
    
    @property
    def jwt_token(self) -> Optional[str]:
        """Get JWT authentication token."""
        with self._lock:
            return self._jwt_token
    
    @jwt_token.setter
    def jwt_token(self, value: Optional[str]):
        """Set JWT authentication token."""
        with self._lock:
            self._jwt_token = value
    
    # ========== DU Data Methods ==========
    
    def set_du_data(
        self,
        du_number: str,
        display_number: str,
        raw_bytes: bytes,
        is_encrypted: bool = False,
        encryption_key: Optional[bytes] = None
    ):
        """
        Store DU handshake data and extract bootloader version.
        
        This method stores all data from the 512-byte handshake and automatically
        extracts the bootloader version from bytes 392-393 (0-indexed).
        
        Args:
            du_number (str): DU serial number (8 digits, starts with 99).
            display_number (str): Display serial number (8 digits, starts with 12).
            raw_bytes (bytes): Full 512-byte data from handshake (after decryption if needed).
            is_encrypted (bool): Whether encryption is enabled for this DU.
            encryption_key (bytes | None): 32-byte AES encryption key if encrypted.
        
        Raises:
            ValueError: If raw_bytes is not exactly 512 bytes.
        """
        with self._lock:
            # Validate input
            if len(raw_bytes) != 512:
                raise ValueError(f"Expected 512 bytes, got {len(raw_bytes)}")
            
            # Store DU data
            self._du_number = str(du_number)
            self._display_number = str(display_number)
            self._raw_512_bytes = raw_bytes
            self._is_encryption_enabled = is_encrypted
            self._encryption_key = encryption_key
            
            # Extract bootloader version using protocol-defined offsets
            v1 = raw_bytes[FW_V1_OFFSET]
            v2 = raw_bytes[FW_V2_OFFSET]
            
            self._bootloader_version = (v1, v2)
            self._bootloader_version_string = f"{v1}.{v2}"
            
            # Extract hardware type for v1.2 only
            if (v1, v2) == (1, 2):
                hw_byte = raw_bytes[HARDWARE_TYPE_OFFSET]
                if hw_byte in VALID_HARDWARE_TYPES:
                    self._hardware_type = hw_byte
                    logger.info(f"Hardware type: 0x{hw_byte:02x} ({HARDWARE_TYPE_NAMES.get(hw_byte, 'unknown')})")
                else:
                    self._hardware_type = hw_byte  # Store raw value; validation happens in du_reader
                    logger.warning(f"Unknown hardware type byte: 0x{hw_byte:02x}")
            else:
                self._hardware_type = None
            
    
    @property
    def du_number(self) -> Optional[str]:
        """Get DU serial number."""
        with self._lock:
            return self._du_number

    @property
    def service_engineer(self) -> Optional[str]:
        """Get service engineer name."""
        with self._lock:
            return self._service_engineer

    @service_engineer.setter
    def service_engineer(self, value: Optional[str]):
        """Set service engineer name."""
        with self._lock:
            self._service_engineer = value
    
    @property
    def employee_id(self) -> Optional[str]:
        """Get employee ID."""
        with self._lock:
            return self._employee_id

    @employee_id.setter
    def employee_id(self, value: Optional[str]):
        """Set employee ID."""
        with self._lock:
            self._employee_id = value
    
    @property
    def display_number(self) -> Optional[str]:
        """Get Display serial number."""
        with self._lock:
            return self._display_number
    
    @property
    def raw_512_bytes(self) -> Optional[bytes]:
        """Get raw 512-byte handshake data."""
        with self._lock:
            return self._raw_512_bytes
    
    @property
    def bootloader_version(self) -> Optional[tuple[int, int]]:
        """
        Get bootloader version as tuple.
        
        Returns:
            tuple[int, int] | None: Bootloader version as (v1, v2), e.g., (11, 8).
        """
        with self._lock:
            return self._bootloader_version
    
    @property
    def bootloader_version_string(self) -> Optional[str]:
        """
        Get bootloader version as formatted string.
        
        Returns:
            str | None: Bootloader version as string, e.g., "11.8".
        """
        with self._lock:
            return self._bootloader_version_string
    
    @property
    def hardware_type(self) -> Optional[int]:
        """
        Get hardware type identifier (v1.2 only).
        
        Returns:
            int | None: 0x01 (display), 0x02 (slave_display), or None for older versions.
        """
        with self._lock:
            return self._hardware_type
    
    @property
    def hardware_type_name(self) -> Optional[str]:
        """
        Get human-readable hardware type name (v1.2 only).
        
        Returns:
            str | None: "display", "slave_display", or None.
        """
        with self._lock:
            if self._hardware_type is None:
                return None
            return HARDWARE_TYPE_NAMES.get(self._hardware_type)
    
    # ========== Encryption Methods ==========
    
    @property
    def is_encryption_enabled(self) -> bool:
        """Get encryption enabled status."""
        with self._lock:
            return self._is_encryption_enabled
    
    @is_encryption_enabled.setter
    def is_encryption_enabled(self, value: bool):
        """Set encryption enabled status."""
        with self._lock:
            self._is_encryption_enabled = value
    
    @property
    def encryption_key(self) -> Optional[bytes]:
        """Get 32-byte AES encryption key."""
        with self._lock:
            return self._encryption_key
    
    @encryption_key.setter
    def encryption_key(self, value: Optional[bytes]):
        """
        Set 32-byte AES encryption key.
        
        Args:
            value (bytes | None): 32-byte encryption key.
        
        Raises:
            ValueError: If key is not None and not 32 bytes.
        """
        if value is not None and len(value) != 32:
            raise ValueError(f"Encryption key must be 32 bytes, got {len(value)}")
        with self._lock:
            self._encryption_key = value
    
    # ========== Firmware Selection Methods ==========
    
    def set_firmware_selection(self, file_id: str, file_name: str):
        """
        Set selected firmware file for update.
        
        Args:
            file_id (str): File ID from server.
            file_name (str): Human-readable file name.
        """
        with self._lock:
            self._selected_file_id = file_id
            self._selected_file_name = file_name
    
    @property
    def selected_file_id(self) -> Optional[str]:
        """Get selected firmware file ID."""
        with self._lock:
            return self._selected_file_id
    
    @selected_file_id.setter
    def selected_file_id(self, value: Optional[str]):
        """Set selected firmware file ID."""
        with self._lock:
            self._selected_file_id = value
    
    @property
    def selected_file_name(self) -> Optional[str]:
        """Get selected firmware file name."""
        with self._lock:
            return self._selected_file_name
    
    @selected_file_name.setter
    def selected_file_name(self, value: Optional[str]):
        """Set selected firmware file name."""
        with self._lock:
            self._selected_file_name = value
    
    @property
    def du_options(self) -> Optional[dict]:
        """Get DU options from DU_Update API."""
        with self._lock:
            return self._du_options
    
    @du_options.setter
    def du_options(self, value: Optional[dict]):
        """Set DU options from DU_Update API."""
        with self._lock:
            self._du_options = value
    
    # ========== Utility Methods ==========
    
    def get_state_summary(self) -> dict:
        """
        Get a summary of current state for debugging.
        
        Returns:
            dict: Dictionary containing current state (sanitized, no sensitive data).
        """
        with self._lock:
            return {
                "has_auth": self._jwt_token is not None,
                "phone_number": self._phone_number,
                "du_number": self._du_number,
                "display_number": self._display_number,
                "bootloader_version": self._bootloader_version_string,
                "is_encryption_enabled": self._is_encryption_enabled,
                "has_encryption_key": self._encryption_key is not None,
                "selected_file_name": self._selected_file_name,
                "has_du_options": self._du_options is not None,
            }
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        summary = self.get_state_summary()
        return f"AppState({summary})"
