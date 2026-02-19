"""
Serial Port Abstraction for the Python Bootloader Application.

Provides a context manager wrapper around pyserial's serial.Serial,
centralizing port configuration, open/close lifecycle, error handling,
and common read/write patterns.

Previously, serial ports were opened/closed manually with scattered
error handling across du_reader.py and bootloader_download.py.

Usage:
    from core.serial_port import SerialPort

    # Context manager — port closes automatically on exit
    with SerialPort(timeout=0.5) as ser:
        data = ser.read(256)
        ser.write(packet)

    # High-level read (replaces 40-line while loop in du_reader.py)
    port = SerialPort(timeout=0.5)
    hex_data = port.read_hex_until(
        expected_length=1024,
        timeout_secs=15,
        on_progress=lambda n: print(f"Received {n} hex chars"),
    )

    # High-level write (replaces write/validate/flush in bootloader_download.py)
    with SerialPort(timeout=5) as ser:
        SerialPort.write_packet(ser, final_packet)
"""

import time
import serial

from config import config
from utils.logger import logger


class SerialPortError(Exception):
    """Base exception for serial port errors."""
    pass


class SerialPortOpenError(SerialPortError):
    """Raised when the serial port cannot be opened."""
    pass


class SerialPortTimeoutError(SerialPortError):
    """Raised when a read operation times out."""
    pass


class SerialPortWriteError(SerialPortError):
    """Raised when a write operation fails."""
    pass


class SerialPort:
    """
    Context manager wrapper for serial port communication.
    
    Centralizes serial port configuration, lifecycle management, and
    common read/write patterns. Falls back to config values for
    port, baudrate, and timeout if not explicitly provided.
    
    Attributes:
        port (str): Serial port device path.
        baudrate (int): Communication baud rate.
        timeout (float): Read timeout in seconds.
    """
    
    def __init__(
        self,
        port: str = None,
        baudrate: int = None,
        timeout: float = None,
    ):
        """
        Initialize serial port configuration.
        
        Args:
            port: Serial port path. Defaults to config.SERIAL_PORT.
            baudrate: Baud rate. Defaults to config.SERIAL_BAUD.
            timeout: Read timeout in seconds. Defaults to config.SERIAL_TIMEOUT.
        """
        self.port = port or config.SERIAL_PORT
        self.baudrate = baudrate or config.SERIAL_BAUD
        self.timeout = timeout if timeout is not None else config.SERIAL_TIMEOUT
        self._serial: serial.Serial = None
    
    def __enter__(self) -> serial.Serial:
        """
        Open the serial port.
        
        Returns:
            serial.Serial: The opened serial port instance.
            
        Raises:
            SerialPortOpenError: If the port cannot be opened.
        """
        try:
            self._serial = serial.Serial(
                self.port,
                baudrate=self.baudrate,
                timeout=self.timeout,
            )
            logger.info(
                f"Serial port opened: {self.port} "
                f"(baud={self.baudrate}, timeout={self.timeout}s)"
            )
            return self._serial
        except serial.SerialException as e:
            raise SerialPortOpenError(
                f"Failed to open serial port {self.port}: {e}"
            ) from e
        except Exception as e:
            raise SerialPortOpenError(
                f"Unexpected error opening serial port {self.port}: {e}"
            ) from e
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Close the serial port safely.
        
        Always closes the port, even if an exception occurred.
        Logs any errors during close but does not re-raise them.
        """
        if self._serial is not None:
            try:
                if self._serial.is_open:
                    self._serial.close()
                    logger.info(f"Serial port closed: {self.port}")
            except Exception as e:
                logger.warning(f"Error closing serial port {self.port}: {e}")
            finally:
                self._serial = None
        return False  # Don't suppress exceptions
    
    def read_hex_until(
        self,
        expected_length: int,
        timeout_secs: float,
        chunk_size: int = 256,
        on_progress=None,
    ) -> str:
        """
        Read hex data from the serial port until expected length or timeout.
        
        Opens the port, accumulates data as hex string, and returns when
        enough data has been received or the timeout expires.
        
        This replaces the ~40-line while loop that was in du_reader.py.
        
        Args:
            expected_length: Number of hex characters to accumulate
                            (e.g., 1024 for 512 bytes).
            timeout_secs: Maximum seconds to wait for data.
            chunk_size: Bytes to read per iteration. Default 256.
            on_progress: Optional callback(hex_len: int) called after each chunk.
            
        Returns:
            str: Accumulated hex string of at least expected_length chars.
            
        Raises:
            SerialPortOpenError: If the port cannot be opened.
            SerialPortTimeoutError: If timeout expires before enough data arrives.
            SerialPortError: If a read error occurs.
        """
        received_hex = ""
        start_time = time.time()
        
        with self as ser:
            while True:
                elapsed = time.time() - start_time
                
                # Timeout check
                if elapsed > timeout_secs:
                    if len(received_hex) == 0:
                        raise SerialPortTimeoutError(
                            f"No data received within {timeout_secs}s timeout"
                        )
                    else:
                        raise SerialPortTimeoutError(
                            f"Timeout after {timeout_secs}s: "
                            f"received {len(received_hex)} hex chars, "
                            f"need {expected_length}"
                        )
                
                # Read chunk
                try:
                    chunk = ser.read(chunk_size)
                except Exception as e:
                    raise SerialPortError(
                        f"Serial read error: {e}"
                    ) from e
                
                if not chunk:
                    continue
                
                # Accumulate hex
                received_hex += chunk.hex()
                
                if on_progress:
                    on_progress(len(received_hex))
                
                # Check if we have enough data
                if len(received_hex) >= expected_length:
                    logger.info(
                        f"Data received: {len(received_hex)} hex chars "
                        f"(expected {expected_length})"
                    )
                    return received_hex
    
    @staticmethod
    def write_packet(ser: serial.Serial, packet: bytes) -> None:
        """
        Write a packet to an open serial port with validation.
        
        Validates that packet is bytes, writes it, and flushes.
        
        Args:
            ser: Open serial.Serial instance.
            packet: Bytes data to write.
            
        Raises:
            SerialPortWriteError: If packet is invalid or write fails.
        """
        if not isinstance(packet, bytes):
            raise SerialPortWriteError(
                f"Packet must be bytes, got {type(packet).__name__}"
            )
        
        try:
            logger.info(f"Writing {len(packet)}-byte packet to serial port")
            logger.debug(f"Packet (hex): {packet.hex()}")
            ser.write(packet)
            ser.flush()
            logger.info("Packet written and flushed successfully")
        except Exception as e:
            raise SerialPortWriteError(
                f"Failed to write packet: {e}"
            ) from e
