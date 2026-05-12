"""
GPIO Control Module for Python Bootloader Application.

This module provides functions to control GPIO pins on the hardware device,
specifically for bootloader detection (BL_DETECT) and display power control.
It uses gpiozero for modern hardware support (Raspberry Pi 5 compatible).

Hardware Pins (configurable via environment variables):
    - BL_DETECT_PIN: Bootloader detection signal pin (default: GPIO 17)
    - DISPLAY_ON_PIN: Display power control pin (default: GPIO 4)

Platform Support:
    - Linux: Uses gpiozero with lgpio backend (required for RPi 5)
    - Windows: Uses gpiozero mock factory for development/testing
"""

import platform
from config import config
from utils.logger import logger

# Platform detection
IS_WINDOWS = platform.system() == "Windows"

# GPIO initialization
try:
    if IS_WINDOWS:
        from gpiozero.pins.mock import MockFactory
        from gpiozero import Device
        Device.pin_factory = MockFactory()
        logger.info("[GPIO] Initializing in MOCK mode (Windows)")
    
    from gpiozero import DigitalOutputDevice
    
    # Initialize pins as DigitalOutputDevices
    # active_high=True is default, which matches GPIO.HIGH logic
    bl_detect = DigitalOutputDevice(config.BL_DETECT_PIN)
    display_on = DigitalOutputDevice(config.DISPLAY_ON_PIN)
    
    GPIO_AVAILABLE = True
    logger.info(f"[GPIO] Pins initialized: BL_DETECT={config.BL_DETECT_PIN}, DISPLAY_ON={config.DISPLAY_ON_PIN}")

except Exception as e:
    logger.error(f"[GPIO] Initialization failed: {e}")
    GPIO_AVAILABLE = False
    # Create dummy objects to prevent NameErrors if initialization fails
    class DummyPin:
        def on(self): pass
        def off(self): pass
    bl_detect = DummyPin()
    display_on = DummyPin()


def turn_BL_Detect_High() -> None:
    """Set the bootloader detect GPIO pin to HIGH."""
    try:
        bl_detect.on()
        logger.info("BL Pin High")
    except Exception as e:
        logger.error(f"Failed to set BL Pin High: {e}")


def turn_BL_Detect_Low() -> None:
    """Set the bootloader detect GPIO pin to LOW."""
    try:
        bl_detect.off()
        logger.info("BL DETECT TURNED LOW!")
    except Exception as e:
        logger.error(f"Failed to set BL Pin Low: {e}")


def turn_display_On() -> None:
    """Turn on the external display."""
    try:
        display_on.on()
        logger.info("DISPLAY TURNED ON!")
    except Exception as e:
        logger.error(f"Failed to turn display ON: {e}")


def turn_display_Off() -> None:
    """Turn off the external display."""
    try:
        display_on.off()
        logger.info("DISPLAY TURNED OFF!")
    except Exception as e:
        logger.error(f"Failed to turn display OFF: {e}")


def safe_cleanup() -> None:
    """Safely turn off all GPIO-controlled hardware."""
    safe_bl_low()
    try:
        turn_display_Off()
    except Exception as e:
        logger.warning(f"Warning: turn_display_Off failed: {e}")


def safe_bl_low() -> None:
    """Safely turn off the bootloader detect signal only."""
    try:
        turn_BL_Detect_Low()
    except Exception as e:
        logger.warning(f"Warning: turn_BL_Detect_Low failed: {e}")
