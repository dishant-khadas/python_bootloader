"""
GPIO Control Module for Python Bootloader Application.

This module provides functions to control GPIO pins on the hardware device,
specifically for bootloader detection (BL_DETECT) and display power control.
Optimized for Raspberry Pi 5 using gpiozero + lgpio.
"""

import platform
import os
from config import config
from utils.logger import logger

# Platform detection
IS_WINDOWS = platform.system() == "Windows"

# GPIO initialization
try:
    from gpiozero import DigitalOutputDevice, Device
    
    if IS_WINDOWS:
        from gpiozero.pins.mock import MockFactory
        Device.pin_factory = MockFactory()
        logger.info("[GPIO] Initializing in MOCK mode (Windows)")
    else:
        # Force lgpio factory for RPi 5 support if available
        try:
            from gpiozero.pins.lgpio import LPiFactory
            Device.pin_factory = LPiFactory()
            logger.info("[GPIO] Using LPiFactory (RPi 5 compatible)")
        except ImportError:
            logger.warning("[GPIO] LPiFactory not found, falling back to default factory")

    # Initialize pins
    bl_detect = DigitalOutputDevice(config.BL_DETECT_PIN)
    display_on = DigitalOutputDevice(config.DISPLAY_ON_PIN)
    
    GPIO_AVAILABLE = True
    logger.info(f"[GPIO] Pins initialized: BL_DETECT={config.BL_DETECT_PIN}, DISPLAY_ON={config.DISPLAY_ON_PIN}")

except Exception as e:
    logger.error(f"[GPIO] Initialization failed: {e}")
    GPIO_AVAILABLE = False
    class DummyPin:
        def on(self): pass
        def off(self): pass
    bl_detect = DummyPin()
    display_on = DummyPin()


def turn_BL_Detect_High() -> None:
    """Set the bootloader detect GPIO pin to HIGH."""
    try:
        bl_detect.on()
        logger.info(f"BL Pin {config.BL_DETECT_PIN} -> HIGH")
    except Exception as e:
        logger.error(f"Failed to set BL Pin High: {e}")


def turn_BL_Detect_Low() -> None:
    """Set the bootloader detect GPIO pin to LOW."""
    try:
        bl_detect.off()
        logger.info(f"BL Pin {config.BL_DETECT_PIN} -> LOW")
    except Exception as e:
        logger.error(f"Failed to set BL Pin Low: {e}")


def turn_display_On() -> None:
    """Turn on the external display."""
    try:
        display_on.on()
        logger.info(f"Display Pin {config.DISPLAY_ON_PIN} -> HIGH")
    except Exception as e:
        logger.error(f"Failed to turn display ON: {e}")


def turn_display_Off() -> None:
    """Turn off the external display."""
    try:
        display_on.off()
        logger.info(f"Display Pin {config.DISPLAY_ON_PIN} -> LOW")
    except Exception as e:
        logger.error(f"Failed to turn display OFF: {e}")


def safe_cleanup() -> None:
    """Safely turn off all GPIO-controlled hardware."""
    try:
        turn_BL_Detect_Low()
        turn_display_Off()
    except Exception as e:
        logger.warning(f"Cleanup failed: {e}")


if __name__ == "__main__":
    import time
    import sys
    
    print("\n" + "="*40)
    print(" GPIO TEST MODE (Raspberry Pi 5) ")
    print("="*40)
    print(f"Testing BL_DETECT_PIN: {config.BL_DETECT_PIN} (BCM)")
    print(f"Testing DISPLAY_ON_PIN: {config.DISPLAY_ON_PIN} (BCM)")
    print("Press Ctrl+C to stop.")
    print("="*40 + "\n")

    try:
        while True:
            print(">>> Setting pins HIGH...")
            turn_BL_Detect_High()
            turn_display_On()
            time.sleep(2)
            
            print(">>> Setting pins LOW...")
            turn_BL_Detect_Low()
            turn_display_Off()
            time.sleep(2)
            print("-" * 20)
    except KeyboardInterrupt:
        print("\nStopping test...")
        safe_cleanup()
        sys.exit(0)
