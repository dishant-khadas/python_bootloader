"""
GPIO Control Module for Python Bootloader Application.

This module provides functions to control GPIO pins on the hardware device,
specifically for bootloader detection (BL_DETECT) and display power control.
It uses the Linux gpioset utility to manipulate GPIO pins.

Hardware Pins (configurable via environment variables):
    - BL_DETECT_PIN: Bootloader detection signal pin (default: GPIO 17)
    - DISPLAY_ON_PIN: Display power control pin (default: GPIO 4)

Platform Support:
    - Linux: Uses gpioset command for actual GPIO control
    - Windows: Mock mode for development/testing (prints commands without executing)

Functions:
    turn_BL_Detect_High(): Set bootloader detect pin HIGH
    turn_BL_Detect_Low(): Set bootloader detect pin LOW
    turn_display_On(): Turn on the display
    turn_display_Off(): Turn off the display
    safe_cleanup(): Safely turn off all controlled pins
    safe_bl_low(): Safely turn off bootloader detect pin only
"""

import subprocess
import platform

from config import config

# Platform detection for mock mode on Windows
IS_WINDOWS = platform.system() == "Windows"

# GPIO pin configuration from centralized config
BL_DETECT_Pin = config.BL_DETECT_PIN
DISPLAY_ON_PIN = config.DISPLAY_ON_PIN
GPIOCHIP = config.GPIOCHIP


def run_cmd(cmd: str) -> None:
    """
    Execute a shell command safely with error handling.
    
    On Windows, this function operates in mock mode and only prints
    the command that would be executed without actually running it.
    
    Args:
        cmd (str): The shell command to execute.
        
    Raises:
        subprocess.CalledProcessError: If the command fails (caught and logged).
    """
    if IS_WINDOWS:
        print(f"[MOCK-GPIO] Would execute: {cmd}")
        return

    try:
        print("Executing:", cmd)
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print("GPIO Command Error:", e)


def turn_BL_Detect_High() -> None:
    """
    Set the bootloader detect GPIO pin to HIGH.
    
    This signals to the connected hardware that the bootloader
    programming mode should be activated.
    """
    run_cmd(f"gpioset {GPIOCHIP} {BL_DETECT_Pin}=1")
    if not IS_WINDOWS:
        print(f"GPIO {BL_DETECT_Pin} HIGH")


def turn_BL_Detect_Low() -> None:
    """
    Set the bootloader detect GPIO pin to LOW.
    
    This signals to the connected hardware that the bootloader
    programming mode should be deactivated.
    """
    run_cmd(f"gpioset {GPIOCHIP} {BL_DETECT_Pin}=0")
    if not IS_WINDOWS:
        print(f"GPIO {BL_DETECT_Pin} LOW")


def turn_display_On() -> None:
    """
    Turn on the external display by setting DISPLAY_ON_PIN to HIGH.
    
    This activates power to the connected display unit.
    """
    run_cmd(f"gpioset {GPIOCHIP} {DISPLAY_ON_PIN}=1")
    print("DISPLAY ON")


def turn_display_Off() -> None:
    """
    Turn off the external display by setting DISPLAY_ON_PIN to LOW.
    
    This cuts power to the connected display unit.
    """
    run_cmd(f"gpioset {GPIOCHIP} {DISPLAY_ON_PIN}=0")
    print("DISPLAY OFF")


def safe_cleanup() -> None:
    """
    Safely turn off all GPIO-controlled hardware.
    
    This function turns off both the bootloader detect signal and
    the display, catching and logging any errors that occur.
    It's designed to be called during error handling or application
    shutdown to ensure a clean state.
    
    This replaces repetitive try/except blocks throughout the codebase.
    """
    try:
        turn_BL_Detect_Low()
    except Exception as e:
        print(f"Warning: turn_BL_Detect_Low failed: {e}")
    
    try:
        turn_display_Off()
    except Exception as e:
        print(f"Warning: turn_display_Off failed: {e}")


def safe_bl_low() -> None:
    """
    Safely turn off the bootloader detect signal only.
    
    This is a convenience function that wraps turn_BL_Detect_Low()
    with error handling. Use this when you only need to disable
    the bootloader detect without affecting the display.
    """
    try:
        turn_BL_Detect_Low()
    except Exception as e:
        print(f"Warning: turn_BL_Detect_Low failed: {e}")
