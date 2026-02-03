import subprocess
import platform

from config import config

IS_WINDOWS = platform.system() == "Windows"

# Use centralized config values
BL_DETECT_Pin = config.BL_DETECT_PIN
DISPLAY_ON_PIN = config.DISPLAY_ON_PIN
GPIOCHIP = config.GPIOCHIP


def run_cmd(cmd):
    """Execute shell command safely and print output."""
    if IS_WINDOWS:
        print(f"[MOCK-GPIO] Would execute: {cmd}")
        return

    try:
        print("Executing:", cmd)
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print("GPIO Command Error:", e)


def turn_BL_Detect_High():
    run_cmd(f"gpioset {GPIOCHIP} {BL_DETECT_Pin}=1")
    if not IS_WINDOWS:
        print(f"GPIO {BL_DETECT_Pin} HIGH")


def turn_BL_Detect_Low():
    run_cmd(f"gpioset {GPIOCHIP} {BL_DETECT_Pin}=0")
    if not IS_WINDOWS:
        print(f"GPIO {BL_DETECT_Pin} LOW")


def turn_display_On():
    run_cmd(f"gpioset {GPIOCHIP} {DISPLAY_ON_PIN}=1")
    print("DISPLAY ON")


def turn_display_Off():
    run_cmd(f"gpioset {GPIOCHIP} {DISPLAY_ON_PIN}=0")
    print("DISPLAY OFF")


def safe_cleanup():
    """
    Safely turn off BL detect and display, catching any errors.
    This replaces the repetitive try/except blocks throughout the codebase.
    """
    try:
        turn_BL_Detect_Low()
    except Exception as e:
        print(f"Warning: turn_BL_Detect_Low failed: {e}")
    
    try:
        turn_display_Off()
    except Exception as e:
        print(f"Warning: turn_display_Off failed: {e}")


def safe_bl_low():
    """Safely turn BL detect low, catching any errors."""
    try:
        turn_BL_Detect_Low()
    except Exception as e:
        print(f"Warning: turn_BL_Detect_Low failed: {e}")
