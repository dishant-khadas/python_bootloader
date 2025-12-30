import subprocess
import os
import platform

IS_WINDOWS = platform.system() == "Windows"

# BL_DETECT_Pin = int(os.getenv("BL_DETECT_PIN", "26"))      # example default
BL_DETECT_Pin = 17
DISPLAY_ON_PIN = 27

# DISPLAY_ON_PIN = int(os.getenv("DISPLAY_ON_PIN", "19"))    # example default

GPIOCHIP = "gpiochip4"  # same as your Node code


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


