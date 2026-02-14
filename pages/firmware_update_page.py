"""
Firmware Update Page for Python Bootloader Application.

Runs btl_host.py to flash firmware to the display hardware and
shows real-time progress updates.
"""

import os
import sys
import subprocess
import threading
import time
import ttkbootstrap as ttk
from ttkbootstrap.constants import INFO

from config import config
from utils.gpio_control import safe_cleanup, turn_display_Off
from core.logGenerator import write_log
from utils.logger import logger


class FirmwareUpdatePage(ttk.Frame):
    """
    Firmware flashing page.
    
    Executes btl_host.py with the decrypted firmware file and
    displays progress updates in real-time.
    
    Attributes:
        controller: Reference to the main App controller.
        output_path (str): Path to decrypted firmware file.
        encryption_key_hex (str): Hex string of encryption key.
        is_enc_flag (str): "1" if encrypted, "0" otherwise.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the firmware update page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = controller.lm
        
        # Parameters for btl_host.py
        self.output_path = None
        self.encryption_key_hex = ""
        self.is_enc_flag = "0"
        self.process = None
        
        # UI
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(container, text="Updating Firmware", font=lm.font(24)).pack(pady=lm.scaled(30))
        
        self.progress = ttk.Progressbar(
            container, mode='indeterminate', bootstyle=INFO,
            length=lm.scaled(300)
        )
        self.progress.pack(pady=lm.scaled(20))
        
        self.status_label = ttk.Label(
            container, text="Please wait...", font=lm.font(20),
            foreground="black", wraplength=lm.scaled(400), justify="center"
        )
        self.status_label.pack(pady=lm.scaled(20))
    
    def set_params(self, output_path: str, encryption_key_hex: str, is_enc_flag: str):
        """Set parameters for btl_host.py before showing this page."""
        self.output_path = output_path
        self.encryption_key_hex = encryption_key_hex
        self.is_enc_flag = is_enc_flag
    
    def on_show(self):
        """Called when the page is shown - starts firmware update."""
        # Reset status label to prevent old text from briefly appearing
        self.status_label.config(text="Please wait...", foreground="black")
        self.progress.start(10)
        threading.Thread(target=self.run_btl_host, daemon=True).start()
    
    def run_btl_host(self):
        """Run btl_host.py with the specified arguments."""
        from pages.login_page import LoginPage
        
        try:
            # Get path to btl_host.py - handle PyInstaller bundle
            if getattr(sys, 'frozen', False):
                # Running as PyInstaller bundle
                # Data files are in sys._MEIPASS (the _internal folder)
                base_dir = sys._MEIPASS
            else:
                # Running as normal Python script
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
            default_btl_path = os.path.join(base_dir, "btl_host.py")
            btl_host_path = os.getenv("BTL_HOST_PATH", default_btl_path)
            
            logger.info(f"[DEBUG] Looking for btl_host.py at: {btl_host_path}")
            logger.info(f"[DEBUG] File exists: {os.path.exists(btl_host_path)}")
            python_path = os.getenv("PYTHON_PATH", "python3")
            serial_port = os.getenv("SERIAL_PORT", "/dev/ttyAMA0")
            
            # Build command
            cmd = [
                python_path,
                btl_host_path,
                "-v",
                "-i", serial_port,
                "-d", "pic32mz",
                "-a", "0x9D000000",
                self.encryption_key_hex,
                self.is_enc_flag,
                "-f", self.output_path
            ]
            
            logger.info(f"[FIRMWARE UPDATE] Running command: {' '.join(cmd)}")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Read stdout in real-time with error handling
            try:
                for line in iter(self.process.stdout.readline, ''):
                    if line:
                        output_text = line.strip()
                        logger.info(f"[BTL_HOST STDOUT]: {output_text}")
                        try:
                            float(output_text)
                            display_text = f"{output_text}%"
                        except ValueError:
                            display_text = output_text
                        
                        self.controller.after(0, lambda t=display_text: self.status_label.config(text=t))
            except (BrokenPipeError, IOError) as e:
                logger.info(f"[FIRMWARE UPDATE] Pipe error (process may have ended): {e}")
            self.process.wait()
            return_code = self.process.returncode
            
            logger.info(f"[FIRMWARE UPDATE] Process exited with code {return_code}")
            time.sleep(3)
            try:
                turn_display_Off()
            except Exception as e:
                logger.warning(f"Warning: turn_display_Off failed: {e}")
            if return_code == 0:
                self.controller.after(0, self.on_update_success)
            else:
                stderr_output = self.process.stderr.read()
                logger.info(f"[BTL_HOST STDERR]: {stderr_output}")
                error_detail = self._parse_btl_error(stderr_output, return_code)
                self.controller.after(0, lambda e=error_detail: self.on_update_error(e))
                
        except FileNotFoundError:
            error_msg = f"btl_host.py not found at {btl_host_path}"
            logger.info(f"[FIRMWARE UPDATE ERROR]: {error_msg}")
            self.controller.after(0, lambda: self.on_update_error(error_msg))
        except Exception as e:
            error_msg = f"Firmware update error: {e}"
            logger.info(f"[FIRMWARE UPDATE ERROR]: {error_msg}")
            self.controller.after(0, lambda: self.on_update_error(error_msg))
    
    def _parse_btl_error(self, stderr_output: str, return_code: int) -> str:
        """
        Parse btl_host.py stderr output to extract a clean error message.
        
        Args:
            stderr_output: Raw stderr output from btl_host.py
            return_code: Process exit code
            
        Returns:
            Clean, user-friendly error message
        """
        if not stderr_output:
            return f"Firmware update failed (exit code {return_code})"
        
        # Split into lines and find the actual error
        lines = stderr_output.strip().split('\n')
        
        # Filter out warning/retry lines, keep only actual error
        error_lines = []
        for line in lines:
            line = line.strip()
            # Skip empty lines and warning/retry messages
            if not line:
                continue
            if line.startswith("Warning:") and "retrying" in line:
                continue
            error_lines.append(line)
        
        if error_lines:
            # Return the last meaningful error line (usually the final error)
            final_error = error_lines[-1]
            # Clean up common patterns
            if final_error.startswith("Error:"):
                final_error = final_error[6:].strip()
            return f"Firmware update failed: {final_error}"
        
        return f"Firmware update failed (exit code {return_code})"
    
    def cleanup_temp_file(self):
        """Delete the temporary decrypted firmware file."""
        if self.output_path and os.path.exists(self.output_path):
            try:
                os.remove(self.output_path)
                logger.info(f"[CLEANUP] Deleted temp file: {self.output_path}")
            except Exception as e:
                logger.warning(f"[CLEANUP WARNING] Failed to delete temp file: {e}")
    
    def on_update_success(self):
        """Called when firmware update completes successfully."""
        from pages.login_page import LoginPage
        
        self.cleanup_temp_file()
        self.progress.stop()
        self.status_label.config(text="Firmware updated successfully!", foreground="green")
        
        # Log successful firmware update
        write_log(
            errorCode="S-01",
            errorName="Firmware Update Success",
            result="Success",
            description="Firmware updated successfully",
            device_id=config.DEVICE_ID,
            phoneNo=getattr(self.controller, "phone", ""),
            duNumber=getattr(self.controller, "du_options", {}).get("duNumber", ""),
            displayNumber=getattr(self.controller, "du_options", {}).get("displayNumber", ""),
            fileName=getattr(self.controller, "selected_file_name", ""),
        )
        
        self.controller.after(3000, lambda: self.controller.show_frame(LoginPage))
    
    def on_update_error(self, error_msg):
        """Called when firmware update fails."""
        from pages.login_page import LoginPage
        
        self.cleanup_temp_file()
        self.progress.stop()
        self.status_label.config(text="Update failed", foreground="red")
        
        # Log error
        write_log(
            errorCode="E-15",
            errorName="Firmware Update Failed",
            result="Fail",
            description=error_msg,
            device_id=config.DEVICE_ID,
            phoneNo=getattr(self.controller, "phone", ""),
            duNumber=getattr(self.controller, "du_options", {}).get("duNumber", ""),
            displayNumber=getattr(self.controller, "du_options", {}).get("displayNumber", ""),
            fileName=getattr(self.controller, "selected_file_name", ""),
        )
        
        safe_cleanup()
        self.controller.show_error("Firmware Update Failed", error_msg, return_frame=LoginPage)
