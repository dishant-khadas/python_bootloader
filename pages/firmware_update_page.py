"""
Firmware Update Page for Python Bootloader Application.

Runs btl_host.py to flash firmware to the display hardware and
shows real-time progress updates.
"""

import os
import sys
import threading
import time
import ttkbootstrap as ttk
from ttkbootstrap.constants import INFO

from config import config
from utils.gpio_control import safe_cleanup, turn_display_Off
from core.logGenerator import write_log
from core.app_state import AppState
from utils.logger import logger
from btl_host import run_btl_host


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
            container, text="Please wait...", font=lm.font(14),
            foreground="black", wraplength=lm.scaled(350), justify="center"
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
        """Run the firmware update logic directly within the application."""
        try:
            serial_port = os.getenv("SERIAL_PORT", "/dev/ttyAMA0")
            
            # Progress callback for real-time GUI updates
            def progress_callback(percent):
                logger.info(f"[FIRMWARE UPDATE PROGRESS]: {percent}%")
                display_text = f"{percent}%"
                self.controller.after(0, lambda t=display_text: self.status_label.config(text=t))

            logger.info(f"[FIRMWARE UPDATE] Starting update on port {serial_port}")
            
            # Call btl_host logic directly (same Python environment, same bundled libs)
            success = run_btl_host(
                port_name=serial_port,
                file_path=self.output_path,
                device_name="pic32mz",
                address_hex="0x9D000000",
                encryption_key_hex=self.encryption_key_hex,
                encryption_enabled=self.is_enc_flag,
                progress_callback=progress_callback
            )
            
            if success:
                logger.info("[FIRMWARE UPDATE] Process completed successfully")
                time.sleep(1)
                try:
                    turn_display_Off()
                except Exception as e:
                    logger.warning(f"Warning: turn_display_Off failed: {e}")
                self.controller.after(0, self.on_update_success)
                
        except (Exception, SystemExit) as e:
            error_msg = f"Firmware update failed: {str(e)}"
            logger.error(f"[FIRMWARE UPDATE ERROR]: {error_msg}")
            try:
                turn_display_Off()
            except:
                pass
            self.controller.after(0, lambda msg=error_msg: self.on_update_error(msg))
    
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
        
        # Print complete AppState AFTER successful firmware update
        state = AppState.get_instance()
        logger.info("="*80)
        logger.info("🎉 FIRMWARE UPDATE SUCCESSFUL - Final AppState Summary")
        logger.info("="*80)
        
        logger.info("\n✅ Authentication:")
        logger.info(f"   Phone Number: {state.phone_number}")
        logger.info(f"   JWT Token: {'Present' if state.jwt_token else 'Missing'}")
        
        logger.info("\n✅ Device Information:")
        logger.info(f"   DU Number: {state.du_number}")
        logger.info(f"   Display Number: {state.display_number}")
        
        logger.info("\n✅ Bootloader Version (from bytes 392-393):")
        if state.bootloader_version:
            logger.info(f"   Version Tuple: {state.bootloader_version}")
            logger.info(f"   Version String: {state.bootloader_version_string}")
        else:
            logger.info("   Not available")
        
        logger.info("\n✅ Encryption:")
        logger.info(f"   Encryption Enabled: {state.is_encryption_enabled}")
        if state.encryption_key:
            logger.info(f"   Encryption Key: Present (32 bytes)")
            logger.info(f"   Key Preview: {state.encryption_key[:8].hex()}...")
        else:
            logger.info(f"   Encryption Key: Not required")
        
        logger.info("\n✅ Firmware Update:")
        logger.info(f"   File ID: {state.selected_file_id}")
        logger.info(f"   File Name: {state.selected_file_name}")
        logger.info(f"   Status: Successfully Flashed ✓")
        
        logger.info("\n✅ Complete State Summary:")
        summary = state.get_state_summary()
        for key, value in summary.items():
            logger.info(f"   {key}: {value}")
        
        logger.info("\n" + "="*80)
        logger.info("✅ All operations completed successfully!")
        logger.info("="*80 + "\n")
        
        # Log successful firmware update
        write_log(
            errorCode="S-01",
            errorName="Firmware Update Success",
            result="Success",
            description="Firmware updated successfully",
            device_id=config.DEVICE_ID,
            phoneNo=state.phone_number or "",
            duNumber=state.du_number or "",
            displayNumber=state.display_number or "",
            fileName=state.selected_file_name or "",
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
