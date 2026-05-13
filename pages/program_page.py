"""
Program Page for Python Bootloader Application.

Main interface for initiating the DU detection and firmware update
process. Shows "PROGRAM" button to start serial handshake.
"""

import os
import threading
import ttkbootstrap as ttk
from ttkbootstrap.constants import PRIMARY, WARNING

from utils.gpio_control import safe_cleanup
from core.du_reader import read_du_from_serial
from core.app_state import AppState
from utils.logger import logger


class ProgramPage(ttk.Frame):
    """
    DU programming initiation page.
    
    Displays welcome message and PROGRAM button to start the
    serial handshake and DU detection process.
    
    Attributes:
        controller: Reference to the main App controller.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the program page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm

        ttk.Label(self, text="Welcome", font=lm.font(40)).pack(pady=lm.scaled(100))

        ttk.Button(
            self, text="PROGRAM", bootstyle=PRIMARY,
            padding=lm.scaled(30), command=self.start_program_logic
        ).pack(pady=lm.scaled(20))
        
        from pages.test_page import TestPage
        ttk.Button(
            self, text="TEST", bootstyle=INFO,
            padding=lm.scaled(30), command=lambda: self.controller.show_frame(TestPage)
        ).pack(pady=lm.scaled(20))

        self.status_label = ttk.Label(self, text="", font=lm.font(14), bootstyle=WARNING)
        self.status_label.pack(pady=lm.scaled(20))

    def on_show(self):
        """Called when page is shown - print current AppState for debugging."""
        state = AppState.get_instance()
        
        logger.info("=" * 70)
        logger.info("PROGRAM PAGE - Current AppState:")
        logger.info("=" * 70)
        
        # Authentication
        logger.info("Authentication:")
        logger.info(f"  Phone Number: {state.phone_number or 'Not set'}")
        logger.info(f"  JWT Token: {'Present' if state.jwt_token else 'Not set'}")
        if state.jwt_token:
            logger.info(f"    Token (first 20 chars): {state.jwt_token[:20]}...")
        
        # DU/Display Information
        logger.info("\nDU/Display Information:")
        logger.info(f"  DU Number: {state.du_number or 'Not set'}")
        logger.info(f"  Display Number: {state.display_number or 'Not set'}")
        logger.info(f"  Raw 512 bytes: {'Present' if state.raw_512_bytes else 'Not set'}")
        
        # Bootloader Version
        logger.info("\nBootloader Version:")
        if state.bootloader_version:
            logger.info(f"  Version (tuple): {state.bootloader_version}")
            logger.info(f"  Version (string): {state.bootloader_version_string}")
        else:
            logger.info("  Not extracted yet")
        
        # Encryption
        logger.info("\nEncryption:")
        logger.info(f"  Encryption Enabled: {state.is_encryption_enabled}")
        logger.info(f"  Encryption Key: {'Present (32 bytes)' if state.encryption_key else 'Not set'}")
        if state.encryption_key:
            logger.info(f"    Key (first 8 bytes): {state.encryption_key[:8].hex()}...")
        
        # Firmware Selection
        logger.info("\nFirmware Selection:")
        logger.info(f"  Selected File ID: {state.selected_file_id or 'Not selected'}")
        logger.info(f"  Selected File Name: {state.selected_file_name or 'Not selected'}")
        logger.info(f"  DU Options: {'Present' if state.du_options else 'Not set'}")
        if state.du_options:
            file_count = len(state.du_options.get('fileName', []))
            logger.info(f"    Available Files: {file_count}")
        
        # Complete Summary
        logger.info("\nState Summary:")
        summary = state.get_state_summary()
        for key, value in summary.items():
            logger.info(f"  {key}: {value}")
        
        logger.info("=" * 70)

    def start_program_logic(self):
        """Start the DU detection and handshake process."""
        from pages.download_page import DownloadPage
        from pages.login_page import LoginPage
        
        logger.info("Starting Program Logic - Fetching from Server")
        dp = self.controller.frames[DownloadPage]
        dp.file_id = None
        dp.status_label.config(text="Please Wait...")
        self.controller.show_frame(DownloadPage)
        
        def ui_message(msg):
            logger.info(f"STATUS: {msg}")
            self.controller.after(0, lambda: dp.status_label.config(text=msg))

        def ui_error(msg):
            logger.error(f"ERROR: {msg}")
            safe_cleanup()
            self.controller.after(0, lambda: self.controller.show_error(
                "FAILED TO HANDSHAKE", msg, LoginPage
            ))

        # Read authentication from AppState
        state = AppState.get_instance()
        
        threading.Thread(
            target=read_du_from_serial,
            args=(
                state.jwt_token,
                state.phone_number or "",
                ui_message,
                self.ui_success,
                ui_error,
                os.getenv("SERIAL_PORT", "/dev/ttyAMA0"),
                115200
            ),
            daemon=True
        ).start()

    def on_download_and_flash(self, selected_file_id):
        """Handle file selection and start download."""
        from pages.download_page import DownloadPage
        
        dp = self.controller.frames[DownloadPage]
        dp.file_id = None
        self.controller.show_frame(DownloadPage)

        def on_ui_message(msg):
            logger.info(f"[DU Reader] {msg}")
            self.controller.after(0, lambda: dp.status_label.config(text=msg))

        def on_ui_success(data):
            self.controller.after(0, lambda: self.ui_success(data))

        def on_ui_error(err_msg):
            logger.info(f"[DU Reader Error] {err_msg}")
            self.controller.after(0, lambda: self.controller.show_error(
                "FAILED TO HANDSHAKE", err_msg, ProgramPage
            ))

        def run_thread():
            state = AppState.get_instance()
            read_du_from_serial(
                token=state.jwt_token,
                phoneNo=state.phone_number or "",
                callback_ui_message=on_ui_message,
                callback_ui_success=on_ui_success,
                callback_ui_error=on_ui_error
            )

        threading.Thread(target=run_thread, daemon=True).start()

    def ui_success(self, data):
        """Handle successful DU detection."""
        from pages.file_selection_page import FileSelectionPage
        from pages.download_page import DownloadPage
        
        options = data.get("options", {})
        is_enc = data.get("isEncryptionEnable", False)
        du_num = data.get("duNumber")
        disp_num = data.get("displayNumber")
        enc_key = data.get("encryptionKey")


        logger.info(f"SUCCESS — DU List: {options}")
        if enc_key:
            logger.info(f"Encryption key stored: {len(enc_key)} bytes")
        
        # Note: DU data is already stored in AppState by du_reader.py
        # Just update the controller's du_options for backward compatibility
        self.controller.du_options = options
        self.controller.du_options["duNumber"] = du_num
        self.controller.du_options["displayNumber"] = disp_num
        self.controller.is_encryption_enable = is_enc
        self.controller.encryption_key = enc_key
        
        # Check for single file auto-download
        file_names = options.get("fileName", [])
        file_ids = options.get("fileId", [])
        
        if len(file_names) == 1 and len(file_ids) == 1:
            logger.info(f"Auto-downloading single file: {file_names[0]}")
            # Store selected file in AppState
            state = AppState.get_instance()
            state.set_firmware_selection(file_ids[0], file_names[0])
            
            download_page = self.controller.frames[DownloadPage]
            download_page.file_id = file_ids[0]
            self.controller.show_frame(DownloadPage)
        else:
            self.controller.show_frame(FileSelectionPage)

    def ui_error(self, msg):
        """Handle DU detection error."""
        from tkinter import messagebox
        logger.error(f"ERROR: {msg}")
        messagebox.showerror("Error", msg)
