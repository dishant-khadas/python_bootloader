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
        ).pack(pady=lm.scaled(50))

        self.status_label = ttk.Label(self, text="", font=lm.font(14), bootstyle=WARNING)
        self.status_label.pack(pady=lm.scaled(20))

    def start_program_logic(self):
        """Start the DU detection and handshake process."""
        from pages.download_page import DownloadPage
        from pages.login_page import LoginPage
        
        print("Starting Program Logic - Fetching from Server")
        
        # Show download page as loading screen
        dp = self.controller.frames[DownloadPage]
        dp.file_id = None
        dp.status_label.config(text="Please Wait...")
        self.controller.show_frame(DownloadPage)
        
        def ui_message(msg):
            print("STATUS:", msg)
            self.controller.after(0, lambda: dp.status_label.config(text=msg))

        def ui_error(msg):
            print("ERROR:", msg)
            safe_cleanup()
            self.controller.after(0, lambda: self.controller.show_error(
                "FAILED TO HANDSHAKE", msg, LoginPage
            ))

        threading.Thread(
            target=read_du_from_serial,
            args=(
                self.controller.token,
                getattr(self.controller, "phone", ""),
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
            print(f"[DU Reader] {msg}")
            self.controller.after(0, lambda: dp.status_label.config(text=msg))

        def on_ui_success(data):
            self.controller.after(0, lambda: self.ui_success(data))

        def on_ui_error(err_msg):
            print(f"[DU Reader Error] {err_msg}")
            self.controller.after(0, lambda: self.controller.show_error(
                "FAILED TO HANDSHAKE", err_msg, ProgramPage
            ))

        def run_thread():
            token = self.controller.token
            read_du_from_serial(
                token=token,
                phoneNo=getattr(self.controller, "phone", ""),
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


        print("SUCCESS — DU List:", options)
        if enc_key:
            print(f"Encryption key stored: {len(enc_key)} bytes")  # SECURITY: Only log length
        
        # Save info
        self.controller.du_options = options
        self.controller.du_options["duNumber"] = du_num
        self.controller.du_options["displayNumber"] = disp_num
        self.controller.is_encryption_enable = is_enc
        self.controller.encryption_key = enc_key
        
        # Check for single file auto-download
        file_names = options.get("fileName", [])
        file_ids = options.get("fileId", [])
        
        if len(file_names) == 1 and len(file_ids) == 1:
            print(f"Auto-downloading single file: {file_names[0]}")
            self.controller.selected_file_name = file_names[0]
            download_page = self.controller.frames[DownloadPage]
            download_page.file_id = file_ids[0]
            self.controller.show_frame(DownloadPage)
        else:
            self.controller.show_frame(FileSelectionPage)

    def ui_error(self, msg):
        """Handle DU detection error."""
        from tkinter import messagebox
        print("ERROR:", msg)
        messagebox.showerror("Error", msg)
