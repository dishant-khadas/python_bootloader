"""
Download Page for Python Bootloader Application.

Handles firmware download, verification, and preparation for flashing.
Shows progress with indeterminate progress bar and status updates.
"""

import threading
import ttkbootstrap as ttk
from ttkbootstrap.constants import INFO

from gpio_control import safe_cleanup
from bootloader_download import download_and_flash


class DownloadPage(ttk.Frame):
    """
    Firmware download and verification page.
    
    Downloads encrypted firmware, verifies hashes, decrypts file,
    and prepares for firmware flashing via btl_host.py.
    
    Attributes:
        controller: Reference to the main App controller.
        file_id (str): ID of the file to download.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the download page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = controller.lm

        self.file_id = None

        # Center Container
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.5, anchor="center")

        # Title
        ttk.Label(container, text="Please Wait...", font=lm.font(20)).pack(pady=lm.scaled(30))

        # Progress bar
        self.progress = ttk.Progressbar(
            container, mode='indeterminate', bootstyle=INFO,
            length=lm.scaled(300)
        )
        self.progress.pack(pady=lm.scaled(20))
        self.progress.start(10)

        # Status Label
        self.status_label = ttk.Label(
            container, text="Initializing...", font=lm.font(16),
            foreground="black", wraplength=lm.scaled(400), justify="center"
        )
        self.status_label.pack(pady=lm.scaled(20))

    def on_show(self):
        """Called when page is shown."""
        self.progress.start(10)
        
        if hasattr(self, 'file_id') and self.file_id:
            self.status_label.config(text="Starting download...")
            threading.Thread(
                target=self.start_download_logic, args=(self.file_id,),
                daemon=True
            ).start()
        else:
            self.status_label.config(text="Please wait...")

    def start_download(self, file_id):
        """Set file ID for download."""
        self.file_id = file_id

    def start_download_logic(self, file_id):
        """Background thread for download and verification."""
        from pages.firmware_update_page import FirmwareUpdatePage
        from pages.login_page import LoginPage
        
        token = self.controller.token
        device_id = "41999990"

        is_enc = getattr(self.controller, "is_encryption_enable", False)
        enc_key = getattr(self.controller, "encryption_key", None)

        def on_msg(text):
            self.controller.after(0, lambda: self.status_label.config(text=text))
        
        def on_success(res):
            self.controller.after(0, lambda: self.download_success(res))

        def on_err(err_text):
            self.controller.after(0, lambda: self.serialPort_error(f"Serial Port Error: {err_text}"))
        
        def on_firmware_update(output_path, encryption_key_hex, is_enc_flag):
            self.controller.after(0, lambda: self.start_firmware_update(
                output_path, encryption_key_hex, is_enc_flag
            ))

        download_and_flash(
            file_id=file_id,
            token=token,
            device_id=device_id,
            is_encryption_enable=is_enc,
            encryption_key=enc_key,
            phoneNo=getattr(self.controller, "phone", ""),
            duNumber=getattr(self.controller, "du_options", {}).get("duNumber", ""),
            displayNumber=getattr(self.controller, "du_options", {}).get("displayNumber", ""),
            callback_message=on_msg,
            callback_success=on_success,
            callback_error=on_err,
            callback_firmware_update=on_firmware_update
        )
    
    def start_firmware_update(self, output_path, encryption_key_hex, is_enc_flag):
        """Navigate to FirmwareUpdatePage and start btl_host.py."""
        from pages.firmware_update_page import FirmwareUpdatePage
        
        firmware_page = self.controller.frames[FirmwareUpdatePage]
        firmware_page.set_params(output_path, encryption_key_hex, is_enc_flag)
        self.controller.show_frame(FirmwareUpdatePage)

    def download_success(self, res):
        """Handle successful download."""
        from pages.program_page import ProgramPage
        
        self.progress.stop()
        self.status_label.config(text="Download & Flash Complete!", foreground="green")
        self.controller.show_frame(ProgramPage)

    def download_error(self, err_text):
        """Handle download error."""
        from pages.login_page import LoginPage
        
        self.progress.stop()
        self.status_label.config(text="Error occurred", foreground="red")
        safe_cleanup()
        self.controller.show_error("Download Failed", err_text, return_frame=LoginPage)

    def serialPort_error(self, err_text):
        """Handle serial port error."""
        from pages.login_page import LoginPage
        
        self.progress.stop()
        self.status_label.config(text="Serial Port Error", foreground="red")
        safe_cleanup()
        self.controller.show_error("Serial Port Error", err_text, return_frame=LoginPage)
