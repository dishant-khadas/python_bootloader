"""
Manual WiFi Page for Python Bootloader Application.

Allows manual entry of SSID and password for networks not found
during scanning.
"""

import threading
import time
import ttkbootstrap as ttk
from ttkbootstrap.constants import SUCCESS, SECONDARY, INFO
from tkinter import messagebox

from t9_keypad import T9Keypad
from wifi_utils import connect_wifi


class ManualWifiPage(ttk.Frame):
    """
    Manual WiFi entry page.
    
    Provides form fields for manually entering SSID and password
    when the target network isn't visible in the scan results.
    
    Attributes:
        controller: Reference to the main App controller.
        keyboard (T9Keypad): On-screen keyboard widget.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the manual WiFi page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm
        self.keyboard = None
        
        ttk.Label(
            self, text="Enter Wi-Fi Network",
            font=lm.font(22), foreground="white"
        ).pack(pady=lm.scaled(20))
        
        # SSID Entry
        ttk.Label(self, text="SSID", font=lm.font(12)).pack(pady=(0, 5))
        self.ssid_entry = ttk.Entry(self, font=lm.font(12))
        self.ssid_entry.pack(padx=lm.scaled(40), fill="x", ipady=lm.scaled(6))

        # Password Label
        ttk.Label(
            self, text="Password", font=lm.font(12), foreground="white"
        ).pack(pady=(lm.scaled(10), lm.scaled(5)))
        
        pw_frame = ttk.Frame(self)
        pw_frame.pack(padx=lm.scaled(40), fill="x")
        
        self.password_entry = ttk.Entry(pw_frame, font=lm.font(12), show="*")
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=lm.scaled(6))
            
        ttk.Button(
            pw_frame, text="👁", width=4, bootstyle=INFO,
            command=self.toggle_password
        ).pack(side="left", padx=(lm.scaled(8), 0))

        # Keyboard bindings
        self.ssid_entry.bind("<FocusIn>", lambda e: self.open_keyboard(self.ssid_entry))
        self.password_entry.bind("<FocusIn>", lambda e: self.open_keyboard(self.password_entry))

        # Button row
        btn_row = ttk.Frame(self)
        btn_row.pack(pady=lm.scaled(25))

        ttk.Button(
            btn_row, text="Connect", bootstyle=SUCCESS,
            padding=lm.scaled(12), command=self.connect_manual
        ).pack(side="left", padx=lm.scaled(10))

        ttk.Button(
            btn_row, text="Back", bootstyle=SECONDARY,
            padding=lm.scaled(12), command=self._go_back
        ).pack(side="left", padx=lm.scaled(10))
    
    def _go_back(self):
        """Navigate back to scan page."""
        from pages.scan_page import ScanPage
        self.controller.show_frame(ScanPage)
    
    def toggle_password(self):
        """Toggle password visibility."""
        current = self.password_entry.cget("show")
        self.password_entry.config(show="" if current == "*" else "*")
        
    def open_keyboard(self, entry):
        """Show on-screen keyboard for the given entry."""
        self.close_keyboard()
        self.keyboard = T9Keypad(self, entry, self.close_keyboard, self.controller.lm)
        self.keyboard.pack(side="bottom", fill="x")
    
    def close_keyboard(self):
        """Hide the on-screen keyboard."""
        if self.keyboard:
            self.keyboard.destroy()
            self.keyboard = None
    
    def connect_manual(self):
        """Start manual WiFi connection."""
        from pages.wifi_connecting_page import WifiConnectingPage
        
        ssid = self.ssid_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not ssid:
            messagebox.showerror("Invalid Input", "Please enter the SSID.")
            return
        
        self.controller.selected_ssid = ssid
        self.controller.wifi_password = password
        
        connecting_page = self.controller.frames[WifiConnectingPage]
        connecting_page.set_text(f"Connecting to \n {ssid}...")
        self.controller.show_frame(WifiConnectingPage)
        
        threading.Thread(target=self.process_connect, daemon=True).start()
    
    def process_connect(self):
        """Background thread for WiFi connection."""
        from pages.login_page import LoginPage
        
        start_time = time.time()
        TIMEOUT = 5

        success = False
        while time.time() - start_time < TIMEOUT:
            success = connect_wifi(
                self.controller.selected_ssid,
                self.controller.wifi_password
            )
            if success:
                break
            time.sleep(1)

        if success:
            self.controller.after(0, lambda: self.controller.show_frame(LoginPage))
        else:
            self.controller.after(0, lambda: self.controller.show_error(
                title="Connection Failed",
                message="Unable to connect. Password may be incorrect or network unavailable.",
                return_frame=ManualWifiPage
            ))
