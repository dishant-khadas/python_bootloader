"""
WiFi Password Page for Python Bootloader Application.

Provides password entry interface with T9 keyboard for connecting
to the selected WiFi network.
"""

import threading
import time
import ttkbootstrap as ttk
from ttkbootstrap.constants import PRIMARY, SECONDARY, INFO

from t9_keypad import T9Keypad
from utils.wifi_utils import connect_wifi, check_internet, wait_for_wifi_connected, disconnect_wifi


class WifiPasswordPage(ttk.Frame):
    """
    WiFi password entry page.
    
    Allows user to enter password for the selected WiFi network
    with T9 keyboard support for touchscreen input.
    
    Attributes:
        controller: Reference to the main App controller.
        keyboard (T9Keypad): On-screen keyboard widget.
        keyboard_visible (bool): Whether keyboard is currently shown.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the password entry page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm
        self.keyboard = None

        # Title with SSID
        self.title_label = ttk.Label(self, font=lm.font(15), wraplength=lm.scaled(400), justify="center")
        self.title_label.pack(pady=lm.scaled(15))

        # Password Label
        ttk.Label(self, text="Password", font=lm.font(12)).pack(pady=(lm.scaled(10), lm.scaled(3)))

        # Password field frame
        pw_field_frame = ttk.Frame(self)
        pw_field_frame.pack(pady=lm.scaled(10), padx=lm.scaled(40), fill="x")

        self.password_entry = ttk.Entry(pw_field_frame, font=lm.font(12), show="*")
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=lm.scaled(6))

        # Show password button
        ttk.Button(
            pw_field_frame, text="Show", bootstyle=INFO,
            command=self.toggle_password
        ).pack(side="left", padx=lm.scaled(8))

        self.password_entry.bind("<FocusIn>", self.open_keyboard)
        
        # Button frame
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=lm.scaled(15))

        # Connect button
        ttk.Button(
            btn_frame, text="Connect", padding=lm.scaled(12), bootstyle=PRIMARY,
            command=self.start_connect
        ).pack(side="left", padx=lm.scaled(15))
        
        # Back button
        ttk.Button(
            btn_frame, text="Back", padding=lm.scaled(12), bootstyle=SECONDARY,
            command=self._go_back
        ).pack(side="right", padx=lm.scaled(15))

        # Initialize keyboard (hidden)
        self.keyboard = T9Keypad(self, self.password_entry, self.close_keyboard, self.controller.lm)
        self.keyboard_visible = False

    def _go_back(self):
        """Navigate back to scan page."""
        from pages.scan_page import ScanPage
        self.controller.show_frame(ScanPage)

    def toggle_password(self):
        """Toggle password visibility."""
        cur = self.password_entry.cget("show")
        self.password_entry.config(show="" if cur == "*" else "*")

    def open_keyboard(self, _):
        """Show the on-screen keyboard."""
        if not self.keyboard_visible:
            self.keyboard.pack(side="bottom", fill="x")
            self.keyboard_visible = True

    def close_keyboard(self):
        """Hide the on-screen keyboard."""
        if self.keyboard_visible:
            self.keyboard.pack_forget()
            self.keyboard_visible = False

    def start_connect(self):
        """Start WiFi connection process."""
        from pages.wifi_connecting_page import WifiConnectingPage
        
        pwd = self.password_entry.get()
        if not pwd:
            return

        self.controller.wifi_password = pwd
        connecting_page = self.controller.frames[WifiConnectingPage]
        connecting_page.set_text(f"Connecting to \n {self.controller.selected_ssid}...")
        self.controller.show_frame(WifiConnectingPage)

        threading.Thread(target=self.process_connect, daemon=True).start()

    def process_connect(self):
        """Background thread for WiFi connection."""
        from pages.wifi_connecting_page import WifiConnectingPage
        from pages.scan_page import ScanPage
        from pages.login_page import LoginPage
        
        connecting_page = self.controller.frames[WifiConnectingPage]
        
        ssid = self.controller.selected_ssid
        pwd = self.controller.wifi_password
        
        disconnect_wifi()
        time.sleep(1)

        # Try to connect
        connect_wifi(ssid, pwd)
        connected = wait_for_wifi_connected(ssid, timeout=20)
        
        if not connected:
            self.controller.wifi_password = None
            self.controller.after(0, lambda: self.controller.show_error(
                title="Wrong Password", 
                message="Incorrect password. Try again.",
                return_frame=WifiPasswordPage
            ))
            return
            
        connecting_page.set_text("Checking Internet...")
        time.sleep(1)
        
        if connecting_page.is_cancelled:
            return
            
        if not check_internet():
            self.controller.wifi_password = None
            self.controller.after(0, lambda: self.controller.show_error(
                title="No Internet or Incorrect WiFi Password",
                message="Cannot connected to WiFi. Try another network.",
                return_frame=ScanPage
            ))
            return
        
        # Success
        self.controller.wifi_password = None
        self.controller.after(0, lambda: self.controller.show_frame(LoginPage))
