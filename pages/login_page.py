"""
Login Page for Python Bootloader Application.

Provides user authentication interface with phone number and password
entry, T9 keyboard support, and login API integration.
"""

import threading
import ttkbootstrap as ttk
from ttkbootstrap.constants import SUCCESS, SECONDARY, INFO

from t9_keypad import T9Keypad


class LoginPage(ttk.Frame):
    """
    User authentication page.
    
    Handles service engineer login with phone number and password,
    validates credentials via API, and stores authentication token.
    
    Attributes:
        controller: Reference to the main App controller.
        keyboard (T9Keypad): On-screen keyboard widget.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the login page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm
        self.keyboard = None

        # Title
        ttk.Label(self, text="Log In", font=lm.font(20)).pack(pady=lm.scaled(15))

        # Mobile Number
        ttk.Label(self, text="Mobile Number", font=lm.font(12)).pack(pady=(lm.scaled(10), lm.scaled(3)))
        self.phone = ttk.Entry(self, font=lm.font(12))
        self.phone.pack(pady=(0, lm.scaled(10)), padx=lm.scaled(40), ipady=lm.scaled(6), fill="x")
        self.phone.bind("<FocusIn>", lambda e: self.open_keyboard(self.phone))

        # Password Label
        ttk.Label(self, text="Password", font=lm.font(12)).pack(pady=(0, lm.scaled(3)))

        # Password field container
        pw_container = ttk.Frame(self)
        pw_container.pack(pady=lm.scaled(10), padx=lm.scaled(40), fill="x")

        pw_frame = ttk.Frame(pw_container)
        pw_frame.pack(fill="x")

        self.password = ttk.Entry(pw_frame, font=lm.font(12), show="*")
        self.password.pack(fill="x", ipady=lm.scaled(6))
        self.password.configure(style='Password.TEntry')

        # Show password button
        self.eye_btn = ttk.Button(
            pw_frame, text="Show", bootstyle=INFO,
            command=self.toggle_password
        )
        self.eye_btn.place(relx=1.0, rely=0.5, anchor="e", x=-lm.scaled(5))

        self.password.bind("<FocusIn>", lambda e: self.open_keyboard(self.password))

        # Button row
        btn_row = ttk.Frame(self)
        btn_row.pack(pady=lm.scaled(15))

        # Log In button
        self.signin_btn = ttk.Button(
            btn_row, text="Log In", bootstyle=SUCCESS,
            padding=lm.scaled(12), command=self.start_login
        )
        self.signin_btn.pack(side="left", padx=lm.scaled(10))

        # Change Wi-Fi button
        self.change_wifi_btn = ttk.Button(
            btn_row, text="Change Wi-Fi", bootstyle=SECONDARY,
            padding=lm.scaled(12), command=self._go_wifi
        )
        self.change_wifi_btn.pack(side="left", padx=lm.scaled(10))

        # Hidden Change Wi-Fi button (for later use)
        self.change_wifi_btn_hidden = ttk.Button(
            btn_row, text="Change Wi-Fi", bootstyle=SECONDARY,
            padding=lm.scaled(20), command=self._go_wifi
        )

    def _go_wifi(self):
        """Navigate to WiFi scan page."""
        from pages.scan_page import ScanPage
        self.controller.show_frame(ScanPage)

    def on_show(self):
        """Reset DU info when returning to login page."""
        self.controller.update_du_info(None, None)

    def start_login(self):
        """Start the login process."""
        from pages.wifi_connecting_page import WifiConnectingPage
        
        phone = self.phone.get().strip()
        if not phone.startswith("+"):
            phone = "+91" + phone

        password = self.password.get().strip()

        if not phone or not password:
            self.controller.show_error(
                title="Invalid Input",
                message="Please enter both phone number and password.",
                return_frame=LoginPage
            )
            return

        # Show connecting animation
        connecting_page = self.controller.frames[WifiConnectingPage]
        connecting_page.set_text("Signing In...")
        self.controller.show_frame(WifiConnectingPage)

        threading.Thread(target=self.process_login, args=(phone, password), daemon=True).start()

    def process_login(self, phone, password):
        """Background thread for login API call."""
        from api.auth_api import login_api
        from pages.program_page import ProgramPage
        
        ok, token_or_error, error_type = login_api(phone, password)

        if not ok:
            if error_type == "network_error":
                self.controller.after(0, lambda: self.controller.show_error(
                    title="Connection Error",
                    message=token_or_error,
                    return_frame=LoginPage
                ))
            else:
                self.controller.after(0, lambda: self.controller.show_error(
                    title="Login Failed",
                    message="Incorrect phone or password.",
                    return_frame=LoginPage
                ))
            return

        # Save token and phone
        self.controller.token = token_or_error
        self.controller.phone = phone
        self.controller.after(0, lambda: self.controller.show_frame(ProgramPage))

    def show_change_wifi_button(self):
        """Show the hidden change WiFi button."""
        pass

    def toggle_password(self):
        """Toggle password visibility."""
        cur = self.password.cget("show")
        self.password.config(show="" if cur == "*" else "*")
        
    def _create_keyboard_if_needed(self):
        """Create keyboard widget if not exists."""
        if not self.keyboard:
            self.keyboard = T9Keypad(self, None, self.close_keyboard, self.controller.lm)

    def open_keyboard(self, entry):
        """Show on-screen keyboard for the given entry."""
        self._create_keyboard_if_needed()
        self.keyboard.set_target(entry)
        self.keyboard.pack(side="bottom", fill="x")

    def close_keyboard(self):
        """Hide the on-screen keyboard."""
        if self.keyboard:
            self.keyboard.destroy()
            self.keyboard = None
