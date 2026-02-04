"""
WiFi Connecting Page for Python Bootloader Application.

Displays connection progress with animated dots and cancel option.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import DANGER


class WifiConnectingPage(ttk.Frame):
    """
    Connection progress display page.
    
    Shows animated status text during WiFi connection or login
    operations, with option to cancel.
    
    Attributes:
        controller: Reference to the main App controller.
        mode (str): Current mode - "wifi" or "login".
        text (str): Current status text to display.
        is_cancelled (bool): Whether operation was cancelled.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the connecting page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm
        self.mode = "wifi"
        self.text = ""
        self.dots = 0
        self.is_cancelled = False

        # Status label
        self.label = ttk.Label(self, text="", font=lm.font(24))
        self.label.pack(pady=lm.scaled(150))

        # Cancel button
        ttk.Button(
            self, text="Cancel", bootstyle=DANGER,
            padding=lm.scaled(20), command=self.cancel_connection
        ).pack(pady=lm.scaled(40))

        # Start animation loop
        self.animate()

    def set_text(self, text):
        """
        Set the status text to display.
        
        Args:
            text (str): Status message to show.
        """
        self.text = text
        self.is_cancelled = False

    def cancel_connection(self):
        """Handle cancel button press."""
        from pages.scan_page import ScanPage
        from pages.login_page import LoginPage
        
        self.is_cancelled = True

        if self.mode == "wifi":
            self.controller.show_frame(ScanPage)
        else:
            self.controller.show_frame(LoginPage)

    def animate(self):
        """Dot animation loop."""
        if self.text and not self.is_cancelled:
            self.label.config(text=self.text + "." * (self.dots % 4))
            self.dots += 1
        self.after(500, self.animate)
