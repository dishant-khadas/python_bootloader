"""
Error Page for Python Bootloader Application.

Generic error display page that shows error title, message, and
a back button to return to the previous page.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import SECONDARY


class ErrorPage(ttk.Frame):
    """
    Generic error display page.
    
    Shows error information with customizable title and message,
    plus a back button to return to a specified page.
    
    Attributes:
        controller: Reference to the main App controller.
        return_frame: Page class to return to on back button.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the error page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = controller.lm

        self.configure(style="Danger.TFrame")

        container = ttk.Frame(self, padding=lm.scaled(30))
        container.pack(expand=True)

        self.title_label = ttk.Label(
            container, text="", font=lm.font(18),
            foreground="#020202"
        )
        self.title_label.pack(pady=(0, lm.scaled(10)))

        self.message_label = ttk.Label(
            container, text="", font=lm.font(12),
            foreground="#020202", wraplength=lm.scaled(400),
            justify="center"
        )
        self.message_label.pack(pady=(0, lm.scaled(20)))

        ttk.Button(
            container, text="Back", bootstyle=SECONDARY,
            padding=lm.scaled(12), command=self.go_back
        ).pack()

        self.return_frame = None

    def set_error(self, title, message, return_frame):
        """
        Set the error details to display.
        
        Args:
            title (str): Error title/heading.
            message (str): Detailed error message.
            return_frame: Page class to navigate to on back button.
        """
        self.title_label.config(text=title)
        self.message_label.config(text=message)
        self.return_frame = return_frame

    def go_back(self):
        """Navigate back to the return frame."""
        self.controller.show_frame(self.return_frame)
