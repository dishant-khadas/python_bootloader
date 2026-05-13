"""
Test Page for Python Bootloader Application.

Provides manual control over GPIO pins for testing purposes.
Includes buttons to turn Display and BTL Detect on/off.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import PRIMARY, SECONDARY, INFO, SUCCESS, DANGER
from utils.gpio_control import (
    turn_display_On, 
    turn_display_Off, 
    turn_BL_Detect_High, 
    turn_BL_Detect_Low,
    safe_cleanup
)
from utils.logger import logger

class TestPage(ttk.Frame):
    """
    Manual GPIO testing page.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the test page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm

        # Track hardware states
        self.display_is_on = False
        self.btl_is_on = False

        # Title
        ttk.Label(self, text="GPIO Hardware Test", font=lm.font(24)).pack(pady=lm.scaled(30))

        # Main container for buttons - Vertical layout
        btn_container = ttk.Frame(self)
        btn_container.pack(pady=lm.scaled(10), fill="both", expand=True)

        # Display Control Section
        self.display_btn = ttk.Button(
            btn_container, 
            text="Display: OFF", 
            bootstyle=DANGER,
            padding=lm.scaled(25),
            command=self.toggle_display
        )
        self.display_btn.pack(pady=lm.scaled(20), padx=lm.scaled(40), fill="x")

        # BTL Detect Control Section
        self.btl_btn = ttk.Button(
            btn_container, 
            text="BTL Detect: OFF", 
            bootstyle=DANGER,
            padding=lm.scaled(25),
            command=self.toggle_btl
        )
        self.btl_btn.pack(pady=lm.scaled(20), padx=lm.scaled(40), fill="x")

        # Status indicator
        self.status_label = ttk.Label(
            btn_container, 
            text="Hardware: IDLE", 
            font=lm.font(12),
            foreground="#666666"
        )
        self.status_label.pack(pady=lm.scaled(20))

        # Navigation Footer
        footer = ttk.Frame(self)
        footer.pack(side="bottom", fill="x", pady=lm.scaled(30))

        ttk.Button(
            footer, text="BACK", bootstyle=SECONDARY,
            padding=lm.scaled(15), command=self.go_back
        ).pack(pady=lm.scaled(10))

    def toggle_display(self):
        """Toggle Display power state."""
        if self.display_is_on:
            turn_display_Off()
            self.display_is_on = False
            self.display_btn.config(text="Display: OFF", bootstyle=DANGER)
            logger.info("[TestPage] Display toggled -> OFF")
        else:
            turn_display_On()
            self.display_is_on = True
            self.display_btn.config(text="Display: ON", bootstyle=SUCCESS)
            logger.info("[TestPage] Display toggled -> ON")
        self.update_status()

    def toggle_btl(self):
        """Toggle BTL Detect state."""
        if self.btl_is_on:
            turn_BL_Detect_Low()
            self.btl_is_on = False
            self.btl_btn.config(text="BTL Detect: OFF", bootstyle=DANGER)
            logger.info("[TestPage] BTL Detect toggled -> OFF")
        else:
            turn_BL_Detect_High()
            self.btl_is_on = True
            self.btl_btn.config(text="BTL Detect: ON", bootstyle=SUCCESS)
            logger.info("[TestPage] BTL Detect toggled -> ON")
        self.update_status()

    def update_status(self):
        """Update the status label based on hardware states."""
        if self.display_is_on or self.btl_is_on:
            self.status_label.config(text="Hardware: ACTIVE", foreground="#ff0000")
        else:
            self.status_label.config(text="Hardware: IDLE", foreground="#666666")

    def go_back(self):
        """Return to ProgramPage and turn off hardware."""
        logger.info("[TestPage] Returning to Program Page. Cleaning up GPIO.")
        safe_cleanup()
        
        # Reset UI states
        self.display_is_on = False
        self.btl_is_on = False
        self.display_btn.config(text="Display: OFF", bootstyle=DANGER)
        self.btl_btn.config(text="BTL Detect: OFF", bootstyle=DANGER)
        self.update_status()
        
        from pages.program_page import ProgramPage
        self.controller.show_frame(ProgramPage)
