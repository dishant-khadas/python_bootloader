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

        # Title
        ttk.Label(self, text="GPIO Hardware Test", font=lm.font(30)).pack(pady=lm.scaled(40))

        # Main container for buttons
        btn_container = ttk.Frame(self)
        btn_container.pack(pady=lm.scaled(20), fill="both", expand=True)

        # Display Controls
        display_frame = ttk.LabelFrame(btn_container, text="Display Control", padding=lm.scaled(20))
        display_frame.pack(side="left", padx=lm.scaled(40), fill="both", expand=True)

        ttk.Button(
            display_frame, text="Display ON", bootstyle=SUCCESS,
            padding=lm.scaled(20), command=self.on_display_on
        ).pack(fill="x", pady=lm.scaled(10))

        ttk.Button(
            display_frame, text="Display OFF", bootstyle=DANGER,
            padding=lm.scaled(20), command=self.on_display_off
        ).pack(fill="x", pady=lm.scaled(10))

        # BTL Detect Controls
        btl_frame = ttk.LabelFrame(btn_container, text="BTL Detect Control", padding=lm.scaled(20))
        btl_frame.pack(side="left", padx=lm.scaled(40), fill="both", expand=True)

        ttk.Button(
            btl_frame, text="BTL Detect ON", bootstyle=SUCCESS,
            padding=lm.scaled(20), command=self.on_btl_on
        ).pack(fill="x", pady=lm.scaled(10))

        ttk.Button(
            btl_frame, text="BTL Detect OFF", bootstyle=DANGER,
            padding=lm.scaled(20), command=self.on_btl_off
        ).pack(fill="x", pady=lm.scaled(10))

        # Navigation Footer
        footer = ttk.Frame(self)
        footer.pack(side="bottom", fill="x", pady=lm.scaled(40))

        ttk.Button(
            footer, text="BACK", bootstyle=SECONDARY,
            padding=lm.scaled(15), command=self.go_back
        ).pack()

    def on_display_on(self):
        logger.info("[TestPage] Manual Display ON")
        turn_display_On()

    def on_display_off(self):
        logger.info("[TestPage] Manual Display OFF")
        turn_display_Off()

    def on_btl_on(self):
        logger.info("[TestPage] Manual BTL Detect ON")
        turn_BL_Detect_High()

    def on_btl_off(self):
        logger.info("[TestPage] Manual BTL Detect OFF")
        turn_BL_Detect_Low()

    def go_back(self):
        """Return to ProgramPage and turn off hardware."""
        logger.info("[TestPage] Returning to Program Page. Cleaning up GPIO.")
        safe_cleanup()
        from pages.program_page import ProgramPage
        self.controller.show_frame(ProgramPage)
