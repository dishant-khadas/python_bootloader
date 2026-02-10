"""
Scan Page for Python Bootloader Application.

Provides the initial WiFi scanning interface with a button to trigger
network discovery.
"""

import threading
import time
import ttkbootstrap as ttk
from ttkbootstrap.constants import PRIMARY

from utils.wifi_utils import scan_wifi


class ScanPage(ttk.Frame):
    """
    WiFi scanning initiation page.
    
    Simple page with a "Scan Wi-Fi" button that triggers network
    scanning and navigates to the network list.
    
    Attributes:
        controller: Reference to the main App controller.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the scan page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm

        # Centering Container
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(container, text="Connect to Wi-Fi", font=lm.font(24)).pack(pady=lm.scaled(30))
        ttk.Button(
            container, 
            text="Scan Wi-Fi", 
            padding=lm.scaled(20), 
            bootstyle=PRIMARY,
            command=self.start_scan
        ).pack(pady=lm.scaled(120))

    def start_scan(self):
        """Start WiFi scanning in background thread."""
        from pages.wifi_connecting_page import WifiConnectingPage
        
        self.controller.show_frame(WifiConnectingPage)
        self.controller.frames[WifiConnectingPage].set_text("Scanning WiFi...")
        threading.Thread(target=self.process_scan, daemon=True).start()

    def process_scan(self):
        """Background thread: Scan for networks and update UI."""
        from pages.wifi_list_page import WifiListPage
        
        ssids = scan_wifi()
        time.sleep(1)
        self.controller.frames[WifiListPage].load_list(ssids)
        self.controller.show_frame(WifiListPage)
        self.controller.frames[WifiListPage].focus_set()
