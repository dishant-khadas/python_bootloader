"""
Main Application Module for Python Bootloader Application.

This is the entry point and UI controller for the CZAR Bootloader application.
It manages the tkinter-based GUI with multiple pages for WiFi configuration,
user authentication, and firmware update operations.

Application Pages:
    - SplashScreen: Initial loading screen with logo
    - ScanPage: WiFi scanning status page
    - WifiListPage: Display available WiFi networks
    - WifiPasswordPage: Password entry for WiFi connection
    - ManualWifiPage: Manual WiFi SSID/password entry
    - WifiConnectingPage: Connection status display
    - LoginPage: Service engineer authentication
    - ProgramPage: DU detection and handshake
    - FileSelectionPage: Firmware file selection
    - DownloadPage: Firmware download and verification
    - FirmwareUpdatePage: Firmware flashing progress
    - ErrorPage: Error display and retry options

Key Features:
    - Responsive layout via LayoutManager
    - T9 on-screen keyboard for touchscreen input
    - Threading for non-blocking serial operations
    - GPIO control for hardware signaling
    - Modular page architecture for maintainability
"""

import ttkbootstrap as ttk
from dotenv import load_dotenv

from utils.ui_utils import LayoutManager

# Import all page classes from pages package
from pages import (
    SplashScreen,
    ScanPage,
    WifiListPage,
    WifiPasswordPage,
    ManualWifiPage,
    WifiConnectingPage,
    LoginPage,
    ProgramPage,
    FileSelectionPage,
    DownloadPage,
    FirmwareUpdatePage,
    ErrorPage,
)

load_dotenv()

# Initialise SQLite3 database — creates tables if they don't exist
from core.models import init_db
init_db()


class App(ttk.Window):
    """
    Main application window and frame controller.
    
    Manages the application lifecycle, page navigation, and global state
    including WiFi credentials, authentication token, and DU information.
    
    Attributes:
        lm (LayoutManager): Responsive layout manager for scaling.
        selected_ssid (str): Currently selected WiFi network name.
        wifi_password (str): WiFi password for connection.
        token (str): Authentication token from login.
        phone (str): Phone number used for login.
        frames (dict): Dictionary of page frames keyed by class.
        du_options (dict): DU options from server API.
        is_encryption_enable (bool): Whether firmware is encrypted.
        encryption_key (bytes): 32-byte AES encryption key.
    """
    
    def __init__(self):
        """Initialize the main application window and all pages."""
        super().__init__(themename="litera")
        self.title("CZAR BOOTLOADER")

        # Open in full-screen mode (hides title bar — comment out to show close/minimize buttons)
        # self.attributes('-fullscreen', True)
        # Note: state('zoomed') is Windows-only; use attributes('-zoomed', True) on Linux
        self.attributes('-zoomed', True)

        # Get actual screen dimensions for the layout manager


        # self.update_idletasks()
        SIM_WIDTH = self.winfo_screenwidth()
        SIM_HEIGHT = self.winfo_screenheight()

        # Initialize Layout Manager with actual screen size
        self.lm = LayoutManager(self, width=SIM_WIDTH, height=SIM_HEIGHT)
        
        # Configure global style scaling
        style = ttk.Style()
        default_btn_size = 12
        style.configure('TButton', font=self.lm.font(default_btn_size))
        
        # Custom Combobox Style
        style.configure('Custom.TCombobox',
                        fieldbackground='#ffffff',
                        background='#ffffff',
                        foreground='black',
                        arrowcolor='black',
                        bordercolor='#cccccc',
                        darkcolor='#f0f0f0',
                        lightcolor='#ffffff',
                        borderwidth=1)
        
        style.map('Custom.TCombobox',
                  fieldbackground=[('readonly', '#ffffff')],
                  selectbackground=[('readonly', '#ffffff')],
                  selectforeground=[('readonly', 'black')],
                  bordercolor=[('focus', '#cccccc')],
                  lightcolor=[('focus', '#cccccc')],
                  darkcolor=[('focus', '#cccccc')])

        self.option_add('*TCombobox*Listbox.font', self.lm.font(14))

        # Global state
        self.selected_ssid = None
        self.wifi_password = None
        self.token = None
        self.phone = None
        self.du_options = {}
        self.is_encryption_enable = False
        self.encryption_key = None

        # Container for all pages
        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)

        # Initialize all page frames
        self.frames = {}
        page_classes = (
            SplashScreen,
            ScanPage,
            WifiListPage,
            WifiPasswordPage,
            ManualWifiPage,
            WifiConnectingPage,
            LoginPage,
            ProgramPage,
            FileSelectionPage,
            DownloadPage,
            FirmwareUpdatePage,
            ErrorPage,
        )
        
        for Page in page_classes:
            frame = Page(parent=self.container, controller=self)
            frame.place(relwidth=1, relheight=1)
            self.frames[Page] = frame

        # Global DU info label at top-right
        self.du_info_label = ttk.Label(
            self, 
            text="", 
            font=self.lm.font(12), 
            foreground="#666666",
            background="#ffffff"
        )
        self.du_info_label.place(relx=0.98, rely=0.02, anchor="ne")
        self.du_info_label.lower()

        # Show splash screen first
        self.show_frame(SplashScreen)

    def update_du_info(self, du_number, display_number, firmware_file_name=None):
        """
        Update the global DU info label shown at top-right of all pages.
        
        Args:
            du_number: DU serial number.
            display_number: Display serial number.
            firmware_file_name: Optional firmware file name.
        """
        if du_number and display_number:
            if firmware_file_name:
                self.du_info_label.config(
                    text=f"DU: {du_number}\nDisplay: {display_number}\nFile: {firmware_file_name}"
                )
            else:
                self.du_info_label.config(
                    text=f"DU: {du_number} | Display: {display_number}"
                )
            self.du_info_label.lift()
        else:
            self.du_info_label.config(text="")
            self.du_info_label.lower()

    def show_frame(self, page):
        """
        Switch to the specified page.
        
        Args:
            page: Page class to show.
        """
        frame = self.frames[page]
        frame.tkraise()
        
        # Keep DU info label on top if it has content
        if self.du_info_label.cget("text"):
            self.du_info_label.lift()
            
        # Call on_show if the page has it
        if hasattr(frame, "on_show"):
            frame.on_show()
        
    def show_error(self, title, message, return_frame):
        """
        Display the error page with specified details.
        
        Args:
            title: Error title/heading.
            message: Error message details.
            return_frame: Page class to return to on back button.
        """
        error_page = self.frames[ErrorPage]
        error_page.set_error(title, message, return_frame)
        self.show_frame(ErrorPage)


# ------------ RUN ------------
if __name__ == "__main__":
    app = App()
    app.mainloop()
