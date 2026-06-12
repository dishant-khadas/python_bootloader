"""
Pages Package for Python Bootloader Application.

This package contains all UI page classes extracted from main.py for
better maintainability and code organization.

Each page is a ttk.Frame subclass that receives parent and controller
arguments. The controller (App) provides navigation and shared state.
"""

# Import all page classes for easy access
from pages.splash_screen import SplashScreen
from pages.scan_page import ScanPage
from pages.wifi_list_page import WifiListPage
from pages.wifi_password_page import WifiPasswordPage
from pages.manual_wifi_page import ManualWifiPage
from pages.wifi_connecting_page import WifiConnectingPage
from pages.login_page import LoginPage
from pages.program_page import ProgramPage
from pages.file_selection_page import FileSelectionPage
from pages.download_page import DownloadPage
from pages.firmware_update_page import FirmwareUpdatePage
from pages.error_page import ErrorPage
from pages.test_page import TestPage


__all__ = [
    'SplashScreen',
    'ScanPage', 
    'WifiListPage',
    'WifiPasswordPage',
    'ManualWifiPage',
    'WifiConnectingPage',
    'LoginPage',
    'ProgramPage',
    'FileSelectionPage',
    'DownloadPage',
    'FirmwareUpdatePage',
    'ErrorPage',
    'TestPage',
]

