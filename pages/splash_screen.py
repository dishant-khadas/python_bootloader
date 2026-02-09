"""
Splash Screen Page for Python Bootloader Application.

Displays an animated logo splash screen on application startup.
Automatically transitions to either LoginPage (if WiFi connected) or
ScanPage (if no WiFi connection).
"""

import os
import ttkbootstrap as ttk
from PIL import Image, ImageTk


class SplashScreen(ttk.Frame):
    """
    Animated splash screen with logo.
    
    Displays the CZAR logo with a fade-in animation effect, then
    automatically navigates to the appropriate next page based on
    WiFi connection status.
    
    Attributes:
        controller: Reference to the main App controller.
        alpha (float): Current animation alpha value.
        animation_running (bool): Whether animation is in progress.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the splash screen.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm
        
        # Set background to white
        self.configure(style='TFrame')
        
        # Center container
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        # Load and display logo
        try:
            # Load the PNG image
            logo_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "czar.png")
            self.original_image = Image.open(logo_path)
            
            # Resize to fit nicely on screen
            max_size = (lm.scaled(300), lm.scaled(300))
            self.original_image.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            # Create PhotoImage
            self.photo = ImageTk.PhotoImage(self.original_image)
            
            # Display image
            self.logo_label = ttk.Label(container, image=self.photo)
            self.logo_label.pack()
            ttk.Label(container, text="Please Wait...", font=lm.font(18)).pack(pady=lm.scaled(24))
            
        except Exception as e:
            # Fallback if image can't be loaded
            ttk.Label(container, text="CZAR", font=lm.font(48)).pack()
            print(f"Error loading splash image: {e}")
        
        # Animation state
        self.alpha = 0.0
        self.animation_running = False
    
    def on_show(self):
        """Called when the splash screen is shown."""
        if not self.animation_running:
            self.animation_running = True
            self.alpha = 0.0
            self.animate_fade_in()
    
    def animate_fade_in(self):
        """Fade in animation loop."""
        if self.alpha < 1.0:
            self.alpha += 0.05
            self.after(30, self.animate_fade_in)
        else:
            # Animation complete, wait a bit then transition
            self.after(1000, self.transition_to_next_page)
    
    def transition_to_next_page(self):
        """Transition to the appropriate next page based on WiFi status."""
        from utils.wifi_utils import get_connected_ssid
        from pages.login_page import LoginPage
        from pages.scan_page import ScanPage
        
        self.animation_running = False
        
        # Auto-detect WiFi and go to appropriate page
        ssid = get_connected_ssid()
        if ssid:
            self.controller.frames[LoginPage].show_change_wifi_button()
            self.controller.show_frame(LoginPage)
        else:
            self.controller.show_frame(ScanPage)
