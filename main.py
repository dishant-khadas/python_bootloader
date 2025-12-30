import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from wifi_utils import scan_wifi, connect_wifi, check_internet, get_connected_ssid
from t9_keypad import T9Keypad
from tkinter import messagebox
from ui_utils import LayoutManager
import os

from gpio_control import (
    turn_BL_Detect_High,
    turn_BL_Detect_Low,
    turn_display_On,
    turn_display_Off
)

from dotenv import load_dotenv
load_dotenv()


import threading 
from du_reader import read_du_from_serial
from bootloader_download import download_and_flash

import time


# ------------ MAIN APP ------------
class App(ttk.Window):
    def __init__(self):
        super().__init__(themename="darkly")
        self.title("Setup Wizard")
        # self.attributes("-fullscreen", True)

        # Phone size simulation
        SIM_WIDTH=480 
        SIM_HEIGHT=800 
        self.geometry(f"{SIM_WIDTH}x{SIM_HEIGHT}")

        # Initialize Layout Manager with fixed size
        self.lm = LayoutManager(self, width=SIM_WIDTH, height=SIM_HEIGHT)
        
        # Configure global style scaling
        style = ttk.Style()
        default_btn_size = 12 # Base size for buttons
        style.configure('TButton', font=self.lm.font(default_btn_size))


        self.selected_ssid = None
        self.wifi_password = None
        self.token = None 

        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self.frames = {}
        for Page in (ScanPage, WifiListPage, WifiPasswordPage, WifiConnectingPage, LoginPage, ProgramPage):
            frame = Page(parent=self.container, controller=self)
            frame.place(relwidth=1, relheight=1)
            self.frames[Page] = frame

        # ---- Auto-detect WiFi ----
        ssid = get_connected_ssid()
        if ssid:
            self.frames[LoginPage].show_change_wifi_button()
            self.show_frame(LoginPage)
        else:
            self.show_frame(ScanPage)

    def show_frame(self, page):
        self.frames[page].tkraise()


# ------------ PAGE 1: Scan WiFi ------------
class ScanPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        self.controller = controller
        lm = self.controller.lm

        # Centering Container
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(container, text="Connect to Wi-Fi", font=lm.font(24), foreground="white").pack(pady=lm.scaled(30))
        ttk.Button(container, text="Scan Wi-Fi", padding=lm.scaled(20), bootstyle=PRIMARY,
                   command=self.start_scan).pack(pady=lm.scaled(120))

    def start_scan(self):
        self.controller.show_frame(WifiConnectingPage)
        self.controller.frames[WifiConnectingPage].set_text("Scanning WiFi...")
        threading.Thread(target=self.process_scan).start()

    def process_scan(self):
        ssids = scan_wifi()
        time.sleep(1)
        self.controller.frames[WifiListPage].load_list(ssids)
        self.controller.show_frame(WifiListPage)


# ------------ PAGE 2: WiFi List ------------
class WifiListPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm

        # Title with better spacing
        ttk.Label(self, text="Available Networks", font=lm.font(24), foreground="white").pack(pady=lm.scaled(20))
        
        # Listbox with better styling
        self.listbox = tk.Listbox(
            self, 
            font=lm.font(16), 
            height=8,  # Show 8 networks at once
            bg="#2d2d2d",  # Dark background
            fg="white",  # White text
            selectbackground="#00d4aa",  # Teal selection (matching ttkbootstrap success)
            selectforeground="white",
            highlightthickness=2,
            highlightcolor="#00d4aa",
            highlightbackground="#444444",
            relief="flat",
            borderwidth=0,
            activestyle="none"
        )
        self.listbox.pack(fill="both", expand=True, padx=lm.scaled(30), pady=lm.scaled(20))

        # Next button with better styling
        ttk.Button(
            self, 
            text="Next", 
            padding=lm.scaled(15), 
            bootstyle=SUCCESS,
            command=self.go_next
        ).pack(pady=lm.scaled(25))

    def load_list(self, ssids):
        self.listbox.delete(0, tk.END)
        # Add empty line at top for spacing
        self.listbox.insert(tk.END, "")
        for idx, s in enumerate(ssids):
            # Add WiFi icon and padding
            self.listbox.insert(tk.END, f"  📶  {s}")
            # Add spacing between networks (except after last one)
            if idx < len(ssids) - 1:
                self.listbox.insert(tk.END, "")

    def go_next(self):
        selection = self.listbox.curselection()
        if not selection:
            return
        selected_text = self.listbox.get(selection[0]).strip()
        # Remove WiFi icon and extra spaces to get the actual SSID
        if selected_text.startswith("📶"):
            ssid = selected_text.replace("📶", "").strip()
        else:
            ssid = selected_text
        
        # Skip if empty line selected
        if not ssid:
            return
            
        self.controller.selected_ssid = ssid
        self.controller.show_frame(WifiPasswordPage)


# ------------ PAGE 3: WiFi Password ------------
class WifiPasswordPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm
        self.keyboard = None

        # Title
        ttk.Label(self, text="Enter Wi-Fi Password", font=lm.font(20)).pack(pady=lm.scaled(15))

        # Password Label
        ttk.Label(self, text="Password", font=lm.font(12), foreground="white").pack(pady=(lm.scaled(10), lm.scaled(3)))

        # Password field frame
        pw_field_frame = ttk.Frame(self)
        pw_field_frame.pack(pady=lm.scaled(10), padx=lm.scaled(40), fill="x")

        self.password_entry = ttk.Entry(pw_field_frame, font=lm.font(12), show="*")
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=lm.scaled(6))

        # Show password button
        ttk.Button(pw_field_frame, text="👁", width=4, bootstyle=INFO,
                   command=self.toggle_password).pack(side="left", padx=lm.scaled(8))

        self.password_entry.bind("<FocusIn>", self.open_keyboard)

        # Connect button
        ttk.Button(self, text="Connect", padding=lm.scaled(12), bootstyle=PRIMARY,
                   command=self.start_connect).pack(pady=lm.scaled(15))

    def toggle_password(self):
        cur = self.password_entry.cget("show")
        self.password_entry.config(show="" if cur == "*" else "*")

    def open_keyboard(self, _):
        self.close_keyboard()
        # Pass layout manager for scaling
        self.keyboard = T9Keypad(self, self.password_entry, self.close_keyboard, self.controller.lm)
        self.keyboard.pack(side="bottom", fill="x")

    def close_keyboard(self):
        if self.keyboard:
            self.keyboard.destroy()
            self.keyboard = None

    def start_connect(self):
        pwd = self.password_entry.get()
        if not pwd:
            return

        self.controller.wifi_password = pwd
        connecting_page = self.controller.frames[WifiConnectingPage]
        connecting_page.set_text(f"Connecting to \n {self.controller.selected_ssid}...")
        self.controller.show_frame(WifiConnectingPage)

        threading.Thread(target=self.process_connect).start()

    def process_connect(self):
        connecting_page = self.controller.frames[WifiConnectingPage]

        # Step 1: try to connect
        ok = connect_wifi(self.controller.selected_ssid, self.controller.wifi_password)
        time.sleep(1)

        # Check if user cancelled during connect
        if connecting_page.is_cancelled:
            return

        if not ok:
            self.controller.after(0, lambda: messagebox.showerror(
                "Wrong Password", "Incorrect password. Try again."
            ))
            self.controller.after(0, lambda: self.controller.show_frame(ScanPage))
            return

        # Step 2: check internet
        connecting_page.set_text("Checking Internet...")
        time.sleep(1)

        # Check if user cancelled during checking
        if connecting_page.is_cancelled:
            return

        if not check_internet():
            self.controller.after(0, lambda: messagebox.showerror(
                "No Internet",
                "Connected to WiFi but no internet. Try another network."
            ))
            self.controller.after(0, lambda: self.controller.show_frame(ScanPage))
            return

        # Success
        self.controller.after(0, lambda: self.controller.show_frame(LoginPage))

# ------------ PAGE 4: Connecting ------------
class WifiConnectingPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm
        self.mode = "wifi"   # can be "wifi" or "login"
        self.text = ""
        self.dots = 0
        self.is_cancelled = False

        # Title / Status text
        self.label = ttk.Label(self, text="", font=lm.font(24))
        self.label.pack(pady=lm.scaled(150))

        # CANCEL Button
        ttk.Button(
            self,
            text="Cancel",
            bootstyle=DANGER,
            padding=lm.scaled(20),
            command=self.cancel_connection
        ).pack(pady=lm.scaled(40))

        # Start animation loop
        self.animate()

    # Update main message
    def set_text(self, text):
        self.text = text
        self.is_cancelled = False  # reset cancel flag

    # When cancel button pressed
    def cancel_connection(self):
        self.is_cancelled = True

        if self.mode == "wifi":
            self.controller.show_frame(ScanPage)
        else:
            self.controller.show_frame(LoginPage)


    # Dot animation loop
    def animate(self):
        if self.text and not self.is_cancelled:
            self.label.config(text=self.text + "." * (self.dots % 4))
            self.dots += 1
        self.after(500, self.animate)


# ------------ PAGE 5: Login Page ------------

class ProgramPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm

        ttk.Label(self, text="Welcome", font=lm.font(40)).pack(pady=lm.scaled(100))

        ttk.Button(
            self,
            text="PROGRAM",
            bootstyle=PRIMARY,
            padding=lm.scaled(30),
            command=self.start_program_logic
        ).pack(pady=lm.scaled(100))

    def start_program_logic(self):
        print("Turning pins HIGH, LED ON, Display ON")
        turn_BL_Detect_High()
        turn_display_On()

        from du_reader import read_du_from_serial

        def ui_message(msg):
            print("STATUS:", msg)

        def ui_success(data):
            print("SUCCESS — DU List:", data)
            messagebox.showinfo("DU Loaded", "DU Data Received")
            # Save DU response for next page (file list)
            self.controller.du_options = data["options"]
            self.controller.is_encryption_enable = data["isEncryptionEnable"]
            # TODO: Navigate to File Selection Page

        def ui_error(msg):
            print("ERROR:", msg)
            messagebox.showerror("Error", msg)

        threading.Thread(
            target=read_du_from_serial,
            args=(
                self.controller.token,  # auth token
                ui_message,
                ui_success,
                ui_error,
                os.getenv("SERIAL_PORT", "/dev/ttyAMA0"),   # UART Port
                115200
            ),
            daemon=True
        ).start()

    # inside ProgramPage class - on file selected & Download button pressed
    def on_download_and_flash(self, selected_file_id):
        token = self.controller.token
        device_id = os.getenv("DEVICE_ID", "UNKNOWN")
        is_encryption = self.controller.is_encryption_enable if hasattr(self.controller, "is_encryption_enable") else False

        def ui_msg(s): 
            print("STATUS:", s)
            # update a label in GUI via after if needed
            self.controller.after(0, lambda: self.status_label.config(text=s))

        def ui_success(data):
            print("SUCCESS:", data)
            self.controller.after(0, lambda: messagebox.showinfo("Success", "Flashed successfully"))

        def ui_error(err):
            print("ERROR:", err)
            self.controller.after(0, lambda: messagebox.showerror("Error", err))

        threading.Thread(
            target=download_and_flash,
            args=(selected_file_id, token, device_id, is_encryption, ui_msg, ui_success, ui_error),
            daemon=True
        ).start()






class LoginPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm
        self.keyboard = None

        # Title
        ttk.Label(self, text="Log In", font=lm.font(20)).pack(pady=lm.scaled(15))

        # ---- MOBILE LABEL ----
        ttk.Label(self, text="Mobile Number", font=lm.font(12), foreground="white").pack(pady=(lm.scaled(10), lm.scaled(3)))

        self.phone = ttk.Entry(self, font=lm.font(12))
        self.phone.pack(pady=(0, lm.scaled(10)), padx=lm.scaled(40), ipady=lm.scaled(6), fill="x")
        self.phone.bind("<FocusIn>", lambda e: self.open_keyboard(self.phone))

        # ---- PASSWORD LABEL ----
        ttk.Label(self, text="Password", font=lm.font(12), foreground="white").pack(pady=(0, lm.scaled(3)))

        pw_frame = ttk.Frame(self)
        pw_frame.pack(pady=lm.scaled(10), padx=lm.scaled(40), fill="x")

        self.password = ttk.Entry(pw_frame, font=lm.font(12), show="*")
        self.password.pack(side="left", fill="x", expand=True, ipady=lm.scaled(6))

        ttk.Button(
            pw_frame, text="👁", width=4, bootstyle=INFO,
            command=self.toggle_password
        ).pack(side="left", padx=lm.scaled(8))

        self.password.bind("<FocusIn>", lambda e: self.open_keyboard(self.password))


        # --------- BUTTON ROW ---------
        btn_row = ttk.Frame(self)
        btn_row.pack(pady=lm.scaled(15))

        # Log In button
        self.signin_btn = ttk.Button(
            btn_row,
            text="Log In",
            bootstyle=SUCCESS,
            padding=lm.scaled(12),
            command=self.start_login
        )
        self.signin_btn.pack(side="left", padx=lm.scaled(10))

        # Change Wi-Fi button
        self.change_wifi_btn = ttk.Button(
            btn_row,
            text="Change Wi-Fi",
            bootstyle=SECONDARY,
            padding=lm.scaled(12),
            command=lambda: controller.show_frame(ScanPage)
        )
        self.change_wifi_btn.pack(side="left", padx=lm.scaled(10))


        # Change Wi-Fi button (hidden until needed)
        self.change_wifi_btn_hidden = ttk.Button(
            btn_row,
            text="Change Wi-Fi",
            bootstyle=SECONDARY,
            padding=lm.scaled(20),
            command=lambda: controller.show_frame(ScanPage)
        )
        # will be shown later using show_change_wifi_button()

    def start_login(self):
        phone = self.phone.get().strip()
        if not phone.startswith("+"):
            phone = "+91" + phone

        password = self.password.get().strip()

        if not phone or not password:
            messagebox.showerror("Error", "Enter phone number and password")
            return

        # Start connecting page animation
        connecting_page = self.controller.frames[WifiConnectingPage]
        connecting_page.set_text("Signing In...")
        self.controller.show_frame(WifiConnectingPage)

        threading.Thread(target=self.process_login, args=(phone, password)).start()


    def process_login(self, phone, password):
        from auth_api import login_api
        ok, token = login_api(phone, password)

        if not ok:
            self.controller.after(0, lambda: messagebox.showerror(
                "Login Failed",
                "Incorrect phone or password."
            ))
            self.controller.after(0, lambda: self.controller.show_frame(LoginPage))
            return

        # Save token globally on controller
        self.controller.token = token

        # Move to program page
        self.controller.after(0, lambda: self.controller.show_frame(ProgramPage))


    def show_change_wifi_button(self):
        pass


    # Password visibility toggle
    def toggle_password(self):
        cur = self.password.cget("show")
        self.password.config(show="" if cur == "*" else "*")

    # Open keyboard
    def open_keyboard(self, entry):
        self.close_keyboard()
        self.keyboard = T9Keypad(self, entry, self.close_keyboard, self.controller.lm)
        self.keyboard.pack(side="bottom", fill="x")

    # Close keyboard
    def close_keyboard(self):
        if self.keyboard:
            self.keyboard.destroy()
            self.keyboard = None


# ------------ RUN ------------
if __name__ == "__main__":
    app = App()
    app.mainloop()
