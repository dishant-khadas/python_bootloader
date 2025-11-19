import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from wifi_utils import scan_wifi, connect_wifi, check_internet, get_connected_ssid
from keyboard import OnScreenKeyboard
from tkinter import messagebox

from gpio_control import (
    turn_BL_Detect_High,
    turn_BL_Detect_Low,
    turn_display_On,
    turn_display_Off
)


import threading 
from du_reader import read_du_from_serial

import time


# ------------ MAIN APP ------------
class App(ttk.Window):
    def __init__(self):
        super().__init__(themename="darkly")
        self.title("Setup Wizard")
        self.attributes("-fullscreen", True)

        self.selected_ssid = None
        self.wifi_password = None

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

        ttk.Label(self, text="Connect to Wi-Fi", font=("Segoe UI", 42)).pack(pady=120)
        ttk.Button(self, text="Scan Wi-Fi", padding=20, bootstyle=PRIMARY,
                   command=self.start_scan).pack(pady=50)

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

        ttk.Label(self, text="Available Networks", font=("Segoe UI", 36)).pack(pady=50)
        self.listbox = tk.Listbox(self, font=("Segoe UI", 24), height=10)
        self.listbox.pack(fill="both", expand=True, padx=50, pady=20)

        ttk.Button(self, text="Next", padding=20, bootstyle=SUCCESS,
                   command=self.go_next).pack(pady=40)

    def load_list(self, ssids):
        self.listbox.delete(0, tk.END)
        for s in ssids:
            self.listbox.insert(tk.END, s)

    def go_next(self):
        ssid = self.listbox.get(tk.ACTIVE)
        if not ssid:
            return
        self.controller.selected_ssid = ssid
        self.controller.show_frame(WifiPasswordPage)


# ------------ PAGE 3: WiFi Password ------------
class WifiPasswordPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.keyboard = None

        ttk.Label(self, text="Enter Wi-Fi Password", font=("Segoe UI", 36)).pack(pady=60)

        frame = ttk.Frame(self)
        frame.pack(pady=20, padx=60, fill="x")

        self.password_entry = ttk.Entry(frame, font=("Segoe UI", 28), show="*")
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=10)

        # Show password button
        ttk.Button(frame, text="👁", width=5, bootstyle=INFO,
                   command=self.toggle_password).pack(side="left", padx=10)

        self.password_entry.bind("<FocusIn>", self.open_keyboard)

        ttk.Button(self, text="Connect", padding=20, bootstyle=PRIMARY,
                   command=self.start_connect).pack(pady=40)

    def toggle_password(self):
        cur = self.password_entry.cget("show")
        self.password_entry.config(show="" if cur == "*" else "*")

    def open_keyboard(self, _):
        self.close_keyboard()
        self.keyboard = OnScreenKeyboard(self, self.password_entry, self.close_keyboard)
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
        connecting_page.set_text(f"Connecting to {self.controller.selected_ssid}...")
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
        self.mode = "wifi"   # can be "wifi" or "login"
        self.text = ""
        self.dots = 0
        self.is_cancelled = False

        # Title / Status text
        self.label = ttk.Label(self, text="", font=("Segoe UI", 32))
        self.label.pack(pady=150)

        # CANCEL Button
        ttk.Button(
            self,
            text="Cancel",
            bootstyle=DANGER,
            padding=20,
            command=self.cancel_connection
        ).pack(pady=40)

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

        ttk.Label(self, text="Welcome", font=("Segoe UI", 40)).pack(pady=100)

        ttk.Button(
            self,
            text="PROGRAM",
            bootstyle=PRIMARY,
            padding=30,
            command=self.start_program_logic
        ).pack(pady=100)

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
                "/dev/ttyAMA0",   # RasPi UART
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
        self.keyboard = None

        # Title
        ttk.Label(self, text="Sign In", font=("Segoe UI", 40)).pack(pady=40)

        # ---- MOBILE LABEL ----
        ttk.Label(self, text="Mobile Number", font=("Segoe UI", 24)).pack(pady=(20, 5))

        self.phone = ttk.Entry(self, font=("Segoe UI", 28))
        self.phone.pack(pady=(0, 30), padx=60, ipady=10, fill="x")
        self.phone.bind("<FocusIn>", lambda e: self.open_keyboard(self.phone))

        # ---- PASSWORD LABEL ----
        ttk.Label(self, text="Password", font=("Segoe UI", 24)).pack(pady=(0, 5))

        pw_frame = ttk.Frame(self)
        pw_frame.pack(pady=20, padx=60, fill="x")

        self.password = ttk.Entry(pw_frame, font=("Segoe UI", 28), show="*")
        self.password.pack(side="left", fill="x", expand=True, ipady=10)

        ttk.Button(
            pw_frame, text="👁", width=5, bootstyle=INFO,
            command=self.toggle_password
        ).pack(side="left", padx=10)

        self.password.bind("<FocusIn>", lambda e: self.open_keyboard(self.password))


        # --------- BUTTON ROW (FIXED GRID-ONLY APPROACH) ---------
        # --------- BUTTON ROW (FIXED & CLEAN) ---------
        btn_row = ttk.Frame(self)
        btn_row.pack(pady=40, fill="x")

        # Configure columns for center alignment
        btn_row.columnconfigure(0, weight=1)
        btn_row.columnconfigure(1, weight=1)

        # Sign In button
        self.signin_btn = ttk.Button(
            btn_row,
            text="Sign In",
            bootstyle=SUCCESS,
            padding=20,
            command=self.start_login
        )
        self.signin_btn.grid(row=0, column=0, padx=40, sticky="e")

        # Change Wi-Fi button
        self.change_wifi_btn = ttk.Button(
            btn_row,
            text="Change Wi-Fi",
            bootstyle=SECONDARY,
            padding=20,
            command=lambda: controller.show_frame(ScanPage)
        )
        self.change_wifi_btn.grid(row=0, column=1, padx=40, sticky="w")


        # Change Wi-Fi button
        self.change_wifi_btn = ttk.Button(
            btn_row,
            text="Change Wi-Fi",
            bootstyle=SECONDARY,
            padding=20,
            command=lambda: controller.show_frame(ScanPage)
        )
        self.change_wifi_btn.grid(row=0, column=1, padx=40, sticky="w")



        # Change Wi-Fi button (hidden until needed)
        self.change_wifi_btn = ttk.Button(
            btn_row,
            text="Change Wi-Fi",
            bootstyle=SECONDARY,
            padding=20,
            command=lambda: controller.show_frame(ScanPage)
        )


        # Change Wi-Fi button (hidden until needed)
        self.change_wifi_btn = ttk.Button(
            btn_row,
            text="Change Wi-Fi",
            bootstyle=SECONDARY,
            padding=20,
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
    # already placed using grid → do nothing
        pass


    # Password visibility toggle
    def toggle_password(self):
        cur = self.password.cget("show")
        self.password.config(show="" if cur == "*" else "*")

    # Open keyboard
    def open_keyboard(self, entry):
        self.close_keyboard()
        self.keyboard = OnScreenKeyboard(self, entry, self.close_keyboard)
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
