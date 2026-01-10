import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from wifi_utils import scan_wifi, connect_wifi, check_internet, get_connected_ssid
from t9_keypad import T9Keypad
from tkinter import messagebox
from ui_utils import LayoutManager
import os
from PIL import Image, ImageTk


from dotenv import load_dotenv
load_dotenv()


import threading 
from du_reader import read_du_from_serial
from bootloader_download import download_and_flash

import time


# ------------ MAIN APP ------------
class App(ttk.Window):
    def __init__(self):
        super().__init__(themename="litera")
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
        
        # Custom Combobox Style to remove blue focus ring and match dark theme
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

        # Global setting for Combobox Dropdown (Listbox) Font
        self.option_add('*TCombobox*Listbox.font', self.lm.font(14))

        self.selected_ssid = None
        self.wifi_password = None
        self.token = None 

        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self.frames = {}
        for Page in (SplashScreen, ScanPage, WifiListPage, WifiPasswordPage, WifiConnectingPage, LoginPage, ProgramPage, FileSelectionPage, DownloadPage, ErrorPage):
           frame = Page(parent=self.container, controller=self)
           frame.place(relwidth=1, relheight=1)
           self.frames[Page] = frame


        # Show splash screen first
        self.show_frame(SplashScreen)

    def show_frame(self, page):
        frame = self.frames[page]
        frame.tkraise()
        # Optionally call a method like on_show if it exists
        if hasattr(frame, "on_show"):
            frame.on_show()
        
    def show_error(self, title, message, return_frame):
        error_page = self.frames[ErrorPage]
        error_page.set_error(title, message, return_frame)
        self.show_frame(ErrorPage)




# ------------ SPLASH SCREEN ------------
class SplashScreen(ttk.Frame):
    def __init__(self, parent, controller):
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
            logo_path = os.path.join(os.path.dirname(__file__), "czar.png")
            self.original_image = Image.open(logo_path)
            
            # Resize to fit nicely on screen
            max_size = (lm.scaled(300), lm.scaled(300))
            self.original_image.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            # Create PhotoImage
            self.photo = ImageTk.PhotoImage(self.original_image)
            
            # Display image
            self.logo_label = ttk.Label(container, image=self.photo)
            # s
            self.logo_label.pack()
            ttk.Label(container, text="Please Wait...",font=lm.font(18)).pack(pady=lm.scaled(24))  # Spacer

            
        except Exception as e:
            # Fallback if image can't be loaded
            ttk.Label(container, text="CZAR", font=lm.font(48)).pack()
            print(f"Error loading splash image: {e}")
        
        # Animation state
        self.alpha = 0.0
        self.animation_running = False
    
    def on_show(self):
        """Called when the splash screen is shown"""
        if not self.animation_running:
            self.animation_running = True
            self.alpha = 0.0
            self.animate_fade_in()
    
    def animate_fade_in(self):
        """Fade in animation"""
        if self.alpha < 1.0:
            self.alpha += 0.05  # Increment alpha
            # Note: tkinter doesn't support alpha transparency directly on widgets
            # So we'll just use a delay and then transition
            self.after(30, self.animate_fade_in)
        else:
            # Animation complete, wait a bit then transition
            self.after(1000, self.transition_to_next_page)
    
    def transition_to_next_page(self):
        """Transition to the appropriate next page"""
        self.animation_running = False
        
        # Auto-detect WiFi and go to appropriate page
        ssid = get_connected_ssid()
        if ssid:
            self.controller.frames[LoginPage].show_change_wifi_button()
            self.controller.show_frame(LoginPage)
        else:
            self.controller.show_frame(ScanPage)


# ------------ PAGE 1: Scan WiFi ------------
class ScanPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        self.controller = controller
        lm = self.controller.lm

        # Centering Container
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(container, text="Connect to Wi-Fi", font=lm.font(24)).pack(pady=lm.scaled(30))
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
        ttk.Label(self, text="Available Networks", font=lm.font(24)).pack(pady=lm.scaled(20))
        
        # Listbox with better styling
        self.listbox = tk.Listbox(
            self, 
            font=lm.font(16), 
            height=8,  # Show 8 networks at once
            bg="white",  # White background
            fg="black",  # Black text
            selectbackground="#00d4aa",  # Teal selection
            selectforeground="white",
            highlightthickness=2,
            highlightcolor="#00d4aa",
            highlightbackground="#cccccc",
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
        ).pack(pady=lm.scaled(40))

    def load_list(self, ssids):
        self.listbox.delete(0, tk.END)
        # Add empty line at top for spacing
        self.listbox.insert(tk.END, "")
        for idx, s in enumerate(ssids):
            # Add WiFi icon and padding
            self.listbox.insert(tk.END, f"  >  {s}")
            # Add spacing between networks (except after last one)
            if idx < len(ssids) - 1:
                self.listbox.insert(tk.END, "")

    def go_next(self):
        selection = self.listbox.curselection()
        if not selection:
            return
        selected_text = self.listbox.get(selection[0]).strip()
        # Remove WiFi icon and extra spaces to get the actual SSID
        if selected_text.startswith(">"):
            ssid = selected_text.replace(">", "").strip()
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
        ttk.Label(self, text="Password", font=lm.font(12)).pack(pady=(lm.scaled(10), lm.scaled(3)))

        # Password field frame
        pw_field_frame = ttk.Frame(self)
        pw_field_frame.pack(pady=lm.scaled(10), padx=lm.scaled(40), fill="x")

        self.password_entry = ttk.Entry(pw_field_frame, font=lm.font(12), show="*")
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=lm.scaled(6))

        # Show password button
        ttk.Button(pw_field_frame, text="Show", bootstyle=INFO,
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
            self.controller.after(0, lambda: self.controller.show_error(
                title="Wrong Password", 
                message="Incorrect password. Try again.",
                return_frame=WifiPasswordPage
                )
            )
            return
        self.controller.after(0, lambda: self.controller.show_frame(ScanPage))
            

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
        ).pack(pady=lm.scaled(50))

        self.status_label = ttk.Label(self, text="", font=lm.font(14), bootstyle=WARNING)
        self.status_label.pack(pady=lm.scaled(20))

    def start_program_logic(self):
        print("Starting Program Logic - Fetching from Server")
        
        # read_du_from_serial
        from du_reader import read_du_from_serial

        # Get DownloadPage reference
        dp = self.controller.frames[DownloadPage]
        dp.file_id = None # Generic loading mode
        self.controller.show_frame(DownloadPage)

        def on_ui_message(msg):
             print(f"[DU Reader] {msg}")
             self.controller.after(0, lambda: dp.status_label.config(text=msg))

        def on_ui_success(data):
             # data = {duNumber, displayNumber, options, isEncryptionEnable}
             self.controller.after(0, lambda: self.ui_success(data))

        def on_ui_error(err_msg):
             print(f"[DU Reader Error] {err_msg}")
             # Switch to ErrorPage
             self.controller.after(0, lambda: self.controller.show_error("Operation Failed", err_msg, ProgramPage))

        def run_thread():
             token = self.controller.token
             read_du_from_serial(
                 token=token,
                 callback_ui_message=on_ui_message,
                 callback_ui_success=on_ui_success,
                 callback_ui_error=on_ui_error
             )

        threading.Thread(target=run_thread, daemon=True).start()

    def ui_success(self, data):
        options = data.get("options", {})
        is_enc = data.get("isEncryptionEnable", False)
        du_num = data.get("duNumber")
        disp_num = data.get("displayNumber")

        print("SUCCESS — DU List:", options)
        
        # Save info for next page
        self.controller.du_options = options # The options from API (fileName, fileId etc)
        # We might want to save duNumber/displayNumber too if needed
        self.controller.du_options["duNumber"] = du_num
        self.controller.du_options["displayNumber"] = disp_num
        
        self.controller.is_encryption_enable = is_enc
        
        self.controller.show_frame(FileSelectionPage)

    def ui_error(self, msg):
        print("ERROR:", msg)
        messagebox.showerror("Error", msg)


class DownloadPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        lm = controller.lm

        self.file_id = None

        # Center Container
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.5, anchor="center")

        # Title
        ttk.Label(container, text="Please Wait...", font=lm.font(20)).pack(pady=lm.scaled(30))

        # Spinner (using a label as placeholder or maybe infinite progressbar)
        self.progress = ttk.Progressbar(container, mode='indeterminate', bootstyle=INFO, length=lm.scaled(300))
        self.progress.pack(pady=lm.scaled(20))
        self.progress.start(10)

        # Status Label
        self.status_label = ttk.Label(container, text="Initializing...", font=lm.font(14), bootstyle=WARNING, wraplength=lm.scaled(400), justify="center")
        self.status_label.pack(pady=lm.scaled(20))

    def on_show(self):
        # Reset UI
        self.progress.start(10)
        
        # Start download if file_id is set
        if hasattr(self, 'file_id') and self.file_id:
             self.status_label.config(text="Starting download...")
             threading.Thread(target=self.start_download_logic, args=(self.file_id,), daemon=True).start()
        else:
             # Generic wait state (e.g. Serial Reading)
             self.status_label.config(text="Please wait...")

    def start_download(self, file_id):
        self.file_id = file_id

    def start_download_logic(self, file_id):
        token = self.controller.token
        # device_id logic if needed
        device_id = "41999990" # Hardcoded or from env

        is_enc = getattr(self.controller, "is_encryption_enable", False)

        def on_msg(text):
            self.controller.after(0, lambda: self.status_label.config(text=text))
        
        def on_success(res):
            self.controller.after(0, lambda: self.download_success(res))

        def on_err(err_text):
            self.controller.after(0, lambda: self.download_error(err_text))

        def on_serialPort(err_text):
            self.controller.after(0, lambda: self.serialPort_error(f"Serial Port Error: {err_text}"))

        download_and_flash(
            file_id=file_id,
            token=token,
            device_id=device_id,
            is_encryption_enable=is_enc,
            callback_message=on_msg,
            callback_success=on_success,
            callback_error=on_serialPort
        )

    def download_success(self, res):
        self.progress.stop()
        self.status_label.config(text="Download & Flash Complete!", foreground="green")
        # Logic to go somewhere else? Or stay here? 
        # User didn't specify success page, maybe go back to file selection or program page?
        # For now, stay here with success message or maybe go to ProgramPage to restart.
        messagebox.showinfo("Success", "Firmware updated successfully!")
        self.controller.show_frame(ProgramPage)

    def download_error(self, err_text):
        self.progress.stop()
        self.status_label.config(text="Error occurred", foreground="red")
        # Redirect to ErrorPage, which usually goes BACK. 
        # User requested: "redirect to login page" from error page
        self.controller.show_error("Download Failed", err_text, return_frame=LoginPage)

    def serialPort_error(self, err_text):
        self.progress.stop()
        self.status_label.config(text="Serial Port Error", foreground="red")
        self.controller.show_error("Serial Port Error", err_text, return_frame=LoginPage)
        




class FileSelectionPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm

        # Center Container
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.4, anchor="center")

        # Title
        ttk.Label(container, text="Select Firmware", font=lm.font(24)).pack(pady=lm.scaled(30))

        # DU Info Frame
        info_frame = ttk.Frame(container)
        info_frame.pack(fill="x", pady=lm.scaled(20))

        self.du_label = ttk.Label(info_frame, text="DU: --", font=lm.font(16), foreground="#00d4aa")
        self.du_label.pack(anchor="center", pady=lm.scaled(5))
        
        self.disp_label = ttk.Label(info_frame, text="Display: --", font=lm.font(16), foreground="#00d4aa")
        self.disp_label.pack(anchor="center", pady=lm.scaled(5))

        # Files Dropdown
        # ttk.Label(container, text="Available Files:", font=lm.font(14)).pack(pady=(lm.scaled(30), lm.scaled(10)))

        self.file_var = tk.StringVar()
        self.combobox = ttk.Combobox(
            container, 
            textvariable=self.file_var,
            font=lm.font(14),
            state="readonly",
            width=30,
            style="Custom.TCombobox"
        )
        self.combobox.pack(pady=lm.scaled(10), ipady=lm.scaled(5))

        # Next Button
        ttk.Button(
            container,
            text="Next",
            bootstyle=SUCCESS,
            padding=lm.scaled(15),
            command=self.on_next
        ).pack(pady=lm.scaled(40))

    def on_show(self):
        # Update DU info
        options = getattr(self.controller, "du_options", {})
        du_num = options.get("duNumber", "Unknown")
        disp_num = options.get("displayNumber", "Unknown")
        
        self.du_label.config(text=f"DU: {du_num}")
        self.disp_label.config(text=f"Display: {disp_num}")

        # Update Combobox
        files = options.get("fileName", [])
        if not files:
            self.combobox['values'] = ["No files available"]
            self.combobox.set("No files available")
            self.combobox.state(["disabled"])
        else:
            self.combobox['values'] = files
            self.combobox.state(["!disabled"])
            self.combobox.set("Select File")

    def on_next(self):
        selected_file = self.file_var.get()
        if not selected_file or selected_file == "No files available" or selected_file == "Select File":
            messagebox.showwarning("Selection", "Please select a valid file.")
            return

        print(f"Next Clicked. Selected: {selected_file}")
        
        # Get corresponding fileId if needed
        options = getattr(self.controller, "du_options", {})
        file_names = options.get("fileName", [])
        file_ids = options.get("fileId", [])
        
        if selected_file in file_names:
            idx = file_names.index(selected_file)
            print("---------------- DEBUG SELECTION ----------------")
            print(f"Selected File: '{selected_file}'")
            print(f"Index found: {idx}")
            print(f"File Names List: {file_names}")
            print(f"File IDs List: {file_ids}")
            
            if idx < len(file_ids):
                file_id = file_ids[idx]
                # Trigger the download logic in ProgramPage
                # Trigger the download logic via DownloadPage
                download_page = self.controller.frames[DownloadPage]
                download_page.file_id = file_id
                self.controller.show_frame(DownloadPage)






class LoginPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm
        self.keyboard = None

        # Title
        ttk.Label(self, text="Log In", font=lm.font(20)).pack(pady=lm.scaled(15))

        # ---- MOBILE LABEL ----
        ttk.Label(self, text="Mobile Number", font=lm.font(12)).pack(pady=(lm.scaled(10), lm.scaled(3)))

        self.phone = ttk.Entry(self, font=lm.font(12))
        self.phone.pack(pady=(0, lm.scaled(10)), padx=lm.scaled(40), ipady=lm.scaled(6), fill="x")
        self.phone.bind("<FocusIn>", lambda e: self.open_keyboard(self.phone))

        # ---- PASSWORD LABEL ----
        ttk.Label(self, text="Password", font=lm.font(12)).pack(pady=(0, lm.scaled(3)))

        # Password field container with padding
        pw_container = ttk.Frame(self)
        pw_container.pack(pady=lm.scaled(10), padx=lm.scaled(40), fill="x")

        # Inner frame for the password field with relative positioning
        pw_frame = ttk.Frame(pw_container)
        pw_frame.pack(fill="x")

        # Password entry with right padding to make room for the icon
        self.password = ttk.Entry(pw_frame, font=lm.font(12), show="*")
        self.password.pack(fill="x", ipady=lm.scaled(6))
        # Add right padding to make room for the eye icon
        self.password.configure(style='Password.TEntry')

        # Eye icon button positioned on top of the entry field (right side)
        self.eye_btn = ttk.Button(
            pw_frame, text="Show", bootstyle=INFO,
            command=self.toggle_password
        )
        # Place the button on the right side of the entry
        self.eye_btn.place(relx=1.0, rely=0.5, anchor="e", x=-lm.scaled(5))

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
            self.controller.show_error(
                title="Invalid Input",
                message="Please enter both phone number and password.",
                return_frame=LoginPage
                )
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
            self.controller.after(0, lambda: self.controller.show_error(
                title="Login Failed",
                message="Incorrect phone or password.",
                return_frame=LoginPage
            )
        )                          
            
            return

        # Save token globally on controller
        self.controller.token = token
        self.controller.after(
            0,
                lambda: self.controller.show_frame(ProgramPage)
        )

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
            
class ErrorPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        lm = controller.lm

        self.configure(style="Danger.TFrame")  # red background

        container = ttk.Frame(self, padding=lm.scaled(30))
        container.pack(expand=True)

        self.title_label = ttk.Label(
            container,
            text="",
            font=lm.font(18),
            foreground="#020202",
        )
        self.title_label.pack(pady=(0, lm.scaled(10)))

        self.message_label = ttk.Label(
            container,
            text="",
            font=lm.font(12),
            foreground="#020202",
            wraplength=lm.scaled(400),
            justify="center"
        )
        self.message_label.pack(pady=(0, lm.scaled(20)))

        ttk.Button(
            container,
            text="Back",
            bootstyle=SECONDARY,
            padding=lm.scaled(12),
            command=self.go_back
        ).pack()

        self.return_frame = None

    def set_error(self, title, message, return_frame):
        self.title_label.config(text=title)
        self.message_label.config(text=message)
        self.return_frame = return_frame

    def go_back(self):
        self.controller.show_frame(self.return_frame)



# ------------ RUN ------------
if __name__ == "__main__":
    app = App()
    app.mainloop()
