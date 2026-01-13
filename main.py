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
        for Page in (ScanPage, WifiListPage, WifiPasswordPage, WifiConnectingPage, ManualWifiPage, LoginPage, ProgramPage, ErrorPage):
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
        
    def show_error(self, title, message, return_frame):
        error_page = self.frames[ErrorPage]
        error_page.set_error(title, message, return_frame)
        self.show_frame(ErrorPage)



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
        self.controller.frames[WifiListPage].focus_set()

# REPLACED tk.Listbox list_container canvas for better readability and flexibility for the user to select the WiFi Networks.
# ------------ PAGE 2: WiFi List ------------
class WifiListPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm

        # Title with better spacing
        ttk.Label(self, text="Available Networks", font=lm.font(24), foreground="white").pack(pady=lm.scaled(20))
        # OLD TTK List box code
        # Listbox with better styling
       # self.listbox = tk.Listbox(
           # self, 
           # font=lm.font(16), 
           # height=8,  # Show 8 networks at once
           # bg="#2d2d2d",  # Dark background
           # fg="white",  # White text
           # selectbackground="#00d4aa",  # Teal selection (matching ttkbootstrap success)
           # selectforeground="white",
           # highlightthickness=2,
           # highlightcolor="#00d4aa",
           # highlightbackground="#444444",
           # relief="flat",
           # borderwidth=0,
           # activestyle="none"
       # ) 
       # self.listbox.pack(fill="both", expand=True, padx=lm.scaled(25), pady=lm.scaled(50))
    #list_container canvas with better styling for rendering Wi-Fi Networks in a smmoth and efficient manner
        list_container = ttk.Frame(self)
        list_container.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(list_container, bg="#2d2d2d", highlightthickness=0)
        self.canvas.pack(side="left",fill="both", expand=True, padx=lm.scaled(30), pady=lm.scaled(20))
        self.scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.canvas.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.list_frame=ttk.Frame(self.canvas)
        self.canvas.create_window((0,0), window=self.list_frame, anchor="nw")
        self.list_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        btn_row = ttk.Frame(self)
        btn_row.pack(pady=(0, lm.scaled(10)))
        # Refresh button with better styling for rescanning the list of WiFi Networks
        ttk.Button(
            self,
            text="Refresh",
            padding=lm.scaled(12),
            bootstyle=SECONDARY,
            command=self.refresh_networks   
        ).pack(side="left",padx= lm.scaled(10))
        # Add Network for manually entering WiFi Network SSID and Password
        ttk.Button(
            self,
            text="Add Network",
            padding=lm.scaled(10),
            bootstyle=INFO,
            command=lambda: self.controller.show_frame(ManualWifiPage),
        ).pack(side="left", padx=lm.scaled(10))
        
        # Next button with better styling
        ttk.Button(
            self, 
            text="Next", 
            padding=lm.scaled(15), 
            bootstyle=SUCCESS,
            command=self.go_next
        ).pack(pady=lm.scaled(25))
    # Controls for navigating through the list of Wi-Fi Networks
        self.network_buttons = []
        self.selected_index = 0
        self.focus_set()
        self.bind_all("<Up>", self.on_up_key)
        self.bind_all("<Down>", self.on_down_key)
        self.bind_all("<Return>", lambda e: self.go_next())
        self.canvas.bind("<ButtonPress-1>", self._on_touch_start)
        self.canvas.bind("<B1-Motion>", self._on_touch_move)
        self.bind_all("<MouseWheel>", self._on_mousewheel)
    # Scroll feature function to scroll over the list of WiFi-Networks
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(-1 * (event.delta // 120), "units")
    def _on_touch_start(self, event):
        self.canvas.scan_mark(event.x, event.y)
    def _on_touch_move(self, event):
        self.canvas.scan_dragto(event.x, event.y, gain=1)
    # OLD load_list function used to list the WiFi networks which had selection bugs earlier 
    # and was replaced by a new load_list function
    #def load_list(self, ssids):
        #self.listbox.delete(0, tk.END)
        # Add empty line at top for spacing
        #for s in (ssids):
            # Add WiFi icon and padding
            #self.listbox.insert(tk.END, f"\n\n  📶  {s}\n\n")
            # Add spacing between networks (except after last one)
    # UPDATED load_list function for fetchimg and rendering the WiFi Networks
    def load_list(self, ssids):
        for widget in self.list_frame.winfo_children():
            widget.destroy()
        
        self.network_buttons.clear()
        self.selected_index=0
        
        for idx, ssid in enumerate(ssids):
            btn = ttk.Button(
                self.list_frame,
                text=f"📶 {ssid}",
                bootstyle="secondary",
                padding=self.controller.lm.scaled(16),
                command=lambda s=ssid, i=idx: self._select_network(i,s)
            )
            btn.pack(fill="x", pady=self.controller.lm.scaled(10))
            self.network_buttons.append(btn)
        if self.network_buttons:
            self._highlight_selected()
            self.after(50, lambda: self.network_buttons[0].focus_set())
    
    # OLD go_next function      
    #def go_next(self):
      #selection = self.listbox.curselection()
       #if not selection:
        #    return
        #selected_text = self.listbox.get(selection[0]).strip()
        # Remove WiFi icon and extra spaces to get the actual SSID
        #if "📶" in selected_text:
            #ssid = selected_text.replace("📶", "").strip()
        #else:
            #ssid = selected_text
        
        # Skip if empty line selected
        #if not ssid:
            #return
            
#-------Functions for Refresh Networks Button-----------------#    
    def refresh_networks(self):
        self.controller.show_frame(WifiConnectingPage)
        self.controller.frames[WifiConnectingPage].set_text("Scanning WiFi...")
        threading.Thread(target=self._do_refresh, daemon=True).start()
        
        
    def _do_refresh(self):
        ssids = scan_wifi()
        time.sleep(2)
        self.controller.after(0, lambda: self._finish_refresh(ssids))
        
        
    def _finish_refresh(self, ssids):
        self.load_list(ssids)
        self.controller.show_frame(WifiListPage)
        self.focus_set()
    # UPDATED go_next function 
    def go_next(self):
        ssid = self.controller.selected_ssid
        if not ssid:
            return
        password_page = self.controller.frames[WifiPasswordPage]
        password_page.title_label.config(text=f"SSID : {ssid}")
        self.controller.show_frame(WifiPasswordPage)
        
    def _select_network(self, index, ssid):
        self.selected_index = index
        self.controller.selected_ssid = ssid
        self._highlight_selected()
        
    def _highlight_selected(self):
        self.canvas.update_idletasks()
        bbox_all = self.canvas.bbox("all")
        if not bbox_all:
           return

        for i, btn in enumerate(self.network_buttons):
           if i == self.selected_index:
               btn.configure(bootstyle="secondary")
           else:
               btn.configure(bootstyle="secondary")

            

        # --- Proper Canvas auto-scroll ---#
        btn = self.network_buttons[self.selected_index] 
        btn_y = btn.winfo_y()
        btn_h = btn.winfo_height()
        canvas_h = self.canvas.winfo_height()

        if btn_y < self.canvas.canvasy(0):
            self.canvas.yview_moveto(btn_y / bbox_all[3])
        elif btn_y + btn_h > self.canvas.canvasy(0) + canvas_h:
            self.canvas.yview_moveto(
                (btn_y + btn_h - canvas_h) / bbox_all[3]
            )
    
    def on_up_key(self, event):
        if self.selected_index > 0:
            self.selected_index -= 1
            ssid = self.network_buttons[self.selected_index].cget("text").replace("📶", "").strip()
            self.controller.selected_ssid = ssid
            self._highlight_selected()
            self.canvas.yview_scroll(-1, "units")
        return "break"
    def on_down_key(self, event):
        if self.selected_index < len(self.network_buttons) - 1:
            self.selected_index += 1
            ssid = self.network_buttons[self.selected_index].cget("text").replace("📶", "").strip()
            self.controller.selected_ssid = ssid
            self._highlight_selected()
            self.canvas.yview_scroll(+1,"units")
        return "break"


# ------------ PAGE 3: WiFi Password ------------
class WifiPasswordPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm
        self.keyboard = None

        # Title (fetched from lines 258-260 (go_next function) to display "SSID : {Actual name of SSID})
        self.title_label=ttk.Label(self, font=lm.font(15),wraplength=lm.scaled(400),justify="center")
        self.title_label.pack(pady=lm.scaled(15))

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
        
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=lm.scaled(15))

        # Connect button
        ttk.Button(btn_frame, text="Connect", padding=lm.scaled(12), bootstyle=PRIMARY,
                   command=self.start_connect).pack(side="left",padx=lm.scaled(15))
        # Back to Wifi Scan Page
        ttk.Button(btn_frame, text="Back", padding=lm.scaled(12),bootstyle=SECONDARY,
                   command=lambda: controller.show_frame(ScanPage)).pack(side="right",padx=lm.scaled(15))

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
#------------PAGE 3.1 : Manual WiFi Entry Page ------------#
class ManualWifiPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller=controller
        lm=self.controller.lm
        self.keyboard = None
        
        ttk.Label(
            self,
            text="Enter Wi-Fi Network",
            font=lm.font(22),
            foreground="white"
        ).pack(pady=lm.scaled(20))
        
    #---------------SSID Details----------------#
        ttk.Label(self, text="SSID", font=lm.font(12)).pack(pady=(0, 5))
        self.ssid_entry = ttk.Entry(self, font=lm.font(12))
        self.ssid_entry.pack(
            padx=lm.scaled(40),
            fill="x",
            ipady=lm.scaled(6)
        )

        # ---- PASSWORD -------------------------#
        # ---- PASSWORD LABEL -------------------#
        ttk.Label(
        self,
        text="Password",
        font=lm.font(12),
        foreground="white"
        ).pack(
        pady=(lm.scaled(10), lm.scaled(5))
        )
        pw_frame = ttk.Frame(self)
        pw_frame.pack(padx=lm.scaled(40), fill="x")
        self.password_entry = ttk.Entry(pw_frame, font=lm.font(12), show="*")
        
        self.password_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=lm.scaled(6)
        )
            
        ttk.Button(
            pw_frame,
            text="👁",
            width=4,
            bootstyle=INFO,
            command=self.toggle_password
        ).pack(
            side="left",
            padx=(lm.scaled(8), 0 )
        )

        # Keyboard support
        self.ssid_entry.bind("<FocusIn>", lambda e: self.open_keyboard(self.ssid_entry))
        self.password_entry.bind("<FocusIn>", lambda e: self.open_keyboard(self.password_entry))

        # ---- BUTTONS ----#
        btn_row = ttk.Frame(self)
        btn_row.pack(pady=lm.scaled(25))

        ttk.Button(
            btn_row,
            text="Connect",
            bootstyle=SUCCESS,
            padding=lm.scaled(12),
            command=self.connect_manual
        ).pack(side="left", padx=lm.scaled(10))

        ttk.Button(
            btn_row,
            text="Back",
            bootstyle=SECONDARY,
            padding=lm.scaled(12),
            command=lambda: controller.show_frame(ScanPage)
        ).pack(side="left", padx=lm.scaled(10))
    
    def toggle_password(self):
        current = self.password_entry.cget("show")
        self.password_entry.config(show="" if current == "*" else "*")
        
    def open_keyboard(self, entry):
        self.close_keyboard()
        self.keyboard = T9Keypad(self, entry, self.close_keyboard, self.controller.lm)
        self.keyboard.pack(side="bottom", fill="x")
    
    def close_keyboard(self):
        if self.keyboard:
            self.keyboard.destroy()
            self.keyboard = None
    
    def connect_manual(self):
        ssid = self.ssid_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not ssid:
            messagebox.showerror("Invalid Input", "Please enter the SSID.")
            return
        
        self.controller.selected_ssid = ssid
        self.controller.wifi_password = password
        
        connecting_page = self.controller.frames[WifiConnectingPage]
        connecting_page.set_text(f"Connecting to \n {ssid}...")
        self.controller.show_frame(WifiConnectingPage)
        
        threading.Thread(target=self.process_connect, daemon=True).start()
    
    def process_connect(self):
        start_time = time.time()
        TIMEOUT = 15  # seconds

        success = False

        while time.time() - start_time < TIMEOUT:
            success = connect_wifi(
            self.controller.selected_ssid,
            self.controller.wifi_password
            )

            if success:
               break

            time.sleep(1)  # avoid hammering OS

    # ---- Back to UI thread ----
        if success:
           self.controller.after(
            0,
            lambda: self.controller.show_frame(LoginPage)
        )
        else:
            self.controller.after(
            0,
            lambda: self.controller.show_error(
                title="Connection Failed",
                message="Unable to connect. Password may be incorrect or network unavailable.",
                return_frame=ManualWifiPage
            )
        )
        
    
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
#--------------Error Page Class which can be reused for different types of errors (When there is an error in connecting to the WiFi network, data transfer etc.)           
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
            foreground="white"
        )
        self.title_label.pack(pady=(0, lm.scaled(10)))

        self.message_label = ttk.Label(
            container,
            text="",
            font=lm.font(12),
            foreground="white",
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
