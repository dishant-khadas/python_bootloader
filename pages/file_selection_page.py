"""
File Selection Page for Python Bootloader Application.

Displays available firmware files from the server and allows
user to select one for download.
"""

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import SUCCESS
from tkinter import messagebox


class FileSelectionPage(ttk.Frame):
    """
    Firmware file selection page.
    
    Shows DU information and a dropdown of available firmware
    files retrieved from the server API.
    
    Attributes:
        controller: Reference to the main App controller.
        file_var (StringVar): Selected file name.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the file selection page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
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

        self.du_label = ttk.Label(
            info_frame, text="DU: --", font=lm.font(16), foreground="#00d4aa"
        )
        self.du_label.pack(anchor="center", pady=lm.scaled(5))
        
        self.disp_label = ttk.Label(
            info_frame, text="Display: --", font=lm.font(16), foreground="#00d4aa"
        )
        self.disp_label.pack(anchor="center", pady=lm.scaled(5))

        # Files Dropdown
        self.file_var = tk.StringVar()
        self.combobox = ttk.Combobox(
            container, textvariable=self.file_var,
            font=lm.font(14), state="readonly", width=30,
            style="Custom.TCombobox"
        )
        self.combobox.pack(pady=lm.scaled(10), ipady=lm.scaled(5))

        # Next Button
        ttk.Button(
            container, text="Next", bootstyle=SUCCESS,
            padding=lm.scaled(15), command=self.on_next
        ).pack(pady=lm.scaled(40))

    def on_show(self):
        """Update display when page is shown."""
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
        """Handle Next button click."""
        from pages.download_page import DownloadPage
        
        selected_file = self.file_var.get()
        if not selected_file or selected_file in ("No files available", "Select File"):
            messagebox.showwarning("Selection", "Please select a valid file.")
            return

        print(f"Next Clicked. Selected: {selected_file}")
        
        # Get corresponding fileId
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
                # Store selected file name on controller for logging
                self.controller.selected_file_name = selected_file
                # Start download
                download_page = self.controller.frames[DownloadPage]
                download_page.file_id = file_id
                self.controller.show_frame(DownloadPage)
