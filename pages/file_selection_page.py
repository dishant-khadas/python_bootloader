"""
File Selection Page for Python Bootloader Application.

Displays available firmware files from the server and allows
user to select one for download.
"""

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import SUCCESS
from tkinter import messagebox
from core.app_state import AppState
from utils.logger import logger


class FileSelectionPage(ttk.Frame):
    """
    Firmware file selection page.
    
    Shows DU information and a custom touch-friendly dropdown
    of available firmware files retrieved from the server API.
    
    Attributes:
        controller: Reference to the main App controller.
        selected_file (str): Currently selected file name.
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
        self.selected_file = ""
        self._dropdown_open = False

        # Center Container (title, DU info, selector field)
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.35, anchor="center")

        # Title
        ttk.Label(container, text="Select Firmware", font=lm.font(24)).pack(pady=lm.scaled(30))

        # DU Info Frame
        info_frame = ttk.Frame(container)
        info_frame.pack(fill="x", pady=lm.scaled(15))

        self.du_label = ttk.Label(
            info_frame, text="DU: --", font=lm.font(14), foreground="#00d4aa"
        )
        self.du_label.pack(anchor="center", pady=lm.scaled(5))
        
        self.disp_label = ttk.Label(
            info_frame, text="DISPLAY: --", font=lm.font(14), foreground="#00d4aa"
        )
        self.disp_label.pack(anchor="center", pady=lm.scaled(5))

        # ---- Selector Field (looks like a combobox) ----
        self.selector_frame = tk.Frame(
            container, bg="#ffffff",
            highlightbackground="#cccccc", highlightthickness=1,
            cursor="hand2"
        )
        self.selector_frame.pack(pady=lm.scaled(10), ipadx=lm.scaled(10))

        self.selector_inner = tk.Frame(self.selector_frame, bg="#ffffff")
        self.selector_inner.pack(fill="x", padx=lm.scaled(10), pady=lm.scaled(8))

        self.selector_label = tk.Label(
            self.selector_inner, text="Select File",
            font=lm.font(12), bg="#ffffff", fg="#333333",
            anchor="w", width=22
        )
        self.selector_label.pack(side="left", fill="x", expand=True)

        self.selector_arrow = tk.Label(
            self.selector_inner, text="\u25bc",
            font=lm.font(12), bg="#ffffff", fg="#333333",
            anchor="e"
        )
        self.selector_arrow.pack(side="right")

        # Bind tap
        self.selector_frame.bind("<Button-1>", self._toggle_dropdown)
        self.selector_label.bind("<Button-1>", self._toggle_dropdown)
        self.selector_arrow.bind("<Button-1>", self._toggle_dropdown)
        self.selector_inner.bind("<Button-1>", self._toggle_dropdown)

        # ---- Dropdown overlay (placed on self, the page frame) ----
        self.dropdown_frame = tk.Frame(
            self, bg="#ffffff",
            highlightbackground="#aaaaaa", highlightthickness=1
        )
        self._file_buttons = []

        # Next Button - anchored at bottom-right
        bottom_frame = ttk.Frame(self)
        bottom_frame.place(relx=1.0, rely=1.0, anchor="se",
                           x=-lm.scaled(20), y=-lm.scaled(25))

        ttk.Button(
            bottom_frame, text="Next", bootstyle=SUCCESS,
            padding=(lm.scaled(20), lm.scaled(8)),
            command=self.on_next
        ).pack()

    def _toggle_dropdown(self, event=None):
        """Open or close the dropdown list."""
        if self._dropdown_open:
            self._close_dropdown()
        else:
            self._open_dropdown()

    def _open_dropdown(self):
        """Show the dropdown list below the selector field."""
        if self._dropdown_open:
            return
        lm = self.controller.lm

        # Clear old items
        for btn in self._file_buttons:
            btn.destroy()
        self._file_buttons.clear()

        options = getattr(self.controller, "du_options", {})
        files = options.get("fileName", [])

        if not files:
            lbl = tk.Label(
                self.dropdown_frame, text="No files available",
                font=lm.font(14), bg="#f5f5f5", fg="#999999",
                anchor="w", padx=lm.scaled(10), pady=lm.scaled(10)
            )
            lbl.pack(fill="x")
            self._file_buttons.append(lbl)
        else:
            for fname in files:
                btn = tk.Label(
                    self.dropdown_frame, text=fname,
                    font=lm.font(14), bg="#ffffff", fg="#333333",
                    anchor="w", padx=lm.scaled(10), pady=lm.scaled(12),
                    cursor="hand2"
                )
                btn.pack(fill="x")
                btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#e8f0fe"))
                btn.bind("<Leave>", lambda e, b=btn: b.config(bg="#ffffff"))
                btn.bind("<Button-1>", lambda e, f=fname: self._select_file(f))
                self._file_buttons.append(btn)

        # Position the dropdown below the selector field
        self.update_idletasks()
        sx = self.selector_frame.winfo_rootx() - self.winfo_rootx()
        sy = self.selector_frame.winfo_rooty() - self.winfo_rooty() + self.selector_frame.winfo_height()
        sw = self.selector_frame.winfo_width()

        self.dropdown_frame.place(x=sx, y=sy, width=sw)
        self.dropdown_frame.lift()
        self._dropdown_open = True

    def _close_dropdown(self):
        """Hide the dropdown list."""
        self.dropdown_frame.place_forget()
        self._dropdown_open = False

    def _select_file(self, filename):
        """Handle file selection from dropdown."""
        self.selected_file = filename
        self.selector_label.config(text=filename)
        self._close_dropdown()

    def on_show(self):
        """Update display when page is shown."""
        options = getattr(self.controller, "du_options", {})
        du_num = options.get("duNumber", "Unknown")
        disp_num = options.get("displayNumber", "Unknown")
        
        self.du_label.config(text=f"DU: {du_num}")
        self.disp_label.config(text=f"Display: {disp_num}")

        # Reset dropdown state
        self.selected_file = ""
        self.selector_label.config(text="Select File")
        self._close_dropdown()

    def on_next(self):
        """Handle Next button click."""
        from pages.download_page import DownloadPage
        
        if not self.selected_file:
            messagebox.showwarning("Selection", "Please select a firmware file.")
            return

        selected_file = self.selected_file
        logger.info(f"Next Clicked. Selected: {selected_file}")
        options = getattr(self.controller, "du_options", {})
        file_names = options.get("fileName", [])
        file_ids = options.get("fileId", [])
        
        if selected_file in file_names:
            idx = file_names.index(selected_file)
            logger.debug("---------------- DEBUG SELECTION ----------------")
            logger.info(f"Selected File: '{selected_file}'")
            logger.info(f"Index found: {idx}")
            logger.info(f"File Names List: {file_names}")
            logger.info(f"File IDs List: {file_ids}")
            
            if idx < len(file_ids):
                file_id = file_ids[idx]
                
                # Store selected file in AppState
                state = AppState.get_instance()
                state.set_firmware_selection(file_id, selected_file)
                
                # Start download
                download_page = self.controller.frames[DownloadPage]
                download_page.file_id = file_id
                self.controller.show_frame(DownloadPage)
