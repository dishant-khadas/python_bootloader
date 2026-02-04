"""
WiFi List Page for Python Bootloader Application.

Displays a scrollable list of available WiFi networks with a canvas-based
UI for smooth scrolling and touch support.
"""

import tkinter as tk
import threading
import time
import ttkbootstrap as ttk
from ttkbootstrap.constants import SECONDARY, INFO, SUCCESS

from wifi_utils import scan_wifi


class WifiListPage(ttk.Frame):
    """
    WiFi network list page with scrollable network selection.
    
    Provides a canvas-based scrollable list of WiFi networks with
    keyboard navigation, touch scrolling, and network selection.
    
    Attributes:
        controller: Reference to the main App controller.
        network_buttons (list): List of network button widgets.
        selected_index (int): Currently selected network index.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the WiFi list page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = self.controller.lm
        
        # Frame layout
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x")
        middle_frame = ttk.Frame(self)
        middle_frame.pack(fill="both", expand=True)
        bottom_frame = ttk.Frame(self)
        bottom_frame.pack(fill="x")

        # Title
        ttk.Label(top_frame, text="Available Networks", font=lm.font(24), foreground="white").pack(pady=lm.scaled(20))
        
        # Canvas-based list container
        list_container = ttk.Frame(middle_frame)
        list_container.pack(fill="both", expand=True, padx=lm.scaled(80), pady=lm.scaled(10))
        self.canvas = tk.Canvas(list_container, bg="#2d2d2d", highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar = tk.Scrollbar(list_container, orient="vertical", command=self.canvas.yview, width=18)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.list_frame = ttk.Frame(self.canvas)
        self.canvas_window = self.canvas.create_window((0, 0), window=self.list_frame, anchor="nw")
        self.canvas.bind("<Configure>", self._on_canvas_resize)
        self.list_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        
        ttk.Label(self, text="Available Networks", font=lm.font(24)).pack(pady=lm.scaled(20))
        
        # Legacy listbox (kept for compatibility)
        self.listbox = tk.Listbox(
            self, 
            font=lm.font(16), 
            height=8,
            bg="white",
            fg="black",
            selectbackground="#00d4aa",
            selectforeground="white",
            highlightthickness=2,
            highlightcolor="#00d4aa",
            highlightbackground="#cccccc",
            relief="flat",
            borderwidth=0,
            activestyle="none"
        )
        
        # Button row
        btn_row = ttk.Frame(bottom_frame)
        btn_row.pack(pady=lm.scaled(10))
        btn_width = 10
        
        ttk.Button(
            btn_row, text="Refresh", width=btn_width, padding=lm.scaled(8),
            bootstyle=SECONDARY, command=self.refresh_networks   
        ).pack(side="left", padx=lm.scaled(10))
        
        ttk.Button(
            btn_row, text="Add Network", width=12, padding=lm.scaled(8),
            bootstyle=INFO, command=self._go_manual_wifi
        ).pack(side="left", padx=lm.scaled(13))
        
        ttk.Button(
            btn_row, text="Next", width=btn_width, padding=lm.scaled(8),
            bootstyle=SUCCESS, command=self.go_next
        ).pack(side="right", padx=lm.scaled(10))
        
        # State
        self.network_buttons = []
        self.selected_index = 0
        self.focus_set()
        
        # Keyboard bindings
        self.bind_all("<Up>", self.on_up_key)
        self.bind_all("<Down>", self.on_down_key)
        self.bind_all("<Return>", lambda e: self.go_next())
        
        # Scroll bindings
        self.canvas.bind("<ButtonPress-1>", self._on_touch_start)
        self.canvas.bind("<B1-Motion>", self._on_touch_move)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel_linux)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel_linux)

    def _go_manual_wifi(self):
        """Navigate to manual WiFi entry page."""
        from pages.manual_wifi_page import ManualWifiPage
        self.controller.show_frame(ManualWifiPage)

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling (Windows/Mac)."""
        self.canvas.yview_scroll(-1 * (event.delta // 120), "units")
        
    def _on_mousewheel_linux(self, event):
        """Handle mouse wheel scrolling (Linux)."""
        if event.num == 4:
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            self.canvas.yview_scroll(1, "units")
            
    def _on_touch_start(self, event):
        """Handle touch drag start."""
        self.canvas.scan_mark(event.x, event.y)
        
    def _on_touch_move(self, event):
        """Handle touch drag move."""
        self.canvas.scan_dragto(event.x, event.y, gain=1)

    def load_list(self, ssids):
        """
        Load WiFi networks into the list.
        
        Args:
            ssids (list): List of SSID strings.
        """
        self.listbox.delete(0, tk.END)
        
        for widget in self.list_frame.winfo_children():
            widget.destroy()
        
        self.network_buttons.clear()
        self.selected_index = 0
        
        for idx, ssid in enumerate(ssids):
            btn = ttk.Button(
                self.list_frame,
                text=f"📶 {ssid}",
                bootstyle="secondary",
                padding=self.controller.lm.scaled(16),
                command=lambda s=ssid, i=idx: self._select_network(i, s)
            )
            btn.pack(fill="x", pady=self.controller.lm.scaled(10))
            self.network_buttons.append(btn)
            
        if self.network_buttons:
            self._highlight_selected()
            self.after(50, lambda: self.network_buttons[0].focus_set())
            
    def _center_list_frame(self, event=None):
        """Center the list frame in canvas."""
        canvas_width = self.canvas.winfo_width()
        self.canvas.itemconfig(self.canvas_window, canvas_width // 2, 0)
        
    def _on_canvas_resize(self, event):
        """Handle canvas resize to adjust list frame width."""
        self.canvas.itemconfig(self.canvas_window, width=event.width)
    
    def refresh_networks(self):
        """Refresh the network list."""
        from pages.wifi_connecting_page import WifiConnectingPage
        
        self.controller.show_frame(WifiConnectingPage)
        self.controller.frames[WifiConnectingPage].set_text("Scanning WiFi...")
        threading.Thread(target=self._do_refresh, daemon=True).start()
        
    def _do_refresh(self):
        """Background thread for network refresh."""
        ssids = scan_wifi()
        time.sleep(2)
        self.controller.after(0, lambda: self._finish_refresh(ssids))
        
    def _finish_refresh(self, ssids):
        """Callback after refresh completes."""
        from pages.wifi_list_page import WifiListPage
        
        self.load_list(ssids)
        self.controller.show_frame(WifiListPage)
        self.focus_set()
    
    def go_next(self):
        """Navigate to password entry page."""
        from pages.wifi_password_page import WifiPasswordPage
        
        ssid = self.controller.selected_ssid
        if not ssid:
            return
        password_page = self.controller.frames[WifiPasswordPage]
        password_page.title_label.config(text=f"SSID : {ssid}")
        self.controller.show_frame(WifiPasswordPage)
        
    def _select_network(self, index, ssid):
        """Select a network from the list."""
        self.selected_index = index
        self.controller.selected_ssid = ssid
        self._highlight_selected()
        
    def _highlight_selected(self):
        """Update visual highlighting of selected network."""
        self.canvas.update_idletasks()
        bbox_all = self.canvas.bbox("all")
        if not bbox_all:
            return

        for i, btn in enumerate(self.network_buttons):
            btn.configure(bootstyle="secondary")

        # Auto-scroll to selected button
        btn = self.network_buttons[self.selected_index]
        btn_y = btn.winfo_y()
        btn_h = btn.winfo_height()
        canvas_h = self.canvas.winfo_height()

        if btn_y < self.canvas.canvasy(0):
            self.canvas.yview_moveto(btn_y / bbox_all[3])
        elif btn_y + btn_h > self.canvas.canvasy(0) + canvas_h:
            self.canvas.yview_moveto((btn_y + btn_h - canvas_h) / bbox_all[3])
    
    def on_up_key(self, event):
        """Handle up arrow key."""
        if self.selected_index > 0:
            self.selected_index -= 1
            ssid = self.network_buttons[self.selected_index].cget("text").replace("📶", "").strip()
            self.controller.selected_ssid = ssid
            self._highlight_selected()
            self.canvas.yview_scroll(-1, "units")
        return "break"
        
    def on_down_key(self, event):
        """Handle down arrow key."""
        if self.selected_index < len(self.network_buttons) - 1:
            self.selected_index += 1
            ssid = self.network_buttons[self.selected_index].cget("text").replace("📶", "").strip()
            self.controller.selected_ssid = ssid
            self._highlight_selected()
            self.canvas.yview_scroll(+1, "units")
        return "break"
