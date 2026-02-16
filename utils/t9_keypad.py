"""
T9 Keypad Module for Python Bootloader Application.

This module provides a T9-style on-screen keyboard component for tkinter,
simulating the classic multi-tap phone keyboard input (like old Nokia phones).
It's designed for touchscreen input on devices without physical keyboards.

Features:
    - Multi-tap character cycling (press same key repeatedly to cycle)
    - Capital, lowercase, and symbol layouts
    - Numpad mode for numeric-only input
    - Backspace and layout switching
    - Responsive scaling via LayoutManager

Classes:
    T9Keypad: Tkinter frame containing the T9 keyboard.

Usage:
    keypad = T9Keypad(parent, target_entry, close_callback, layout_manager)
    keypad.pack()
"""

import tkinter as tk
from tkinter import font as tkfont
import time

class T9Keypad(tk.Frame):
    """
    T9 Keypad Component for Tkinter
    Simulates classic phone keyboard input (like old Nokia phones)
    Compatible with OnScreenKeyboard interface
    """
    
    def __init__(self, parent, target_entry, close_callback, layout_manager=None):
        """
        Initialize T9 Keypad
        
        Args:
            parent: Parent tkinter widget
            target_entry: Entry widget to type into
            close_callback: Function to call when keyboard should close
            layout_manager: LayoutManager instance for scaling (optional)
        """
        super().__init__(parent, bg="#2b2b2b")
        
        self.target = target_entry
        self.close_callback = close_callback
        self.lm = layout_manager
        self.numpad_mode = False  # Default to T9 mode
        
        
        # Define T9 key mappings
        self.cap_keys = [
            {"number": "1", "letters": ["1"], "showletters": [""]},
            {"number": "2", "letters": ["2", "A", "B", "C"], "showletters": ["A", "B", "C"]},
            {"number": "3", "letters": ["3", "D", "E", "F"], "showletters": ["D", "E", "F"]},
            {"number": "4", "letters": ["4", "G", "H", "I"], "showletters": ["G", "H", "I"]},
            {"number": "5", "letters": ["5", "J", "K", "L"], "showletters": ["J", "K", "L"]},
            {"number": "6", "letters": ["6", "M", "N", "O"], "showletters": ["M", "N", "O"]},
            {"number": "7", "letters": ["7", "P", "Q", "R", "S"], "showletters": ["P", "Q", "R", "S"]},
            {"number": "8", "letters": ["8", "T", "U", "V"], "showletters": ["T", "U", "V"]},
            {"number": "9", "letters": ["9", "W", "X", "Y", "Z"], "showletters": ["W", "X", "Y", "Z"]},
            {"number": "10", "letters": ["⇩"], "showletters": [""]},
            {"number": "0", "letters": ["0", " "], "showletters": [" "]},
            {"number": "11", "letters": ["⌫"], "showletters": [""]}
        ]
        
        self.lower_keys = [
            {"number": "1", "letters": ["1"], "showletters": [""]},
            {"number": "2", "letters": ["2", "a", "b", "c"], "showletters": ["a", "b", "c"]},
            {"number": "3", "letters": ["3", "d", "e", "f"], "showletters": ["d", "e", "f"]},
            {"number": "4", "letters": ["4", "g", "h", "i"], "showletters": ["g", "h", "i"]},
            {"number": "5", "letters": ["5", "j", "k", "l"], "showletters": ["j", "k", "l"]},
            {"number": "6", "letters": ["6", "m", "n", "o"], "showletters": ["m", "n", "o"]},
            {"number": "7", "letters": ["7", "p", "q", "r", "s"], "showletters": ["p", "q", "r", "s"]},
            {"number": "8", "letters": ["8", "t", "u", "v"], "showletters": ["t", "u", "v"]},
            {"number": "9", "letters": ["9", "w", "x", "y", "z"], "showletters": ["w", "x", "y", "z"]},
            {"number": "10", "letters": ["?123"], "showletters": [""]},
            {"number": "0", "letters": ["0", " "], "showletters": [" "]},
            {"number": "11", "letters": ["⌫"], "showletters": [""]}
        ]
        
        self.symbol_keys = [
            {"number": "1", "letters": ["!"], "showletters": [""]},
            {"number": "2", "letters": ["@"], "showletters": [""]},
            {"number": "3", "letters": ["#"], "showletters": [""]},
            {"number": "4", "letters": ["$"], "showletters": [""]},
            {"number": "5", "letters": ["%"], "showletters": [""]},
            {"number": "6", "letters": ["^"], "showletters": [""]},
            {"number": "7", "letters": ["&"], "showletters": [""]},
            {"number": "8", "letters": ["*"], "showletters": [""]},
            {"number": "9", "letters": ["-"], "showletters": [""]},
            {"number": "10", "letters": ["⇧"], "showletters": [""]},
            {"number": "0", "letters": ["_"], "showletters": [""]},
            {"number": "11", "letters": ["⌫"], "showletters": [""]}
        ]
        
        self.number_keys = [
            {"number": "1", "letters": ["1"], "showletters": [""]},
            {"number": "2", "letters": ["2"], "showletters": [""]},
            {"number": "3", "letters": ["3"], "showletters": [""]},
            {"number": "4", "letters": ["4"], "showletters": [""]},
            {"number": "5", "letters": ["5"], "showletters": [""]},
            {"number": "6", "letters": ["6"], "showletters": [""]},
            {"number": "7", "letters": ["7"], "showletters": [""]},
            {"number": "8", "letters": ["8"], "showletters": [""]},
            {"number": "9", "letters": ["9"], "showletters": [""]},
            {"number": "10", "letters": [""], "showletters": [""]},
            {"number": "0", "letters": ["0"], "showletters": [""]},
            {"number": "11", "letters": ["⌫"], "showletters": [""]}
        ]
        
        # State management
        self.layouts = [self.cap_keys, self.lower_keys, self.symbol_keys]
        self.layout_number = 0
        self.t9_keys = self.cap_keys  # Start with capital letters
        self.last_key = None
        self.cycle_index = 0
        self.last_press_time = 0
        self.multi_tap_delay = 0.7
        self.timeout_id = None
        self.buttons = {}

        # Initialize fonts once
        main_size = self.lm.scaled(20) if self.lm else 20
        sub_size = self.lm.scaled(10) if self.lm else 10
        self.main_font = tkfont.Font(family="Arial", size=main_size, weight="bold")
        self.sub_font = tkfont.Font(family="Arial", size=sub_size)
        
        # Create UI
        self.create_keyboard()
    
    def create_keyboard(self):
        """Create the keyboard UI"""
        # Keyboard frame with 3-column grid
        keyboard_frame = tk.Frame(self, bg="#2b2b2b")
        keyboard_frame.pack(expand=True, fill="both")
        
        # Configure grid weights for responsive layout
        for i in range(3):
            keyboard_frame.columnconfigure(i, weight=1)
        for i in range(4):
            keyboard_frame.rowconfigure(i, weight=1)
        
        # Create buttons
        self.create_buttons(keyboard_frame)
    
    def create_buttons(self, parent):
        """Create button widgets once"""
        self.buttons.clear()
        
        # Create 3x4 grid of buttons
        pad_val = self.lm.scaled(5) if self.lm else 5
        
        # We process keys in order, mapping them to 1-9, *, 0, # equivalent positions
        # The key definitions in self.t9_keys match the 12 positions
        
        for idx in range(12):
            row = idx // 3
            col = idx % 3
            
            # Use a stable key identifier based on position for widget storage
            # The actual logic key (e.g. "1", "2") comes from the current layout object
            
            # Create button frame to hold main and sub text
            btn_frame = tk.Frame(
                parent,
                bg="#f0f0f0",
                relief="raised",
                borderwidth=2,
                cursor="hand2"
            )
            btn_frame.grid(row=row, column=col, padx=pad_val, pady=pad_val, sticky="nsew")
            
            # Main text label
            main_label = tk.Label(
                btn_frame,
                text="",
                font=self.main_font,
                bg="#f0f0f0",
                fg="#333333"
            )
            main_label.pack(expand=True)
            
            # Sub text label
            sub_label = tk.Label(
                btn_frame,
                text="",
                font=self.sub_font,
                bg="#f0f0f0",
                fg="#666666"
            )
            sub_label.pack()
            
            # Store widgets
            self.buttons[idx] = {
                "frame": btn_frame,
                "main": main_label,
                "sub": sub_label
            }

            # Bind events (using closure to capture current index)
            # We bind to the specific index, and look up the key at runtime
            btn_frame.bind("<Button-1>", lambda e, i=idx: self.handle_key_press_by_index(i))
            main_label.bind("<Button-1>", lambda e, i=idx: self.handle_key_press_by_index(i))
            sub_label.bind("<Button-1>", lambda e, i=idx: self.handle_key_press_by_index(i))

        # Initial populate
        self.update_buttons()

    def update_buttons(self):
        """Update text and style of existing buttons based on current layout"""
        for idx, key_obj in enumerate(self.t9_keys):
            if idx not in self.buttons:
                continue

            widgets = self.buttons[idx]
            btn_frame = widgets["frame"]
            main_label = widgets["main"]
            sub_label = widgets["sub"]

            key_num = key_obj["number"]
            main_text = key_obj["letters"][0]
            sub_text = "".join(key_obj["showletters"])

            # Update text
            main_label.config(text=main_text)
            sub_label.config(text=sub_text)

            # Update style for visual feedback / specific keys
            # Disable key 10 in numpad mode handling
            if self.numpad_mode and key_num == "10":
                btn_frame.config(bg="#d0d0d0", cursor="")
                main_label.config(bg="#d0d0d0", fg="#999999")
                sub_label.config(bg="#d0d0d0")
            else:
                 btn_frame.config(bg="#f0f0f0", cursor="hand2")
                 main_label.config(bg="#f0f0f0", fg="#333333")
                 sub_label.config(bg="#f0f0f0", fg="#666666")

    def handle_key_press_by_index(self, index):
        """Indirect handler to lookup clean key object"""
        if 0 <= index < len(self.t9_keys):
            key_obj = self.t9_keys[index]
            self.handle_key_press(key_obj["number"])

    def handle_key_press(self, key):
        """Handle key press events"""
        key_obj = next((k for k in self.t9_keys if k["number"] == key), None)
        if not key_obj:
            return
        
        letters = key_obj["letters"]
        now = time.time()
        
        # T9 mode with cycling
        if key == "10":
            # Switch layout
            self.layout_number = (self.layout_number + 1) % len(self.layouts)
            self.t9_keys = self.layouts[self.layout_number]
            
            # Efficient update: just change text, don't recreate widgets
            self.update_buttons()
            
            self.last_key = None
            print(f"Layout switched to {self.layout_number}")
        elif key == "11":
            # Backspace
            self.add_backspace()
            self.last_key = None
        else:
            cursor = self.target.index("insert")
            if cursor != len(self.target.get()):
                self.last_key = None
            same_key_quickly = (
                key == self.last_key and now-self.last_press_time < self.multi_tap_delay
            )
            # Character input with cycling
            if same_key_quickly:
                self.cycle_index = (self.cycle_index + 1) % len(letters)
                if cursor > 0:
                    self.target.delete(cursor-1, cursor)
                current_char = letters[self.cycle_index]
            else:
                self.cycle_index = 0
                current_char = letters[0]
            
            self.add_char(current_char)
            self.last_key = key
            self.last_press_time = now
    
    
    def set_target(self, target_entry):
        """Update the target entry widget"""
        self.target = target_entry

    def add_char(self, char):
        """Add character to target entry"""
        if self.target:
             self.target.insert("insert", char)
    
    def add_backspace(self):
        """Remove last character from target entry"""
        if self.target:
             cursor=self.target.index("insert")
             if cursor > 0:
                 self.target.delete(cursor-1, cursor)
    
    def reset_last_key(self):
        """Reset the last key after timeout"""
        print("Timeout triggered - resetting last key")
        self.last_key = None
        self.cycle_index = 0
        self.timeout_id = None

