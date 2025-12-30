import tkinter as tk
from tkinter import font as tkfont


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
            {"number": "10", "letters": ["@"], "showletters": [""]},
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
        self.timeout_id = None
        self.buttons = {}
        
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
        self.render_buttons(keyboard_frame)
    
    def render_buttons(self, parent):
        """Render keyboard buttons"""
        # Clear existing buttons
        for widget in parent.winfo_children():
            widget.destroy()
        self.buttons.clear()
        
        # Font settings (scaled if layout manager available)
        main_size = self.lm.scaled(20) if self.lm else 20
        sub_size = self.lm.scaled(10) if self.lm else 10
        main_font = tkfont.Font(family="Arial", size=main_size, weight="bold")
        sub_font = tkfont.Font(family="Arial", size=sub_size)
        
        # Create 3x4 grid of buttons
        pad_val = self.lm.scaled(5) if self.lm else 5
        
        for idx, key_obj in enumerate(self.t9_keys):
            row = idx // 3
            col = idx % 3
            
            key_num = key_obj["number"]
            main_text = key_obj["letters"][0]
            sub_text = "".join(key_obj["showletters"])
            
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
                text=main_text,
                font=main_font,
                bg="#f0f0f0",
                fg="#333333"
            )
            main_label.pack(expand=True)
            
            # Sub text label
            sub_label = tk.Label(
                btn_frame,
                text=sub_text,
                font=sub_font,
                bg="#f0f0f0",
                fg="#666666"
            )
            sub_label.pack()
            
            # Disable key 10 in numpad mode
            if self.numpad_mode and key_num == "10":
                btn_frame.config(bg="#d0d0d0", cursor="")
                main_label.config(bg="#d0d0d0", fg="#999999")
                sub_label.config(bg="#d0d0d0")
            else:
                # Bind click events to all widgets
                btn_frame.bind("<Button-1>", lambda e, k=key_num: self.handle_key_press(k))
                main_label.bind("<Button-1>", lambda e, k=key_num: self.handle_key_press(k))
                sub_label.bind("<Button-1>", lambda e, k=key_num: self.handle_key_press(k))
            
            self.buttons[key_num] = (btn_frame, main_label, sub_label)
    
    def handle_key_press(self, key):
        """Handle key press events"""
        key_obj = next((k for k in self.t9_keys if k["number"] == key), None)
        if not key_obj:
            return
        
        letters = key_obj["letters"]
        
        # T9 mode with cycling
        if key == "10":
            # Switch layout
            self.layout_number = (self.layout_number + 1) % len(self.layouts)
            self.t9_keys = self.layouts[self.layout_number]
            # Re-render entire keyboard
            for widget in self.winfo_children():
                widget.destroy()
            self.create_keyboard()
            print(f"Layout switched to {self.layout_number}")
        elif key == "11":
            # Backspace
            self.add_backspace()
        else:
            # Character input with cycling
            if key == self.last_key:
                # Same key pressed - cycle to next letter
                new_index = (self.cycle_index + 1) % len(letters)
                current_char = letters[new_index]
                
                # Delete last character first, then add new one
                self.add_backspace()
                self.cycle_index = new_index
                
                # Clear previous timeout
                if self.timeout_id:
                    self.after_cancel(self.timeout_id)
            else:
                # Different key pressed
                current_char = letters[0]
                self.last_key = key
                self.cycle_index = 0
            
            # Add the character
            self.add_char(current_char)
            
            # Set timeout to reset last_key after 3 seconds
            if self.timeout_id:
                self.after_cancel(self.timeout_id)
            self.timeout_id = self.after(3000, self.reset_last_key)
    
    def add_char(self, char):
        """Add character to target entry"""
        self.target.insert(tk.END, char)
    
    def add_backspace(self):
        """Remove last character from target entry"""
        text = self.target.get()
        if text:
            self.target.delete(len(text)-1)
    
    def reset_last_key(self):
        """Reset the last key after timeout"""
        print("Timeout triggered - resetting last key")
        self.last_key = None
        self.cycle_index = 0
        self.timeout_id = None

