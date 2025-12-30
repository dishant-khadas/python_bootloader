import tkinter as tk
class LayoutManager:
    def __init__(self, root, base_width=450, base_height=750, width=None, height=None):
        self.root = root
        self.base_width = base_width
        self.base_height = base_height
        
        # Get actual screen dimensions or use provided
        if width and height:
            self.screen_width = width
            self.screen_height = height
        else:
            self.screen_width = self.root.winfo_screenwidth()
            self.screen_height = self.root.winfo_screenheight()
        
        # Calculate scale factors
        self.scale_x = self.screen_width / self.base_width
        self.scale_y = self.screen_height / self.base_height
        
        # Use the smaller scale factor to ensure everything fits (maintain aspect ratio roughly)
        # or use average. Usually, for UI sizing, min is safer to prevent overflow.
        self.scale_factor = min(self.scale_x, self.scale_y)
    def scaled(self, value):
        """Converts a base pixel value to a scaled pixel value."""
        return int(value * self.scale_factor)
    
    def font(self, size, family="Segoe UI"):
        """Returns a scaled font tuple."""
        return (family, self.scaled(size))