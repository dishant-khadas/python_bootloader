"""
UI Utilities Module for Python Bootloader Application.

This module provides responsive layout management utilities for the tkinter-based UI.
It enables the application to scale properly across different screen sizes and resolutions.

Classes:
    LayoutManager: Handles dynamic scaling of UI elements based on screen dimensions.

Usage:
    from ui_utils import LayoutManager
    
    lm = LayoutManager(root_window)
    button = ttk.Button(root, padding=lm.scaled(20))
    label = ttk.Label(root, font=lm.font(14))
"""

import tkinter as tk


class LayoutManager:
    """
    Manages responsive layout scaling for tkinter applications.
    
    This class calculates scale factors based on the difference between a base
    design resolution and the actual screen dimensions, allowing UI elements
    to be sized proportionally across different displays.
    
    Attributes:
        root: The root tkinter window.
        base_width (int): The base design width (default: 450).
        base_height (int): The base design height (default: 750).
        screen_width (int): Actual screen width or provided width.
        screen_height (int): Actual screen height or provided height.
        scale_x (float): Horizontal scale factor.
        scale_y (float): Vertical scale factor.
        scale_factor (float): The minimum of scale_x and scale_y to maintain aspect ratio.
    """
    
    def __init__(self, root, base_width=450, base_height=750, width=None, height=None):
        """
        Initialize the LayoutManager with base dimensions and screen info.
        
        Args:
            root: The root tkinter window.
            base_width (int): Base design width in pixels. Default is 450.
            base_height (int): Base design height in pixels. Default is 750.
            width (int, optional): Override screen width. If None, auto-detected.
            height (int, optional): Override screen height. If None, auto-detected.
        """
        self.root = root
        self.base_width = base_width
        self.base_height = base_height
        
        # Get actual screen dimensions or use provided values
        if width and height:
            self.screen_width = width
            self.screen_height = height
        else:
            self.screen_width = self.root.winfo_screenwidth()
            self.screen_height = self.root.winfo_screenheight()
        
        # Calculate scale factors for each dimension
        self.scale_x = self.screen_width / self.base_width
        self.scale_y = self.screen_height / self.base_height
        
        # Use the smaller scale factor to ensure everything fits
        # This maintains aspect ratio and prevents UI overflow
        self.scale_factor = min(self.scale_x, self.scale_y)

    def scaled(self, value: int) -> int:
        """
        Convert a base pixel value to a scaled pixel value.
        
        Args:
            value (int): The base pixel value to scale.
            
        Returns:
            int: The scaled pixel value.
        """
        return int(value * self.scale_factor)
    
    def font(self, size: int, family: str = "Segoe UI") -> tuple:
        """
        Generate a scaled font tuple for tkinter widgets.
        
        Args:
            size (int): The base font size to scale.
            family (str): The font family name. Default is "Segoe UI".
            
        Returns:
            tuple: A (family, size) tuple suitable for tkinter font parameter.
        """
        return (family, self.scaled(size))