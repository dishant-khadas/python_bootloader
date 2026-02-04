"""
Firmware Update Page for Python Bootloader Application.

Runs btl_host.py to flash firmware to the display hardware and
shows real-time progress updates.
"""

import os
import subprocess
import threading
import time
import ttkbootstrap as ttk
from ttkbootstrap.constants import INFO

from config import config
from gpio_control import safe_cleanup, turn_display_Off
from logGenerator import write_log


class FirmwareUpdatePage(ttk.Frame):
    """
    Firmware flashing page.
    
    Executes btl_host.py with the decrypted firmware file and
    displays progress updates in real-time.
    
    Attributes:
        controller: Reference to the main App controller.
        output_path (str): Path to decrypted firmware file.
        encryption_key_hex (str): Hex string of encryption key.
        is_enc_flag (str): "1" if encrypted, "0" otherwise.
    """
    
    def __init__(self, parent, controller):
        """
        Initialize the firmware update page.
        
        Args:
            parent: Parent tkinter widget.
            controller: Main App controller for navigation.
        """
        super().__init__(parent)
        self.controller = controller
        lm = controller.lm
        
        # Parameters for btl_host.py
        self.output_path = None
        self.encryption_key_hex = ""
        self.is_enc_flag = "0"
        self.process = None
        
        # UI
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(container, text="Updating Firmware", font=lm.font(24)).pack(pady=lm.scaled(30))
        
        self.progress = ttk.Progressbar(
            container, mode='indeterminate', bootstyle=INFO,
            length=lm.scaled(300)
        )
        self.progress.pack(pady=lm.scaled(20))
        
        self.status_label = ttk.Label(
            container, text="Please wait...", font=lm.font(20),
            foreground="black", wraplength=lm.scaled(400), justify="center"
        )
        self.status_label.pack(pady=lm.scaled(20))
    
    def set_params(self, output_path: str, encryption_key_hex: str, is_enc_flag: str):
        """Set parameters for btl_host.py before showing this page."""
        self.output_path = output_path
        self.encryption_key_hex = encryption_key_hex
        self.is_enc_flag = is_enc_flag
    
    def on_show(self):
        """Called when the page is shown - starts firmware update."""
        self.progress.start(10)
        threading.Thread(target=self.run_btl_host, daemon=True).start()
    
    def run_btl_host(self):
        """Run btl_host.py with the specified arguments."""
        from pages.login_page import LoginPage
        
        try:
            # Get path to btl_host.py
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            default_btl_path = os.path.join(script_dir, "btl_host.py")
            btl_host_path = os.getenv("BTL_HOST_PATH", default_btl_path)
            python_path = os.getenv("PYTHON_PATH", "python3")
            serial_port = os.getenv("SERIAL_PORT", "/dev/ttyAMA0")
            
            # Build command
            cmd = [
                python_path,
                btl_host_path,
                "-v",
                "-i", serial_port,
                "-d", "pic32mz",
                "-a", "0x9D000000",
                self.encryption_key_hex,
                self.is_enc_flag,
                "-f", self.output_path
            ]
            
            print(f"[FIRMWARE UPDATE] Running command: {' '.join(cmd)}")
            
            # Run process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Read stdout in real-time
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    output_text = line.strip()
                    print(f"[BTL_HOST STDOUT]: {output_text}")
                    
                    # Format percentage display
                    try:
                        float(output_text)
                        display_text = f"{output_text}%"
                    except ValueError:
                        display_text = output_text
                    
                    self.controller.after(0, lambda t=display_text: self.status_label.config(text=t))
            
            # Wait for completion
            self.process.wait()
            return_code = self.process.returncode
            
            print(f"[FIRMWARE UPDATE] Process exited with code {return_code}")
            
            # Wait then turn off display
            time.sleep(3)
            try:
                turn_display_Off()
            except Exception as e:
                print(f"Warning: turn_display_Off failed: {e}")
            
            # Update UI based on result
            if return_code == 0:
                self.controller.after(0, self.on_update_success)
            else:
                stderr_output = self.process.stderr.read()
                print(f"[BTL_HOST STDERR]: {stderr_output}")
                self.controller.after(0, lambda: self.on_update_error(
                    f"btl_host.py failed with code {return_code}"
                ))
                
        except FileNotFoundError:
            error_msg = f"btl_host.py not found at {btl_host_path}"
            print(f"[FIRMWARE UPDATE ERROR]: {error_msg}")
            self.controller.after(0, lambda: self.on_update_error(error_msg))
        except Exception as e:
            error_msg = f"Firmware update error: {e}"
            print(f"[FIRMWARE UPDATE ERROR]: {error_msg}")
            self.controller.after(0, lambda: self.on_update_error(error_msg))
    
    def on_update_success(self):
        """Called when firmware update completes successfully."""
        from pages.login_page import LoginPage
        
        self.progress.stop()
        self.status_label.config(text="Firmware updated successfully!", foreground="green")
        self.controller.after(3000, lambda: self.controller.show_frame(LoginPage))
    
    def on_update_error(self, error_msg):
        """Called when firmware update fails."""
        from pages.login_page import LoginPage
        
        self.progress.stop()
        self.status_label.config(text="Update failed", foreground="red")
        
        # Log error
        write_log(
            errorCode="E-15",
            errorName="Firmware Update Failed",
            result="Failed",
            description=error_msg,
            device_id=config.DEVICE_ID,
            phoneNo=getattr(self.controller, "phone", ""),
            duNumber=getattr(self.controller, "du_options", {}).get("duNumber", ""),
            displayNumber=getattr(self.controller, "du_options", {}).get("displayNumber", ""),
            fileName=os.path.basename(self.output_path) if self.output_path else "",
        )
        
        safe_cleanup()
        self.controller.show_error("Firmware Update Failed", error_msg, return_frame=LoginPage)
