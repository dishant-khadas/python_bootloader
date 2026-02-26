import os
import sys

def get_app_data_dir():
    """
    Get a persistent, user-writable directory for the application.
    Following Linux conventions, this uses ~/.czar-bootloader/
    """
    home = os.path.expanduser("~")
    app_dir = os.path.join(home, ".czar-bootloader")
    
    # Ensure the directory exists
    if not os.path.exists(app_dir):
        try:
            os.makedirs(app_dir, exist_ok=True)
        except Exception:
            # Fallback to current directory for edge cases,
            # though this will fail in /opt as well.
            return os.path.dirname(os.path.abspath(__file__))
            
    return app_dir

def get_log_path(filename="logs.csv"):
    """Get the full path to a log file in the app data directory."""
    return os.path.join(get_app_data_dir(), filename)
