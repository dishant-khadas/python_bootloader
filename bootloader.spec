# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for CZAR Bootloader Application.
Run with: pyinstaller bootloader.spec
"""

import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect hidden imports for dynamically loaded modules
hidden_imports = [
    'ttkbootstrap',
    'PIL',
    'PIL._tkinter_finder',
    'Crypto',
    'Crypto.Cipher',
    'Crypto.Cipher.AES',
    'boto3',
    'botocore',
    'requests',
    'serial',
    'dotenv',
    # Pages package
    'pages',
    'pages.splash_screen',
    'pages.scan_page',
    'pages.wifi_list_page',
    'pages.wifi_password_page',
    'pages.manual_wifi_page',
    'pages.wifi_connecting_page',
    'pages.login_page',
    'pages.program_page',
    'pages.file_selection_page',
    'pages.download_page',
    'pages.firmware_update_page',
    'pages.error_page',
    # Utils package
    'utils',
    'utils.decrypt_utils',
    'utils.du_utils',
    'utils.wifi_utils',
    'utils.gpio_control',
    'utils.ui_utils',
    # API package
    'api',
    'api.auth_api',
    'api.du_api',
    # Core package
    'core',
    'core.bootloader_download',
    'core.du_reader',
    'core.logGenerator',
]

# Collect all submodules for packages that dynamically import
hidden_imports += collect_submodules('ttkbootstrap')
hidden_imports += collect_submodules('boto3')
hidden_imports += collect_submodules('botocore')

# Data files to include
datas = [
    ('assets/czar.png', '.'),    # Logo image
    ('.env', '.'),               # Environment config (if exists)
    ('btl_host.py', '.'),        # Firmware flashing script
]

# Add ttkbootstrap themes and assets
datas += collect_data_files('ttkbootstrap')

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='czar_bootloader',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # Set to True if you need to see console output for debugging
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='czar_bootloader',
)
