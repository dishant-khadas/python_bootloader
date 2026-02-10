# CZAR Bootloader - Error Codes Reference

## Success Codes

| Code | Name | Description |
|------|------|-------------|
| S-01 | Firmware Update Success | Firmware updated successfully |

## Error Codes

### Authentication Errors (E-5x)

| Code | Name | Description |
|------|------|-------------|
| E-51 | Login Failed | Invalid credentials during login |

### Download Errors (E-2x)

| Code | Name | Description |
|------|------|-------------|
| E-21 | File Download Failed | Failed to download firmware file from server |
| E-23 | Encrypted File Hash Mismatch | Downloaded file hash doesn't match expected encrypted hash |
| E-24 | Original File Hash Mismatch | Decrypted file hash doesn't match expected original hash |

### Handshake/Communication Errors (E-3x, E-4x)

| Code | Name | Description |
|------|------|-------------|
| E-31 | No Data Received | No data received during serial handshake |
| E-42 | Invalid Data Received | CRC mismatch, SOP/EOP mismatch, or decrypt failure |

### Validation Errors (E-5x)

| Code | Name | Description |
|------|------|-------------|
| E-58 | Invalid DU/Display Number | DU number must start with 99, Display with 12, both 8 digits |

### Firmware Update Errors (E-1x)

| Code | Name | Description |
|------|------|-------------|
| E-15 | Firmware Update Failed | btl_host.py failed during firmware flashing |

## Error Code Ranges

| Range | Category |
|-------|----------|
| S-xx | Success codes |
| E-1x | Firmware update errors |
| E-2x | Download/file errors |
| E-3x | Handshake/connection errors |
| E-4x | Data validation errors |
| E-5x | Authentication/validation errors |
