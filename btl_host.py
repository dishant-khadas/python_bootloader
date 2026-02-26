"""*****************************************************************************
* Copyright (C) 2019 Microchip Technology Inc. and its subsidiaries.
*
* Subject to your compliance with these terms, you may use Microchip software
* and any derivatives exclusively with Microchip products. It is your
* responsibility to comply with third party license terms applicable to your
* use of third party software (including open source software) that may
* accompany Microchip software.
*
* THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
* EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
* WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
* PARTICULAR PURPOSE.
*
* IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
* INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
* WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
* BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
* FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN
* ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
* THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
*****************************************************************************"""

import os
import sys
import time
import serial
import optparse
from Crypto.Cipher import AES

#------------------------------------------------------------------------------
BL_CMD_UNLOCK       = 0xa0
BL_CMD_DATA         = 0xa1
BL_CMD_VERIFY       = 0xa2
BL_CMD_RESET        = 0xa3
BL_CMD_BKSWAP_RESET = 0xa4

BL_RESP_OK          = 0x50
BL_RESP_ERROR       = 0x51
BL_RESP_INVALID     = 0x52
BL_RESP_CRC_OK      = 0x53
BL_RESP_CRC_FAIL    = 0x54

BL_GUARD            = 0x5048434D

# Should be equal to Device Erase size
ERASE_SIZE        = 256

BOOTLOADER_SIZE     = 2048

# Supported Devices [ERASE_SIZE, BOOTLOADER_SIZE]
devices = {
            "SAME7X"    : [8192, 8192],
            "SAME5X"    : [8192, 8192],
            "SAMD5X"    : [8192, 8192],
            "SAMG5X"    : [8192, 8192],
            "SAMC2X"    : [256, 2048],
            "SAMD1X"    : [256, 2048],
            "SAMD2X"    : [256, 2048],
            "SAMDA1"    : [256, 2048],
            "SAML1X"    : [256, 2048],
            "SAML2X"    : [256, 2048],
            "SAMHA1"    : [256, 2048],
            "PIC32MK"   : [4096, 8192],
            "PIC32MZ"   : [16384, 16384],
            "PIC32MZW"  : [4096, 8192],
            "PIC32MX"   : [1024, 4096],
            "PIC32CM"   : [256, 2048],
}

#fixed initialization vector 
ivkey = bytes([
    0x2E, 0xF4, 0x51, 0xF1, 0xDE, 0x8A, 0x2F, 0xDE,
    0x02, 0xA9, 0xFC, 0x34, 0x72, 0x8D, 0x2A, 0x66
])


#------------------------------------------------------------------------------
def error(text):
    sys.stderr.write('\nError: %s\n' % text)
    sys.exit(-1)

#------------------------------------------------------------------------------
def warning(text):
    sys.stderr.write('\nWarning: %s\n' % text)

#------------------------------------------------------------------------------
def verbose(verb, text):
    if verb:
        print("\n" + text,flush=True)

#------------------------------------------------------------------------------
def crc32_tab_gen():
    res = []

    for i in range(256):
        value = i

        for j in range(8):
            if value & 1:
                value = (value >> 1) ^ 0xedb88320
            else:
                value = value >> 1

        res += [value]

    return res

#------------------------------------------------------------------------------
def crc32(tab, data):
    crc = 0xffffffff

    for d in data:
        crc = tab[(crc ^ d) & 0xff] ^ (crc >> 8)

    return crc

#------------------------------------------------------------------------------
def uint32(v):
    return [(v >> 0) & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff]

#------------------------------------------------------------------------------
def get_response(port):
    v = port.read()

    if len(v) == 0:
        return None
    elif len(v) > 1:
        error('invalid response received (size > 1)')

    return (v[0])

#------------------------------------------------------------------------------
def send_request(port, cmd, size, data):
    req = uint32(BL_GUARD) + size + [cmd] + data

    port.write(bytes(bytearray(req)))

    for i in range(3):
        resp = get_response(port)

        if (resp is None):
            warning('no response received, retrying %d' % (i+1))
            time.sleep(0.2)
        else:
            return resp

    error('no response received, giving up')

# Print iterations progress
def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '|'):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)

    print ('\r%s |%s| %s%% %s \r' % (prefix, bar, percent, suffix), end =""),

    if iteration == total: 
        print()

#------------------------------------------------------------------------------
def run_btl_host(port_name, file_path, device_name, address_hex,
                 encryption_key_hex=None, encryption_enabled='0',
                 baud=115200, is_verbose=False, tune=False,
                 sector_size=None, boot=False, swap=False,
                 progress_callback=None):
    """
    Run the firmware update logic directly (callable from the GUI).
    
    This is the same logic as main() but accepts parameters directly
    instead of reading from sys.argv, making it safe to import and call
    from within the PyInstaller bundle.
    
    Args:
        port_name: Serial port path (e.g. /dev/ttyAMA0)
        file_path: Path to binary firmware file
        device_name: Target device (e.g. 'pic32mz')
        address_hex: Destination address (e.g. '0x9D000000')
        encryption_key_hex: Hex string of AES key (or None)
        encryption_enabled: '1' to enable encryption, '0' to disable
        baud: UART baudrate (default 115200)
        is_verbose: Enable verbose output
        tune: Auto-tune UART baudrate
        sector_size: Device sector size (required for PIC32MX)
        boot: Enable write to bootloader area
        swap: Swap banks after programming
        progress_callback: Optional function(percent) for GUI progress updates
    
    Returns:
        True on success
    
    Raises:
        Exception on failure
    """
    device = device_name.upper()

    if (device in devices):
        if (device == "PIC32MX"):
            if sector_size is None:
                raise Exception('device sector size is required for PIC32MX')
            erase_size = int(sector_size)
        else:
            erase_size = devices[device][0]
        boot_size = devices[device][1]
    else:
        raise Exception('invalid device')

    if (swap == True):
        if ((device != "SAME5X") and (device != "SAMD5X") and (device != "PIC32MZ") and (device != "PIC32MK")):
            raise Exception('Bank Swapping not supported on this device')

    try:
        address = int(address_hex, 0)
    except ValueError as inst:
        raise Exception('invalid address value: %s' % address_hex)

    if (("SAM" in device) or ("PIC32C" in device)):
        if address < boot_size and boot == False:
            raise Exception('address is within the bootlaoder area, use --boot options to unlock writes')
    else:
        if boot == True:
            raise Exception('--boot option is not supported on this device')

    try:
        port = serial.Serial(port_name, baud, timeout=1)
    except serial.serialutil.SerialException as inst:
        raise Exception(str(inst))

    if tune:
        verbose(is_verbose, 'Auto-tuning UART baudrate')
        port.send_break(duration=0.01)
        port.write(chr(0x55))

    try:
        data = data = [(x) for x in open(file_path, 'rb').read()]
    except Exception as inst:
        port.close()
        raise Exception(str(inst))

    while len(data) % erase_size > 0:
        data += [0xff]

    crc32_tab = crc32_tab_gen()
    crc = crc32(crc32_tab, data)

    size = len(data)

    resp = send_request(port, BL_CMD_UNLOCK, uint32(8), uint32(address) + uint32(size))

    if resp != BL_RESP_OK:
        port.close()
        raise Exception('Unlocking invalid response code (0x%02x). Check that your file size and address are correct.' % resp)

    # Create data blocks of ERASE_SIZE each
    blocks = [data[i:i + erase_size] for i in range(0, len(data), erase_size)]

    # Pre-encrypt all blocks before serial transfer
    if encryption_enabled == '1' and encryption_key_hex:
        key = bytes.fromhex(encryption_key_hex)
        encrypted_blocks = []
        for blk in blocks:
            cipher = AES.new(key, AES.MODE_CBC, ivkey)
            encrypted_blocks.append(list(cipher.encrypt(bytes(blk))))
        blocks = encrypted_blocks

    addr = address

    for idx, blk in enumerate(blocks):
        percent = int((((idx+1)/len(blocks))*100))

        # Report progress via callback (GUI) or print (CLI)
        if progress_callback:
            progress_callback(percent)
        else:
            print(percent, flush=True)

        resp = send_request(port, BL_CMD_DATA, uint32(erase_size + 4), uint32(addr) + blk)
        addr += erase_size

        if resp != BL_RESP_OK:
            port.close()
            raise Exception('Programming invalid response code (0x%02x)' % resp)

    # Send Verification command
    resp = send_request(port, BL_CMD_VERIFY, uint32(4), uint32(crc))
    print("response after programming : ",resp)

    if resp == BL_RESP_CRC_OK:
        verbose(is_verbose, '... success')
    else:
        port.close()
        raise Exception('Verification ... fail (status = 0x%02x)' % resp)

    # Send Reboot Command
    if (swap == True):
        verbose(is_verbose, 'Swapping Bank And Rebooting')
        resp = send_request(port, BL_CMD_BKSWAP_RESET, uint32(16), uint32(0) * 4)
    else:
        verbose(is_verbose, 'Rebooting')
        resp = send_request(port, BL_CMD_RESET, uint32(16), uint32(0) * 4)

    if resp == BL_RESP_OK:
        verbose(is_verbose, 'Reboot Done')
    else:
        port.close()
        raise Exception('... Reset fail (status = 0x%02x)' % resp)

    port.close()
    return True

#------------------------------------------------------------------------------
def main():
    parser = optparse.OptionParser(usage = 'usage: %prog [options]')
    parser.add_option('-v', '--verbose', dest='verbose', help='enable verbose output', default=False, action='store_true')
    parser.add_option('-r', '--baud', dest='baud', help='UART baudrate', default=115200, metavar='BAUD')
    parser.add_option('-t', '--tune', dest='tune', help='auto-tune UART baudrate', default=False, action='store_true')
    parser.add_option('-i', '--interface', dest='port', help='communication interface', metavar='PATH')
    parser.add_option('-f', '--file', dest='file', help='binary file to program', metavar='FILE')
    parser.add_option('-a', '--address', dest='address', help='destination address', metavar='ADDR')
    parser.add_option('-p', '--sectorSize', dest='sectSize', help='Device Sector Size in Bytes', metavar='SectSize')
    parser.add_option('-b', '--boot', dest='boot', help='enable write to the bootloader area', default=False, action='store_true')
    parser.add_option('-s', '--swap', dest='swap', help='swap banks after programming', default=False, action='store_true')
    parser.add_option('-d', '--device', dest='device', help='target device (samc2x/samd1x/samd2x/samd5x/samda1/same7x/same5x/samg5x/saml2x/samha1/pic32mk/pic32mx/pic32mz/pic32mzw/pic32cm)', metavar='DEV')

    (options, args) = parser.parse_args()

    if options.port is None:
        error('communication port is required (try -h option)')

    if options.file is None:
        error('file name is required (use -f option)')

    if options.device is None:
        error('target device is required (use -d option)')

    if options.address is None:
        error('destination address is required (use -a option)')

    # Read encryption key and flag from positional args (legacy CLI usage)
    encryption_key_hex = sys.argv[8] if len(sys.argv) > 8 else None
    encryption_enabled = sys.argv[9] if len(sys.argv) > 9 else '0'

    try:
        run_btl_host(
            port_name=options.port,
            file_path=options.file,
            device_name=options.device,
            address_hex=options.address,
            encryption_key_hex=encryption_key_hex,
            encryption_enabled=encryption_enabled,
            baud=int(options.baud),
            is_verbose=options.verbose,
            tune=options.tune,
            sector_size=options.sectSize,
            boot=options.boot,
            swap=options.swap,
        )
    except Exception as e:
        error(str(e))

#------------------------------------------------------------------------------

if __name__ == "__main__":
    main()
