#!/usr/bin/env python3
"""
Serial Port RX/TX Test Script for Raspberry Pi
Port: /dev/ttyAMA0
Baud: 115200

Continuously sends data every 2 seconds and prints any received responses.
"""

import serial
import time
import sys

SERIAL_PORT = "/dev/ttyAMA0"
BAUDRATE = 115200

def continuous_send_receive():
    """Continuously send data every 2 seconds and print any received data"""
    print("=" * 50)
    print("Serial TX/RX Continuous Test")
    print(f"Port: {SERIAL_PORT} | Baud: {BAUDRATE}")
    print("Sending every 2 seconds - Press Ctrl+C to stop")
    print("=" * 50)
    
    # Test message to send (you can change this)
    test_message = b"PING\r\n"
    send_count = 0
    
    try:
        # Open serial port
        ser = serial.Serial(SERIAL_PORT, baudrate=BAUDRATE, timeout=0.5)
        print(f"✓ Port opened: {ser.name}\n")
        
        # Flush buffers
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        
        last_send_time = 0
        
        while True:
            current_time = time.time()
            
            # Send data every 2 seconds
            if current_time - last_send_time >= 2:
                send_count += 1
                bytes_sent = ser.write(test_message)
                print(f"[TX #{send_count}] Sent {bytes_sent} bytes: {test_message.hex()} | ASCII: {test_message.strip()}")
                last_send_time = current_time
            
            # Check for incoming data
            if ser.in_waiting > 0:
                received = ser.read(ser.in_waiting)
                print(f"[RX] Received {len(received)} bytes: {received.hex()} | ASCII: {received}")
            
            # Small delay to prevent CPU hogging
            time.sleep(0.05)
            
    except KeyboardInterrupt:
        print(f"\n\n{'=' * 50}")
        print(f"Stopped. Total messages sent: {send_count}")
        print("=" * 50)
        ser.close()
    except serial.SerialException as e:
        print(f"\n✗ Serial Error: {e}")
        print("\nTry: sudo python3 serial_test.py")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)


def continuous_send_hex(hex_data):
    """Continuously send specific hex data every 2 seconds"""
    print("=" * 50)
    print("Serial TX/RX - Custom Hex Data")
    print(f"Port: {SERIAL_PORT} | Baud: {BAUDRATE}")
    print("Sending every 2 seconds - Press Ctrl+C to stop")
    print("=" * 50)
    
    try:
        data_bytes = bytes.fromhex(hex_data)
    except ValueError:
        print(f"Invalid hex string: {hex_data}")
        sys.exit(1)
    
    send_count = 0
    
    try:
        ser = serial.Serial(SERIAL_PORT, baudrate=BAUDRATE, timeout=0.5)
        print(f"✓ Port opened: {ser.name}")
        print(f"✓ Data to send: {hex_data}\n")
        
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        
        last_send_time = 0
        
        while True:
            current_time = time.time()
            
            # Send every 2 seconds
            if current_time - last_send_time >= 2:
                send_count += 1
                ser.write(data_bytes)
                print(f"[TX #{send_count}] Sent {len(data_bytes)} bytes: {hex_data}")
                last_send_time = current_time
            
            # Check for response
            if ser.in_waiting > 0:
                received = ser.read(ser.in_waiting)
                print(f"[RX] Received {len(received)} bytes: {received.hex()}")
            
            time.sleep(0.05)
            
    except KeyboardInterrupt:
        print(f"\n\nStopped. Total sent: {send_count}")
        ser.close()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Send custom hex data
        continuous_send_hex(sys.argv[1])
    else:
        # Default: send "PING" every 2 seconds
        continuous_send_receive()
