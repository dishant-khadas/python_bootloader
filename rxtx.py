
import serial
import time
import sys

def test_serial_loopback(port='/dev/serial0', baudrate=9600):
    print(f"--- Serial Loopback Test on {port} ---")
    print("Pre-requisite: Ensure TX (Pin 14) and RX (Pin 15) are connected (shorted).")
    
    try:
        # Initialize serial port
        ser = serial.Serial(
            port=port,
            baudrate=baudrate,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=1
        )
        
        if not ser.is_open:
            ser.open()
            
        print(f"Serial port {port} opened successfully.")
        
        # Clear buffers
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        
        # Test Data
        test_message = b"Hello Raspberry Pi Serial!"
        print(f"Sending: {test_message}")
        
        # Write data
        ser.write(test_message)
        
        # Wait a tiny bit for loopback
        time.sleep(0.1)
        
        # Read data
        received_message = ser.read(len(test_message))
        print(f"Received: {received_message}")
        
        # Verify
        if test_message == received_message:
            print("\nSUCCESS: Loopback test passed! RX received exactly what TX sent.")
            return True
        else:
            print("\nFAILURE: Received data does not match sent data.")
            print(f"Expected: {test_message}")
            print(f"Actual:   {received_message}")
            return False
            
    except serial.SerialException as e:
        print(f"\nERROR: Serial communication failed: {e}")
        print("Tip: Make sure serial interface is enabled in raspi-config and checking the correct port (default: /dev/serial0)")
        return False
    except KeyboardInterrupt:
        print("\nTest cancelled by user.")
        return False
    finally:
        if 'ser' in locals() and ser.is_open:
            ser.close()
            print("Serial port closed.")

if __name__ == "__main__":
    # Allow user to specify port via argument, e.g., python3 rxtx.py /dev/ttyS0
    target_port = '/dev/serial0'
    if len(sys.argv) > 1:
        target_port = sys.argv[1]
        
    test_serial_loopback(target_port)
