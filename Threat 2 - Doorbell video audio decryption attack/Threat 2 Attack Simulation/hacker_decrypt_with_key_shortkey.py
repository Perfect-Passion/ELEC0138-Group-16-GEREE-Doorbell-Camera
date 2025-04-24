import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys

RECOVERED_PADDED_KEY = b'123456\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # enter the recovered key

ENCRYPTED_INPUT_FILE = 'captured_weak_shortkey_traffic.bin'

# set output filenames, use None if the file is not available
DECRYPTED_VIDEO_FILE = 'reconstructed_video_shortkey.mp4'
DECRYPTED_AUDIO_FILE = 'reconstructed_audio_shortkey.wav'

# type flags
VIDEO_FLAG = b'\x01'
AUDIO_FLAG = b'\x02'

# AES Decryption Function
def aes_decrypt(encrypted_data, key, iv):
    """Decrypts data using AES CBC mode with unpadding."""
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)
        return decrypted_data
    except ValueError as e:
        return None
    except Exception as e:
        return None

# Main Decryption Process
print(f"--- Hacker Simulation: Decrypting with Recovered Short Key ---")
print(f"Using Recovered PADDED Key: {RECOVERED_PADDED_KEY.hex()}")
print(f"Input File: {ENCRYPTED_INPUT_FILE}")
print(f"Output Video File: {DECRYPTED_VIDEO_FILE if DECRYPTED_VIDEO_FILE else 'None'}")
print(f"Output Audio File: {DECRYPTED_AUDIO_FILE if DECRYPTED_AUDIO_FILE else 'None'}")

if not DECRYPTED_VIDEO_FILE and not DECRYPTED_AUDIO_FILE:
     sys.exit("Error: No output files specified.")


f_in = None
f_out_vid = None
f_out_aud = None
files_opened = []

try:
    # open input file
    f_in = open(ENCRYPTED_INPUT_FILE, 'rb')

    if DECRYPTED_VIDEO_FILE:
        try:
            f_out_vid = open(DECRYPTED_VIDEO_FILE, 'wb')
            files_opened.append(f_out_vid)
            print(f"Opened output video file: {DECRYPTED_VIDEO_FILE}")
        except IOError as e:
            print(f"Warning: Could not open output video file '{DECRYPTED_VIDEO_FILE}': {e}")
            f_out_vid = None

    if DECRYPTED_AUDIO_FILE:
         try:
            f_out_aud = open(DECRYPTED_AUDIO_FILE, 'wb')
            files_opened.append(f_out_aud)
            print(f"Opened output audio file: {DECRYPTED_AUDIO_FILE}")
         except IOError as e:
            print(f"Warning: Could not open output audio file '{DECRYPTED_AUDIO_FILE}': {e}")
            f_out_aud = None

    if not files_opened:
        sys.exit("Error: Failed to open any output files.")


    block_number = 0
    while True:
        block_number += 1
        # read IV, length and data 
        iv_read = f_in.read(AES.block_size)
        if not iv_read: break
        if len(iv_read) < AES.block_size: break

        length_bytes = f_in.read(4)
        if not length_bytes or len(length_bytes) < 4: break
        data_len = int.from_bytes(length_bytes, 'big')

        encrypted_data = f_in.read(data_len)
        if len(encrypted_data) < data_len: break

        # decrypt
        decrypted_data = aes_decrypt(encrypted_data, RECOVERED_PADDED_KEY, iv_read)

        if decrypted_data:
            type_flag = decrypted_data[0:1]
            payload = decrypted_data[1:]

            # write to output file
            if type_flag == VIDEO_FLAG and f_out_vid:
                f_out_vid.write(payload)
            elif type_flag == AUDIO_FLAG and f_out_aud:
                f_out_aud.write(payload)
            elif type_flag == VIDEO_FLAG and not f_out_vid:
                 pass
            elif type_flag == AUDIO_FLAG and not f_out_aud:
                 pass
            else:
                 pass
        else:
            # decryption failed for this block
            print(f"\nWarning: Failed to decrypt block {block_number}. Skipping.")
            break


    print(f"\nDecryption attempt complete.")

except FileNotFoundError:
    print(f"\nError: Ensure input file '{ENCRYPTED_INPUT_FILE}' exists.")
except ImportError:
     print("\nError: PyCryptodome library not found (`pip install pycryptodome`).")
except Exception as e:
    print(f"\nAn error occurred during decryption: {e}")
finally:
    # ensure all opened files are closed
    if f_in: f_in.close()
    if f_out_vid: f_out_vid.close()
    if f_out_aud: f_out_aud.close()