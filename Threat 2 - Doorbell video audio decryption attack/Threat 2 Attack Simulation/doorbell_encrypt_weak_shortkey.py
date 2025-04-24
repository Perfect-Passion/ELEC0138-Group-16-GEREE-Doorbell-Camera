import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import sys 

# set input files to None if not used
INPUT_VIDEO_FILE = 'sample_video.mp4'
INPUT_AUDIO_FILE = 'sample_audio.wav'

ENCRYPTED_OUTPUT_FILE = 'captured_weak_shortkey_traffic.bin'
CHUNK_SIZE = 4096

# set a weak key with 6 digit
SHORT_DIGIT_KEY = '123456'
WEAK_PADDED_KEY = SHORT_DIGIT_KEY.encode('ascii').ljust(16, b'\x00')
FIXED_AES_IV = b'0000000000000000'

# type flags
VIDEO_FLAG = b'\x01'
AUDIO_FLAG = b'\x02'

# AES Encryption Function
def aes_encrypt(data, key, iv):
    """Encrypts data using AES CBC mode with padding."""
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data
    except Exception as e:
        print(f"\nError during AES encryption: {e}")
        return None

# Main Encryption Process
print(f"--- Doorbell Simulation: AES Encryption ---")
print(f"Video Input: {INPUT_VIDEO_FILE if INPUT_VIDEO_FILE else 'None'}")
print(f"Audio Input: {INPUT_AUDIO_FILE if INPUT_AUDIO_FILE else 'None'}")
if not INPUT_VIDEO_FILE and not INPUT_AUDIO_FILE:
    sys.exit("Error: No input files specified (both VIDEO and AUDIO are None).")

print(f"Using SHORT digit key (unpadded): '{SHORT_DIGIT_KEY}'")
print(f"Padded to 16 bytes for AES: {WEAK_PADDED_KEY.hex()}")
print(f"Using FIXED IV: {FIXED_AES_IV.decode()}")
print(f"Output File: {ENCRYPTED_OUTPUT_FILE}")


f_in_vid = None
f_in_aud = None
f_out = None

try:
    # open output file first
    f_out = open(ENCRYPTED_OUTPUT_FILE, 'wb')

    # try opening input files
    if INPUT_VIDEO_FILE:
        try:
            f_in_vid = open(INPUT_VIDEO_FILE, 'rb')
            print(f"Opened video file: {INPUT_VIDEO_FILE}")
        except FileNotFoundError:
            print(f"Warning: Video file '{INPUT_VIDEO_FILE}' not found. Skipping video.")
            INPUT_VIDEO_FILE = None

    if INPUT_AUDIO_FILE:
        try:
            f_in_aud = open(INPUT_AUDIO_FILE, 'rb')
            print(f"Opened audio file: {INPUT_AUDIO_FILE}")
        except FileNotFoundError:
            print(f"Warning: Audio file '{INPUT_AUDIO_FILE}' not found. Skipping audio.")
            INPUT_AUDIO_FILE = None

    # check again if any input is available after trying to open
    if not f_in_vid and not f_in_aud:
         sys.exit("Error: Neither specified input file could be opened.")

    chunk_number = 0
    # continue processing as long as at least one input file has data
    while True:
        vid_chunk = f_in_vid.read(CHUNK_SIZE) if f_in_vid else b''
        aud_chunk = f_in_aud.read(CHUNK_SIZE) if f_in_aud else b''

        # exit loop only if both streams are exhausted
        if not vid_chunk and not aud_chunk:
             # check if files were opened before declaring end
             vid_done = (f_in_vid is None) or f_in_vid.tell() == os.fstat(f_in_vid.fileno()).st_size
             aud_done = (f_in_aud is None) or f_in_aud.tell() == os.fstat(f_in_aud.fileno()).st_size
             if vid_done and aud_done:
                 print("\nEnd of all available input files.")
                 break
             else:
                 pass


        chunk_number += 1

        # process video chunk
        if vid_chunk:
            data_to_encrypt = VIDEO_FLAG + vid_chunk
            encrypted_data = aes_encrypt(data_to_encrypt, WEAK_PADDED_KEY, FIXED_AES_IV)
            if encrypted_data:
                f_out.write(FIXED_AES_IV)
                f_out.write(len(encrypted_data).to_bytes(4, 'big'))
                f_out.write(encrypted_data)

        # process audio chunk
        if aud_chunk:
            data_to_encrypt = AUDIO_FLAG + aud_chunk
            encrypted_data = aes_encrypt(data_to_encrypt, WEAK_PADDED_KEY, FIXED_AES_IV)
            if encrypted_data:
                f_out.write(FIXED_AES_IV)
                f_out.write(len(encrypted_data).to_bytes(4, 'big'))
                f_out.write(encrypted_data)

    print(f"\nWeak encryption complete. Output: {ENCRYPTED_OUTPUT_FILE}")

except Exception as e:
    print(f"\nAn error occurred: {e}")
finally:
    # ensure files are closed
    if f_out: f_out.close()
    if f_in_vid: f_in_vid.close()
    if f_in_aud: f_in_aud.close()