import os
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes # for strong key and nonces

# set input files to None if not used
INPUT_VIDEO_FILE = 'sample_video.mp4'
INPUT_AUDIO_FILE = 'sample_audio.wav'

ENCRYPTED_OUTPUT_FILE = 'captured_secure_gcm_traffic.bin'

CHUNK_SIZE = 4096
AES_KEY_SIZE = 32 # bytes (256 bits)
GCM_NONCE_SIZE = 12 # bytes (96 bits is recommended for GCM)
GCM_TAG_SIZE = 16 # bytes (128 bits is standard for GCM tag)

# in a real system, this key would be securely provisioned per device
# for simulation, we generate it randomly
STRONG_AES_KEY = get_random_bytes(AES_KEY_SIZE)
print("-" * 60)
print(f"Generated Random {AES_KEY_SIZE*8}-bit AES Key (Hex): {STRONG_AES_KEY.hex()}")
print("-" * 60)

# type flags
VIDEO_FLAG = b'\x01'
AUDIO_FLAG = b'\x02'

# AES-GCM Encryption Function
def aes_gcm_encrypt(data, key):
    """Encrypts data using AES GCM mode, returning nonce, ciphertext, tag."""
    try:
        # generate a unique random nonce for each encryption
        nonce = get_random_bytes(GCM_NONCE_SIZE)
        # create cipher object
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        # encrypt and generate the tag
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce, ciphertext, tag
    except Exception as e:
        print(f"\nError during AES-GCM encryption: {e}")
        return None, None, None

# Main Encryption Process
print(f"Video Input: {INPUT_VIDEO_FILE if INPUT_VIDEO_FILE else 'None'}")
print(f"Audio Input: {INPUT_AUDIO_FILE if INPUT_AUDIO_FILE else 'None'}")
if not INPUT_VIDEO_FILE and not INPUT_AUDIO_FILE:
    sys.exit("Error: No input files specified.")
print(f"Output File: {ENCRYPTED_OUTPUT_FILE}")

f_in_vid = None
f_in_aud = None
f_out = None

try:
    # open output file
    f_out = open(ENCRYPTED_OUTPUT_FILE, 'wb')

    if INPUT_VIDEO_FILE:
        try: f_in_vid = open(INPUT_VIDEO_FILE, 'rb'); print(f"Opened video: {INPUT_VIDEO_FILE}")
        except FileNotFoundError: print(f"Warning: Video file '{INPUT_VIDEO_FILE}' not found."); INPUT_VIDEO_FILE = None
    if INPUT_AUDIO_FILE:
        try: f_in_aud = open(INPUT_AUDIO_FILE, 'rb'); print(f"Opened audio: {INPUT_AUDIO_FILE}")
        except FileNotFoundError: print(f"Warning: Audio file '{INPUT_AUDIO_FILE}' not found."); INPUT_AUDIO_FILE = None
    if not f_in_vid and not f_in_aud: sys.exit("Error: Neither input file could be opened.")

    chunk_number = 0
    while True:
        vid_chunk = f_in_vid.read(CHUNK_SIZE) if f_in_vid else b''
        aud_chunk = f_in_aud.read(CHUNK_SIZE) if f_in_aud else b''

        if not vid_chunk and not aud_chunk:
             vid_done = (f_in_vid is None) or f_in_vid.tell() == os.fstat(f_in_vid.fileno()).st_size
             aud_done = (f_in_aud is None) or f_in_aud.tell() == os.fstat(f_in_aud.fileno()).st_size
             if vid_done and aud_done: print("\nEnd of all available input files."); break
             else: pass

        chunk_number += 1

        # process video chunk
        if vid_chunk:
            data_to_encrypt = VIDEO_FLAG + vid_chunk
            nonce, ciphertext, tag = aes_gcm_encrypt(data_to_encrypt, STRONG_AES_KEY)
            if ciphertext is not None:
                # write Length (Nonce + Tag + Ciphertext) + Nonce + Tag + Ciphertext
                block_len = len(nonce) + len(tag) + len(ciphertext)
                f_out.write(block_len.to_bytes(4, 'big'))
                f_out.write(nonce)
                f_out.write(tag)
                f_out.write(ciphertext)

        # process audio chunk
        if aud_chunk:
            data_to_encrypt = AUDIO_FLAG + aud_chunk
            nonce, ciphertext, tag = aes_gcm_encrypt(data_to_encrypt, STRONG_AES_KEY)
            if ciphertext is not None:
                # write Length (Nonce + Tag + Ciphertext) + Nonce + Tag + Ciphertext
                block_len = len(nonce) + len(tag) + len(ciphertext)
                f_out.write(block_len.to_bytes(4, 'big'))
                f_out.write(nonce)
                f_out.write(tag)
                f_out.write(ciphertext)

    print(f"\nSecure AES-GCM encryption complete. Output: {ENCRYPTED_OUTPUT_FILE}")

except ImportError:
    print("\nError: PyCryptodome library not found (`pip install pycryptodome`).")
except Exception as e:
    print(f"\nAn error occurred: {e}")
finally:
    if f_out: f_out.close()
    if f_in_vid: f_in_vid.close()
    if f_in_aud: f_in_aud.close()