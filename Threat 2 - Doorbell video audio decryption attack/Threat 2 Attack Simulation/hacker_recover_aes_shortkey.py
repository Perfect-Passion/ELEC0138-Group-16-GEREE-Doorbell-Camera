import os
import itertools
import string
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

CAPTURED_DATA_FILE = 'captured_weak_shortkey_traffic.bin' # input file
EXPECTED_KEY_LENGTH_SHORT = 6 # the length of the  digit key
FIXED_IV_USED = b'0000000000000000' # assume fixed IV is known

BYTES_TO_CHECK = 128

# expected structure after decryption
VIDEO_FLAG = b'\x01'
AUDIO_FLAG = b'\x02'
KNOWN_SIGNATURES = [ b'ftyp', b'RIFF' ] 

# AES Decryption Function
def aes_decrypt(encrypted_data, key, iv):
    """Decrypts data using AES CBC mode with unpadding."""
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)
        return decrypted_data
    except ValueError:
        return None
    except Exception as e:
        return None

# main process
start_time = time.time()
print(f"--- Hacker Simulation: Recovering Weak AES Short Key ---")
print(f"Target File: {CAPTURED_DATA_FILE}")
print(f"Assuming original key length: {EXPECTED_KEY_LENGTH_SHORT}, composed of digits only.")
print(f"Assuming fixed IV: {FIXED_IV_USED.decode()}")

first_block_iv = None
first_block_ciphertext = None

try:
    with open(CAPTURED_DATA_FILE, 'rb') as f_in:
        first_block_iv = f_in.read(AES.block_size)
        if len(first_block_iv) < AES.block_size: raise ValueError("File too short for IV")
        length_bytes = f_in.read(4)
        if len(length_bytes) < 4: raise ValueError("File too short for length")
        data_len = int.from_bytes(length_bytes, 'big')
        first_block_ciphertext = f_in.read(data_len)
        if len(first_block_ciphertext) < data_len: raise ValueError("Incomplete first block")
        print(f"Read first block: IV={first_block_iv.hex()}, Len={data_len}, Size={len(first_block_ciphertext)}")
        if first_block_iv != FIXED_IV_USED:
             print("Warning: IV read from file doesn't match expected fixed IV! Using read IV.")
except FileNotFoundError: exit(f"Error: File '{CAPTURED_DATA_FILE}' not found.")
except Exception as e: exit(f"Error reading first block: {e}")


print(f"Starting brute-force for {10**EXPECTED_KEY_LENGTH_SHORT} possible keys (000000 to 999999)...")

found_key_short = None # store the short version of the key
found_key_padded = None # store the padded version used for decryption
keys_checked = 0

# brute-force loop for keys
for i in range(10**EXPECTED_KEY_LENGTH_SHORT): # loop 0 to 999,999
    keys_checked += 1
    # format number as a 6-digit string
    key_short_str = str(i).zfill(EXPECTED_KEY_LENGTH_SHORT)
    key_short_bytes = key_short_str.encode('ascii')

    # pad the candidate key exactly like the encryption script did
    candidate_key_padded = key_short_bytes.ljust(16, b'\x00')

    # print progress every 50k checks
    if keys_checked % 50000 == 0:
        print(f"\rChecked {keys_checked} keys... Current: {key_short_str}", end="")

    # decrypt the first block
    decrypted_block = aes_decrypt(first_block_ciphertext, candidate_key_padded, FIXED_IV_USED)

    if decrypted_block:
        # check flag and signature
        type_flag = decrypted_block[0:1]
        if type_flag == VIDEO_FLAG or type_flag == AUDIO_FLAG:
            payload_header = decrypted_block[1:BYTES_TO_CHECK]
            for sig in KNOWN_SIGNATURES:
                if sig in payload_header:
                    found_key_short = key_short_bytes
                    found_key_padded = candidate_key_padded
                    goto_end_processing = True
                    break
            if 'goto_end_processing' in locals(): break

# print output
end_time = time.time()
print(f"\n--- Key Recovery Complete ---")
print(f"Total time: {end_time - start_time:.2f} seconds")

if found_key_padded:
    print(f"Recovered short key: {found_key_short.decode()}")
    print(f"Padded key for decryption: {found_key_padded.hex()}\n")
else:
    print("\nFailed to recover key.")