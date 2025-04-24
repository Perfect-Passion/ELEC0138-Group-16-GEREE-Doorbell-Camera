import os
import sys
import time
import math
from decimal import Decimal, getcontext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CAPTURED_DATA_FILE = 'captured_secure_gcm_traffic.bin'
DURATION_SECONDS = 30 # duration to run the brute-force attempt
AES_KEY_SIZE = 32 
GCM_NONCE_SIZE = 12 
GCM_TAG_SIZE = 16

# AES-GCM Decryption & Verification Function
def aes_gcm_decrypt_verify(nonce, ciphertext, tag, key):
    """Attempts to decrypt AES GCM data AND verify the tag."""
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError:
        return None
    except Exception:
        return None

# Main Brute-Force Estimation Logic
print(f"--- AES-256-GCM Brute-Force Feasibility Estimation ---")
print(f"Target File: {CAPTURED_DATA_FILE}")
print(f"Attempting decryption with random {AES_KEY_SIZE*8}-bit keys for {DURATION_SECONDS} seconds...")

nonce = None
tag = None
ciphertext = None
block_len = 0

# read the first block
try:
    with open(CAPTURED_DATA_FILE, 'rb') as f_in:
        length_bytes = f_in.read(4)
        if len(length_bytes) < 4: raise ValueError("File too short for length")
        block_len = int.from_bytes(length_bytes, 'big')

        nonce = f_in.read(GCM_NONCE_SIZE)
        if len(nonce) < GCM_NONCE_SIZE: raise ValueError("File too short for nonce")

        tag = f_in.read(GCM_TAG_SIZE)
        if len(tag) < GCM_TAG_SIZE: raise ValueError("File too short for tag")

        ciphertext_len = block_len - GCM_NONCE_SIZE - GCM_TAG_SIZE
        if ciphertext_len < 0: raise ValueError(f"Invalid block length {block_len}")
        ciphertext = f_in.read(ciphertext_len)
        if len(ciphertext) < ciphertext_len: raise ValueError("Incomplete first block ciphertext")

        print(f"Read first block (Nonce: {GCM_NONCE_SIZE}B, Tag: {GCM_TAG_SIZE}B, Ciphertext: {ciphertext_len}B)")

except FileNotFoundError:
    sys.exit(f"Error: File '{CAPTURED_DATA_FILE}' not found.")
except Exception as e:
    sys.exit(f"Error reading first block: {e}")

if not all([nonce, tag, ciphertext]):
     sys.exit("Error: Failed to load necessary data from the first block.")

# run brute-force attempt for 30 seconds
keys_checked = 0
start_time = time.time()
end_time = start_time + DURATION_SECONDS
a_key_worked = False

print(f"Starting attempt at {time.strftime('%Y-%m-%d %H:%M:%S')}. Press Ctrl+C to stop early.")

try:
    while time.time() < end_time:
        # generate a random AES-256 key
        candidate_key = get_random_bytes(AES_KEY_SIZE)
        keys_checked += 1

        # attempt decryption
        decrypted_data = aes_gcm_decrypt_verify(nonce, ciphertext, tag, candidate_key)

        if decrypted_data is not None:
            # unlikely to happen
            print("\n\n*** ASTONISHINGLY, a random key successfully decrypted the block! ***")
            print(f"Key (Hex): {candidate_key.hex()}")
            a_key_worked = True
            break # stop the test if a key works


except KeyboardInterrupt:
    print("\nBrute-force attempt stopped by user.")
    end_time = time.time() # record actual end time

actual_elapsed_time = time.time() - start_time
if actual_elapsed_time < 0.001: 
    actual_elapsed_time = 0.001

# calculate time needed
keys_per_second = keys_checked / actual_elapsed_time
total_keyspace = Decimal(2)**(AES_KEY_SIZE * 8) # 2^256

print("\n--- Estimation Results ---")
print(f"Attempt duration: {actual_elapsed_time:.2f} seconds")
print(f"Keys checked: {keys_checked:,}")

if keys_per_second > 0:
    estimated_total_seconds = total_keyspace / Decimal(keys_per_second)

    # convert seconds to years
    seconds_per_year = Decimal(365.25 * 24 * 60 * 60)
    estimated_years = estimated_total_seconds / seconds_per_year

    getcontext().prec = 80 

    print(f"Total keyspace (2^{AES_KEY_SIZE*8}): {total_keyspace:e}")
    print(f"Estimated time to check all keys:")
    print(f"  Seconds: {estimated_total_seconds:e}")
    print(f"  Years:   {estimated_years:e}") 
else:
    print("\nCould not calculate rate (0 keys checked or zero time elapsed).")
    print("Conclusion: Brute-forcing this AES key is computationally infeasible.")

if a_key_worked:
     print("\nWARNING: A random key appeared to work. This is statistically almost impossible and may indicate an issue.")