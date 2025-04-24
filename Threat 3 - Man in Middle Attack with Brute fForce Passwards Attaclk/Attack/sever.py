from flask import Flask, render_template, request, jsonify
import bcrypt
import logging
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Initialize Flask app; templates directory for front-end pages
app = Flask(__name__, template_folder="templates", static_folder="templates", static_url_path="")

# Configure logging to console and app.log file
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app.log", encoding="utf-8")
    ]
)

# In-memory user storage
users = []

# AES key and IV matching front-end configuration
KEY_BYTES = b'1234567890123456'
IV_BYTES  = b'6543210987654321'

def decrypt_field(enc_b64: str) -> str:
    """AES-CBC decryption with PKCS7 padding removal"""
    cipher_bytes = b64decode(enc_b64)
    cipher = Cipher(algorithms.AES(KEY_BYTES), modes.CBC(IV_BYTES))
    decryptor = cipher.decryptor()
    padded = decryptor.update(cipher_bytes) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    return data.decode('utf-8')

@app.route('/', methods=['GET'])
def index():
    # Return the front-end page
    return render_template("index.html")

@app.route('/register', methods=['POST'])
def register():
    data = request.json or {}
    # Decrypt fields sent from front end
    try:
        username = decrypt_field(data['username'])
        email    = decrypt_field(data['email'])
        phone    = decrypt_field(data.get('phone', ''))
        password = decrypt_field(data['password'])
    except Exception as e:
        logging.error("Decryption failed: %s", e)
        return jsonify({"message": "Decryption failed"}), 400

    # Validate required fields
    if not username or not email or not password:
        return jsonify({"message": "Missing required registration information"}), 400

    # Check if user already exists (unique by email)
    if any(u["email"] == email for u in users):
        logging.warning("Registration failed - user already exists: %s", email)
        return jsonify({"message": "User already registered"}), 409

    # Hash password with bcrypt
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Store username, email, phone number, and hashed password
    users.append({
        "username": username,
        "email":    email,
        "phone":    phone,
        "password": hashed
    })

    # Log all decrypted fields
    logging.info(
        "New user registered successfully - Username: %s, Email: %s, Phone: %s, Password: %s",
        username, email, phone, password
    )
    return jsonify({"message": "Registration successful"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    # Decrypt login fields
    try:
        login_input = decrypt_field(data['email'])
        password    = decrypt_field(data['password'])
    except Exception as e:
        logging.error("Decryption failed: %s", e)
        return jsonify({"message": "Decryption failed"}), 400

    # Validate required fields
    if not login_input or not password:
        return jsonify({"message": "Missing required login information"}), 400

    # Find user by username, email, or phone number
    user = next((u for u in users if login_input in (u["username"], u["email"], u["phone"])), None)
    if not user:
        logging.warning("Login failed - user not found: %s", login_input)
        return jsonify({"message": "User does not exist or wrong password"}), 401

    # Verify password
    if bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        # Log successful login and decrypted fields
        logging.info(
            "User login successful - Identifier: %s, Password: %s",
            login_input, password
        )
        return jsonify({"message": "Login successful"}), 200
    else:
        logging.warning("Login failed - incorrect password: %s", login_input)
        return jsonify({"message": "User does not exist or wrong password"}), 401

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
