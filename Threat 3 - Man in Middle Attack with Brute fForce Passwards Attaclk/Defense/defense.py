# defense.py
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import bcrypt
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from base64 import b64decode
import random
import time
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

# RSA key generation
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Export public key PEM to send to front-end
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

app = Flask(__name__, template_folder="templates", static_folder="static", static_url_path="/static")
CORS(app)

# Logging setup: record to app.log
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app.log", encoding="utf-8")
    ]
)

# In-memory storage for registered users and OTP codes
users = []  # stores encrypted user data
codes = {}  # stores temporary OTP codes

def send_email(to_addr, code):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "ouyangwenjie888@gmail.com"
    sender_password = "wrla dmbl aylb fbjc"

    subject = "Your verification code"
    body = f"Your code is {code}, valid for 60 seconds."

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_addr

    try:
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, [to_addr], msg.as_string())
        server.quit()
        logging.info("Email sent successfully: %s", to_addr)
        return True
    except Exception:
        logging.exception("Failed to send email")
        return False

def decrypt_field(enc_b64: str) -> str:
    """
    Decrypt Base64 ciphertext from front-end using RSA private key PKCS#1 v1.5,
    return UTF-8 plaintext string
    """
    cipher_bytes = b64decode(enc_b64)
    plain = private_key.decrypt(
        cipher_bytes,
        asym_padding.PKCS1v15()
    )
    return plain.decode('utf-8')

@app.route('/', methods=['GET'])
def defense():
    # Render defense.html and inject public key PEM
    return render_template("defense.html", public_key=public_pem)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    # Decrypt RSA-encrypted fields from front-end
    try:
        username = decrypt_field(data.get("username", ""))
        email    = decrypt_field(data.get("email", ""))
        phone    = decrypt_field(data.get("phone", "")) if data.get("phone") else ""
        password = decrypt_field(data.get("password", ""))
    except Exception as e:
        logging.error("Decryption failed: %s", e)
        return jsonify({"message": "Decryption failed"}), 400

    if not username or not email or not password:
        return jsonify({"message": "Missing required registration information"}), 400

    # Log full registration info to app.log
    logging.info(
        "[REGISTER] username: %s, email: %s, phone: %s, password: %s",
        username, email, phone, password
    )

    # Check if email already registered
    for u in users:
        try:
            dec_email = private_key.decrypt(
                u["email"],
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            if dec_email == email:
                return jsonify({"message": "User already registered"}), 409
        except:
            continue

    # Hash password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)

    # Encrypt and store (RSA OAEP)
    encrypted_username = public_key.encrypt(
        username.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_email = public_key.encrypt(
        email.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_phone = None
    if phone:
        encrypted_phone = public_key.encrypt(
            phone.encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    users.append({
        "username": encrypted_username,
        "email":    encrypted_email,
        "phone":    encrypted_phone,
        "password": hashed_password
    })

    return jsonify({"message": "Registration successful"}), 201

@app.route('/sendcode', methods=['POST'])
def sendcode():
    data = request.json
    try:
        identifier = decrypt_field(data.get("email", ""))
        password   = decrypt_field(data.get("password", ""))
    except Exception as e:
        logging.error("Decryption failed: %s", e)
        return jsonify({"message": "Decryption failed"}), 400

    if not identifier or not password:
        return jsonify({"message": "Please provide username and password"}), 400

    # Find user and decrypt email/username/phone
    target = None
    user_email = None
    for u in users:
        try:
            dec_email = private_key.decrypt(
                u["email"],
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            dec_user = private_key.decrypt(
                u["username"],
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            dec_phone = None
            if u.get("phone"):
                dec_phone = private_key.decrypt(
                    u["phone"],
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode()
        except:
            continue
        if identifier in (dec_email, dec_user, dec_phone):
            target = u
            user_email = dec_email
            break

    if not target:
        return jsonify({"message": "User not found"}), 404

    # Verify password
    if not bcrypt.checkpw(password.encode(), target["password"]):
        return jsonify({"message": "Invalid username or password; cannot send code"}), 401

    code = str(random.randint(100000, 999999))
    expire = time.time() + 60
    codes[identifier] = {"code": code, "expire": expire}

    if send_email(user_email, code):
        logging.info("OTP sent to %s", identifier)
        return jsonify({"message": "Code sent"}), 200
    else:
        return jsonify({"message": "Failed to send code"}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    try:
        identifier = decrypt_field(data.get("email", ""))
        password   = decrypt_field(data.get("password", ""))
    except Exception as e:
        logging.error("Decryption failed: %s", e)
        return jsonify({"message": "Decryption failed"}), 400

    otp = data.get("otp")
    if not identifier or not password or not otp:
        return jsonify({"message": "Missing required login information"}), 400

    target = None
    for u in users:
        try:
            dec_email = private_key.decrypt(
                u["email"],
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            dec_user = private_key.decrypt(
                u["username"],
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            dec_phone = None
            if u.get("phone"):
                dec_phone = private_key.decrypt(
                    u["phone"],
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode()
        except:
            continue
        if identifier in (dec_email, dec_user, dec_phone):
            target = u
            break

    if not target or not bcrypt.checkpw(password.encode(), target["password"]):
        return jsonify({"message": "User not found or wrong password"}), 401

    info = codes.get(identifier)
    if not info:
        return jsonify({"message": "Please send code first"}), 400
    if time.time() > info["expire"]:
        del codes[identifier]
        return jsonify({"message": "Code expired"}), 401
    if otp != info["code"]:
        return jsonify({"message": "Invalid code"}), 401

    # Log full login info to app.log
    logging.info(
        "[LOGIN] identifier: %s, password: %s, otp: %s",
        identifier, password, otp
    )

    del codes[identifier]
    return jsonify({"message": "Login successful"}), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
