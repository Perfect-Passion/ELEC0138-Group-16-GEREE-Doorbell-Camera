# ELEC0138-Group-16-GEREE-Doorbell-Camera
For the threat 3
FOR ATTACK,
Front-End (index.html)
User input (username, email, password) is AES-CBC encrypted using:
Key: 1234567890123456
IV: 6543210987654321
Data is then sent to the backend via HTTP POST requests.
Backend Server (sever.py)
Accepts encrypted fields from the front end.
Decrypts using the known key and IV.
Performs user validation, bcrypt password hashing, and in-memory storage.
Provides /register and /login endpoints.
MITM Proxy (MITM Sever.py)
Acts as a transparent proxy between the front end and the backend.
Reads encrypted fields and attempts to brute-force decrypt them using brute force keys.txt.
Logs cracked data to mitm_capture.log.
Forwards the original encrypted data to the real backend
How to run? Start the backend server Start the backend server and then Start the MITM proxy Proxy listening at: http://127.0.0.1:8081.
Finally check the MITM log. can find the user register information 
For threat 3 defense,
Feature:/n.
RSA Encryption: All credentials are encrypted on the client side using RSA (2048-bit) before being sent to the server.
Email-Based OTP Verification: A 6-digit verification code is sent to the user's email to complete login.
Password Hashing: Passwords are securely stored with bcrypt hashing.
Frontend UI: Polished HTML interface with smooth toggling between login and registration.
Logging: All major actions (registration, login attempts, code sending) are logged to app.log.
How to run?  Install Dependencies pip install flask flask-cors bcrypt cryptography Start the Server.
