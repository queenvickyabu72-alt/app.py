import base64
import os

from flask import Flask, request, render_template_string
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(name)

HTML = """

<!DOCTYPE html><html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Vicky Secure Cipher Tool</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f0f4f8;
            padding: 20px;
            max-width: 650px;
            margin: auto;
        }
        h2 {
            text-align: center;
            color: #123456;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px #0002;
            margin-bottom: 20px;
        }
        input, textarea {
            width: 100%;
            padding: 12px;
            margin: 8px 0 15px;
            border: 1px solid #ccc;
            border-radius: 5px;
            box-sizing: border-box;
            font-size: 15px;
        }
        button {
            background: #0759b5;
            color: white;
            padding: 12px 18px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
        }
        button:hover {
            background: #06458b;
        }
        .result {
            background: #e8f0f7;
            padding: 12px;
            border-radius: 5px;
            overflow-wrap: anywhere;
            white-space: pre-wrap;
        }
        .error {
            color: #b00020;
        }
        .note {
            font-size: 13px;
            color: #555;
        }
    </style>
</head>
<body><h2>VICKY SECURE CIPHER TOOL</h2>
<p style="text-align:center">
    Encrypt and decrypt messages using a passcode.
</p>

<div class="card">
    <h3>Encrypt Message</h3>
    <form method="POST" action="/encrypt-web">
        <label>Enter your message:</label>
        <textarea name="message" rows="4" required>{{ enc_msg }}</textarea>

        <label>Create a passcode:</label>
        <input type="password" name="passcode"
               minlength="8" required
               autocomplete="new-password">

        <button type="submit">Encrypt Message</button>
    </form>

    {% if enc_result %}
        <h4>Encrypted Result</h4>
        <div class="result">{{ enc_result }}</div>
    {% endif %}
</div>

<div class="card">
    <h3>Decrypt Message</h3>
    <form method="POST" action="/decrypt-web">
        <label>Enter ciphertext:</label>
        <textarea name="ciphertext" rows="4" required>{{ dec_cipher }}</textarea>

        <label>Enter the same passcode:</label>
        <input type="password" name="passcode"
               required autocomplete="current-password">

        <button type="submit">Decrypt Message</button>
    </form>

    {% if dec_result %}
        <h4>Decryption Result</h4>
        <div class="result">{{ dec_result }}</div>
    {% endif %}
</div>

<p class="note">
    Keep your passcode safe. The original message cannot be recovered
    without the correct passcode.
</p>

</body>
</html>
"""def derive_key(passcode, salt):
kdf = PBKDF2HMAC(
algorithm=hashes.SHA256(),
length=32,
salt=salt,
iterations=600000,
)

key = kdf.derive(passcode.encode("utf-8"))
return base64.urlsafe_b64encode(key)

@app.route("/")
def home():
return render_template_string(HTML)

@app.route("/encrypt-web", methods=["POST"])
def encrypt_web():
message = request.form.get("message", "")
passcode = request.form.get("passcode", "")

if not message or len(passcode) < 8:
    return render_template_string(
        HTML,
        enc_msg=message,
        enc_result="Enter a message and a passcode of at least 8 characters."
    ), 400

salt = os.urandom(16)
key = derive_key(passcode, salt)

ciphertext = Fernet(key).encrypt(message.encode("utf-8"))

# Store the salt with the ciphertext so it can be recovered for decryption.
result = base64.urlsafe_b64encode(
    b"VSM1" + salt + ciphertext
).decode("ascii")

return render_template_string(
    HTML,
    enc_msg=message,
    enc_result=result
)

@app.route("/decrypt-web", methods=["POST"])
def decrypt_web():
ciphertext = request.form.get("ciphertext", "").strip()
passcode = request.form.get("passcode", "")

try:
    raw = base64.b64decode(ciphertext, validate=True)

    if not raw.startswith(b"VSM1") or len(raw) < 21:
        raise ValueError("Invalid format")

    salt = raw[4:20]
    encrypted_data = raw[20:]

    key = derive_key(passcode, salt)
    original_message = Fernet(key).decrypt(
        encrypted_data
    ).decode("utf-8")

    return render_template_string(
        HTML,
        dec_cipher=ciphertext,
        dec_result=original_message
    )

except (ValueError, InvalidToken, UnicodeDecodeError):
    return render_template_string(
        HTML,
        dec_cipher=ciphertext,
        dec_result="Decryption failed. Check your ciphertext and passcode."
    ), 400

if name == "main":
app.run(host="0.0.0.0", port=5000, debug=False)
