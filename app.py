import os
import json
import base64
import hmac
import hashlib
import secrets
from datetime import timedelta
from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="static")

app.secret_key = os.environ.get("SECRET_KEY", "abcdefg")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

CORS(app, supports_credentials=True)

VAULT_FILE = "vault.json"


# ----------------------------
# crypto-helper class
# ----------------------------

class CryptoEngine:
    SALT_SIZE = 16
    NONCE_SIZE = 16
    KEY_SIZE = 32
    PBKDF2_ITERATIONS = 310_000

    def generate_salt(self) -> bytes:
        return os.urandom(self.SALT_SIZE)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            self.PBKDF2_ITERATIONS,
            dklen=self.KEY_SIZE,
        )

    def hash_master_password(self, master_password: str) -> str:
        salt = self.generate_salt()
        key = self.derive_key(master_password, salt)
        return base64.b64encode(salt).decode() + "$" + base64.b64encode(key).decode()

    def verify_master_password(self, stored_hash: str, password_attempt: str) -> bool:
        try:
            salt_b64, key_b64 = stored_hash.split("$", 1)
            salt = base64.b64decode(salt_b64)
            stored_key = base64.b64decode(key_b64)
            attempted_key = self.derive_key(password_attempt, salt)
            return hmac.compare_digest(stored_key, attempted_key)
        except Exception:
            return False

    def _keystream(self, key: bytes, nonce: bytes, length: int) -> bytes:
        output = b""
        counter = 0
        while len(output) < length:
            counter_bytes = counter.to_bytes(8, "big")
            output += hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
            counter += 1
        return output[:length]

    def encrypt(self, plaintext: bytes, master_password: str, salt: bytes) -> str:
        key = self.derive_key(master_password, salt)
        nonce = os.urandom(self.NONCE_SIZE)
        stream = self._keystream(key, nonce, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
        tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
        payload = nonce + tag + ciphertext
        return base64.b64encode(payload).decode("utf-8")

    def decrypt(self, token: str, master_password: str, salt: bytes) -> bytes | None:
        try:
            key = self.derive_key(master_password, salt)
            payload = base64.b64decode(token.encode("utf-8"))
            nonce = payload[:self.NONCE_SIZE]
            tag = payload[self.NONCE_SIZE:self.NONCE_SIZE + 32]
            ciphertext = payload[self.NONCE_SIZE + 32:]

            expected_tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected_tag):
                return None

            stream = self._keystream(key, nonce, len(ciphertext))
            return bytes(a ^ b for a, b in zip(ciphertext, stream))
        except Exception:
            return None


crypto_engine = CryptoEngine()


class VaultManager:
    def __init__(self, master_password: str, salt: bytes):
        self.master_password = master_password
        self.salt = salt
        self.entries = {}

    def add_entry(self, title: str, username: str, password: str, url: str = "", category: str = ""):
        self.entries[title.lower()] = {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "category": category or "Uncategorized",
        }

    def get_entry(self, title: str):
        return self.entries.get(title.lower())

    def get_all_entries(self):
        return list(self.entries.values())

    def delete_entry(self, title: str) -> bool:
        key = title.lower()
        if key in self.entries:
            del self.entries[key]
            return True
        return False

    def update_entry(self, original_title: str, new_data: dict):
        self.delete_entry(original_title)
        self.add_entry(
            new_data.get("title", "").strip(),
            new_data.get("username", "").strip(),
            new_data.get("password", "").strip(),
            new_data.get("url", "").strip(),
            new_data.get("category", "").strip(),
        )

    def encrypt_and_serialize(self) -> str:
        raw = json.dumps(self.entries).encode("utf-8")
        return crypto_engine.encrypt(raw, self.master_password, self.salt)

    def decrypt_and_load(self, encrypted_vault: str) -> bool:
        raw = crypto_engine.decrypt(encrypted_vault, self.master_password, self.salt)
        if raw is None:
            return False
        self.entries = json.loads(raw.decode("utf-8"))
        return True


@app.before_request
def refresh_session():
    session.permanent = True
    session.modified = True


# ----------------------------
# Page routes
# ----------------------------
@app.route("/")
def serve_login():
    return send_from_directory("static", "login.html")


@app.route("/vault")
def serve_vault():
    if "master_password" not in session:
        return send_from_directory("static", "login.html")
    return send_from_directory("static", "vault.html")


# ----------------------------
# Auth routes
# ----------------------------
@app.route("/api/status", methods=["GET"])
def status():
    return jsonify({"setup_needed": not os.path.exists(VAULT_FILE)})


@app.route("/api/signup", methods=["POST"])
@app.route("/api/setup", methods=["POST"])
def signup():
    if os.path.exists(VAULT_FILE):
        return jsonify({"error": "Vault already exists. Please log in."}), 400

    data = request.get_json() or {}
    master_password = data.get("master_password", "").strip()

    if not master_password:
        return jsonify({"error": "Master password is required."}), 400

    vault_salt = crypto_engine.generate_salt()
    hashed_master_password = crypto_engine.hash_master_password(master_password)

    vault = VaultManager(master_password, vault_salt)
    encrypted_vault = vault.encrypt_and_serialize()

    vault_file_data = {
        "vault_salt": base64.b64encode(vault_salt).decode("utf-8"),
        "hashed_master_password": hashed_master_password,
        "vault_data": encrypted_vault,
    }

    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(vault_file_data, f, indent=2)

    session["master_password"] = master_password
    return jsonify({"message": "Signup successful!"}), 201


@app.route("/api/login", methods=["POST"])
def login():
    if not os.path.exists(VAULT_FILE):
        return jsonify({"error": "No account exists. Please sign up first."}), 404

    data = request.get_json() or {}
    master_password = data.get("master_password", "").strip()

    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        vault_file_data = json.load(f)

    if not crypto_engine.verify_master_password(vault_file_data["hashed_master_password"], master_password):
        return jsonify({"error": "Invalid master password."}), 401

    session["master_password"] = master_password
    return jsonify({"message": "Login successful!"})


@app.route("/api/check-auth", methods=["GET"])
def check_auth():
    if "master_password" in session:
        return jsonify({"authenticated": True})
    return jsonify({"authenticated": False}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully."})


# ----------------------------
# Vault helpers
# ----------------------------
def get_vault_manager():
    if "master_password" not in session:
        return None

    if not os.path.exists(VAULT_FILE):
        return None

    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as f:
            vault_file_data = json.load(f)

        salt = base64.b64decode(vault_file_data["vault_salt"])
        encrypted_vault = vault_file_data["vault_data"]

        vault = VaultManager(session["master_password"], salt)

        if not vault.decrypt_and_load(encrypted_vault):
            return None

        return vault
    except Exception as e:
        print("Vault load error:", e)
        return None


def save_vault_manager(vault: VaultManager):
    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        vault_file_data = json.load(f)

    vault_file_data["vault_data"] = vault.encrypt_and_serialize()

    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(vault_file_data, f, indent=2)


# ----------------------------
# Password routes
# ----------------------------
@app.route("/api/passwords", methods=["GET", "POST"])
def manage_passwords():
    vault = get_vault_manager()

    if not vault:
        return jsonify({"error": "Not authenticated or vault is corrupt."}), 401

    if request.method == "GET":
        return jsonify(vault.get_all_entries())

    data = request.get_json() or {}
    title = data.get("title", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    url = data.get("url", "").strip()
    category = data.get("category", "").strip()

    if not title or not username or not password:
        return jsonify({"error": "Title, username and password are required."}), 400

    vault.add_entry(title, username, password, url, category)
    save_vault_manager(vault)

    return jsonify({"message": f"Entry '{title}' added."}), 201


@app.route("/api/passwords/<path:title>", methods=["GET", "PUT", "DELETE"])
def manage_single_password(title):
    vault = get_vault_manager()

    if not vault:
        return jsonify({"error": "Not authenticated or vault is corrupt."}), 401

    if request.method == "GET":
        entry = vault.get_entry(title)
        if not entry:
            return jsonify({"error": "Entry not found."}), 404
        return jsonify(entry)

    if request.method == "PUT":
        data = request.get_json() or {}
        new_title = data.get("title", "").strip()
        new_username = data.get("username", "").strip()
        new_password = data.get("password", "").strip()

        if not new_title or not new_username or not new_password:
            return jsonify({"error": "Title, username and password are required."}), 400

        vault.update_entry(title, data)
        save_vault_manager(vault)
        return jsonify({"message": f"Entry '{new_title}' updated."})

    if request.method == "DELETE":
        if vault.delete_entry(title):
            save_vault_manager(vault)
            return jsonify({"message": f"Entry '{title}' deleted."})
        return jsonify({"error": "Entry not found."}), 404


if __name__ == "__main__":
    print("Server starting...")
    print("Open: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
