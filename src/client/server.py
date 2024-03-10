from flask import Flask, request, jsonify
import os
import subprocess

app = Flask(__name__)

# Simple in-memory storage for users for demonstration
users = {"user1": "pass1", "user2": "pass2"}

# Generate a single AES key for all sessions
aes_key = os.urandom(32).hex()  # 256-bit AES key
print("Server started. AES key generated.")


@app.route('/authenticate_and_get_key', methods=['POST'])
def authenticate_and_get_key():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if users.get(username) == password:
        return jsonify({"status": "success", "aes_key": aes_key}), 200
    else:
        return jsonify({"status": "failure"}), 401


def generate_self_signed_cert(cert_name="cert.pem", key_name="key.pem"):
    print("Starting the generation of a self-signed certificate and private key...")

    # Command to generate a self-signed certificate and private key using openssl
    subprocess.call([
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", key_name, "-out", cert_name,
        "-days", "365", "-nodes", "-subj",
        "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com"
    ])
    print(f"Self-signed certificate '{cert_name}' and private key '{
          key_name}' generated successfully.")


if __name__ == '__main__':
    # Check if certificate and key files exist, generate if not
    if not (os.path.exists("cert.pem") and os.path.exists("key.pem")):
        generate_self_signed_cert()

    # Load SSL context
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=False, port=5000)
