from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Simple in-memory storage for users for demonstration
users = {"user1": "pass1", "user2": "pass2"}

# Generate a single AES key for all sessions
# Doing it this way for easier testing, but we can change this later
aes_key = os.urandom(32).hex()  # 256-bit AES key
print("Server started. AES key generated.")

@app.route('/authenticate_and_get_key', methods=['POST'])
def authenticate_and_get_key():
    data = request.json
    print(f"Received authentication request: {data}")
    username = data.get('username')
    password = data.get('password')
    
    if users.get(username) == password:
        print(f"User {username} authenticated successfully.")
        return jsonify({"status": "success", "aes_key": aes_key}), 200
    else:
        print(f"Authentication failed for user {username}.")
        return jsonify({"status": "failure"}), 401

if __name__ == '__main__':
    app.run(debug=False, port=5000)
