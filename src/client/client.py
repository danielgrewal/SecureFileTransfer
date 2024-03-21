import base64
import requests
import zmq
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import zlib

# Suppress InsecureRequestWarning when making unverified HTTPS requests
urllib3.disable_warnings(InsecureRequestWarning)
SERVER_URL_BASE = "https://localhost"
AUTH_ENDPOINT = "authenticate"

#TEST Variables
errorMsg = ""

def authenticate(username, password):
    print("Sending authentication request to key server...")
    data = {"username": username, "password": password}
    response = requests.post(
        f'{SERVER_URL_BASE}/{AUTH_ENDPOINT}', data=data, verify=False)
    # Verify=False disables the trusted CA check. For dev/testing we are using self signed certificates
    # In production verify=True would be used to ensure a trusted CA issues the certifcate.
    if response.status_code == 200:
        print("Authenticated!")
        access_token = response.json().get("access_token")
        return access_token
    else:
        errorMsg = response.json().get("detail")
        print(errorMsg)
        return None


def calculate_crc(data):
    return zlib.crc32(data) & 0xffffffff


def is_valid_responder(username: str, headers):
    response = requests.post(f'{SERVER_URL_BASE}/validateuser',
                             json={"username": username}, headers=headers, verify=False)
    if response.status_code == 200:
        return True
    else:
        print(response.json().get("detail"))
        return False


def start_session(responder_username: str, choice: str, port: str, headers):
    connection_details = {
        'responder': responder_username, 'role': choice, 'port': port}
    response = requests.post(f'{SERVER_URL_BASE}/startsession',
                             json=connection_details, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def close_session(session_id: str, headers):
    response = requests.post(f'{SERVER_URL_BASE}/endsession',
                             json={"session_id": session_id}, headers=headers, verify=False)
    return (response.json().get("status") == "Success")


def accept_invite(headers):
    response = requests.get(
        f'{SERVER_URL_BASE}/joinsession', headers=headers, verify=False)
    return (response.json())


def encrypt_data_with_aes(aes_key, data):
    print("Encrypting data with AES...")
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    return cipher_aes.encrypt(pad(data, AES.block_size)), cipher_aes.iv


def decrypt_data_with_aes(aes_key, iv, data):
    print("Decrypting data with AES...")
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher_aes.decrypt(data), AES.block_size)


def send_file(file_path, aes_key, address, zmq_port):

    # Caller is the initiating user
    if not address:
        print("Initializing ZeroMQ PUSH socket...")
        context = zmq.Context()
        socket = context.socket(zmq.PUSH)
        socket.bind(f"tcp://*:{zmq_port}")

    # Caller is the responding user
    else:
        print("Initializing ZeroMQ PUSH socket...")
        context = zmq.Context()
        socket = context.socket(zmq.PUSH)
        socket.connect(f"tcp://{address}:{zmq_port}")

    print(f"Reading file: {file_path}")
    with open(file_path, 'rb') as file:
        data = file.read()
        # Calculate CRC value of the file data, convert to 4-byte block and prepend to the file data before sending
        print("Calculating CRC for integrity check...")
        crc_value = calculate_crc(data)
        crc_data = crc_value.to_bytes(4, 'big')
        data_with_crc = crc_data + data
        # Encrypt the data w/ AES and get the initialization vector value
        encrypted_data, iv = encrypt_data_with_aes(aes_key, data_with_crc)
        print("Waiting to send file...")
        socket.send(iv + encrypted_data)    # Prepend IV for decryption
        print(f"Encrypted data sent: {encrypted_data.hex()}")

    print("File sent successfully.")
    socket.close()
    context.term()


def receive_file(output_file, aes_key, address, zmq_port):

    # Caller is the initiating user
    if not address:
        print("Initializing ZeroMQ PULL socket...")
        context = zmq.Context()
        socket = context.socket(zmq.PULL)
        socket.bind(f"tcp://*:{zmq_port}")
        print("Waiting to receive file...")

    # Caller is the responding user
    else:
        print("Initializing ZeroMQ PUSH socket...")
        context = zmq.Context()
        socket = context.socket(zmq.PULL)
        socket.connect(f"tcp://{address}:{zmq_port}")

    data = socket.recv()
    iv, encrypted_data = data[:16], data[16:]  # Extract IV and encrypted data
    print(f"Encrypted data received: {encrypted_data.hex()}")
    decrypted_data_with_crc = decrypt_data_with_aes(
        aes_key, iv, encrypted_data)

    # Separate CRC value from file data (first 4 byte block prepended by sender)
    received_crc_data = decrypted_data_with_crc[:4]
    file_data = decrypted_data_with_crc[4:]

    # Calculate CRC of the decrypted file data
    calculated_crc = calculate_crc(file_data)

    # Compare CRC values, only if they match the new fi
    if received_crc_data == calculated_crc.to_bytes(4, 'big'):
        print("CRC Check OK. File integrity verified.")

        with open(output_file, 'wb') as file:
            file.write(file_data)
        print("File received and decrypted successfully.")
    else:
        print("CRC does not match. File integrity check failed!")
    socket.close()
    context.term()


def main():
    print("Welcome to the Secure File Sharing System")
    username = input("Enter username: ")
    password = input("Enter password: ")
    # Authenticate user
    access_token = authenticate(username, password)
    if not access_token:
        exit()

    # Set bearer token in the header
    headers = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token}"}

    # Check if user has any outstanding connection requests
    response = requests.get(
        f'{SERVER_URL_BASE}/sessions', headers=headers, verify=False)
    outstanding_requests = response.json().get('sessions')
    print(f"You have {outstanding_requests} outstanding invite(s). \n")

    # User has no outstanding requests to connect. User can initiate an invite.
    if outstanding_requests == 0:
        while True:
            # Prompt user for username of connecting party (responder)
            responder_username = input("Request connection with (username): ")
            if is_valid_responder(responder_username, headers):
                break

        while True:
            print("Would you like to send or receive an encrypted file? Choose 1 or 2")
            print("1. I am the sender.")
            print("2. I am the receiver.")
            choice = input()
            if choice == '1' or choice == '2':
                break
            else:
                print("You have entered an invalid option.\n")

        while True:
            port = input("Port # Responder will connect to: ")
            if port.isnumeric():
                break

        session = start_session(responder_username, choice, port, headers)
        aes_key = base64.b64decode(session.get("aes_key"))

        # If the user is the sender
        if choice == "1":
            file_path = input("Enter the file path (to send): ")
            send_file(file_path, aes_key, None, port)

        # User is the receiver
        else:
            output_file = input("Enter the output file path (to receive): ")
            receive_file(output_file, aes_key, None, port)

    # User has outstanding invites.
    else:
        session = accept_invite(headers)

        session_id = session.get('session_id')
        username_initiator = session.get('username_initiator')
        role_initiator = session.get('role_initiator')
        address = 'localhost'  # all local clients will be localhost
        port = session.get('port')
        aes_key = base64.b64decode(session.get("aes_key"))

        # If the initiating user is the sender, receive file.
        if role_initiator == "1":
            output_file = input("Enter the output file name (to receive): ")
            receive_file(output_file, aes_key, address, port)

        # If the initiating user is the receiver, send file.
        else:
            file_path = input("Enter the file name (to send): ")
            send_file(file_path, aes_key, address, port)

        # File successfully sent/received. Close the open session.
        session_closed = close_session(session_id, headers)

        if session_closed:
            print(f"Session #{session_id} completed successfully.")
        else:
            print(f"Unable to close session #{session_id}")


if __name__ == "__main__":
    main()
