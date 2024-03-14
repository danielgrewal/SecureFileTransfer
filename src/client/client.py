import base64
import requests
import zmq
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning when making unverified HTTPS requests
urllib3.disable_warnings(InsecureRequestWarning)
SERVER_URL_BASE = "https://localhost"
AUTH_ENDPOINT = "authenticate"

def authenticate(username, password):
    print("Sending authentication request to key server...")
    data = { "username": username, "password": password }
    response = requests.post(f'{SERVER_URL_BASE}/{AUTH_ENDPOINT}', data=data, verify=False)
    
    # Verify=False disabled trusted CA check. For dev/testing we are using self signed cert
    # timeout is used so the client does not hang if no response from server, set to 5 seconds
    if response.status_code == 200:
        print("Authenticated!")
        access_token = response.json().get("access_token")
        return access_token
    else:
        print(response.json().get("detail"))
        return None
    
def is_valid_responder(username:str, headers):
    response = requests.post(f'{SERVER_URL_BASE}/validateuser', json = {"username": username}, headers=headers, verify=False)
    if response.status_code == 200:
        return True
    else:
        print(response.json().get("detail"))
        return False

def start_session(responder_username:str, choice:str, port:str, headers):
    connection_details = {'responder': responder_username, 'role': choice, 'port': port }
    response = requests.post(f'{SERVER_URL_BASE}/startsession', json = connection_details, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def close_session(session_id:str, headers):
    response = requests.post(f'{SERVER_URL_BASE}/endsession',json={"session_id": session_id}, headers=headers, verify=False)
    return(response.json().get("status") == "Success")
    
    
def accept_invite(headers):
    response = requests.get(f'{SERVER_URL_BASE}/joinsession', headers=headers, verify=False)
    return(response.json())

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
        encrypted_data, iv = encrypt_data_with_aes(aes_key, data)
        print("Waiting to send file...")
        socket.send(iv + encrypted_data)  # Prepend IV for decryption
        # Print encrypted data in hex format
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
    # Print received encrypted data in hex format
    print(f"Encrypted data received: {encrypted_data.hex()}")
    decrypted_data = decrypt_data_with_aes(aes_key, iv, encrypted_data)

    print(f"Writing decrypted data to file: {output_file}")
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

    print("File received and decrypted successfully.")
    socket.close()
    context.term()

    
def main():
    username = input("Enter username: ")
    password = input("Enter password: ")
    # Authenticate user
    access_token = authenticate(username, password)
    if not access_token:
        exit()

    # Set bearer token in the header
    headers = { "Accept": "application/json", "Authorization": f"Bearer {access_token}" }
    
    # Check if user has any outstanding connection requests
    response = requests.get(f'{SERVER_URL_BASE}/sessions', headers=headers, verify=False)
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
            port = input("Port Responder will connect to: ")
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
        address = 'localhost' # all local clients will be localhost
        port = session.get('port')
        aes_key = base64.b64decode(session.get("aes_key"))

        # If the initiating user is the sender, receive file.
        if role_initiator == "1":
            output_file = input("Enter the output file path (to receive): ")
            receive_file(output_file, aes_key, address, port)
            
        # If the initiating user is the receiver, send file.
        else:
            file_path = input("Enter the file path (to send): ")
            send_file(file_path, aes_key, address, port)
        
        # File successfully sent/received. Close the open session.
        session_closed = close_session(session_id, headers)

        if session_closed:
            print(f"Session {session_id} completed successfully.")
        else:
            print(f"Unable to close session {session_id}")
        


if __name__ == "__main__":
    main()
