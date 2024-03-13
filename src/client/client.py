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

def encrypt_data_with_aes(aes_key, data):
    print("Encrypting data with AES...")
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    return cipher_aes.encrypt(pad(data, AES.block_size)), cipher_aes.iv


def decrypt_data_with_aes(aes_key, iv, data):
    print("Decrypting data with AES...")
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher_aes.decrypt(data), AES.block_size)


def send_file(file_path, aes_key, zmq_ip, zmq_port):
    print("Initializing ZeroMQ PUSH socket...")
    context = zmq.Context()
    socket = context.socket(zmq.PUSH)
    socket.connect(f"tcp://{zmq_ip}:{zmq_port}")

    print(f"Reading and encrypting file: {file_path}")
    with open(file_path, 'rb') as file:
        data = file.read()
        encrypted_data, iv = encrypt_data_with_aes(aes_key, data)
        socket.send(iv + encrypted_data)  # Prepend IV for decryption
        # Print encrypted data in hex format
        print(f"Encrypted data sent: {encrypted_data.hex()}")

    print("File sent successfully.")
    socket.close()
    context.term()


def receive_file(output_file, aes_key, zmq_port):
    print("Initializing ZeroMQ PULL socket...")
    context = zmq.Context()
    socket = context.socket(zmq.PULL)
    socket.bind(f"tcp://*:{zmq_port}")

    print("Waiting to receive file...")
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
        print(session.get("aes_key"))
        aes_key = base64.b64decode(session.get("aes_key"))

        # If the user is the sender
        if choice == "1":
            file_path = input("Enter the file path: ")
            send_file(file_path, aes_key, None, port)

        # User is the receiver
        else:
            output_file = input("Enter the output file name: ")
            receive_file(output_file, aes_key, port)
    
        
            
    # User has outstanding invites.            
    else:
        
        
    
    



    # mode = input("Do you want to send or receive a file? (send/receive): ")
    # if mode == "send":
    #     file_path = input("Enter the file path: ")
    #     zmq_ip = input("Enter the receiver's IP address: ")
    #     zmq_port = input("Enter the receiver's ZMQ port: ")
    #     send_file(file_path, aes_key, zmq_ip, zmq_port)
    # elif mode == "receive":
    #     output_file = input("Enter the output file name: ")
    #     zmq_port = input("Enter the ZMQ port to listen on: ")
    #     receive_file(output_file, aes_key, zmq_port)


if __name__ == "__main__":
    main()
