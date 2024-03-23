import requests
import base64
import zmq
import threading

from src.client import client

lock = threading.Lock() # obj for syncing the threads

def send_file(file_path, aes_key, address, zmq_port):

    lock.acquire() # block the execution of receive method
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
        crc_value = client.calculate_crc(data)

        print("\n------------SENDER CRC VAL START------------")
        print(crc_value)
        print("-------------SENDER CRC VAL END-------------\n")

        crc_data = crc_value.to_bytes(4, 'big')
        data_with_crc = crc_data + data
        # Encrypt the data w/ AES and get the initialization vector value
        encrypted_data, iv = client.encrypt_data_with_aes(aes_key, data_with_crc)
        print("Waiting to send file...")
        # release lock to allow receive method to execute
        lock.release()

        socket.send(iv + encrypted_data)    # Prepend IV for decryption
        print(f"Encrypted data sent: {encrypted_data.hex()}")

    print("File sent successfully.")
    socket.close()
    context.term()

def receive_file(output_file, aes_key, address, zmq_port):

    lock.acquire()
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
    decrypted_data_with_crc = client.decrypt_data_with_aes(
        aes_key, iv, encrypted_data)

    # Separate CRC value from file data (first 4 byte block prepended by sender)
    received_crc_data = decrypted_data_with_crc[:4]
    file_data = decrypted_data_with_crc[4:]

    # Calculate CRC of the decrypted file data
    calculated_crc = client.calculate_crc(file_data)

    print("\n------------RECEIVER CRC VAL START------------")
    print(calculated_crc)
    print("-------------RECEIVER CRC VAL END-------------\n")

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
    lock.release()

def encryption():

    user1 = "angad"
    pass1 = "newpass"

    user2 = "kinjal"

    access_token1 = client.authenticate(user1, pass1)

    header1 = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token1}"}

    session = client.start_session(user2, '1', '8888', header1)
    aes_key = base64.b64decode(session.get("aes_key"))

    print("\n------------AES KEY START------------")
    print(aes_key)
    print("-------------AES KEY END-------------\n")

    file_path = "src/client/test.txt"
    output_file = "src/client/receive.txt"

    t1 = threading.Thread(target=send_file, args=(file_path, aes_key, None, '8888'))
    t2 = threading.Thread(target=receive_file, args=(output_file, aes_key, 'localhost', '8888'))
 
    t1.start()
    t2.start()
 
    t1.join()
    t2.join()

    session_id = 1

    session_closed = client.close_session(session_id, header1)

    if session_closed:
        print(f"Session #{session_id} completed successfully.")
    else:
        print(f"Unable to close session #{session_id}")