from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import os

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    print("RSA keys generated.")
    return private_key, public_key

def encrypt_data_with_aes(key, data):
    cipher_aes = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(data, AES.block_size))
    print("Data encrypted with AES.")
    return cipher_aes.iv + ct_bytes

def decrypt_data_with_aes(key, data):
    iv = data[:AES.block_size]  # initialization vector
    ct = data[AES.block_size:]  # cipher text
    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher_aes.decrypt(ct), AES.block_size)  # plaintext
    print("Data decrypted with AES.")
    return pt

def encrypt_key_with_rsa(public_key, key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_key = cipher_rsa.encrypt(key)
    print("AES key encrypted with RSA.")
    return enc_key

def decrypt_key_with_rsa(private_key, enc_key):
    recipient_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    key = cipher_rsa.decrypt(enc_key)
    print("Encrypted AES key decrypted with RSA.")
    return key

def send_file(target_ip, target_port, file_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((target_ip, target_port))
        print("Connected to receiver.")
        public_key = s.recv(2048)  # Receive public key from receiver
        print("Public key received from receiver.")
        aes_key = get_random_bytes(32)  # AES-256 key
        print("AES-256 key generated.")
        encrypted_aes_key = encrypt_key_with_rsa(public_key, aes_key)
        print("AES key encrypted with receiver's public RSA key.")
        s.sendall(encrypted_aes_key)  # Send encrypted AES key
        print("Encrypted AES key sent.")
        with open(file_path, 'rb') as f:
            encrypted_data = encrypt_data_with_aes(aes_key, f.read())
            print("File data encrypted with AES.")
            s.sendall(encrypted_data)
            print("Encrypted file data sent.")

def receive_file(listen_port, output_file):
    private_key, public_key = generate_rsa_keys()
    print("Receiver RSA keys generated.")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', listen_port))
        s.listen()
        print("Listening for incoming connections...")
        conn, _ = s.accept()
        with conn:
            print("Connection established.")
            conn.sendall(public_key)  # Send public key to sender
            print("Public RSA key sent to sender.")
            encrypted_aes_key = conn.recv(256)  # Receive encrypted AES key
            print("Encrypted AES key received.")
            aes_key = decrypt_key_with_rsa(private_key, encrypted_aes_key)
            print("AES key decrypted with private RSA key.")
            encrypted_data = b''
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                encrypted_data += data
            print("Encrypted file data received.")
            decrypted_data = decrypt_data_with_aes(aes_key, encrypted_data)
            print("File data decrypted with AES.")
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
                print(f"Decrypted file data written to {output_file}.")

def main():
    mode = input("Do you want to send or receive a file? (send/receive): ")
    if mode == "send":
        target_ip = input("Enter the target IP address: ")
        target_port = int(input("Enter the target port: "))
        file_path = input("Enter the file path: ")
        send_file(target_ip, target_port, file_path)
    elif mode == "receive":
        listen_port = int(input("Enter the port to listen on: "))
        output_file = input("Enter the output file name: ")
        receive_file(listen_port, output_file)

if __name__ == "__main__":
    main()
