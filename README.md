# SOFE4840 Final Project - Secure File Transfer System

This application demonstrates secure file transfer using a key server for AES key distribution, a client that can act as either a sender or receiver, and ZeroMQ with CurveZMQ for encrypted communication. The key server provides AES keys to authenticated clients, which then use these keys to encrypt and decrypt files during transfer.

## Prerequisites

- Python 3.6 or higher
- Flask: For the key server's web interface
- PyZMQ: For messaging between the client and server
- PyCryptodome: For AES encryption and decryption
- Requests: For HTTP requests from the client to the key server
- OpenSSL: For generating self-signed certificates (development/testing)

## Installation

First, ensure you have Python installed on your machine. Then, install the required libraries using pip:

pip install flask pyzmq pycryptodome requests

## Running the Application

### Key Server

Run the key server using server.py
The server will start, and a self-signed SSL certificate will be generated if it doesn't already exist.

### Client

Run the client using client.py in a seperate terminal (or use another instance of python debugger).
Follow the prompts in the console to authenticate with the key server, and choose whether to send or receive a file.

## Security Notes

The application uses self-signed SSL certificates for HTTPS communication in development. For production environments, use certificates signed by a trusted Certificate Authority (CA).
The verify=False parameter is used in the client's requests.post call for simplicity in development and testing. This disables SSL certificate verification and is not recommended for production use. Ensure proper certificate verification in production environments.
