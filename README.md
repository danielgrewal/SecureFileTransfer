# SOFE4840 Final Project - Secure File Transfer System

This Python program enables secure file transfer between a sender and a receiver using RSA for key exchange and AES-256 for encryption of the actual file data. The program dynamically generates RSA keys for each session, ensuring secure key exchange over an insecure channel, and then uses AES-256 to securely encrypt the file data being transferred.
(NOTE: more to be added with server authentication component)

## Features

- **RSA Key Exchange**: Securely exchanges AES keys using RSA encryption to ensure that file transfers are secure even over public networks.
- **AES-256 Encryption**: Utilizes AES-256 encryption to secure file data during transfer, providing a high level of security.
- **Dynamic Key Generation**: RSA keys are generated dynamically for each session, enhancing security by ensuring that keys are not reused across sessions.
- **(NOTE: more to be added with server authentication component)**

## Requirements

- Python 3.6 or higher
- PyCryptodome library

## Installation

To use this program, you need to have Python installed on your machine. If you haven't already, download and install Python from [python.org](https://www.python.org/).

Then, install the required PyCryptodome library using pip:

pip install pycryptodome

## Usage

Run main.py and select either sender or receiver mode. (add more when server component is added)
