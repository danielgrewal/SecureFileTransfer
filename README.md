# SOFE4840 Final Project - Secure File Transfer System

## Overview

The “Secure File Sharing System” utilizes a design that focuses on security, session management and direct client-to-client data transfer. The system follows a centralized approach using a trusted third-party; the key distribution and session management server. The third-party server is responsible for authenticating clients, managing sessions and distributing AES-256 keys to clients for file encryption and decryption.

All communications between the clients and server are encrypted via HTTPS using signed certificates. This ensures that all parties in the system are legitimate and can trust each other and prevents messages from being intercepted and read by unauthorized entities.

Once authenticated, clients can start or join in a file transfer session hosted by the server. The initiator provides their predefined IP/port for eventually establishing a direct TCP/IP connection with the responder. This connection information is sent to the server, which will in turn share it with the responder once they authenticate and join the session with the initiator. Once both the initiator and responder clients are authenticated, in a session, and receive the AES key, the responder will establish a direct connection with the initiator using the provided connection details in the session.

The sender then encrypts the file using the provided AES-256 key and sends the encrypted data. Once the transfer is complete, the receiver will decrypt the file and perform a CRC check to ensure the file’s integrity. Upon success, the client will inform the server that the file was successfully transmitted. Once confirmed, the server closes the session.

This implementation provides a secure, authenticated and direct file exchange between clients utilizing a trusted third party server for authentication, session management and AES-256 key generation.

## Prerequisites

- Python 3.6+
- Docker
- OpenSSL (if you want to generate your own certificates, you can use the provided certificate files for development/testing purposes)

## Dependencies

### Client:

```
Flask==3.0.2
pyzmq==25.1.1
Requests==2.31.0
urllib3==2.2.1
pycryptodome==3.20.0
```

### Server:

```
bcrypt==4.0.1
fastapi==0.110.0
mysql-connector-python==8.3.0
passlib[bcrypt]==1.7.4
pycryptodome==3.20.0
python-jose[cryptography]==3.3.0
pydantic==2.6.3
python-multipart==0.0.9
uvicorn==0.28.0
```

Refer to `requirements.txt` in the `src/client` and `src/server` folders for your environment setup.

## Running the Application

### Key Distribution and Session Management Server

A Docker image is provided to easily deploy and start the server application and the MySQL database service. Ensure you have Docker running before proceeding.
1. Open a new terminal and run `docker-compose up` from the project root folder (where the `docker-compose.yaml` file is located). You should see something like this:
![image](https://github.com/danielgrewal/SecureFileTransfer/assets/58871999/7e783506-cc1c-4efd-b3ac-5a1fd1ff8fc9)

2. Once the container is running, connect to the database using MySQL Workbench. Create a new database connection with the default connection settings. For the username, use `root` and `rootpass` for the password. Ignore any compliance warnings from MySQL Workbench if they occur. Test the connection and open the database. Once you open the database, make sure it is in context and open a new query. Your window should look like this:
![image](https://github.com/danielgrewal/SecureFileTransfer/assets/58871999/a72b25cd-dcc1-4c7b-b205-aae88b790fe2)

3. Copy the contents of the `create_db.sql` file in the `src/database` folder and paste it into the new query window in MySQL Workbench. Run the query. Refresh the schema panel on the left side of the screen and you should see the tables created by the script:
![image](https://github.com/danielgrewal/SecureFileTransfer/assets/58871999/36df2d24-4eba-49f7-8103-f65938812998)

The server is now running and the database is initialized.

### Client Program

From the `src/client` folder, run `python client.py` to start the client program. Repeat this in a seperate terminal to start a second client.
Follow the prompts in the console to authenticate with the server and begin using the file sharing system. Here is an example of a file transfer between clients.
![image](https://github.com/danielgrewal/SecureFileTransfer/assets/58871999/9f343580-0be6-461d-bbbc-ce25e967db3a)

## Disclaimer

The application uses self-signed SSL certificates for HTTPS communication in development. For production environments, use certificates signed by a trusted Certificate Authority (CA).
The verify=False parameter is used in the client's requests.post call for simplicity in development and testing. This disables SSL certificate verification and is not recommended for production use. Ensure proper certificate verification in production environments.
