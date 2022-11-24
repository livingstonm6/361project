"""
    Email system (Server side)
    
    Server side email system that allows Client's to send emails to each other and view the emails. 
    This utilizes encryption to verify the identity of Server and Client, and terminates the connection immediately if either side cannot verify themselves.


    Author: Alex Creencia, 

"""


# modules

import socket 
import sys
import os
import random
import json

# Symmetrical crypto modules
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# RSA crypto modules
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
# store full directory path this python file is in
dir_path = os.path.dirname(os.path.realpath(__file__))

def server():
    # Server port
    serverPort = 13000

    # Create server socket that uses IPv4 and TCP protocols

    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print("Error in server socket creation:", e)
        sys.exit(1)
    
    # associate 13000 port number to the server socket

    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print("Error in server socket binding:", e)
        sys.exit(1)
    
    print("The server is ready to accept connections")

    # The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)

    while 1:
        try:
            # Server accepts client connection
            connectionSocket, addr = serverSocket.accept()

            # obtain encryption key
            #with open(dir_path + "/key", mode='rb') as file: 
            #    key = file.read()
            #cipher = AES.new(key, AES.MODE_ECB)
            
            # obtain server private key
            serverPrivateKey = RSA.import_key(open("server_private.pem").read())


            pid = os.fork()

            # If it is a client/child process
            if pid == 0:
                serverSocket.close()

                # connection is established with client and server, server receives RSA encrypted client username + password 
                encryptedMessage = connectionSocket.recv(2048)
                serverCipher = PKCS1_OAEP.new(serverPrivateKey)
                message = serverCipher.decrypt(encryptedMessage)
                message = message.decode("ascii")

                print("decrypted Message")

                # Verify if credentials are correct
                clientInfo = message.split(" ")
                if credentials(clientInfo[0], clientInfo[1]):
                    # credentials are verified, start symmetrical encryption using AES. 

                    # need to generate a key of 32 bytes for 256 AES symmetrical key, rather than 16 (which would be for 128 AES sym key)
                    symKey = get_random_bytes(32)
                    print(f"symKey: {symKey}")
                    try:
                        # Encrypt using RSA Public Key for the final time
                        clientPublicKey = RSA.import_key(open(f"{clientInfo[0]}_public.pem").read())
                        clientCipher = PKCS1_OAEP.new(clientPublicKey)
                        encryptedMessage = clientCipher.encrypt(symKey)
                        connectionSocket.send(encryptedMessage)
                        print(f"Connection Accepted and Symmetric Key Generated for client: {clientInfo[0]}")

                        # receive the symmetrical encryption starting here
                        encryptedMessage = connectionSocket.recv(2048)
                        message = decrypt(encryptedMessage)

                        # Email system starts here


                    except:
                        print("encryption went wrong")



                else:
                    # Send an unencrypted message to client
                    connectionSocket.send("Invalid username or password".encode("ascii"))
                    print(f"The received client information: {clientInfo[0]} is invalid (Connection Terminated)")


                # message contains client's user name and password

                # Client has chosen to terminate, thus server should terminate connection Socket on its end
                connectionSocket.close()
                return

            connectionSocket.close()
        
        except socket.error as e:
            print("An error occured:", e)
            serverSocket.close()
            sys.exit(1)
        except:
            print("Goodbye")
            serverSocket.close()
            sys.exit(0)

"""

"""


"""
    Opens a json file containing registered Clients user and pass, by passing it into a dictionary and verifying it is within the key:value pairs.
    Depending on whether they are found within the dictionary or not, returns either True or False
    
    Parameters
    =============
    username: the Client's username
            - <string> type
    password: the Client's password
            - <string> type
    
    Returns:
    True/False: Boolean value of whether Client's credentials are correct

"""
def credentials(username, password):
    credentialsFile = open("user_pass.json")
    credentialDict = json.load(credentialsFile)
    
    # verify username and password
    if username in credentialDict:
        if password == credentialDict[username]:
            return True
    else:
        return False


"""
    ECB Encrypt function that pads messages and encrypts them for the Client to receive

    Parameters
    =============
    message: the desired message to be encrypted
            - <string> type
    key: The cipher key that is used to encrypt the message
            - <byte> type

   Returns:
    encryptedMessage - the encrypted message to be sent to server
            - <byte> type
"""
def encrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encryptedMessage = message.encode("ascii")
    encryptedMessage = cipher.encrypt(pad(encryptedMessage, 16))
    return encryptedMessage

"""
    ECB Decrypt Function. Decrypts messages received from the client so that the message can be used.

    Parameters
    =============
    message: The encrypted message to be decrypted
            - <byte> type
    key: The cipher key that is used to decrypt the message
            - <byte> type

    [OPTIONAL PARAMETERS]
    name: The name of the client. This is used in conjuction with the helper function serverOutput to log
          who is sending the messages, and the contents of their messages.
            - <string> type


    Returns:
    decryptedMessage: The decrypted message that is readable to the client
            - <string> type
"""
def decrypt(message, key, name=None):
    cipher = AES.new(key, AES.MODE_ECB)
    decryptedMessage = cipher.decrypt(message)
    decryptedMessage = unpad(decryptedMessage, 16)
    decryptedMessage = decryptedMessage.decode("ascii")
    return decryptedMessage
   # return decryptedMessage.decode("ascii")


#----------
server()