# modules
import socket
import sys, os
import random

# Symmetrical crypto modules
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# RSA encryption related
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# store full directory path this python file is in
dir_path = os.path.dirname(os.path.realpath(__file__))

"""
    Client version of the Online Math exam system. 
    The client will be prompted and expected to:
        1) Give their name to the server
        2) Be given a set of 4 questions, and give a response to each question
    
    Parameters
    =============
    None

    Returns:
    None
"""
def client():
    # server information

    
    serverName = input("Enter the server host name or IP:")
    if serverName == "localhost":
        serverName = "127.0.0.1" # 'localhost'
    
    serverPort = 13000

    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print("Error in client socket creation:",e)
        sys.exit(1)
    
    try:
        # attempt to open key
       # with open(dir_path + "/key", mode='rb') as file:
        #    key = file.read()

       # cipher = AES.new(key, AES.MODE_ECB)

        # Client connect with the server
        
        clientSocket.connect((serverName, serverPort))

        # fetch Client's username and password to send to server
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        # fetch Server public key to encrypt username and password to server and verify
        serverPublicKey = RSA.import_key(open("server_public.pem").read())
        
        message = username + " " + password
        
        # encryption doesn't work simply like that.
        RSAcipher = PKCS1_OAEP.new(serverPublicKey)
        encryptedMessage = RSAcipher.encrypt(message.encode("ascii"))
        clientSocket.send(encryptedMessage)

        # receive response
        message = clientSocket.recv(2048)
        print(message)
        # if message is less than 256 bytes, we know its unencrypted
        if len(message) < 256:
            message = clientSocket.recv(2048)
            print(message.decode("ascii"))
        else:
            # receive client public key encrypted new symmetrical key
            clientPrivateKey = RSA.import_key(open(f"{username}_private.pem").read())
            clientCipher = PKCS1_OAEP.new(clientPrivateKey)
            symKey = clientCipher.decrypt(message)
            #print(message)
            
            encryptedMessage = encrypt("OK", symKey)
            clientSocket.send(encryptedMessage)

           # clientCipher = PKCS1_OAEP.new()
            print("Credentials verified")
        

      #  encryptedMessage = encrypt(message, serverPublicKey)
      #  clientSocket.send(encryptedMessage)

        



        # Client terminate connection with the server
        clientSocket.close()
    
    except socket.error as e:
        print("An error occured:", e)
        clientSocket.close()
        sys.exit(1)

"""
    Encrypt function that pads messages and encrypts them for the Server to receive

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
    Decrypts messages received from the server so that the message is readable to this specific Client

    Parameters
    =============
    message: The encrypted message to be decrypted
            - <byte> type
    key: The cipher key that is used to decrypt the message
            - <byte> type
    
    Returns:
    decryptedMessage: The decrypted message that is readable to the client
            - <string> type
"""
def decrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decryptedMessage = cipher.decrypt(message)
    decryptedMessage = unpad(decryptedMessage, 16)
    return decryptedMessage.decode("ascii")


#-------------
client()