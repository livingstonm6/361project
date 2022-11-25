"""
    Email system (Server side)
    
    Server side email system that allows Client's to send emails to each other and view the emails. 
    This utilizes encryption to verify the identity of Server and Client, and terminates the connection immediately if either side cannot verify themselves.


    Author: Alex Creencia, 

"""


# modules

import socket 
import sys
import os, glob, datetime
import json

# Symmetrical crypto modules
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# RSA crypto modules
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
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
                    try:
                        # Encrypt using RSA Public Key for the final time
                        clientPublicKey = RSA.import_key(open(f"{clientInfo[0]}_public.pem").read())
                        clientCipher = PKCS1_OAEP.new(clientPublicKey)
                        encryptedMessage = clientCipher.encrypt(symKey)
                        connectionSocket.send(encryptedMessage)
                        print(f"Connection Accepted and Symmetric Key Generated for client: {clientInfo[0]}")

                        # receive the symmetrical encryption starting here
                        encryptedMessage = connectionSocket.recv(2048)
                        message = decrypt(encryptedMessage, symKey)
                        #print(message)
                        
                        # Email system starts here
                        clientChoice = "1"
                        while clientChoice != "4":
                            # send menu
                            emailMenu = emailOptions()
                            encryptedMenu = encrypt(emailMenu, symKey)
                            connectionSocket.send(encryptedMenu)

                            # receive client choice
                            encryptedMessage = connectionSocket.recv(2048)
                            clientChoice = decrypt(encryptedMessage, symKey)
                            
                            # split subprotocols here
                            if clientChoice == "1":
                                print("They chose 1")
                                sendingEmailSubprotocol(connectionSocket, clientInfo[0], symKey)
                                print("After sendEmailSubprotocol")

                            elif clientChoice == "2":
                                print("they chose 2")
                            else:
                                print("they chose 3")
                        
                        # terminate connection since Client chose "4"
                        terminationSubprotocol(clientInfo[0])
                        connectionSocket.close()
                    except Exception as e:
                        print("encryption went wrong", e) 



                else:
                    # Send an unencrypted message to client
                    connectionSocket.send("Invalid username or password".encode("ascii"))
                    print(f"The received client information: {clientInfo[0]} is invalid (Connection Terminated)")



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
    Sending Email Subprotocol

    Subprotocol for handling email sending from one Client to another Client.

    Parameters
    =============
    key: The key used to encrypt/decrypt for the email exchange
            - <byte> type
    
    clientUsername: The username of the client the socket is connected to (Mainly used for server logging)
            - <string> type
            
    socket: The connection socket between client and server
            - <socket> type
    
    
    Returns:
    None
"""
def sendingEmailSubprotocol(socket, clientUsername, key):
    encryptedMessage = encrypt("Send the email", key)
    socket.send(encryptedMessage)

    encryptedMessage = socket.recv(2048)
    expectedByteSize = int(decrypt(encryptedMessage, key))
    print(f"this is expectedByteSize to receive: {expectedByteSize}")

    encryptedMessage = encrypt("email size received", key)
    socket.send(encryptedMessage)


    # receive email contents now that we know the expected email size
    receivedBytes = 0
    email = ""
    while receivedBytes < expectedByteSize:
        encryptedMessage = socket.recv(2048)
        email += decrypt(encryptedMessage, key)
        receivedBytes += len(email)

    # received email. Need to extract the necessary fields from the email
    destination, emailContentLen = extractEmailFields(email)
    print(f"\nAn email from {clientUsername} is sent to {destination} has a content length of {emailContentLen}.\n")

    # need to add the time and date to the email. It needs to become the new field in the 3rd index, so it must be swapped
    formattedEmail = addTimestampEmail(email)
    print(formattedEmail) #DEBUG: for showing/debug the email. 
  
    return

"""
    Inserts date and time received field of the email into the proper order

    Parameters
    =============
    email: the email the source client sent
            - <string> type

    Returns:

    
"""
def addTimestampEmail(email):
    timestamp = datetime.datetime.now()
    emailTimestampField = f"Time and Date: {timestamp} "
    emailFieldsWithHeaders = email.split("\n", 6)
    formattedEmail = emailFieldsWithHeaders[0] + "\n" + emailFieldsWithHeaders[1] + "\n" + emailTimestampField + emailFieldsWithHeaders[2] + "\n" + emailFieldsWithHeaders[3] + "\n" + emailFieldsWithHeaders[4] + "\n" + emailFieldsWithHeaders[5] + "\n"
    return formattedEmail

"""
    Extract neccessary email fields from the email headers to log (server side)

    Parameters
    =============
    email: a message containing the email as a whole
            - <string> type
    
    Returns:

"""
def extractEmailFields(email):
    emailFieldsWithHeaders = email.split("\n", 4)
    destinationUsernames = emailFieldsWithHeaders[1]
    destinationUsernames = destinationUsernames.split("To: ", 1)[-1]

    contentLengthWithHeader = emailFieldsWithHeaders[3]
    contentLength = contentLengthWithHeader.split("Content Length: ", 1)[-1]
    return destinationUsernames, contentLength

"""
    Email Menu

    Creates a menu string to send to the Client

    Parameters
    =============
    None

    Returns:
    emailMenu: a string holding the menu options the Client can use
            - <string> type
"""
def emailOptions():
    emailMenu = """
    Select the operation:
    \t1) Create and send an email
    \t2) Display the inbox list
    \t3) Display the email contents
    \t4) Terminate the connection choice:
    choice: 
    """
    return emailMenu

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

"""
    Creates and sends a message to the client describing the connection between the server and the client is to be terminated.
    Also prints it out for the server side to see.
    *** mainly exists for maintainability and readability ***
    
    Parameters
    =============
    None

    Returns:
    None
"""
def terminationSubprotocol(clientUsername):
    print(f"Terminating connection with {clientUsername}.")
    return

#----------
server()