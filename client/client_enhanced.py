# modules
import socket
import sys, os

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

    
    serverName = input("Enter the server host name or IP: ")
    if serverName == "localhost":
        serverName = "127.0.0.1" # 'localhost'
    
    serverPort = 13000

    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print("Error in client socket creation:",e)
        sys.exit(1)
    
    try:

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
        #print(message)
        # if message is less than 256 bytes, we know its unencrypted
        if len(message) < 256:
            message = clientSocket.recv(2048)
            print(message.decode("ascii"))
        else:
            # receive client public key encrypted new symmetrical key
            clientPrivateKey = RSA.import_key(open(f"{username}_private.pem").read())
            clientCipher = PKCS1_OAEP.new(clientPrivateKey)
            symKey = clientCipher.decrypt(message)
           
            
            encryptedMessage = encrypt("OK", symKey)
            clientSocket.send(encryptedMessage)
    
            # begin email system
            clientChoice = "1"
            while clientChoice != "4":
                # obtain menu if first loop or if client chose 1
                if clientChoice not in ["2", "3"]:
                    encryptedMessage = clientSocket.recv(2048)
                    menu = decrypt(encryptedMessage, symKey)
                    print(menu, end='')

                # obtain client choice
                clientChoice = validateClientChoice()
                encryptedMessage = encrypt(clientChoice, symKey)
                clientSocket.send(encryptedMessage)

                # execute subprotocols based on client choice here
                if clientChoice == "1":
                    sendingEmailSubprotocol(clientSocket, symKey, username)

                elif clientChoice == "2":
                    # view list subprotocol
                    receiveAndPrintMessage(clientSocket, symKey)

                elif clientChoice == "3":
                    # view email contents subprotocol
                    viewEmailSubprotocol(clientSocket, symKey)

            # Client chose option 4
            terminationSubprotocol()
            clientSocket.close()
                
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
    Sending Email Subprotocol
    
    Handles obtaining necessary information from Client to send an email, and formats it to specifications to be sent to server which is then sent to the desired Client

    Parameters
    =============
    Socket: The connection socket between Client and Server
            - <socket> type
    key: the key used for encryption
            - <byte> type
    clientUsername: the username of the source client
            - <string> type
"""
def sendingEmailSubprotocol(socket, key, clientUsername):
    # receive the Send email message
    encryptedMessage = socket.recv(2048)
    message = decrypt(encryptedMessage, key)

    email, emailByteSize = fetchEmailInfo(clientUsername)
    #print(email)
    # send file size before sending over email so the server knows how many bytes are being sent
    encryptedMessage = encrypt(emailByteSize, key)
    socket.send(encryptedMessage)

    # need to receive an okay response, otherwise server will be left hanging receiving
    encryptedMessage = socket.recv(2048)
    message = decrypt(encryptedMessage, key)

    # start sending email. Since message contents can range, we must ensure all the data is sent 
    encryptedMessage = encrypt(email, key)
    bytesSent = 0
    while bytesSent < int(emailByteSize):
        bytesSent += socket.send(encryptedMessage)

    print("The message has been sent to the server.")
    return

"""
    Obtains necessary email information from client, to be send to the server

    Parameters
    =============

    Returns:

"""
def fetchEmailInfo(clientUsername):
    clientDestination = input("Please enter email destinations (separated by ;): ")
    emailTitle = input("Please enter title of Email: ")
    fileOrTerminalInput = input("Would you like to load contents from a file? (Y/N): ").upper()
    while fileOrTerminalInput not in ["Y", "N"]:
        print("Error: must enter either Y or N")
        fileOrTerminalInput = input("Would you like to load contents from a file? (Y/N): ").upper()
    # if client is entering message contents through terminal

    while True:
        if fileOrTerminalInput == "N":
            messageContents = input("Enter message contents (1000000 character limit): ")
            while len(messageContents) > 1000000:
                print("ERROR: Message length is too long. Please limit to 1000000 characters.")
                messageContents = input("Enter message contents (1000000 character limit): ")
        else:
            fileName = input("Please enter filename: ")
            filePath = dir_path + "/" + fileName
            if os.path.isfile(filePath):
                with open(fileName, "r") as file:
                    messageContents = file.read()
            else:
                messageContents = ""
        if len(messageContents) > 1000000:
            print("ERROR: Message length is too long. Please limit to 1000000 characters.")
        elif len(messageContents) == 0:
            print("ERROR: Invalid message or file. Please try again.")
        else:
            break
    # structure email according to standards
    email = formatEmail(clientDestination, emailTitle, messageContents, clientUsername)
    return email, str(sys.getsizeof(email))
"""
    Formats the email information into a string, to be sent to the server

    Parameters
    =============
    clientDestination: the clients the email is being sent to
            - <string> type
    emailTitle: the title of the email
            - <string> type
    messageContents: the contents of the email
            - <string> type
    clientUsername: The username of the source client who is sending the message
            - <string> type
    
    Returns:
    formattedEmail: a string that has the properly formatted email to be sent to the server
            - <string> type
"""
def formatEmail(clientDestination, emailTitle, messageContents, clientUsername):
    contentLength = len(messageContents)
    email = f"From: {clientUsername} \nTo: {clientDestination} \nTitle: {emailTitle} \nContent Length: {contentLength} \nContent: \n{messageContents}\n"
    return email

"""
    View Email Subprotocol

    Prompts the user to enter an index corresponding to an email
    in their inbox, sends it to the server, then prints the
    server's response: either the email, or an error message.

    Parameters
    =============
    clientSocket: the socket used to communicate with the server
            - <socket> type
    key: the symmetric key used for encryption
            - <byte> type

    Returns:
    Nothing
"""

def viewEmailSubprotocol(clientSocket, key):
    # get prompt for index from server, or error message
    message = receiveAndPrintMessage(clientSocket, key)
    if message[:40] == "Please view an email in the email list.\n":
        return
    # get index from user and send to server
    index = input('')
    encryptedMessage = encrypt(index, key)
    clientSocket.send(encryptedMessage)
    # receive email or error message from server
    receiveAndPrintMessage(clientSocket, key)

    return


"""
    Prints a message to signify to Client that the connection to the server is being terminated.
    ** This function mainly exists for future maintainability if additional features added to termination subprotocol***

    Parameters
    ============
    None

    Returns:
    None
"""
def terminationSubprotocol():
    print("The connection is terminated with the server.")
    return

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


"""
    Receives a message from the server program, decrypts it, then
    prints it to the client user.

    Parameters
    =============
    clientSocket: The socket used to communicate with the server
            - <socket> type
    key: The cipher key that is used to decrypt the message
            - <byte> type

    Returns:
    message: the message send by the server program
            - <string> type
"""

def receiveAndPrintMessage(clientSocket, key):
    encryptedMessage = clientSocket.recv(2048)
    message = decrypt(encryptedMessage, key)
    print(message, end='')
    return message

"""
    validateClientChoice

    verifies the Client choice to either {1, 2, 3, 4}, and will constantly reprompt client if the input is outside of these values

    Parameters
    =============
    menu: the email options the Client can choose from by inputting their choice of {1, 2, 3, 4}
            - <string> type
    
    Returns:
    clientChoice: The selected choice/subprotocol of the Client
            - <string> type
"""
def validateClientChoice():
    clientChoice = input()
    while clientChoice not in {"1", "2", "3", "4"}:
        print("Invalid choice. Please choose between 1, 2, 3 or 4.")
        clientChoice = input()
    return clientChoice
#-------------
client()