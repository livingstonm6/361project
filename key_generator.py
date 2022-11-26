# key generator test

# generate2048 byte key
from Crypto.PublicKey import RSA


def createKeys():
    username = input("Enter username: ")
    # creates a new RSA key object (holds both public and private). need to EXPORT the key otherwise it will not be in proper format
    key = RSA.generate(2048)

    # obtain private key from the generated key pair variable, and save it. We write it in binary so that things like \n are interpreted as a new line not as any character.
    with open(username + "_private.pem", "wb") as privateKeyFile:
        privateKeyFile.write(key.export_key("PEM"))

    # obtain public key from the generated key pair variable
    with open(username + "_public.pem", "wb") as publicKeyFile:
        publicKeyFile.write(key.publickey().export_key("PEM"))

    print("Keys created for: " + username)

#---------------------------------
if __name__ == '__main__':
    createKeys()