# key generator test

# generate2048 byte key
from Crypto.PublicKey import RSA


def createKeys():
    # creates a new RSA key object (holds both public and private). need to EXPORT the key otherwise it will not be in proper format
    key = RSA.generate(2048)

    # obtain private key from the generated key pair variable, and save it. We write it in binary so that things like \n are interpreted as a new line not as any character.
    privateKeyFile = open("client2_private.pem", "wb")
    privateKeyFile.write(key.export_key("PEM"))
    privateKeyFile.close()

    # obtain public key from the generated key pair variable
    publicKeyFile = open("client2_public.pem", "wb")
    publicKeyFile.write(key.export_key("PEM"))
    publicKeyFile.close()

#---------------------------------
createKeys()