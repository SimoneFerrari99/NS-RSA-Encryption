from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import socket

# key = RSA.generate(2048)
# private_key = key.export_key()
# file_out = open("AlicePvt.pem", "wb")
# file_out.write(private_key)
# file_out.close()

# public_key = key.publickey().export_key()
# # hash_object = hashlib.sha1(public_key)
# # hex_digest = hash_object.hexdigest()
# file_out = open("AlicePub.pem", "wb")
# file_out.write(public_key)
# file_out.close()

# Crea il socket "stream based" basato sul protocollo TCP ed indirizzi IPv4
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connetto il client al server
print("> Connessione... ")  

 
clientSocket.connect(("127.0.0.1",9090))
print( "> Connessione eseguita" )

# Recupero chiave pubblica di Bob
Bpbk = RSA.import_key(clientSocket.recv(2048))

clientSocket.send("OK".encode("utf-8"));

session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(Bpbk)
enc_session_key = cipher_rsa.encrypt(session_key)

data = "Hello Word".encode("utf-8")
file_out = open("encrypted_data.bin", "wb")

# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
file_out.close()
clientSocket.send("END".encode("utf-8"))






