from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import socket

# import hashlib

key = RSA.generate(2048)
Bpvtk = key.export_key()
# file_out = open("BobPvt.pem", "wb")
# file_out.write(Bpvtk)
# file_out.close()

Bpbk = key.publickey().export_key()
# hash_object = hashlib.sha1(public_key)
# hex_digest = hash_object.hexdigest()
# file_out = open("BobPub.pem", "wb")
# file_out.write(public_key)
# file_out.close()


bobSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Binding del socket e attesa di connessione da parte del client
bobSocket.bind(("127.0.0.1",9090))
print("> In attesa di connessione...")
bobSocket.listen()

# Avvenuta connessione da parte del processo client
(clientConnected, clientAddress) = bobSocket.accept()
print("  >> Client connesso. (%s:%s)" % (clientAddress[0], clientAddress[1]))

# Invio chiave pubblica di Bob
clientConnected.send(Bpbk)

response = clientConnected.recv(2048).decode("utf-8")

if response == "OK":
    print("  >> Chiave pubblica di Bob inviata correttamente.")

endWriting = clientConnected.recv(2048).decode("utf-8")
if endWriting == "END":
    print("  >> Ricevuto messaggio di fine scrittura.")
    bobSocket.close()
    print("  >> Connessione chiusa.")

file_in = open("encrypted_data.bin", "rb")
print("  >> Apertura file encrypted_data.bin")

Bpvtk = RSA.import_key(Bpvtk)

enc_session_key, nonce, tag, ciphertext = [ file_in.read(x) for x in (Bpvtk.size_in_bytes(), 16, 16, -1) ]

# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(Bpvtk)
session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)
print(data.decode("utf-8"))