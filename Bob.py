from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import socket
import time

# import hashlib

key = RSA.generate(2048)
Bpvtk = key.export_key()

Bpbk = key.publickey().export_key()


bobSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Binding del socket e attesa di connessione da parte del client
bobSocket.bind(("127.0.0.1",9090))
print("> In attesa di connessione...")
bobSocket.listen()

# Avvenuta connessione da parte del processo client
(clientConnected, clientAddress) = bobSocket.accept()
print("  >> Client connesso. (%s:%s)" % (clientAddress[0], clientAddress[1]))

# Invio chiave pubblica di Bob
print("> Invio chiave pubblica di Bob al client...")
clientConnected.send(Bpbk)
print( "  >> Chiave pubblica di Bob inviata." )

print("> Attesa conferma ricezione chiave pubblica di Bob...")
response = clientConnected.recv(2048).decode("utf-8")
print( "  >> Conferma ricezione chiave pubblica di Bob ricevuta." )

if response == "OK":
    print("     >> Chiave pubblica di Bob inviata correttamente.")
else:
    print("     >> Chiave pubblica di Bob inviata con errore.")
    exit()

print("> Attesa conferma terminazione scrittura messaggio crittografato...")
endWriting = clientConnected.recv(2048).decode("utf-8")

if endWriting == "END":
    print("  >> Ricevuto messaggio di fine scrittura correttamente.")
    bobSocket.close()
    print("     >> Connessione chiusa.")
else:
    print("  >> Ricevuto messaggio di fine scrittura con errore.")
    exit()

print("> Inizio lettura messaggio crittografato. Apertura file [encrypted_data.bin]...")
file_in = open("encrypted_data.bin", "rb")
time.sleep(1)
print("  >> File [encrypted_data.bin] aperto.")

time.sleep(3)
Bpvtk = RSA.import_key(Bpvtk)
enc_session_key, nonce, tag, ciphertext = [ file_in.read(x) for x in (Bpvtk.size_in_bytes(), 16, 16, -1) ]
print("  >> Contenuto file [encrypted_data.bin] letto.")
print("     >> Dati crittografati: %s" % ciphertext)

time.sleep(1)
# Decrypt the session key with the private RSA key
print("  >> Decriptazione chiave di sessione con chiave privata di Bob...")
time.sleep(2)
cipher_rsa = PKCS1_OAEP.new(Bpvtk)
session_key = cipher_rsa.decrypt(enc_session_key)
print("     >> Chiave di sessione decriptata.")

time.sleep(1)
# Decrypt the data with the AES session key
print("  >> Decriptazione dati con chiave di sessione...")
time.sleep(2)
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)
print("     >> Dati decriptati.")

print("> Dati decriptati: %s" % data.decode("utf-8"))

time.sleep(1)
file_in.close()
print("  >> File [encrypted_data.bin] chiuso.")
