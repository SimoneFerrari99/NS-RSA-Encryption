from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import socket
import time

key = RSA.generate(2048)
Apvtk = key.export_key()

Apbk = key.publickey().export_key()

# Crea il socket "stream based" basato sul protocollo TCP ed indirizzi IPv4
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connetto il client al server
connected = False
while not connected:
    try:
        print("> Connessione... ") 
        clientSocket.connect(("127.0.0.1",9090))
        print( "  >> Connessione eseguita" )
        connected = True
    except:
        print("  >> Connessione fallita. Riprovo in 5 secondi...")
        time.sleep(5)

time.sleep(1)
# Recupero chiave pubblica di Bob
print("> Recupero chiave pubblica di Bob...")
Bpbk = RSA.import_key(clientSocket.recv(2048))
time.sleep(3)
print("  >> Chiave pubblica di Bob recuperata.")

time.sleep(1)
print("> Invio conferma ricezione chiave pubblica di Bob...")
clientSocket.send("OK".encode("utf-8"));
time.sleep(3)
print("  >> Conferma ricezione chiave pubblica di Bob inviata.")


# Encrypt the session key with the public RSA key
time.sleep(1)
print("> Encrypting della chiave di sessione con la chiave pubblica di Bob...")
session_key = get_random_bytes(16)

cipher_rsa = PKCS1_OAEP.new(Bpbk)
enc_session_key = cipher_rsa.encrypt(session_key)
time.sleep(3)
print("  >> Chiave di sessione crittografata con la chiave pubblica di Bob.")

time.sleep(1)
print("> Inizio scrittura messaggio crittografato. Apertura file [encrypted_data.bin]...")
data = "Ciao Bob, come stai?".encode("utf-8")
file_out = open("encrypted_data.bin", "wb")

# Encrypt the data with the AES session key
time.sleep(3)
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
print("  >> Messaggio crittografato scritto correttamente." )
file_out.close()
print("     >> Chiusura file [encrypted_data.bin].")

time.sleep(1)
print("> Invio conferma terminazione scrittura messaggio crittografato...")
time.sleep(3)
clientSocket.send("END".encode("utf-8"))
print("  >> Conferma terminazione scrittura messaggio crittografato inviata.")






