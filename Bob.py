from turtle import color
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from termcolor import colored, cprint
import socket
import time

slowMode = True
timer = 1

cprint("############################ BOB ############################", "grey")
cprint("# Giallo:   Azione svolta da Alice, attesa da parte di Bob  #", "yellow")
cprint("# Verde:    Ricevuta conferma da Alice, sblocco di Bob      #", "green")
cprint("# Blu:      Azione svolta da Bob                            #", "blue")
cprint("# Cyano:    Conferma positiva di una azione svolta da Bob   #", "cyan")
cprint("# Magenta:  Messaggio crittografato/in chiaro               #", "magenta")
cprint("# Rosso:    Errore                                          #", "red")
cprint("############################ BOB ############################", "grey")
cprint("> SlowMode: "+str(slowMode), "grey")
cprint("> Timer: "+str(timer)+" secondi\n", "grey")

key = RSA.generate(2048)
Bpvtk = key.export_key()

Bpbk = key.publickey().export_key()

# Crea il socket "stream based" basato sul protocollo TCP ed indirizzi IPv4
connectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Binding del socket e attesa di connessione da parte del client
connectionSocket.bind(("127.0.0.1",9090))
cprint("> In attesa di connessione...", "yellow")
connectionSocket.listen()

# Avvenuta connessione da parte del processo client
(aliceConnection, aliceAddress) = connectionSocket.accept()
cprint("  >> Client connesso. (%s:%s)" % (aliceAddress[0], aliceAddress[1]), "green")

# Invio chiave pubblica di Bob
cprint("> Invio chiave pubblica di Bob ad Alice...", "blue")
slowMode and time.sleep(timer)
aliceConnection.send(Bpbk)
cprint("  >> Chiave pubblica di Bob inviata con successo.", "cyan")
slowMode and time.sleep(timer)

cprint("     >>> Attesa conferma ricezione chiave pubblica di Bob da parte di Alice...", "yellow")
slowMode and time.sleep(timer)
response = aliceConnection.recv(2048).decode("utf-8")

if response == "OK":
    cprint("         >>>> Conferma ricevuta con successo.", "green")
    slowMode and time.sleep(timer)
else:
    cprint("         >>>> ERRORE: la chiave pubblica di Bob non è stata ricevuta correttamente da Alice.", "red")
    exit()

cprint("> Alice sta scrivendo il messaggio crittografato...", "yellow")
slowMode and time.sleep(timer)
endWriting = aliceConnection.recv(2048).decode("utf-8")

if endWriting == "END":
    cprint("  >> Alice ha finito di scrivere il messaggio.", "green")
    slowMode and time.sleep(timer)
    connectionSocket.close()
    cprint("     >>> Connessione chiusa.", "green")
    slowMode and time.sleep(timer)
else:
    cprint("  >> ERRORE: Alice non è riuscita a scrivere il messaggio.", "red")
    exit()

cprint("> Inizio lettura messaggio crittografato. Apertura file [encrypted_data.bin]...", "blue")
slowMode and time.sleep(timer)
file_in = open("encrypted_data.bin", "rb")
cprint("  >> File [encrypted_data.bin] aperto.", "cyan")
slowMode and time.sleep(timer)

Bpvtk = RSA.import_key(Bpvtk)
enc_session_key, nonce, tag, ciphertext = [ file_in.read(x) for x in (Bpvtk.size_in_bytes(), 16, 16, -1) ]
cprint("     >>> Contenuto file [encrypted_data.bin] letto.", "cyan")
slowMode and time.sleep(timer)
cprint("         >>>> Messaggio crittografato: %s" % ciphertext, "magenta")
slowMode and time.sleep(timer)

# Decrypt the session key with the private RSA key
cprint("  >> Decrypting chiave di sessione con chiave privata di Bob...", "blue")
slowMode and time.sleep(timer)
cipher_rsa = PKCS1_OAEP.new(Bpvtk)
session_key = cipher_rsa.decrypt(enc_session_key)
cprint("     >>> Chiave di sessione decriptata.", "cyan")
slowMode and time.sleep(timer)

# Decrypt the data with the AES session key
cprint("  >> Decrypting messaggio con chiave di sessione...", "blue")
slowMode and time.sleep(timer)
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)
cprint("     >>> Messaggio decriptato.", "cyan")
slowMode and time.sleep(timer)

cprint("         >>>> Messaggio in chiaro: %s" % data.decode("utf-8"), "magenta")
slowMode and time.sleep(timer)

cprint("  >> Chiusura file [encrypted_data.bin]...", "blue")
file_in.close()
cprint("     >>> File [encrypted_data.bin] chiuso.", "cyan")
