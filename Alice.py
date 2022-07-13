from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from termcolor import colored, cprint
import socket
import time

slowMode = True
timer = 1

cprint("########################### ALICE ###########################", "grey")
cprint("# Giallo:   Azione svolta da Alice                          #", "yellow")
cprint("# Verde:    Conferma positiva di una azione svolta da Alice #", "green")
cprint("# Blu:      Azione svolta da Bob, attesa da parte di Alice  #", "blue")
cprint("# Cyano:    Ricevuta conferma da Bob, sblocco di Alice      #", "cyan")
cprint("# Magenta:  Messaggio crittografato/in chiaro               #", "magenta")
cprint("# Rosso:    Errore                                          #", "red")
cprint("########################### ALICE ###########################", "grey")
cprint("> SlowMode: "+str(slowMode), "grey")
cprint("> Timer: "+str(timer)+" secondi", "grey")

input("\n> Clicca invio per continuare. ")


key = RSA.generate(2048)
Apvtk = key.export_key()

Apbk = key.publickey().export_key()

# Crea il socket "stream based" basato sul protocollo TCP ed indirizzi IPv4
connectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connetto il client al server
connected = False
while not connected:
    try:
        cprint("> Connessione... ", "yellow")
        connectionSocket.connect(("127.0.0.1",9090))
        cprint("  >> Connessione eseguita", "green")
        connected = True
    except:
        cprint("  >> Connessione fallita. Riprovo in 5 secondi...", "red")
        time.sleep(5)

# Recupero chiave pubblica di Bob
cprint("> Attesa chiave pubblica di Bob...", "blue")
Bpbk = RSA.import_key(connectionSocket.recv(2048))
cprint("  >> Chiave pubblica di Bob ricevuta.", "cyan")
slowMode and time.sleep(timer)

cprint("> Invio conferma ricezione chiave pubblica di Bob...", "yellow")
slowMode and time.sleep(timer)
connectionSocket.send("OK".encode("utf-8"))
cprint("  >> Conferma inviata con successo.", "green")
slowMode and time.sleep(timer)


# Encrypt the session key with the public RSA key
cprint("> Encrypting della chiave di sessione con la chiave pubblica di Bob...", "yellow")
slowMode and time.sleep(timer)
session_key = get_random_bytes(16)
cipher_rsa = PKCS1_OAEP.new(Bpbk)
enc_session_key = cipher_rsa.encrypt(session_key)
cprint("  >> Encrypt della chiave completato con successo.", "green")
slowMode and time.sleep(timer)

cprint("> Inizio fase scrittura messaggio crittografato...", "yellow")
slowMode and time.sleep(timer)
data = input("> Inserisci il messaggio da inviare a Bob \n  >> ")
cprint("  >> Messaggio in chiaro: %s" % data, "magenta")
slowMode and time.sleep(timer)

cprint("  >> Apertura file [encrypted_data.bin]...", "yellow")
slowMode and time.sleep(timer)
file_out = open("encrypted_data.bin", "wb")
cprint("     >>> File [encrypted_data.bin] aperto.", "green")
slowMode and time.sleep(timer)


# Encrypt the data with the AES session key
cprint("  >> Encripting del messaggio da scrivere...", "yellow")
slowMode and time.sleep(timer)
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode("utf-8"))
cprint("     >>> Encrypt del messaggio completato con successo.", "green")
slowMode and time.sleep(timer)
cprint("         >>>> Messaggio crittografato: %s" % ciphertext, "magenta")
slowMode and time.sleep(timer)

cprint("  >> Scrittura del messaggio crittografato...", "yellow")
slowMode and time.sleep(timer)
[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
cprint("     >>> Scrittura completata con successo.", "green")
slowMode and time.sleep(timer)

cprint("  >> Chiusura file [encrypted_data.bin]...", "yellow")
slowMode and time.sleep(timer)
file_out.close()
cprint("     >>> File [encrypted_data.bin] chiuso.", "green")
slowMode and time.sleep(timer)

cprint("> Invio conferma terminazione scrittura messaggio crittografato...", "yellow")
slowMode and time.sleep(timer)
connectionSocket.send("END".encode("utf-8"))
cprint("  >> Conferma inviata con successo.","green")
slowMode and time.sleep(timer)

cprint("> Chiusura connessione...", "yellow")
slowMode and time.sleep(timer)
connectionSocket.close()
cprint("  >> Connessione chiusa con successo.", "green")




