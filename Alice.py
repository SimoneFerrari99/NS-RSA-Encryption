from Crypto.PublicKey import RSA            # Algoritmo RSA
from Crypto.Random import get_random_bytes  # Generazione Random di una sequenza di Bytes
from Crypto.Cipher import AES, PKCS1_OAEP   # Algoritmo AES
from termcolor import cprint                # Printing colorato
import socket                               # Socket per comunicazione Alice-Bob
import time                                 # Introdurre delay fittizzi di esecuzione

# Legenda colori
cprint("########################### ALICE ###########################", "grey")
cprint("# Giallo:   Azione svolta da Alice                          #", "yellow")
cprint("# Verde:    Conferma positiva di una azione svolta da Alice #", "green")
cprint("# Blu:      Azione svolta da Bob, attesa da parte di Alice  #", "blue")
cprint("# Cyano:    Ricevuta conferma da Bob, sblocco di Alice      #", "cyan")
cprint("# Magenta:  Messaggio crittografato/in chiaro               #", "magenta")
cprint("# Rosso:    Errore                                          #", "red")
cprint("########################### ALICE ###########################", "grey")

# Impostazioni di esecuzione
slowMode = False if int(input("Modalità lenta (0/1): ")) == 0 else True
timer = slowMode and int(input("Timer (1..5): ")) 
timer = timer if timer >= 0 and timer <= 5 else 0
withKey = False if int(input("Stampa chiavi (0/1): ")) == 0 else True

cprint("> Modalità lenta: "+str(slowMode), "grey")
slowMode and cprint("> Timer: "+str(timer)+" secondi", "grey")
cprint("> Stampa chiavi: "+str(withKey), "grey")

input("\n> Clicca invio per continuare. ")

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
withKey and cprint("     >>> %s" % Bpbk, "grey")
slowMode and time.sleep(timer)

# Invio conferma di avvenuta ricezione della chiave pubblica di Bob
cprint("> Invio conferma ricezione chiave pubblica di Bob...", "yellow")
slowMode and time.sleep(timer)
connectionSocket.send("OK".encode("utf-8"))
cprint("  >> Conferma inviata con successo.", "green")
slowMode and time.sleep(timer)

# Generazione chiave AES di sessione ed encrypting con RSA
cprint("> Encrypting della chiave di sessione con la chiave pubblica di Bob...", "yellow")
slowMode and time.sleep(timer)
sessionKey = get_random_bytes(32)
withKey and cprint("  >> Chiave di sessione in chiaro: %s" % sessionKey, "grey")
rsa = PKCS1_OAEP.new(Bpbk)
encryptedSessionKey = rsa.encrypt(sessionKey)
cprint("  >> Encrypt della chiave completato con successo.", "green")
withKey and cprint("     >>> Chiave di sessione crittografata: %s" % encryptedSessionKey, "grey")
slowMode and time.sleep(timer)

# Inserimento messaggio da inviare a Bob
cprint("> Inizio fase scrittura messaggio crittografato...", "yellow")
slowMode and time.sleep(timer)
message = input("> Inserisci il messaggio da inviare a Bob \n  >> ")
cprint("  >> Messaggio in chiaro: %s" % message, "magenta")
slowMode and time.sleep(timer)

# Apertura del file su cui scrivere il messaggio
cprint("  >> Apertura file [encryptedMessage.bin]...", "yellow")
slowMode and time.sleep(timer)
outputFile = open("encryptedMessage.bin", "wb")
cprint("     >>> File [encryptedMessage.bin] aperto.", "green")
slowMode and time.sleep(timer)

# Encrypting del messaggio con la chiave di sessione generata e l'algoritmo AES
cprint("  >> Encripting del messaggio da scrivere...", "yellow")
slowMode and time.sleep(timer)
aes = AES.new(sessionKey, AES.MODE_EAX)
ciphertext, tag = aes.encrypt_and_digest(message.encode("utf-8"))
cprint("     >>> Encrypt del messaggio completato con successo.", "green")
slowMode and time.sleep(timer)
cprint("         >>>> Messaggio crittografato: %s" % ciphertext, "magenta")
slowMode and time.sleep(timer)

# Scrittura del messaggio crittografato e della chiave di sessione crittografata
cprint("  >> Scrittura del messaggio crittografato...", "yellow")
slowMode and time.sleep(timer)
[ outputFile.write(x) for x in (encryptedSessionKey, aes.nonce, tag, ciphertext) ]
cprint("     >>> Scrittura completata con successo.", "green")
slowMode and time.sleep(timer)

# Chiusura file di scrittura
cprint("  >> Chiusura file [encryptedMessage.bin]...", "yellow")
slowMode and time.sleep(timer)
outputFile.close()
cprint("     >>> File [encryptedMessage.bin] chiuso.", "green")
slowMode and time.sleep(timer)

# Invio conferma a Bob di avvenuta scrittura
cprint("> Invio conferma terminazione scrittura messaggio crittografato...", "yellow")
slowMode and time.sleep(timer)
connectionSocket.send("END".encode("utf-8"))
cprint("  >> Conferma inviata con successo.","green")
slowMode and time.sleep(timer)

# Chiusura connessione con Bob
cprint("> Chiusura connessione...", "yellow")
slowMode and time.sleep(timer)
connectionSocket.close()
cprint("  >> Connessione chiusa con successo.", "green")




