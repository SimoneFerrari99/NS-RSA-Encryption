from turtle import color
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from termcolor import cprint
import socket
import time

# Legenda colori
cprint("############################ BOB ############################", "grey")
cprint("# Giallo:   Azione svolta da Alice, attesa da parte di Bob  #", "yellow")
cprint("# Verde:    Ricevuta conferma da Alice, sblocco di Bob      #", "green")
cprint("# Blu:      Azione svolta da Bob                            #", "blue")
cprint("# Cyano:    Conferma positiva di una azione svolta da Bob   #", "cyan")
cprint("# Magenta:  Messaggio crittografato/in chiaro               #", "magenta")
cprint("# Rosso:    Errore                                          #", "red")
cprint("############################ BOB ############################", "grey")

# Impostazioni di esecuzione
slowMode = False if int(input("Modalità lenta (0/1): ")) == 0 else True
timer = slowMode and int(input("Timer (1..5): ")) 
timer = timer if timer >= 0 and timer <= 5 else 0
withKey = False if int(input("Stampa chiavi (0/1): ")) == 0 else True

cprint("> Modalità lenta: "+str(slowMode), "grey")
slowMode and cprint("> Timer: "+str(timer)+" secondi", "grey")
cprint("> Stampa chiavi: "+str(withKey), "grey")

input("\n> Clicca invio per continuare. ")

# Generazione delle chiavi RSA di Bob
cprint("> Generazione chiavi di Bob...", "blue")
slowMode and time.sleep(timer)
key = RSA.generate(2048)
Bpvtk = key.export_key()
Bpbk = key.publickey().export_key()
cprint("  >> Chiavi di Bob generate con successo.", "cyan")
slowMode and time.sleep(timer)
withKey and cprint("     >>> %s" % Bpvtk, "grey")
withKey and cprint("     >>> %s" % Bpbk, "grey")

# Crea il socket "stream based" basato sul protocollo TCP ed indirizzi IPv4
connectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Binding del socket e attesa di connessione da parte di Alice
connectionSocket.bind(("127.0.0.1",9090))
cprint("> In attesa di connessione...", "yellow")
connectionSocket.listen()

# Avvenuta connessione da parte di Alice
(aliceConnection, aliceAddress) = connectionSocket.accept()
cprint("  >> Client connesso. (%s:%s)" % (aliceAddress[0], aliceAddress[1]), "green")

# Invio ad Alice della chiave pubblica di Bob
cprint("> Invio chiave pubblica di Bob ad Alice...", "blue")
slowMode and time.sleep(timer)
aliceConnection.send(Bpbk)
cprint("  >> Chiave pubblica di Bob inviata con successo.", "cyan")
slowMode and time.sleep(timer)

# Attesa che Alice confermi di aver ricevuto la chiave pubblica di Bob
cprint("     >>> Attesa conferma ricezione chiave pubblica di Bob da parte di Alice...", "yellow")
slowMode and time.sleep(timer)
response = aliceConnection.recv(2048).decode("utf-8")

if response == "OK":
    cprint("         >>>> Conferma ricevuta con successo.", "green")
    slowMode and time.sleep(timer)
else:
    cprint("         >>>> ERRORE: la chiave pubblica di Bob non è stata ricevuta correttamente da Alice.", "red")
    exit()

# Attesa che Alice dica di aver terminato la scrittura del messaggio
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

# Inizio lettura del messaggio e apertura del file
cprint("> Inizio lettura messaggio crittografato. Apertura file [encrypted_data.bin]...", "blue")
slowMode and time.sleep(timer)
inputFile = open("encrypted_data.bin", "rb")
cprint("  >> File [encrypted_data.bin] aperto.", "cyan")
slowMode and time.sleep(timer)

# Recupero chiave di sessione crittografata e del testo crittografato
Bpvtk = RSA.import_key(Bpvtk)
encryptedSessionKey, nonce, tag, ciphertext = [ inputFile.read(x) for x in (Bpvtk.size_in_bytes(), 16, 16, -1) ]
cprint("     >>> Contenuto file [encrypted_data.bin] letto.", "cyan")
slowMode and time.sleep(timer)
cprint("         >>>> Messaggio crittografato: %s" % ciphertext, "magenta")
slowMode and time.sleep(timer)

# Decrittazione della chiave di sessione con la chiave privata di Bob e algoritmo RSA
cprint("  >> Decrypting chiave di sessione con chiave privata di Bob...", "blue")
slowMode and time.sleep(timer)
rsa = PKCS1_OAEP.new(Bpvtk)
withKey and cprint("     >>> Chiave di sessione crittografata: %s" % encryptedSessionKey, "grey")
sessionKey = rsa.decrypt(encryptedSessionKey)
cprint("     >>> Chiave di sessione decriptata.", "cyan")
withKey and cprint("         >>>> Chiave di sessione in chiaro: %s" % sessionKey, "grey")
slowMode and time.sleep(timer)

# Decrittazione del messaggio con la chiave di sessione e algoritmo AES
cprint("  >> Decrypting messaggio con chiave di sessione...", "blue")
slowMode and time.sleep(timer)
aes = AES.new(sessionKey, AES.MODE_EAX, nonce)
data = aes.decrypt_and_verify(ciphertext, tag)
cprint("     >>> Messaggio decriptato.", "cyan")
slowMode and time.sleep(timer)

cprint("         >>>> Messaggio in chiaro: %s" % data.decode("utf-8"), "magenta")
slowMode and time.sleep(timer)

# Chiusura del file
cprint("  >> Chiusura file [encrypted_data.bin]...", "blue")
inputFile.close()
cprint("     >>> File [encrypted_data.bin] chiuso.", "cyan")
