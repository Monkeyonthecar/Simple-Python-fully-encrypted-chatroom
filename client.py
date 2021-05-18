import time, socket

from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

#basic socket client
print('Client Server...')
time.sleep(1)
# Get the hostname, IP Address from socket and set Port
soc = socket.socket()
shost = socket.gethostname()
ip = socket.gethostbyname(shost)
# get information to connect with the server
print(shost, '({})'.format(ip))
server_host = input('Enter server\'s IP address:')
port = input("Please enter the port the server is listening on :")
port = int(port)
name = input('Enter Client\'s name: ')
print('Trying to connect to the server: {}, ({})'.format(server_host, port))
time.sleep(1)
soc.connect((server_host, port))
print("Connected...\n")
soc.send(name.encode())
server_name = soc.recv(1024)
server_name = server_name.decode()
print('{} has joined...'.format(server_name))
print('Type !leave to leave the chat room')


#initialyzing keys
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()
encrypted_key = key.export_key()

# receving server's public key
server_pubkey = soc.recv(1024)
server_pubkey = server_pubkey.decode()
print("RECEIVED SERVER'S PUBLIC KEY")

# sending public key to client
soc.send(public_key)

#receiving encrypted message
ciphertext = soc.recv(1024)
key1 = RSA.importKey(private_key)
decipher = PKCS1_OAEP.new(key1)
sym_key = decipher.decrypt(ciphertext)


while True:
    # Decrypt message from client
    totalciphermessage1 = soc.recv(1024)
    used_iv = totalciphermessage1[:16]
    totalciphermessage = totalciphermessage1[17:]
    cipher = AES.new(sym_key, AES.MODE_CBC, used_iv)
    decoded_mess = unpad(cipher.decrypt(totalciphermessage), AES.block_size)
    decoded_mess = decoded_mess.decode()
    print(server_name, '>', decoded_mess)
    # Ask input
    message = input(str("Me > "))
    message = message.encode()  # turn into bytes
    if message == b'!leave':
        print("Goodbye!")
        break
    # Encrypt message from client
    cipher = AES.new(sym_key,AES.MODE_CBC)
    used_iv = cipher.iv
    ciphermessage = cipher.encrypt(pad(message, AES.block_size)) # TAKE MAX OF 1008 CHARS PER TIME, OTHERWISE ERROR, IF THIS GETS FIXED ITS NOT SIMPLE ENOUGH
    TOTAL_MESS = used_iv + b" " + ciphermessage
    soc.send(TOTAL_MESS)
