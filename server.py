import time, socket

from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

#basic socket server
print('Setup Server...')
time.sleep(1)
#Get the hostname, IP Address from socket and set Port
soc = socket.socket()
host_name = socket.gethostname()
ip = socket.gethostbyname(host_name)
port = input("Please enter the port the server has to listen on :")
port = int(port)
soc.bind((host_name, port))
print(host_name, '({})'.format(ip))
name = input('Enter server\'s name: ')
soc.listen(1) #Try to locate using socket
print('Waiting for incoming connections...')
connection, addr = soc.accept()
print("Received connection from ", addr[0], "(", addr[1], ")\n")
print('Connection Established. Connected From: {}, ({})'.format(addr[0], addr[0]))
#get a connection from client side
client_name = connection.recv(1024)
client_name = client_name.decode()
print(client_name + ' has connected.')
print('Type !leave to leave the chat room')
connection.send(name.encode())
print("Creating keys...")

#change this key if you want, as long it is 16bytes(128bits) or 24(192bits) or 32byte(256bits)
sym_key = b'16bytepasswordd!'

#__________________________________ASSYMETRIC ENCRYPTION PART_______________
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()
encrypted_key = key.export_key()
# sending public key to client
connection.send(public_key)

#receiving public code
server_pubkey = connection.recv(1024)
server_pubkey = server_pubkey.decode()
print("RECEIVED PUBLIC KEY")

key1 = RSA.importKey(server_pubkey)
cipher = PKCS1_OAEP.new(key1)
en_mess = cipher.encrypt(sym_key) # HERE ASSYMETRIC ENCRYPTION PART STOPS AND SYMMETRIC ENCRYPTION GO ON (SYMMETRIC KEY IS SECURELY RECEIVED)
connection.send(en_mess)

while True:
    # User input
    message = input(str("Me > "))
    message = message.encode()  # turn into bytes
    if message == b'!leave':
        print("Goodbye!")
        break
    # Encrypt message towards client
    #cipher = AES.new(sym_key, AES.MODE_CBC)
    cipher = AES.new(sym_key, AES.MODE_CBC)
    used_iv = cipher.iv
    ciphermessage = cipher.encrypt(pad(message,AES.block_size))  # TAKE MAX OF 1008 CHARS PER TIME, OTHERWISE ERROR, IF THIS GETS FIXED ITS NOT SIMPLE ENOUGH
    connection.send(used_iv)
    connection.send(ciphermessage)
    # Decrypt message from server
    used_iv = connection.recv(1024)
    totalciphermessage = connection.recv(1024)
    cipher = AES.new(sym_key, AES.MODE_CBC, used_iv)
    decoded_mess = unpad(cipher.decrypt(totalciphermessage), AES.block_size)
    decoded_mess = decoded_mess.decode()
    print(client_name, '>', decoded_mess)
