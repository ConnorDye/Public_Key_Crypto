from ast import Constant
from lib2to3.pgen2.token import NEWLINE
from random import randrange
from unittest import result
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto import Random
import os
import urllib
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
import codecs
from Crypto.Hash import SHA256

# create_public_key_userA will use a randomly generated Xa between 1 and q
def create_public_key_userA(q, a):
    private_Xa = randrange(1, q)
    public_key_userA = pow(a, private_Xa, q)
    return public_key_userA, private_Xa

def create_public_key_userB(q, a):
    private_Xb = randrange(1, q)
    public_key_userB = pow(a, private_Xb, q)
    return public_key_userB, private_Xb

# Secret Key of User A will use User B's public key and the private_Xa 
# generated while creating User A's public key to create the secret key
def create_secret_key_userA(q,  private_Xa, public_key_userB):
    int_sha_input = pow(public_key_userB, private_Xa, q)
    sha_input = str(int_sha_input)
    sha_input = sha_input.encode()
    
    h = SHA256.new()
    h.update(sha_input)
    secret_key_userA = bytearray( h.hexdigest() , "UTF-8" )
    secret_key_userA = secret_key_userA[0:16]
    return secret_key_userA

# Secret Key of User B will use User A's public key and the private_Xb 
# generated while creating User B's public key to create the secret key, sent to the SHA256 hash function
def create_secret_key_userB(q,  private_Xb, public_key_userA):
    int_sha_input = pow(public_key_userA, private_Xb, q)
    sha_input = str(int_sha_input)
    sha_input = sha_input.encode()
    h = SHA256.new()
    h.update(sha_input)

    # Transform secret key of userB to bytes so we can truncate it to 16 bytes
    secret_key_userB = bytearray( h.hexdigest() , "UTF-8" )
    secret_key_userB = secret_key_userB[0:16]
    return secret_key_userB

#In this function, user B should be able to decrypt a message sent by user A when user A encrypts it using User B's public key
def task1_diffie_hellman():
    print("Generate Key Exchange")
    q = int ("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    a = int ("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    #1.) Generate the public keys based on q and a
    public_key_userA, private_Xa = create_public_key_userA(q, a)
    public_key_userB, private_Xb = create_public_key_userB(q, a)

    #2.) Generate the private keys based on public keys
    secret_key_userA = create_secret_key_userA(q,  private_Xa, public_key_userB)
    secret_key_userB = create_secret_key_userB(q,  private_Xb, public_key_userA)
    
    #3.) Test to see if shared private key is equal
    print("Secret Key for User A is: ", secret_key_userA)
    print("Secret Key for User B is: ", secret_key_userB)

    #4.) User B encrypts a message to send to userA
    bobs_message_to_encrypt = b'Hello Alice'
    iv = os.urandom(16)
    cipher = AES.new(secret_key_userB, AES.MODE_CBC, iv)
    padded_message_to_encrypt = pad(bobs_message_to_encrypt, AES.block_size, 'pkcs7')
    userB_encrypted_message = cipher.encrypt( padded_message_to_encrypt)
    print("Bob's encrypted message: ", userB_encrypted_message)

    #5.) User A should be able to decrypt User B's message
    cipher = AES.new(secret_key_userA, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt( userB_encrypted_message)
    decrypted_message = unpad(decrypted_message, AES.block_size, 'pkcs7')
    decrypted_message = str(decrypted_message, "utf-8")
    print("After Alice decrypts Bob's encrypted message: ", decrypted_message)
   
    #6.) User A (Alice) encrypts a message  to send to userB (Bob)
    alice_message_to_encrypt = b'Hello Bob'
    iv = os.urandom(16)
    cipher = AES.new(secret_key_userA, AES.MODE_CBC, iv)
    padded_message_to_encrypt = pad(alice_message_to_encrypt, AES.block_size, 'pkcs7')
    userA_encrypted_message = cipher.encrypt( padded_message_to_encrypt)
    print("Alice's encrypted message: ", userA_encrypted_message)

    #7.) User B (Bob) should be able to decrypt User A's (Alice's) message
    cipher = AES.new(secret_key_userB, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt( userA_encrypted_message)
    decrypted_message = unpad(decrypted_message, AES.block_size, 'pkcs7')
    decrypted_message = str(decrypted_message, "utf-8")
    print("After Bob decrypts Alice's encrypted message: ", decrypted_message)



def main():
    task1_diffie_hellman()

main()