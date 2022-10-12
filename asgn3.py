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
from Crypto.Util import number

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
    print("Task 1: Generate Key Exchange Between Alice and Bob")
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

def Mallory_Adversary_ABvalues():
    num_to_tamper1 = 10230
    num_to_tamper2 = 10439
    return num_to_tamper1, num_to_tamper2

def Mallory_Adversary_qvalue():
    num_to_tamper = 1
    return num_to_tamper

def Mallory_Adversary_Decryption(secret_key, iv,  encrypted_message):
    print("\nSince Malory Changed p to be 1, she can mathematically compute the other variables to find the secret key...")
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt( encrypted_message)
    decrypted_message = unpad(decrypted_message, AES.block_size, 'pkcs7')
    decrypted_message = str(decrypted_message, "utf-8")
    print("Mallory decryptes the messages after changing p to be 1", decrypted_message)
    
def task2_diffie_hellman():
    print("Task 2: Mallory Interferes with A and B")
    q = int ("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    a = int ("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    #1.) Generate the public keys based on q and a
    public_key_userA, private_Xa = create_public_key_userA(q, a)
    public_key_userB, private_Xb = create_public_key_userB(q, a)

    #2.) MALLORY CHANGES THE A and B SO SHE CAN DISRUPT THE MESSAGING
    public_key_userA, public_key_userB = Mallory_Adversary_ABvalues()

    #3.) Generate the private keys based on public keys
    secret_key_userA = create_secret_key_userA(q,  private_Xa, public_key_userB)
    secret_key_userB = create_secret_key_userB(q,  private_Xb, public_key_userA)
    
    #4.) Test to see if shared private key is equal
    print("Secret Key for User A is: ", secret_key_userA)
    print("Secret Key for User B is: ", secret_key_userB)

    print("About attack 1 (tampering with A and B values) ... As seen above, when Mallory changes A or B values, Bob and Alice no longer share the same secret key so they will not be able to decrypt eachothers messages.")




    #1.) ATTACK 2 MODIFYING THE P value
    print()
    print("Task 2: Mallory Interferes with p (a) value")
    q = int ("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    a = int ("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    #2.) Mallory is able to intercept and modify q
    a = Mallory_Adversary_qvalue()
    print("Mallory changes p to 1")

    #1.) Generate the public keys based on q and a
    public_key_userA, private_Xa = create_public_key_userA(q, a)
    public_key_userB, private_Xb = create_public_key_userB(q, a)

    #2.) Generate the private keys based on public keys
    secret_key_userA = create_secret_key_userA(q,  0, public_key_userB)
    secret_key_userB = create_secret_key_userB(q,  0, public_key_userA)

    #3.) Test to see if shared private key is equal
    print("Secret Key for User A is: ", secret_key_userA)
    print("Secret Key for User B is: ", secret_key_userB)

    #4.) User B encrypts a message to send to userA
    bobs_message_to_encrypt = b'Message c0'
    iv = os.urandom(16)
    cipher = AES.new(secret_key_userB, AES.MODE_CBC, iv)
    padded_message_to_encrypt = pad(bobs_message_to_encrypt, AES.block_size, 'pkcs7')
    userB_encrypted_message = cipher.encrypt( padded_message_to_encrypt)
    print("Bob's encrypted message: ", userB_encrypted_message)

    #5.) User A (Alice) encrypts a message  to send to userB (Bob)
    alice_message_to_encrypt = b'Message c1'
    cipher = AES.new(secret_key_userA, AES.MODE_CBC, iv)
    padded_message_to_encrypt = pad(alice_message_to_encrypt, AES.block_size, 'pkcs7')
    userA_encrypted_message = cipher.encrypt( padded_message_to_encrypt)
    print("Alice's encrypted message: ", userA_encrypted_message)

    Mallory_Adversary_Decryption(secret_key_userB, iv, userB_encrypted_message)
    Mallory_Adversary_Decryption(secret_key_userB, iv, userA_encrypted_message)


def task3_RSA():
    print("RSA TASK 3 Part 1:")
    e = 65537

    # supports variable length primes
    n_length = 220

    # generate prime numbers p and q
    primeNum_p = number.getPrime(n_length)
    primeNum_q = number.getPrime(n_length)
    
    # p cannot be equal to q
    while (primeNum_p == primeNum_q):
        primeNum_q = number.getPrime(n_length)

    #calculate pi(n) where n = primeNum_p x primeNum_q
    n = primeNum_p * primeNum_q
    pi_n = (primeNum_p - 1) * (primeNum_q - 1)

    #d = e ^ -1 (mod pi(n))
    d = pow(e, -1, pi_n) 
    if ((d * e) % pi_n != 1):
        print("Possible Error on computation of d")
    print( "d is d = e ^ -1 (mod pi(n)) which is:", d)
    print("Public Key: {", e, ",", n, "}")
    print("Private Key: {", d, ",", n, "}")

    plaintext = "Hello this is an RSA text"
    byte_plaintext = plaintext.encode("utf-8")
    hex_plaintext = byte_plaintext.hex()
    int_plaintext = int(hex_plaintext, 16)

    #Encrypt the plaintext
    ciphertext = pow(int_plaintext, e, n)
    print("Encrypted ciphertext is: ", ciphertext)

    #Decrypt the ciphertext
    decrypted_message = pow(ciphertext, d, n)
    hex_decrypted = hex(decrypted_message)
    string_decrypted = bytes.fromhex(hex_decrypted.lstrip('0x')).decode()
    print("Decrypted string:", string_decrypted)

def task3_RSA_mall():
    print("RSA TASK 3 Part 2:")
    e = 65537

    # supports variable length primes
    n_length = 220

    # generate prime numbers p and q
    primeNum_p = number.getPrime(n_length)
    primeNum_q = number.getPrime(n_length)
    
    # p cannot be equal to q
    while (primeNum_p == primeNum_q):
        primeNum_q = number.getPrime(n_length)

    #calculate pi(n) where n = primeNum_p x primeNum_q
    n = primeNum_p * primeNum_q
    pi_n = (primeNum_p - 1) * (primeNum_q - 1)

    #d = e ^ -1 (mod pi(n))
    d = pow(e, -1, pi_n) 
    if ((d * e) % pi_n != 1):
        print("Possible Error on computation of d")
    # print( "d is d = e ^ -1 (mod pi(n)) which is:", d)
    # print("Alice's Public Key: {", e, ",", n, "}")
    # print(" Alice's Private Key: {", d, ",", n, "}")
    alice_public_key = [e, n]
    
    #BOB
    print("\n")
    print("Alice will send public key to Bob")
    print("Bob chooses random x such that x exists in range of n")
    bob_x = randrange(1, alice_public_key[1])
    
    print("Bob encrypts random x: ", bob_x)
    bob_y = pow(bob_x, alice_public_key[0], alice_public_key[1])


    #MALLORY
    print("\nMALLORY")
    print("Mallory modifies the encrypted secret ciphertext that Bob sends")
    print("Mallory should change this value to 1 as the computation is s = c^d mod n. We know that if c is 1 then c^d will always be 1 , and our resulting s(SHA INPUT) will just be 1.")
    bob_y = 1

    #Alice
    print(bob_y, n)
    alice_x = pow(bob_y, d, n)
    print("\nAlice decrypts Mallory's intercepted ciphertext value to get: ", alice_x)

    print("Alice creates PRIVATE KEY using sha256 and x value she decrypted which was intercepted and modified by Mallory.")
    sha_input = str(alice_x)
    sha_input = sha_input.encode() 
    alice_key = SHA256.new()
    alice_key.update(sha_input)
    alice_key = alice_key.digest()
    alice_message_to_encrypt = b'Message c1'
    iv = os.urandom(16)
    cipher = AES.new(alice_key, AES.MODE_CBC, iv)
    padded_message_to_encrypt = pad(alice_message_to_encrypt, AES.block_size, 'pkcs7')
    alice_message = cipher.encrypt( padded_message_to_encrypt)
    print("Alice's message to decrypt: ", alice_message_to_encrypt)

    #MALLORY INTERCEPTS AND CAN DECRYPT MESSAGES
    print("\nNow Mallory can generate the same private key to intercept and decrypt the message. Mallory had changed c to 1 so she does not need Alice's private key in the computation and she intercepted n so she can solve for the same private key.")
    # not bob_y is what mallory altered
    mallory_s = pow(bob_y, 100, n)
    sha_input = str(mallory_s) 
    sha_input = sha_input.encode()
    mallory_key = SHA256.new()
    mallory_key.update(sha_input)
    mallory_key = mallory_key.digest()
    cipher = AES.new(mallory_key, AES.MODE_CBC, iv)
    padded_message_to_encrypt = pad(alice_message_to_encrypt, AES.block_size, 'pkcs7')
    decrypted_message = cipher.decrypt( alice_message)
    decrypted_message = unpad(decrypted_message, AES.block_size, 'pkcs7')
    decrypted_message = str(decrypted_message, "utf-8")
    print("After Mallory intercepts decrypts Alice's encrypted message: ", decrypted_message)
    

def main():
    task1_diffie_hellman()
    print() 
    task2_diffie_hellman()
    print()
    task3_RSA()
    print()
    task3_RSA_mall()

main()