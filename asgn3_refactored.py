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

class diffie_hellman_user:
    def __init__(self, q, a) -> None:
        self.public_key_self = None
        self.public_key_other = None
        self.private_key_self = None
        self.private_Xself = randrange(1, q)
        self.q = q
        self.a = a
    
    def create_public_key(self):
        private_Xself = randrange(1, self.q)
        public_key_userA = pow(self.a, private_Xa, self.q)
        self.public_key_self =