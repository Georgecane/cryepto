import hashlib
import random2
import numpy as np
import binascii
import pyscrypt
import Crypto.Cipher
import Crypto.Hash
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import Blowfish
from struct import pack
from Crypto.Cipher import DES
import json
from base64 import b64encode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from base64 import b64decode
from Crypto.Cipher import Salsa20
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import codecs

class algorithms:
    """This class represents all algorithms you need to implement cryptography.
    """
    class cipher:
        """This class implements cryptographic cipher algorithms.
        """
        class symmetrical:
        
            def aes(key:bytes, data:bytes) -> str:
                """This function applies AES (Advanced Encryption Standard) encryption and decryption on your data,
                this algorithm is symmetrical encryption and decryption algorithm, AES (Advanced Encryption Standard) is a symmetric block cipher standardized by NIST
                 . It has a fixed data block size of 16 bytes. Its keys can be 128, 192, or 256 bits long.
                AES is very fast and secure, and it is the de facto standard for symmetric encryption, use a 16-byte key string for key.
                """
                cipher = AES.new(key, AES.MODE_EAX)

                nonce = cipher.nonce
                ciphertext, tag = cipher.encrypt_and_digest(data)
                print(f"ENCRYPTED : {ciphertext}")

                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                plaintext = cipher.decrypt(ciphertext)
                try:
                    cipher.verify(tag)
                    print(f"DECRYPTED: {plaintext}")
                except ValueError:
                    print("Key incorrect or message corrupted")

            def blowfish(key:bytes, data:bytes) -> str:
                """This function applies the Blowfish encryption on your data,
                this algorithm is a symmetric block cipher designed by Bruce Schneier.
                """
                bs = Blowfish.block_size
                cipher = Blowfish.new(key, Blowfish.MODE_CBC)
                plen = bs - len(data) % bs
                padding = [plen]*plen
                padding = pack('b'*plen, *padding)
                msg = cipher.iv + cipher.encrypt(data + padding)
                print(f"ENCRYPTED : {msg}")

            def single_des(key:bytes, data:bytes) -> str:
                """This function applies the single DES (Data Encryption Standard) ecryption on your data,
                DES (Data Encryption Standard) is a symmetric block cipher standardized in FIPS 46-3 (now withdrawn). It has a fixed data block size of 8 bytes.
                Its keys are 64 bits long, even though 8 bits were used for integrity (now they are ignored) and do not contribute to security. The effective key length is therefore 56 bits only.
                DES was never cryptographically broken, but its key length is too short by nowadays standards and it could be brute forced with some effort.
                """
                cipher = DES.new(key, DES.MODE_OFB)
                msg = cipher.iv + cipher.encrypt(data)
                print(f"ENCRYPTED : {msg}")

            def chacha20(data:bytes) -> str:
                """This function applies the ChaCha20 encryption on your data,
                ChaCha20 is a stream cipher designed by Daniel J. Bernstein. The secret key is 256 bits long (32 bytes). The cipher requires a nonce, which must not be reused across encryptions performed with the same key.
                """
                key = get_random_bytes(32)
                print(f"KEY : {key}")
                cipher = ChaCha20.new(key=key)
                ciphertext = cipher.encrypt(data)

                nonce = b64encode(cipher.nonce).decode('utf-8')
                ct = b64encode(ciphertext).decode('utf-8')
                result = json.dumps({'nonce':nonce, 'ciphertext':ct})
                print(f"ENCRYPTED : {result}")

            def salsa20(key:bytes, data:bytes) -> str:
                """This function applies the Salsa20 encryption and decryption on your data,
                Salsa20 is a stream cipher designed by Daniel J. Bernstein. The secret key is by preference 256 bits long, but it can also work with 128 bit keys.
                """
                cipher = Salsa20.new(key=key)
                msg = cipher.nonce + cipher.encrypt(data)
                print(f"ENCRYPTED : {msg}")

                msg_nonce = msg[:8]
                ciphertext = msg[8:]
                cipher = Salsa20.new(key=key, nonce=msg_nonce)
                plaintext = cipher.decrypt(ciphertext)
                print(f"DECRYPTED : {plaintext}")

            def bbha(data:str, index:int) -> str:
                """This function applies the BBHA (Pesudo-Blockchain Based Hash Algorithm) one-way encryption on your data,
                this algorithm was create by George Cane in 2024.
                """
                blocks_dict = {}

                class Block:
                    def __init__(self):
                        key = random.randint(0, 10000000000000000000000000000000)
                        self.key = key
                        self.hash_of_block = hashlib.sha256(str(key).encode()).hexdigest()
                        address = random.randint(len(self.hash_of_block), 10000000000)
                        self.address = address

                def anti_blockchain(k):
                    for i in range(0, k+1):
                        block = Block()
                        blocks_dict["block_" + str(i)] = {"address": block.address, "hash": block.hash_of_block}

                def cryptographer(text, range_of_blocks):
                    k = range_of_blocks
                    anti_blockchain(k)
                    random_block = blocks_dict["block_"+ str(random.randint(0, 1000))]
                    binary = ''.join(format(i, '08b') for i in bytearray(text, encoding ='utf-8'))
                    length_of_binary = len(str(binary))
                    add = str(random_block["address"]) + random_block["hash"]
                    res = add + str(length_of_binary)
                    print(res)

                cryptographer(data, index)

            def etha(data:str) -> str:
                """This function applies the ETHA (Elfman-Turing Hash Algorithm) one-way encryption on your data,
                this algorithm was created by George Cane in 2024.
                """
                def is_prime(n):
                    if n <= 1:
                        return False
                    if n <= 3:
                        return True
                    if n % 2 == 0 or n % 3 == 0:
                        return False
                    i = 5
                    while i * i <= n:
                        if n % i == 0 or n % (i + 2) == 0:
                            return False
                        i += 6
                    return True
                
                def main(text):
                    for i in range(1000):
                        n = random2.randint(1000000000000000000000, 1000000000000000000000000000000000000000000000000000000000)
                    while is_prime(n):
                        for i in range(1000):
                            n = random2.randint(1000000000000000000000, 1000000000000000000000000000000000000000000000000000000000)

                    print("Prime found!")
                    message = hashlib.sha256(codecs.encode(text + str(n), 'ascii').hex().encode("utf-8")).hexdigest()
                    print(f"ENCRYPTED : {message}")

                main(data)

        class asymmetrical:
            def rsa(data:bytes) -> str:
                """This function applies the RSA (Rivest-Shamir-Adleman) encryption and decryption on your data,
                PKCS#1 OAEP is an asymmetric cipher based on RSA and the OAEP padding. It is described in RFC8017 where it is called RSAES-OAEP.
                """
                key = RSA.importKey(open('public.pem').read())
                cipher = PKCS1_OAEP.new(key)
                ciphertext = cipher.encrypt(data)
                print(f"ENCRYPTED : {ciphertext}")

                key = RSA.importKey(open('private.pem').read())
                cipher = PKCS1_OAEP.new(key)
                message = cipher.decrypt(ciphertext)
                print(f"DECRYPTED : {message}")

    class signature:
        """This class implements the signature algorithms.
        """
        def ecdsa(data:bytes, r_data) -> str:
            """This function applies the ECDSA digital signature algorithm on yout data,
            DSA and ECDSA are U.S. federal standards for digital signatures, specified in FIPS PUB 186-4.
            Their security relies on the discrete logarithm problem in a prime finite field (the original DSA, now deprecated) or in an elliptic curve field (ECDSA, faster and with smaller keys, to be used in new applications).
            """
            key = ECC.import_key(open('privkey.der').read())
            h = SHA256.new(data)
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            print(f"SIGNED : {signature}")

            key = ECC.import_key(open('pubkey.der').read())
            h = SHA256.new(r_data)
            verifier = DSS.new(key, 'fips-186-3')
            try:
                verifier.verify(h, signature)
                print("The message is authentic.")
            except ValueError:
                print("The message is not authentic.")
