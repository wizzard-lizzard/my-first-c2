import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.PublicKey import RSA
import hashlib

class AESCipher(object):
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """
    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

class RSAEncryption(object):
    def __init__(self):
        self.generate_keys()

    def generate_keys(self):
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()

    def encrypt(self, data, recipient_public):
        recipient_key = RSA.import_key(recipient_public)
        session_key = Random.get_random_bytes(16)
        data = data.encode('utf-8')
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        return enc_session_key + cipher_aes.nonce + tag + ciphertext





if __name__ == "__main__":
    key = "thisisatestkey"
    plaintext = "Hello world"
    print(f"Plaintext is: {plaintext}")
    cipher = AESCipher(key)
    ciphertext = cipher.encrypt(plaintext)
    print(f"Ciphertext is: {ciphertext}")
    return_to_plaintext = cipher.decrypt(ciphertext)
    print(f"Decrypted it is: {return_to_plaintext}")

    encrypted_text = "eGRUUGJqc1NJdTBma3VyZGxMa2RzUjFkcU1ZZ1o2Wm5URlFWcTBIK2lCaGx5eXY4VnhJd1NaUU1saXZmanhQV2VlSTJ2eXZJeng0d0c1SkNmSnl4OE4wMVVZZDhvaE90ZHAvNERxakE3MHpuUURrT3k4aC9zTjMzNTJOalVaaDY="
    key = "ilikebigbuttsandicannotlie"
    cipher = AESCipher(key)
    plaintext = cipher.decrypt(encrypted_text)
    print(plaintext)