# my-first-c2
This is a simple C2 application I built in python as a learning experience. There isn't anything incredibly complex or interesting it does, but it does function for barebones Command and Control.

## The Server
The server.py application runs an HTTPS server utilizing the Tornado Web Server. Response application paths can be configured in the main function, but by default the following are available:

* / and /register : registers the client
* /command : The client calls this to retrieve commands
* /response : The client sends the results of commands here for processing.

The server stores timestamped commands, responses, and connection histories in a database so that they can be easily retrieved for reporting or verification of what was run on the client.

## The Client
Client.py is a basic client that makes HTTPS requests to the server. It initializes a connection by accessing the Register application. It then contacts the servers command application at intervals based on the jitter variables (jlo and jhi) to determine if any commands have been issued to it. It has the capabily of running OS commands, as well as several predefined commands. These predefined commands include:

*adj_jitter: adjust the jlo and jhi variables.
*listdir: list the contents of the current directory

## Encryption
Communication between the client and server are encrypted with AES encryption. A key exchange occurs initially during registration. The process happens as follows:

* The client generates an RSA public/private keypair using the Crypto.Publickey library
* The client connects to the Register application directory (default /register), and provides the base64 encoded public key in a GET variable.
* The server decodes the key, generates a random client ID and random encryption key, combines the two, encrypts it with the Client's public key, and writes the base64 encoded data to the body of the response
* The client retrieves the data, decodes it, separates the client ID from the encryption key.
* All communication between the two is now encrypted using the shared symmetrical encryption key.

## Usage
* Install server requirements with pip install -r requirements.txt
* Run server.py: python3 server.py
* Run the client on your test target machine: python3 client.py
* The server should now get a registration request, and you can begin issuing commands

The following commands are available on the server:
* list - List connected clients and view their connection status
* interact <client #> - begin an interactive session with the client
* history <client #> - view the history of client # <client #>
* jitter <client #> <jlo> <jhi> - adjust the jitter values for callback frequency
* queue <client #> - view the unprocessed command queue for a client

All client #'s are show in the list command.

## Notes
This should likely not be used in an actual engagement as it is not guaranteed to be secure. It also should not be used against a target you do not have authorization to test against. This is for educational purposes only.

## Credits
Big shout out to @HackingDave and his talk about building C2's for the motiviation to do this. I also stole the AESCipher from trevorc2, which I believe was taken from somewhere else that now has a dead link

## Other notes
I wrote this a while ago and just decided to post it publicly recently. I believe I covered everything in the readme, but there is a real chance I missed something important. Sorry!


