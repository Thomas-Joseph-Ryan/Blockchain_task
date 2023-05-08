from blockchain import *
import queue
import threading
import socket
import pickle
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
import logging
import long_lived_client
from network import *


def make_transaction(message: str, private_key: ed25519.Ed25519PrivateKey, nonce: int) -> dict:
	transaction = {
		"type" : "transaction",
		"payload": {
			"sender": private_key.public_key().public_bytes_raw().hex(),
			"message": message,
			"nonce": nonce,
			"signature": private_key.sign(message.encode('utf-8'))
		}
	}

	return transaction

class RemoteNode():
	def __init__(self, host, port) -> None:
		self.host = host
		self.port = port

	def transaction(self, transaction) -> bool:
		#Need to wait for response from server runner saying transaction is valid or invalid
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.connect((self.host, self.port))
			send_prefixed(s, pickle.dumps(transaction))
		return True


class ServerRunner():
	def __init__(self, host, port, f) -> None:
		self.blockchain = Blockchain()
		self.host = host
		self.port = port
		self.failure_tolerance = f
		self.remote_nodes : list[long_lived_client.LongLivedClient] = []
		self.incoming_msgs = queue.Queue()
		self.stop_event = threading.Event()

		#Set up logger
		self.logger = logging.getLogger(f"{port}")
		handler = logging.FileHandler(f"./logs/{port}.log")
		handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
		self.logger.addHandler(handler)
		self.logger.setLevel(logging.INFO)
		self.logger.info("Node starting")
		self.listen_thread = threading.Thread(target=self.listen)
		
	def start(self):
		self.listen_thread.start()

	def stop(self):
		self.stop_event.set()
		self.listen_thread.join()
		for s in self.remote_nodes:
			s.disconnect()

	def append(self, remote_node: RemoteNode):
		connection_to_other_server_runner = long_lived_client.LongLivedClient(remote_node.host, remote_node.port)
		connection_to_other_server_runner.connect()
		self.remote_nodes.append(connection_to_other_server_runner)

	def listen_long_lived(self, ll_client: long_lived_client.LongLivedClient):
		ll_client.receive_message
	
	def handle_client(self, conn : socket.socket, client_addr):
		try:
			conn.settimeout(5)
			connected = True
			while not self.stop_event.is_set():
				try:
					data = recv_prefixed(conn)
					if data:
						print(f"Received from {client_addr}: {data}")
						self.incoming_msgs.put(data)
						connected = True
					else:
						if connected == False:
							break
						connected = False
				except socket.timeout:
					continue
				except Exception as e:
					print(f"Error while handling client {client_addr}: {e}")
					break
		finally:
			print(f"Closing connection with {client_addr}")
			conn.close()

	def listen(self):
		try:
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
				s.bind((self.host, self.port))
				s.listen()

				while not self.stop_event.is_set():
					try:
						conn, client_addr = s.accept()
						client_thread = threading.Thread(target=self.handle_client, args=(conn, client_addr))
						client_thread.daemon = True
						client_thread.start()
					except Exception as e:
						print(f"Error when connecting to client {e}")

		except Exception as e:
			print(f"Exception in listen thread {e}")

	def validate_transaction(self, transaction: dict):
		payload_keys = ['sender','message', 'nonce','signature']
		try:
			if type(transaction) is not dict:
				return False
			for payload_key in payload_keys:
				if not isinstance(transaction['payload'][payload_key], str):
					return False
			pub_key_hex = transaction['sender']
			if self.blockchain.check_nonce(pub_key_hex, transaction['nonce']) == False:
				return False
			public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(transaction['sender']))
			if len(transaction['message']) > 70 or not transaction['message'].isalnum():
				return False
			
			public_key.verify(transaction['signature'], transaction['message'].encode("utf-8"))
			
		except:
			return False

	def pipeline_thread(self):
		#1.
		#Wait for transaction pool to be ready
		#This can happen when the pool becomes non-empty
		#or when the node recieves a request from another node
		#asking for the value of the next round. This only happens when
		#the remote node has received a transaction and is ready to propose a
		#non - empty block
		
		#After one of these criterions is met, a node should wait for 2.5 seconds
		#before moving to operation 2

		transaction_pool_ready = False
		while not transaction_pool_ready:
			timeout_started = False
			try:
				recieved = pickle.loads(self.incoming_msgs.get(timeout=2.5))
				if recieved['type'] == "transaction":
					self.validate_transaction(recieved['payload'])
					timeout_started = True
				elif recieved['type'] == "values":
					send_block_proposal(recieved['payload'])
					timeout_started = True
			except queue.Empty:
				if timeout_started == True:
					transaction_pool_ready = True
				pass



		#2.
		#With the transactions received from the previous step, 
		#Create a block proposal based on the currenty blockchain

		#3.
		#Start the consensus broadcast routine.
		#Request values for the next block id from all other nodes.
		#The timeout for the response is 5 seonds
		#If the socket is closed or timeout is reached, retry one time
		#If retry fails, the node is considered crashed and should not be
		#Contacted in future rounds
		#The block chosen to be accepted is the one whose hash has the lowest
		#lexigraphical value

		#4.
		#Once the block proposal is accepted, append the block
		#to the blockchain and remove the included transactions from
		#the transaction pool. 
		#Note: there could be conflicting transactions from 
		#the same user based on the transaction nonce, the first
		#of these transactions can be included but any following 
		#transactions that conflict with it should be removed
		#from the block since they became invalid and cannot be comitted.


# For the pool

# Get transaction when listening, then validate the transaction on the server runner
# Send message back to remote node to say transaction is valid and is being added to the pool
# Remote node should wait after sending transaction to server runner for a response, accepted or rejected.
# based on this response, it will return true or false


# 
# Add transactions to the pool once they are validated
# Propose a block with the transactions in your pool
# Only remove transactions from the pool once they are committed 
# in a block
# 
# 
# Validate transaction pool each time a block gets committed
# 