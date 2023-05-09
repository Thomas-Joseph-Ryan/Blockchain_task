from blockchain import *
import queue
import threading
import socket
import pickle
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
import logging
from network import *
import time

def transaction_bytes(transaction: dict):
	return json.dumps({k: transaction.get(k) for k in ['sender', 'message', 'nonce']},
	sort_keys=True).encode()

'''
Returns a transaction dictionary. Needs to be wrapped into a payload before sending. 
This is done for the sake of atomicity
'''
def make_transaction(message: str, private_key: ed25519.Ed25519PrivateKey, nonce: int) -> dict:
	transaction = {
		'sender': private_key.public_key().public_bytes_raw().hex(),
		'message': message,
		'nonce': nonce
		}
	signature = private_key.sign(transaction_bytes(transaction)).hex()
	transaction['signature'] = signature

	return transaction

class RemoteNode():
	def __init__(self, host, port) -> None:
		self.host = host
		self.port = port

	def transaction(self, transaction) -> bool:
		packet = {
			"type": "transaction",
			"payload": transaction
		}
		#Need to wait for response from server runner saying transaction is valid or invalid
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.connect((self.host, self.port))
			send_prefixed(s, pickle.dumps(packet))
			recv = recv_prefixed(s).decode('utf-8')
			# print(f"received: {recv}")
			if recv == "true":
				return True
			else:
				return False


class ServerRunner():
	def __init__(self, host, port, f) -> None:
		self.blockchain = Blockchain()
		self.host = host
		self.port = port
		self.failure_tolerance = f
		self.remote_nodes : list[socket.socket] = []

		self.consensusround_block : dict = {}

		self.consensusround_proposedblocks : dict[int, list[dict]] = {}

		self.current_round = 1

		self.stop_event = threading.Event()
		self.blockchain_lock = threading.Lock()
		self.pool_non_empty = threading.Event()
		self.next_round_request = threading.Event()
		self.s1_cond_lock = threading.Lock()
		self.pipeline_s1_wait_cond = threading.Condition(self.s1_cond_lock)
		self.server_thread = threading.Thread(target=self.start_server)
		self.pipeline_thread = threading.Thread(target=self.pipeline)

		#Set up logger
		self.logger = logging.getLogger(f"{port}")
		handler = logging.FileHandler(f"./logs/{port}.log", mode='w')
		handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
		self.logger.addHandler(handler)
		self.logger.setLevel(logging.INFO)
		self.logger.info("Node starting")
		
	def start(self):
		self.server_thread.start()
		self.pipeline_thread.start()

	def stop(self):
		self.logger.info("Stopping server")
		self.stop_event.set()
		for s in self.remote_nodes:
			s.close()
		self.logger.info("Connection to remote nodes closed")
		self.server_thread.join()
		self.logger.info("Server thread joined")
		self.pipeline_thread.join()
		self.logger.info("Pipeline thread joined")
		self.logger.info("Server Stopped")

	def append(self, remote_node: RemoteNode):
		remote_socket = self.connect_to_node(remote_node.host, remote_node.port)
		self.remote_nodes.append(remote_socket)

	def start_server(self):
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server_socket.bind((self.host, self.port))
		self.server_socket.listen()
		self.server_socket.settimeout(3.0)
		self.logger.info(f"Server listening on {self.host}:{self.port}")

		while not self.stop_event.is_set():
			try:
				client_sock, client_add = self.server_socket.accept()
			except socket.timeout:
				continue
			self.logger.info(f"Connection from {client_add}")
			client_thread = threading.Thread(target=self.handle_client, args=(client_sock,))
			client_thread.start()


# We can use this method to receive requests from remote nodes and send
# them responses
	def handle_client(self, client_socket: socket.socket):
		conn_failed = False
		client_socket.settimeout(3)
		while not self.stop_event.is_set():
			try:
				data = recv_prefixed(client_socket)
				if not data: 
					break
				conn_failed = False
				received_dict = pickle.loads(data)			
				self.logger.info(f"Received from {client_socket.getpeername()}: {received_dict}")
				# So we have the socket here, so when we get a request from
				# a client we can use this socket (i think)
				# The messages received will always be a pickle'd dictionary
				# of the form {"type": x, "payload": x}
				if received_dict["type"] == "transaction":
					# Validate transaction
					self.logger.info("transaction received")
					response = "false"
					transaction = received_dict["payload"]
					valid_transaction = self.validate_transaction(transaction)
					if valid_transaction == True:
						self.logger.info("Valid transaction received")
						with self.blockchain_lock:
							added_to_pool = self.blockchain.add_transaction(transaction)
						if added_to_pool == True:
							self.logger.info("Valid transaction was added to pool")
							response = "true"
							self.pool_non_empty.set()
							with self.s1_cond_lock:
								self.pipeline_s1_wait_cond.notify()
					else:
						self.logger.info(f"Invalid transaction received {valid_transaction}")


					send_prefixed(client_socket, response.encode('utf-8'))
				elif received_dict["type"] == "values":
					# Send block proposal at that index
					round = received_dict["payload"]
					self.ensure_block_for_consensus_round(round)
					proposed_blocks_in_round = self.consensusround_proposedblocks[round]
					self.logger.info(f"Received request for values in round {round}, they are {proposed_blocks_in_round}")
					send_prefixed(client_socket, pickle.dumps(proposed_blocks_in_round))
					if round > self.current_round:
						self.next_round_request.set()
						with self.s1_cond_lock:
							self.pipeline_s1_wait_cond.notify()


			except RuntimeError as e:
				if conn_failed == False:
					self.logger.error(f'Connection failed first time {client_socket.getpeername()}: {type(e).__name__}: {e}')
					conn_failed = True
				elif conn_failed == True:
					self.logger.error(f'Connection failed second time, closing connection {client_socket.getpeername()}: {type(e).__name__}: {e}')
					break
			except socket.timeout as e:
				continue
			except Exception as e:
				self.logger.error(f'Error handling client {client_socket.getpeername()}: {type(e).__name__}: {e}')
		
		client_socket.close()

# We use this functionality including the append() method to send a request from
# this node. Since we never need to send a request to one specific node and instead
# send the request to all nodes, we just need the broadcast function
# Since these nodes are where we send requests, this is where the timeout stuff
# happens
	def connect_to_node(self, remote_host, remote_port):
		remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		remote_socket.connect((remote_host, remote_port))
		# self.socket_port[remote_socket.getpeername()] = remote_socket
		self.logger.info(f"Connected to {remote_host}:{remote_socket}")
		return remote_socket
	
	# def try_reconnect_to_node(self, )

	# This method will be used to broadcast a values message
	def consensus_broadcast_routine(self, proposed_block: dict, round:int):
		self.logger.info(f"Entering consensus broadcast routine for round {round}")
		request = {
			"type": "values",
			"payload": round
		}
		if len(self.remote_nodes) < 2*self.failure_tolerance:
			self.logger.fatal("Number of accepted failures too large relative to number of remote nodes. Quitting")
			return None
		responses_count = [0] * len(self.remote_nodes)
		online = [True] * len(self.remote_nodes)
		for _ in range(self.failure_tolerance+1):
			self.logger.info(f"Failure tolerence round {_ + 1} commencing")
			for idx, remote_node in enumerate(self.remote_nodes):
				# If node is deemed as crashed during this consensus round, we do not try to contact it
				if online[idx] == False:
					continue
				remote_node.settimeout(5)
				fail_count = 0
				response = None
				while fail_count < 2:
					try:
						send_prefixed(remote_node, pickle.dumps(request))
						response = pickle.loads(recv_prefixed(remote_node))
						break
					except socket.timeout as e:
						self.logger.info(f"Remote node {remote_node} failed once")
						fail_count += 1
					except RuntimeError as e:
						self.logger.info(f"Remote node {remote_node} failed twice and will not be contacted for the rest of this round")
						fail_count += 1
				if fail_count >= 2:
					online[idx] = False
				if response != None:
					self.logger.info(f"Received response: {response}")
					for block in response:
						if block not in self.consensusround_proposedblocks[round]:
							self.consensusround_proposedblocks[round].append(block)
					responses_count[idx] += 1
		can_decide = responses_count.count(self.failure_tolerance + 1) >= len(self.remote_nodes) - self.failure_tolerance
		if can_decide == False:
			self.logger.info(f"Not enough responses for a decision to be made")
			return None
		min_hash_block = proposed_block
		min_hash = proposed_block["current_hash"]
		for block in self.consensusround_proposedblocks[round]:
			if len(block["transactions"]) < 1:
				continue

			current_hash = block["current_hash"]
			if current_hash < min_hash:
				min_hash = current_hash
				min_hash_block = block
		
		self.logger.info(f"Decided on {min_hash_block}")
		return min_hash_block
		

	def validate_transaction(self, transaction: dict):
		str_keys = ['sender','message', 'signature']
		try:
			if type(transaction) is not dict:
				self.logger.debug(f"Error when validating transaction: payload is not a dict: {transaction}")
				return False
			if len(transaction) != 4:
				self.logger.debug(f"Error when validating transaction: incorrect number of keys: {transaction}")
				return False
			for key in str_keys:
				if not isinstance(transaction[key], str):
					self.logger.debug("Error when validating transaction: incorrect value types in dict")
					return False
			
			if not isinstance(transaction["nonce"], int):
				self.logger.debug("Error when validating transaction: incorrect value in dict")
				return False
			pub_key_hex = transaction['sender']
			if self.blockchain.check_nonce(pub_key_hex, transaction['nonce']) == False:
				self.logger.debug("Error when validating transaction: Nonce is not valid for key")
				return False
			public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_key_hex))

			if len(transaction['message']) > 70 or not transaction['message'].isalnum():
				self.logger.debug("Error when validating transaction: message length > 70 or is not alnum")
				return False
			
			public_key.verify(bytes.fromhex(transaction['signature']), transaction_bytes(transaction))
			return True
		except Exception as e:
			self.logger.debug(f"Transaction failed to validate {e}")
			return False

	def ensure_block_for_consensus_round(self, round: int):
    # Check if a block has already been proposed for the given round
		if round not in self.consensusround_block:
			proposed_block = self.blockchain.propose_new_block()
			self.logger.info(f"Ensuring block present for consensus round {proposed_block}")
			# Store the new block proposal for the given round
			self.consensusround_block[round] = proposed_block
			self.consensusround_proposedblocks[round] = [proposed_block]



	def pipeline(self):
		#1.
		#Wait for transaction pool to be ready
		#This can happen when the pool becomes non-empty
		#or when the node recieves a request from another node
		#asking for the value of the next round. This only happens when
		#the remote node has received a transaction and is ready to propose a
		#non - empty block
		
		#After one of these criterions is met, a node should wait for 2.5 seconds
		#before moving to operation 2

		while not self.stop_event.is_set():
			with self.s1_cond_lock:
				result = self.pipeline_s1_wait_cond.wait_for(lambda: self.pool_non_empty.is_set() or self.next_round_request.is_set(), 2)
				if result == False:
					continue
			time.sleep(2.5)
			self.current_round += 1

		#2.
		#With the transactions received from the previous step, 
		#Create a block proposal based on the current blockchain
			with self.blockchain_lock:
				self.ensure_block_for_consensus_round(self.current_round)

		#3.
		#Start the consensus broadcast routine.
		#Request values for the next block id from all other nodes.
		#The timeout for the response is 5 seonds
		#If the socket is closed or timeout is reached, retry one time
		#If retry fails, the node is considered crashed and should not be
		#Contacted in future rounds
		#The block chosen to be accepted is the one whose hash has the lowest
		#lexigraphical value
			block_to_commit = self.consensus_broadcast_routine(self.consensusround_block[self.current_round], self.current_round)

		#4.
		#Once the block proposal is accepted, append the block
		#to the blockchain and remove the included transactions from
		#the transaction pool. 
		#Note: there could be conflicting transactions from 
		#the same user based on the transaction nonce, the first
		#of these transactions can be included but any following 
		#transactions that conflict with it should be removed
		#from the block since they became invalid and cannot be comitted.
			with self.blockchain_lock:
				self.blockchain.commit_block(block_to_commit)
				if len(self.blockchain.pool) == 0:
					self.pool_non_empty.clear()
			if self.current_round + 1 not in self.consensusround_block:
				self.next_round_request.clear()

# For the pool


# 
# Add transactions to the pool once they are validated
# Propose a block with the transactions in your pool
# Only remove transactions from the pool once they are committed 
# in a block
# 
# 
# Validate transaction pool each time a block gets committed
# 