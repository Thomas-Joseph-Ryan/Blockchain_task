from node import *
import threading
import time

# private key for transactions
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('6dee02b55d8914c145568cb3f3b84586ead2a85910f5b062d7f3f29ddcb4c7aa'))

# create nodes
runners = [ServerRunner('localhost', 9000 + i, f=1) for i in range(4)]

# start accepting incoming connections
for runner in runners:
	runner.start()

# connect other nodes
for i, runner in enumerate(runners):
	for j in range(4):
		if i != j:
			runner.append(RemoteNode('localhost', 9000 + j))

time.sleep(2)  # Give the nodes time to connect

    # Broadcast a message from the first node
runners[0].broadcast_message("Hello from node 0")

time.sleep(5)  # Give some time for messages to be received

# stop the nodes
for runner in runners:
	runner.stop()
