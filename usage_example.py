from node import *
import threading

# private key for transactions
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('6dee02b55d8914c145568cb3f3b84586ead2a85910f5b062d7f3f29ddcb4c7aa'))
private_key2 = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('6d1e02b55d8914c145568cb3f3b84586ead2a85910f5b062d7f3f29ddcb4c7aa'))

# create nodes
runners = [ServerRunner('localhost', 9000 + i, f=2) for i in range(7)]

# start accepting incoming connections
for runner in runners:
	runner.start()

# connect other nodes
for i, runner in enumerate(runners):
	for j in range(7):
		if i != j:
			runner.append(RemoteNode('localhost', 9000 + j))

# create clients to send transactions
clients = [RemoteNode('localhost', 9000 + i) for i in range(7)]

# create a transaction
transaction = make_transaction('hello', private_key, 0)

transaction2 = make_transaction('howareyou', private_key, 1)
transaction3 = make_transaction('transaction3', private_key2, 0)

# set block callback
lock = threading.Lock()
cond = threading.Condition(lock)
blocks = []
def on_new_block(block):
	with lock:
		blocks.append(block)
		cond.notify()
for runner in runners:
	runner.blockchain.set_on_new_block(on_new_block)

# send the transaction
assert(clients[0].transaction(transaction) == True)

runners[2].stop()
runners.remove(runners[2])
clients.remove(clients[2])
runners[2].stop()
runners.remove(runners[2])
clients.remove(clients[2])

# wait for the block from all nodes
with lock:
	cond.wait_for(lambda: len(blocks) == len(runners))

# check that the transaction is committed
assert(all([block['transactions'][0] == transaction for block in blocks]))

blocks = []

assert(clients[1].transaction(transaction2) == True)
assert(clients[0].transaction(transaction3) == True)

# wait for the block from all nodes
with lock:
	cond.wait_for(lambda: len(blocks) == len(runners))

transaction2_acc = all([block['transactions'][0] == transaction2 for block in blocks])

transaction3_acc = all([block['transactions'][0] == transaction3 for block in blocks])

# check that the transaction is committed
assert(transaction2_acc or transaction3_acc) == True

blocks = []

with lock:
	cond.wait_for(lambda: len(blocks) == len(runners))

if not transaction3_acc:
	transaction3_acc = all([block['transactions'][0] == transaction3 for block in blocks])
	assert(transaction3_acc) == True
	
elif not transaction2_acc:
	transaction2_acc = all([block['transactions'][0] == transaction2 for block in blocks])
	assert(transaction2_acc) == True

# stop the nodes
for runner in runners:
	runner.stop()
