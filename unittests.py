import unittest
from node import *
import threading

NUMBER_OF_SERVER_RUNNERS = 4

last_used_port = 9000

def get_unique_port():
    global last_used_port
    last_used_port += 1
    return last_used_port

class TestNode(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # private keys for transactions
        cls.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('6dee02b55d8914c145568cb3f3b84586ead2a85910f5b062d7f3f29ddcb4c7aa'))
        cls.private_key2 = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('6d1e02b55d8914c145568cb3f3b84586ead2a85910f5b062d7f3f29ddcb4c7aa'))
    
    def on_new_block(self, block):
        with self.lock:
            self.blocks.append(block)
            self.cond.notify()

    def setUp(self):
        # create nodes
        ports = [get_unique_port() for _ in range(NUMBER_OF_SERVER_RUNNERS)]

        # Create and start nodes
        self.runners = [ServerRunner('localhost', port, f=2) for port in ports]
        for runner in self.runners:
            runner.start()

        # Connect other nodes
        for i, runner in enumerate(self.runners):
            for j in range(len(ports)):
                if i != j:
                    runner.append(RemoteNode('localhost', ports[j]))

        # Create clients to send transactions
        self.clients = [RemoteNode('localhost', port) for port in ports]

        # Set block callback
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        self.blocks = []
        def on_new_block(block):
            with self.lock:
                self.blocks.append(block)
                self.cond.notify()
        for runner in self.runners:
            runner.blockchain.set_on_new_block(on_new_block)

    def tearDown(self):
        # stop the nodes
        for runner in self.runners:
            runner.stop()

    def test_transaction_1(self):
        # create a transaction
        transaction = make_transaction('test1', self.private_key, 0)

        # send the transaction
        self.assertTrue(self.clients[0].transaction(transaction))

        # wait for the block from all nodes
        with self.lock:
            self.cond.wait_for(lambda: len(self.blocks) == len(self.runners))

        # check that the transaction is committed
        self.assertTrue(all([block['transactions'][0] == transaction for block in self.blocks]))

    def test_transaction_2(self):

        # create a transaction
        transaction = make_transaction('test2', self.private_key, 0)

        # send the transaction
        self.assertTrue(self.clients[1].transaction(transaction))

        # wait for the block from all nodes
        with self.lock:
            self.cond.wait_for(lambda: len(self.blocks) == len(self.runners))

        # check that the transaction is committed
        self.assertTrue(all([block['transactions'][0] == transaction for block in self.blocks]))

    def test_2_transactions_same_node(self):

        #Create t1
        t1 = make_transaction("test3a", self.private_key2, 0)

        # create a transaction
        t2 = make_transaction('test3b', self.private_key, 0)

        # send the transaction
        self.assertTrue(self.clients[0].transaction(t1))
        self.assertTrue(self.clients[0].transaction(t2))

        # wait for the block from all nodes
        with self.lock:
            self.cond.wait_for(lambda: len(self.blocks) == len(self.runners))

        # check that the transaction is committed
        self.assertTrue(all([block['transactions'][0] == t1 and block['transactions'][1] == t2 for block in self.blocks]))

    def test_2_transactions_different_nodes(self):

        #Create t1
        t1 = make_transaction("test4a", self.private_key2, 0)

        # create a transaction
        t2 = make_transaction('test4b', self.private_key, 0)

        # send the transaction
        self.assertTrue(self.clients[0].transaction(t1))
        self.assertTrue(self.clients[1].transaction(t2))

        # wait for the block from all nodes
        with self.lock:
            self.cond.wait_for(lambda: len(self.blocks) == len(self.runners))

        t1_acc = all([block['transactions'][0] == t1 for block in self.blocks])

        t2_acc = all([block['transactions'][0] == t2 for block in self.blocks])

        # check that the transaction is committed
        self.assertTrue(t1_acc or t2_acc)

        self.blocks = []
        
        with self.lock:
            self.cond.wait_for(lambda: len(self.blocks) == len(self.runners))

        if not t2_acc:
            t2_acc = all([block['transactions'][0] == t2 for block in self.blocks])
            self.assertTrue(t2_acc)
            
        elif not t1_acc:
            t1_acc = all([block['transactions'][0] == t1 for block in self.blocks])
            self.assertTrue(t1_acc)

    def test_transaction_not_alnum(self):

        # create a transaction
        transaction = make_transaction('test 5', self.private_key, 0)

        # send the transaction
        self.assertFalse(self.clients[1].transaction(transaction))

    def test_2_same_nonce_transactions_same_node(self):

        #Create t1
        t1 = make_transaction("test6a", self.private_key, 0)

        # create a transaction
        t2 = make_transaction('test6b', self.private_key, 0)

        # send the transaction
        self.assertTrue(self.clients[0].transaction(t1))
        self.assertFalse(self.clients[0].transaction(t2))

        # wait for the block from all nodes
        with self.lock:
            self.cond.wait_for(lambda: len(self.blocks) == len(self.runners))

        t1_acc = all([block['transactions'][0] == t1 for block in self.blocks])
        # check that the transaction is committed
        self.assertTrue(t1_acc)

    def test_wrong_nonce_transaction(self):

        #Create t1
        t1 = make_transaction("test7", self.private_key, 1)

        # send the transaction
        self.assertFalse(self.clients[0].transaction(t1))

    def test_same_nonce_transactions_same_node_after_block_commit(self):

        #Create t1
        t1 = make_transaction("test8a", self.private_key, 0)

        # create a transaction

        # send the transaction
        self.assertTrue(self.clients[0].transaction(t1))

        # wait for the block from all nodes
        with self.lock:
            self.cond.wait_for(lambda: len(self.blocks) == len(self.runners))

        t1_acc = all([block['transactions'][0] == t1 for block in self.blocks])
        # check that the transaction is committed
        self.assertTrue(t1_acc)
        
        t2 = make_transaction('test8b', self.private_key, 0)
        self.assertFalse(self.clients[0].transaction(t2))

    def test_same_nonce_transactions_different_node_after_block_commit(self):

        #Create t1
        t1 = make_transaction("test8a", self.private_key, 0)

        # create a transaction

        # send the transaction
        self.assertTrue(self.clients[0].transaction(t1))

        # wait for the block from all nodes
        with self.lock:
            self.cond.wait_for(lambda: len(self.blocks) == len(self.runners))

        t1_acc = all([block['transactions'][0] == t1 for block in self.blocks])
        # check that the transaction is committed
        self.assertTrue(t1_acc)
        
        t2 = make_transaction('test8b', self.private_key, 0)
        self.assertFalse(self.clients[1].transaction(t2))

    def test_invalid_signature(self):

        # Create transaction
        t1 = {
            'sender': self.private_key.public_key().public_bytes_raw().hex(),
            'message': "test9",
            'nonce': 0
            }
        signature = self.private_key2.sign(transaction_bytes(t1)).hex()
        t1['signature'] = signature

        # send the transaction
        self.assertFalse(self.clients[0].transaction(t1))

    def test_invalid_format_message_type_wrong(self):

        # Create transaction
        t1 = {
            'sender': self.private_key.public_key().public_bytes_raw().hex(),
            'message': 20,
            'nonce': 0
            }
        signature = self.private_key.sign(transaction_bytes(t1)).hex()
        t1['signature'] = signature

        # send the transaction
        self.assertFalse(self.clients[0].transaction(t1))

    def test_invalid_format_sender_type_wrong(self):

        # Create transaction
        t1 = {
            'sender': "thisisnotakey",
            'message': 20,
            'nonce': 0
            }
        t1['signature'] = "Fakesignature"

        # send the transaction
        self.assertFalse(self.clients[0].transaction(t1))

    def test_invalid_format_nonce_type_wrong(self):

        # Create transaction
        t1 = {
            'sender': self.private_key.public_key().public_bytes_raw().hex(),
            'message': "invalidnoncetest",
            'nonce': "notanint"
            }
        signature = self.private_key.sign(transaction_bytes(t1)).hex()
        t1['signature'] = signature

        # send the transaction
        self.assertFalse(self.clients[0].transaction(t1))

    def test_invalid_format_signature_type_wrong(self):

        # Create transaction
        t1 = {
            'sender': self.private_key.public_key().public_bytes_raw().hex(),
            'message': "invalidSignatureTest",
            'nonce': 0
            }
        signature = self.private_key.sign(transaction_bytes(t1)).hex()
        t1['signature'] = "fakeSigfakeSig"

        # send the transaction
        self.assertFalse(self.clients[0].transaction(t1))

    def test_1_transaction_single_node_fails(self):
        # create a transaction
        transaction = make_transaction('test1', self.private_key, 0)

        # send the transaction
        self.assertTrue(self.clients[0].transaction(transaction))

        self.runners[1].stop
        self.runners.remove(self.runners[1])

        # wait for the block from all nodes
        with self.lock:
            self.cond.wait_for(lambda: len(self.blocks) == len(self.runners))

        # check that the transaction is committed
        self.assertTrue(all([block['transactions'][0] == transaction for block in self.blocks]))


    # In order to include the below test, you must change the number of server runners being tested in each
    # test up to 7. By doing this you dramatically increase the time taken for these tests to complete, so for 
    # now i have this test commented out

    # def test_1_transaction_two_nodes_fail(self):
    #     # create a transaction
    #     transaction = make_transaction('test1', self.private_key, 0)

    #     # send the transaction
    #     self.assertTrue(self.clients[0].transaction(transaction))

    #     self.runners[1].stop
    #     self.runners.remove(self.runners[1])
        
    #     # These turn into different nodes at index 1 because the one currently at 1 gets removed
    #     self.runners[1].stop
    #     self.runners.remove(self.runners[1])


    #     # wait for the block from all nodes
    #     with self.lock:
    #         self.cond.wait_for(lambda: len(self.blocks) == len(self.runners))

    #     # check that the transaction is committed
    #     self.assertTrue(all([block['transactions'][0] == transaction for block in self.blocks]))

    
    

if __name__ == '__main__':
    unittest.main()
