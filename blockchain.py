import json
import hashlib
from typing import Callable

class Blockchain():
    def  __init__(self):
        self.blockchain = []
        self.pool = []
        self.pool_limit = 3
        self.pubkey_nonce = {}
        genesis_block = self.propose_new_block('0' * 64)
        self.commit_block(genesis_block, True)

    def propose_new_block(self, previous_hash=None):
        block = {
            'index': len(self.blockchain) + 1,
            'transactions': self.pool.copy(),
            'previous_hash': previous_hash or self.blockchain[-1]['current_hash'],
        }
        block['current_hash'] = self.calculate_hash(block)
        return block
    
    def commit_block(self, block, genesis=False):
        # Remove transactions from pool that are being committed
        committed_transactions = block["transactions"]
        for commited_transaction in committed_transactions:
            # I think this for loop is not actually needed because
            # the nonce will be out of date if it is updated, however
            # not 100% so not going to do it.
            for transaction in self.pool:
                if commited_transaction == transaction:
                    self.pool.remove(transaction)
            pub_key = commited_transaction["sender"]
            nonce = commited_transaction["nonce"]
            self.pubkey_nonce[pub_key] = commited_transaction["nonce"]
            # print(f"Pubkey {pub_key}, Nonce {nonce}")
        
        # Remove transactions from pool that have nonces that are now out of date
        for transaction in self.pool:
            if not self.check_nonce(transaction["sender"], transaction["nonce"]):
                self.pool.remove(transaction)

        self.blockchain.append(block)
        if not genesis:
            self.on_new_block(block)

    def last_block(self):
        return self.blockchain[-1]

    def calculate_hash(self, block: dict):
        block_object: str = json.dumps({k: block.get(k) for k in ['index', 'transactions', 'previous_hash']}, sort_keys=True)
        block_string = block_object.encode()
        raw_hash = hashlib.sha256(block_string)
        hex_hash = raw_hash.hexdigest()
        return hex_hash

    def set_on_new_block(self, on_new_block: Callable):
        self.on_new_block = on_new_block
	
    def add_transaction(self, transaction):
        if len(self.pool) < self.pool_limit:
            self.pool.append(transaction)
            return True
        return False
    
    def check_nonce(self, pub_key, nonce):

        if pub_key in self.pubkey_nonce:
            if self.pubkey_nonce[pub_key] + 1 == nonce:
                return True
            else:
                return False
        else:
            if nonce == 0:
                return True
            return False