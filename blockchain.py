import json
import hashlib

class Blockchain():
    def  __init__(self):
        self.blockchain = []
        self.pool = []
        self.pool_limit = 3
        self.pubkey_nonce = {}
        self.new_block('0' * 64)

    def new_block(self, previous_hash=None):
        block = {
            'index': len(self.blockchain) + 1,
            'transactions': self.pool.copy(),
            'previous_hash': previous_hash or self.blockchain[-1]['current_hash'],
        }
        block['current_hash'] = self.calculate_hash(block)
        self.pool = []
        self.blockchain.append(block)

    def last_block(self):
        return self.blockchain[-1]

    def calculate_hash(self, block: dict):
        block_object: str = json.dumps({k: block.get(k) for k in ['index', 'transactions', 'previous_hash']}, sort_keys=True)
        block_string = block_object.encode()
        raw_hash = hashlib.sha256(block_string)
        hex_hash = raw_hash.hexdigest()
        return hex_hash

    def set_on_new_block(self, on_new_block: function):
        self.on_new_block = on_new_block
	
    def add_transaction(self, transaction):
        if len(self.pool) < self.pool_limit:
            self.pool.append(transaction)
            return True
        return False
    
    def check_nonce(self, pub_key, nonce):
        if pub_key in self.pubkey_nonce:
            if self.pubkey_nonce[pub_key] == nonce:
                return True
            else:
                return False
        else:
            if nonce == 0:
                return True
            return False