from time import time
from binascii import unhexlify
from hashlib import sha256
def swap(text): return ''.join([text[- i * 2 - 2] + text[- i * 2 - 1] for i in range(len(text) // 2)])
def parse(bits, version, lastHash, merkleRoot, Time = None):
    if Time: from datetime import datetime # You're not supposed to supply Time
    while True:
        target = "%x" % (int(bits[2:], 16) * 2 ** (8 * (int(bits[: 2], 16) - 3)))
        blockData = swap(("%x" % (version)).zfill(8)) + swap(lastHash) + swap(merkleRoot) + swap("%x" % (int(time() if not Time else datetime(*Time).timestamp()))) + swap(bits.zfill(8))
        for nonce in range(0, 2 ** 32):
            hashData = unhexlify(blockData + swap("%x" % nonce))
            hash = swap(sha256(sha256(hashData).digest()).hexdigest())
            if hash <= target.zfill(64): return hashData
print(parse("%x" % 486604799, 1, '0000000000000000000000000000000000000000000000000000000000000000', '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b', (2009,1,3,20,15,5)))
