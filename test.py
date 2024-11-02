import meme_hash
from binascii import unhexlify, hexlify
import unittest

# Block 1 header information
header_hex = (
    "20000000" +  # Version (536870912 in decimal)
    "00000a308cc3b469703a3bc1aa55bc251a71c9287d7b413242592c0ab0a31f13" +  # Previous block hash
    "3f7ab2aa69fd0ea038de256393455890e45cba83ca0f76fc506c416c96109014" +  # Merkle root hash
    "646da2eb" +  # Timestamp (1683906283 in decimal)
    "1e0fffff" +  # Difficulty target
    "05e1e1d"  # Nonce (385501 in decimal)
)

# Known correct hash value for block 1
best_hash = "00000add89b915d985d20a9b8983a3fb3a96516733f4d032f4e4c9da1e7d6223"

class TestMemeHash(unittest.TestCase):

    def setUp(self):
        # Convert the header information from hex string to bytes
        self.block_header = unhexlify(header_hex)
        self.best_hash = best_hash

    def test_meme_hash(self):
        # Use meme_hash to calculate the hash value of the block header
        self.pow_hash = hexlify(meme_hash.getPoWHash(self.block_header)).decode('utf-8')
        # Verify that the calculated hash matches the known correct hash
        self.assertEqual(self.pow_hash, self.best_hash)

if __name__ == '__main__':
    unittest.main()
