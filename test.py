import meme_hash
from binascii import unhexlify, hexlify
import unittest

def reverse_hex(hex_str):
    # Reverse the byte order of the hex string
    return ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))

class TestMemeHash(unittest.TestCase):

    def setUp(self):
        version = "20000000"
        version_le = reverse_hex(version)

        prev_block_hash = "00000a308cc3b469703a3bc1aa55bc251a71c9287d7b413242592c0ab0a31f13"
        prev_block_hash_le = reverse_hex(prev_block_hash)

        merkle_root = "3f7ab2aa69fd0ea038de256393455890e45cba83ca0f76fc506c416c96109014"
        merkle_root_le = reverse_hex(merkle_root)

        timestamp = "646da2eb"
        timestamp_le = reverse_hex(timestamp)

        bits = "1e0fffff"
        bits_le = reverse_hex(bits)

        nonce = "0005e205"  # Ensure it's 4 bytes
        nonce_le = reverse_hex(nonce)

        header_hex = (
            version_le +
            prev_block_hash_le +
            merkle_root_le +
            timestamp_le +
            bits_le +
            nonce_le
        )

        # Convert the header information from hex string to bytes
        self.block_header = unhexlify(header_hex)
        self.best_hash = "00000add89b915d985d20a9b8983a3fb3a96516733f4d032f4e4c9da1e7d6223"

    def test_meme_hash(self):
        # Use meme_hash to calculate the hash value of the block header
        self.pow_hash = hexlify(meme_hash.getPoWHash(self.block_header)).decode('utf-8')
        # Verify that the calculated hash matches the known correct hash
        self.assertEqual(self.pow_hash, self.best_hash)

if __name__ == '__main__':
    unittest.main()
