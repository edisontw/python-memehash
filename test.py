import meme_hash
from binascii import unhexlify, hexlify

import unittest

# 原先的 Dash block #1 參數不需要改變，除非你有新的區塊測試
header_hex = ("02000000" +
    "b67a40f3cd5804437a108f105533739c37e6229bc1adcab385140b59fd0f0000" +
    "a71c1aade44bf8425bec0deb611c20b16da3442818ef20489ca1e2512be43eef"
    "814cdb52" +
    "f0ff0f1e" +
    "dbf70100")

# 這裡需要更新為你計算出的 Meme hash 的期望值
best_hash = 'your_calculated_meme_hash_result_here'  # 更新為正確的 hash 值

class TestSequenceFunctions(unittest.TestCase):

    def setUp(self):
        self.block_header = unhexlify(header_hex)
        self.best_hash = best_hash

    def test_meme_hash(self):
        self.pow_hash = hexlify(meme_hash.getPoWHash(self.block_header)).decode('utf-8')
        self.assertEqual(self.pow_hash, self.best_hash)

if __name__ == '__main__':
    unittest.main()
