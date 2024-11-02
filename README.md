Python module for memehash hashing: meme_hash (v1.0)

Download: git clone https://github.com/edisontw/python-memehash.git

Install: python3 setup.py build & python3 setup.py install

Files Upload: sha2.c, sph_sha2.h

Test: python3 test.py

block 1 information:
{"hash":"00000add89b915d985d20a9b8983a3fb3a96516733f4d032f4e4c9da1e7d6223","confirmations":2188897,"size":179,"height":1,"version":536870912,"merkleroot":"3f7ab2aa69fd0ea038de256393455890e45cba83ca0f76fc506c416c96109014","tx":["3f7ab2aa69fd0ea038de256393455890e45cba83ca0f76fc506c416c96109014"],"time":1683906283,"mediantime":1683906283,"nonce":385501,"bits":"1e0fffff","difficulty":0.0002441371325370145,"chainwork":"0000000000000000000000000000000000000000000000000000000000200002","previousblockhash":"00000a308cc3b469703a3bc1aa55bc251a71c9287d7b413242592c0ab0a31f13","nextblockhash":"000004cd5bb4e193af85f33526f60c8c20d83194fa64cd6dc0414d450265c105"}

error messages:
FAIL: test_meme_hash (__main__.TestMemeHash)
After BLAKE-512: f74e53c8250d6b2844856fdd66539bdf802ac79ab27ddb5bf8672d20c7b6272085d17e6fa3c027b9fdc02e90ddfdf6f93f1633b3e2ee5adead4e386a4dc7e0a0
After SIMD-512: 0e1b248f8373a27b467e843acc6d0ed467d9c35ab05e521b2fcdbdb2b1f5762611e2f26d134150df5f9a14f3db7b466c6d1774b4f821fd302197631914f4020c
After ECHO-512: 3bfb951228a3f03317aab532d6bc4a689132dd720f9ae5ec1f40dfabe462170ad56c443bff18eb9a7cec9fb474eb408edd29fdb5e16a0fb01f8a4c7dd79753c6
After CubeHash-512: c63d4addb9578c9acc11ffe6b7d4410e68afb86e4197ccfc0bc1adf40171df65d0ecfc73436ce4cb1081ec8b7307268cb422525a66513b68d3bcffd98d7f0e98
After SHAvite-512: b96ee3096ad3950bccd78b7c8d940df3f59136977c37d63884111f41978f9b5081ba609b9b80f2f7414f4f9a7a2fce52f2b5c653f5e79c603ccc7160a27fc505
After SHA-256 (First): 6f26290139c0803e744ab571861da76123d9f02397b3bec22eb7b7dc88be24fd
After SHA-256 (Second): 18cca9b2165310c5483067ad4a2b73be3e6fac1112c92857368c2ffbc956da36
After SHA-256 (Third): bdf23513931dee78a0af8ff3dc3045e4a7e3ed212d5a79f0366c8086fb02244d
F
FAIL: test_meme_hash (__main__.TestMemeHash)

Traceback (most recent call last):
  File "/home/ubuntu/python-memehash/test.py", line 29, in test_meme_hash
    self.assertEqual(self.pow_hash, self.best_hash)
AssertionError: '00b012c15cb30000e004baf4ffff0000c02329ad69e60000306b05ad69e60000' != '00000add89b915d985d20a9b8983a3fb3a96516733f4d032f4e4c9da1e7d6223'
- 00b012c15cb30000e004baf4ffff0000c02329ad69e60000306b05ad69e60000
+ 00000add89b915d985d20a9b8983a3fb3a96516733f4d032f4e4c9da1e7d6223
----------------------------------------------------------------------
