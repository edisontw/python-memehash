Python module for memehash hashing: meme_hash (v1.0)

Download: git clone https://github.com/edisontw/python-memehash.git

Install: python3 setup.py build & python3 setup.py install

Files Upload: sha2.c, sph_sha2.h

Test: python3 test.py

block 1 information:
{"hash":"00000add89b915d985d20a9b8983a3fb3a96516733f4d032f4e4c9da1e7d6223","confirmations":2188897,"size":179,"height":1,"version":536870912,"merkleroot":"3f7ab2aa69fd0ea038de256393455890e45cba83ca0f76fc506c416c96109014","tx":["3f7ab2aa69fd0ea038de256393455890e45cba83ca0f76fc506c416c96109014"],"time":1683906283,"mediantime":1683906283,"nonce":385501,"bits":"1e0fffff","difficulty":0.0002441371325370145,"chainwork":"0000000000000000000000000000000000000000000000000000000000200002","previousblockhash":"00000a308cc3b469703a3bc1aa55bc251a71c9287d7b413242592c0ab0a31f13","nextblockhash":"000004cd5bb4e193af85f33526f60c8c20d83194fa64cd6dc0414d450265c105"}

error messages:
FAIL: test_meme_hash (__main__.TestMemeHash)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/ubuntu/python-memehash/test.py", line 29, in test_meme_hash
    self.assertEqual(self.pow_hash, self.best_hash)
AssertionError: '94b69572354e798f1514bee4a6995bd20e54aea31218c7b369c578361d625523' != '00000add89b915d985d20a9b8983a3fb3a96516733f4d032f4e4c9da1e7d6223'
- 94b69572354e798f1514bee4a6995bd20e54aea31218c7b369c578361d625523
+ 00000add89b915d985d20a9b8983a3fb3a96516733f4d032f4e4c9da1e7d6223
----------------------------------------------------------------------
