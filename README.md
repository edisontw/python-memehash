Python module for memehash hashing: meme_hash (v1.0)

Download:

git clone https://github.com/edisontw/python-memehash.git

Install:

python setup.py build

python setup.py install


Test:

python3 test.py


Files Upload:

sha2.c
sph_sha2.h

sha256.c 
sha256.h (sph_sha256.h)
md_helper.c

python3 test.py
======================================================================
FAIL: test_meme_hash (__main__.TestMemeHash)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/ubuntu/python-memehash/test.py", line 29, in test_meme_hash
    self.assertEqual(self.pow_hash, self.best_hash)
AssertionError: '94b69572354e798f1514bee4a6995bd20e54aea31218c7b369c578361d625523' != '00000add89b915d985d20a9b8983a3fb3a96516733f4d032f4e4c9da1e7d6223'
- 94b69572354e798f1514bee4a6995bd20e54aea31218c7b369c578361d625523
+ 00000add89b915d985d20a9b8983a3fb3a96516733f4d032f4e4c9da1e7d6223
----------------------------------------------------------------------

