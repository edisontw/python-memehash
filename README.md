Python module for memehash hashing: meme_hash (v1.0)

Download:

git clone https://github.com/edisontw/python-memehash.git

Install:

python setup.py build

python setup.py install


Test:

python3 test.py


Files Upload:

sph_sha2.c
sph_sha2.h
sha256.c
sha256.h
md_helper.c

Error message:
Traceback (most recent call last):
  File "/home/ubuntu/python-memehash/test.py", line 1, in <module>
    import meme_hash
ImportError: /home/ubuntu/.local/lib/python3.10/site-packages/meme_hash.cpython-310-aarch64-linux-gnu.so: undefined symbol: sph_sha224
