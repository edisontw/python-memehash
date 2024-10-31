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
{'result': '010000000000000000000000000000000000000000000000000000000000000000000000c762a6567f3cc092f0684bb62b7e00a84890b990f07cc71a6bb58d64b98e02e06a855d64ffff0f1e5e5304000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff6204ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000', 'error': None, 'id': 'test'}

Error message:
Traceback (most recent call last):
  File "/home/ubuntu/python-memehash/test.py", line 1, in <module>
    import meme_hash
ImportError: /home/ubuntu/.local/lib/python3.10/site-packages/meme_hash.cpython-310-aarch64-linux-gnu.so: undefined symbol: sph_sha224
