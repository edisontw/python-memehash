from distutils.core import setup, Extension

# meme_hash_module
meme_hash_module = Extension('meme_hash',
                             sources=['mememodule.c',
                                      'memehash.c',
                                      'sha256.c',
                                      'sha3/blake.c',
                                      'sha3/bmw.c',
                                      'sha3/groestl.c',
                                      'sha3/jh.c',
                                      'sha3/keccak.c',
                                      'sha3/skein.c',
                                      'sha3/cubehash.c',
                                      'sha3/echo.c',
                                      'sha3/luffa.c',
                                      'sha3/simd.c',
                                      'sha3/shavite.c',
                                      'sha3/sph_sha2.c',],
                             include_dirs=['.', './sha3'])

setup(name='meme_hash',
      version='1.0',
      description='Binding for Meme proof of work hashing.',
      ext_modules=[meme_hash_module])
