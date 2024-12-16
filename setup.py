from setuptools import setup, Extension

memehash_module = Extension(
    'meme_hash',
    sources = [
        'mememodule.c',
        'memehash.c',
        'sha3/blake.c',
        'sha3/cubehash.c',
        'sha3/shavite.c',
        'sha3/simd.c',
        'sha3/echo.c',
        'sha3/sha2.c'
    ],
    include_dirs = ['.', './sha3'],
    extra_compile_args = [
        '-O2', '-fPIC', '-funroll-loops', '-fomit-frame-pointer',
        '-DSPH_SMALL_FOOTPRINT=1', '-DSHA2_INCLUDE_SHA224'
    ],
    define_macros=[
        ('SPH_SMALL_FOOTPRINT', '1'),
        ('SPH_COMPACT_BLAKE', '1')
    ]
)

setup(
    name = 'meme_hash',
    version = '1.0',
    description = 'Bindings for Memehash proof of work function',
    author = 'Your Name',
    author_email = 'your.email@example.com',
    url = 'https://github.com/yourusername/meme_hash',
    ext_modules = [memehash_module],
    py_modules = ['meme_hash'],
)
