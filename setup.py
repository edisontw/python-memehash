from setuptools import setup, Extension

memehash_module = Extension('meme_hash',
    sources = [
        'mememodule.c',
        'memehash.c',
        'sha3/blake.c',
        'sha3/cubehash.c',
        'sha3/shavite.c',
        'sha3/simd.c',
        'sha3/echo.c',
        'sha3/sha256.c'
    ],
    include_dirs = ['.', './sha3'],
    extra_compile_args = ['-O2', '-funroll-loops', '-fomit-frame-pointer'],
)

setup (
    name = 'meme_hash',
    version = '1.0',
    description = 'Bindings for Memehash proof of work function',
    author = 'Edison Huang',
    url = 'https://github.com/edisontw/python-memehash',
    ext_modules = [memehash_module],
    py_modules = ['meme_hash'],
    test_suite = 'test',
)
