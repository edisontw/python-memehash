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
    extra_compile_args = [
        '-O2', 
        '-funroll-loops', 
        '-fomit-frame-pointer',
        '-DSPH_SMALL_FOOTPRINT=1',
        '-fPIC'  # Ensure position-independent code
    ],
    extra_link_args = [
        '-Wl,--export-dynamic'  # Export all symbols for dynamic linking
    ],
    define_macros = [
        ('SPH_SMALL_FOOTPRINT', '1'),
        ('SPH_COMPACT_BLAKE', '1'),
        ('SPH_KECCAK_UNROLL', '0'),
        ('SPH_SMALL_FOOTPRINT_SIMD', '1'),
        ('SPH_SMALL_FOOTPRINT_ECHO', '1')
    ]
)

setup (
    name = 'meme_hash',
    version = '1.0',
    description = 'Bindings for Memehash proof of work function',
    author = 'Edison Huang',
    author_email = 'your.email@example.com',
    url = 'https://github.com/edisontw/python-memehash',
    ext_modules = [memehash_module]
)
