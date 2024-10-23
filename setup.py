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
        '-fPIC',
        '-fvisibility=hidden'
    ],
    define_macros = [
        ('SPH_SMALL_FOOTPRINT', '1'),
        ('SPH_COMPACT_BLAKE', '1'),
        ('SPH_KECCAK_UNROLL', '0'),
        ('SPH_SMALL_FOOTPRINT_SIMD', '1'),
        ('SPH_SMALL_FOOTPRINT_ECHO', '1'),
        ('SPH_LITTLE_ENDIAN', '1'),  # ARM64 is typically little endian
        ('SPH_64', '1'),            # 64-bit architecture
        ('SPH_64_TRUE', '1'),       # True 64-bit architecture
        ('SPH_LITTLE_FAST', '1'),   # Optimize for little endian
        ('SPH_UNALIGNED', '1'),     # Allow unaligned memory access
        ('_LARGEFILE64_SOURCE', '1'),
        ('_FILE_OFFSET_BITS', '64')
    ]
)

setup (
    name = 'meme_hash',
    version = '1.0',
    description = 'Bindings for Memehash proof of work function',
    author = 'Your Name',
    author_email = 'your.email@example.com',
    url = 'https://github.com/yourusername/meme_hash',
    ext_modules = [memehash_module]
)
