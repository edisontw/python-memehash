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
        '-fPIC',
        '-fvisibility=hidden',  # Hide all symbols by default
        '-DSPH_UPTR=64',        # Specify pointer size for aarch64
        '-DSPH_KECCAK_UNROLL=0'
    ],
    extra_link_args = [
        '-Wl,--export-dynamic',
        '-Wl,--version-script=' + """VERSION
{
    global:
        extern "C" {
            sph_sha*;
            PyInit_meme_hash;
        };
    local: *;
};"""
    ],
    define_macros = [
        ('SPH_SMALL_FOOTPRINT', '1'),
        ('SPH_COMPACT_BLAKE', '1'),
        ('SPH_KECCAK_UNROLL', '0'),
        ('SPH_SMALL_FOOTPRINT_SIMD', '1'),
        ('SPH_SMALL_FOOTPRINT_ECHO', '1'),
        ('SPH_UPTR', '64'),
        ('SPH_SHA256_FAST', '1')
    ]
)

setup (
    name = 'meme_hash',
    version = '1.0',
    description = 'Bindings for Memehash proof of work function',
    author = 'Edison Huang',
    author_email = 'your.email@example.com',
    url = 'https://github.com/yourusername/meme_hash',
    ext_modules = [memehash_module]
)
