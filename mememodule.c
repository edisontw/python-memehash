#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>

#include "memehash.h"  // 要包含我們的 meme_hash.h

// 反轉 32 bytes（用於 prevhash, merkle_root）
static void reverse32(unsigned char* data)
{
    for (int i = 0; i < 16; i++) {
        unsigned char tmp = data[i];
        data[i] = data[31 - i];
        data[31 - i] = tmp;
    }
}

// 反轉 4 bytes（用於 bits, nonce ）
static void reverse4(unsigned char* data)
{
    unsigned char tmp0 = data[0];
    unsigned char tmp1 = data[1];
    data[0] = data[3];
    data[1] = data[2];
    data[2] = tmp1;
    data[3] = tmp0;
}

static PyObject* meme_getpowhash(PyObject* self, PyObject* args)
{
    const unsigned char* block_header = NULL;
    Py_ssize_t header_len = 0;

    // 解析 Python 傳入的 block header bytes (80 bytes)
    if (!PyArg_ParseTuple(args, "s#", &block_header, &header_len)) {
        return NULL;
    }
    if (header_len != 80) {
        PyErr_Format(PyExc_ValueError, "Block header must be exactly 80 bytes, got %zd bytes", header_len);
        return NULL;
    }

    // 複製一份 header，以便在 C 層對其做大小端反轉
    unsigned char real_header[80];
    memcpy(real_header, block_header, 80);

    // === 以下針對瀏覽器格式 head 進行修正 ===
    //  假設 layout: [0..3]:version, [4..35]:prevhash, [36..67]:merkleroot, [68..71]:time, [72..75]:bits, [76..79]:nonce

    // prevhash: reverse 32 bytes
    reverse32(real_header + 4);

    // merkleroot: reverse 32 bytes
    reverse32(real_header + 36);

    // bits: reverse 4 bytes
    reverse4(real_header + 72);

    // nonce: reverse 4 bytes
    reverse4(real_header + 76);

    // 注：若 version, time 也需要反轉，可依實際規則去做。
    // 多數 Bitcoin-like 區塊頭 version/time 已是 little-endian，這裡先不反轉。

    // 呼叫 meme_hash()，得到 32 bytes 雜湊
    unsigned char output[32];
    memset(output, 0, sizeof(output));
    meme_hash((const char*)real_header, (char*)output, 80);

    // 回傳 Python Bytes
#if PY_MAJOR_VERSION >= 3
    return Py_BuildValue("y#", output, 32);
#else
    return Py_BuildValue("s#", output, 32);
#endif
}

// Python 端能調用的方法清單
static PyMethodDef MemeMethods[] = {
    {
        "getPoWHash",
        meme_getpowhash,
        METH_VARARGS,
        "Returns the proof of work hash using meme hash"
    },
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef MemeModule = {
    PyModuleDef_HEAD_INIT,
    "meme_hash",
    "Memehash PoW module",
    -1,
    MemeMethods
};

PyMODINIT_FUNC PyInit_meme_hash(void)
{
    return PyModule_Create(&MemeModule);
}
#else
PyMODINIT_FUNC initmeme_hash(void)
{
    Py_InitModule("meme_hash", MemeMethods);
}
#endif
