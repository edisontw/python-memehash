#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>
#include "memehash.h"

// 反轉 32 bytes
static void reverse32(unsigned char* data) {
    for (int i = 0; i < 16; i++) {
        unsigned char tmp = data[i];
        data[i] = data[31 - i];
        data[31 - i] = tmp;
    }
}
// 反轉 4 bytes
static void reverse4(unsigned char* data) {
    unsigned char tmp0 = data[0], tmp1 = data[1];
    data[0] = data[3];
    data[1] = data[2];
    data[2] = tmp1;
    data[3] = tmp0;
}

static PyObject* meme_getpowhash(PyObject* self, PyObject* args)
{
    const unsigned char* block_header = NULL;
    Py_ssize_t header_len = 0;

    // 1) 解析 python 傳入的 80 bytes
    if (!PyArg_ParseTuple(args, "s#", &block_header, &header_len)) {
        return NULL;
    }
    if (header_len != 80) {
        PyErr_Format(PyExc_ValueError, "Block header must be 80 bytes, got %zd", header_len);
        return NULL;
    }

    // 2) 複製一份，做欄位反轉
    unsigned char real_header[80];
    memcpy(real_header, block_header, 80);

    // ============ 關鍵欄位翻轉 ============
    // layout: ver(4), prevhash(32), merkle(32), time(4), bits(4), nonce(4)
    // prevhash: offset = 4
    reverse32(real_header + 4);
    // merkle: offset = 36
    reverse32(real_header + 36);
    // bits: offset = 72
    reverse4(real_header + 72);
    // nonce: offset = 76
    reverse4(real_header + 76);

    // 3) 呼叫 meme_hash()
    unsigned char output[32];
    memset(output, 0, sizeof(output));
    meme_hash((const char*)real_header, (char*)output, 80);

    // 4) 回傳 Python bytes
#if PY_MAJOR_VERSION >= 3
    return Py_BuildValue("y#", output, 32);
#else
    return Py_BuildValue("s#", output, 32);
#endif
}

static PyMethodDef MemeMethods[] = {
    {"getPoWHash", meme_getpowhash, METH_VARARGS, "Returns the PoW hash using meme hash"},
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

PyMODINIT_FUNC PyInit_meme_hash(void) {
    return PyModule_Create(&MemeModule);
}
#else
PyMODINIT_FUNC initmeme_hash(void) {
    Py_InitModule("meme_hash", MemeMethods);
}
#endif
