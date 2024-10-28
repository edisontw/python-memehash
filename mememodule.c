#include <Python.h>
#include "memehash.h"  // memehash.h
#include "sha3/sph_sha2.h"

static PyObject *meme_getpowhash(PyObject *self, PyObject *args) {
    char *output;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif

    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;

    Py_INCREF(input);
    output = PyMem_Malloc(32);

#if PY_MAJOR_VERSION >= 3
    meme_hash((char *)PyBytes_AsString((PyObject*) input), output, PyBytes_Size((PyObject*) input));  // transfer input lenght
#else
    meme_hash((char *)PyString_AsString((PyObject*) input), output, PyString_Size((PyObject*) input));  // transfer input lenght
#endif

    Py_DECREF(input);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", output, 32);
#else
    value = Py_BuildValue("s#", output, 32);
#endif

    PyMem_Free(output);
    return value;
}

static PyMethodDef MemeMethods[] = {
    { "getPoWHash", meme_getpowhash, METH_VARARGS, "Returns the proof of work hash using meme hash" },
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef MemeModule = {
    PyModuleDef_HEAD_INIT,
    "meme_hash",
    "...",
    -1,
    MemeMethods
};

PyMODINIT_FUNC PyInit_meme_hash(void) {
    return PyModule_Create(&MemeModule);
}

#else

PyMODINIT_FUNC initmeme_hash(void) {
    (void) Py_InitModule("meme_hash", MemeMethods);
}
#endif
