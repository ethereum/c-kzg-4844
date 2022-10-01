#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "c_kzg_4844.h"

static void free_capsule(PyObject *c) {
  free(PyCapsule_GetPointer(c, PyCapsule_GetName(c)));
}

static PyObject* bytes_to_bls_field_wrap(PyObject *self, PyObject *args) {
  PyBytesObject *pybytes;

  if (!PyArg_ParseTuple(args, "S", &pybytes) ||
      PyBytes_Size((PyObject*)pybytes) != 32)
    return PyErr_Format(PyExc_ValueError, "expected 32 bytes");

  BLSFieldElement *out = (BLSFieldElement*)malloc(sizeof(BLSFieldElement));

  if (out == NULL) return PyErr_NoMemory();

  bytes_to_bls_field(out, (const uint8_t*)PyBytes_AsString((PyObject*)pybytes));

  return PyCapsule_New(out, "BLSFieldElement", free_capsule);
}

static PyObject* uint64s_from_BLSFieldElement_wrap(PyObject *self, PyObject *args) {
  PyObject *c;
  if (!PyArg_UnpackTuple(args, "uint64s_from_BLSFieldElement", 1, 1, &c) ||
      !PyCapsule_IsValid(c, "BLSFieldElement"))
    return PyErr_Format(PyExc_ValueError, "expected a BLSFieldElement capsule");
  uint64_t out[4];
  uint64s_from_BLSFieldElement(out, PyCapsule_GetPointer(c, PyCapsule_GetName(c)));
  return PyTuple_Pack(4,
      PyLong_FromUnsignedLong(out[0]),
      PyLong_FromUnsignedLong(out[1]),
      PyLong_FromUnsignedLong(out[2]),
      PyLong_FromUnsignedLong(out[3]));
}

static PyMethodDef ckzgmethods[] = {
  {"uint64s_from_BLSFieldElement", uint64s_from_BLSFieldElement_wrap, METH_VARARGS, "Convert a field element to a 4-tuple of uint64s"},
  {"bytes_to_bls_field", bytes_to_bls_field_wrap, METH_VARARGS, "Convert 32 bytes to a field element"},
  {NULL, NULL, 0, NULL}
};

static struct PyModuleDef ckzg = {
  PyModuleDef_HEAD_INIT,
  "ckzg",
  NULL,
  -1,
  ckzgmethods
};

PyMODINIT_FUNC PyInit_ckzg(void)
{
    return PyModule_Create(&ckzg);
}
