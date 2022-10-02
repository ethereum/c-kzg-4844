#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "c_kzg_4844.h"

static void free_BLSFieldElement(PyObject *c) {
  free(PyCapsule_GetPointer(c, "BLSFieldElement"));
}

static void free_PolynomialEvalForm(PyObject *c) {
  PolynomialEvalForm *p = PyCapsule_GetPointer(c, "PolynomialEvalForm");
  free_polynomial(p);
  free(p);
}

static PyObject* bytes_to_bls_field_wrap(PyObject *self, PyObject *args) {
  PyBytesObject *pybytes;

  if (!PyArg_ParseTuple(args, "S", &pybytes) ||
      PyBytes_Size((PyObject*)pybytes) != 32)
    return PyErr_Format(PyExc_ValueError, "expected 32 bytes");

  BLSFieldElement *out = (BLSFieldElement*)malloc(sizeof(BLSFieldElement));

  if (out == NULL) return PyErr_NoMemory();

  bytes_to_bls_field(out, (const uint8_t*)PyBytes_AsString((PyObject*)pybytes));

  return PyCapsule_New(out, "BLSFieldElement", free_BLSFieldElement);
}

static PyObject* int_from_BLSFieldElement(PyObject *self, PyObject *args) {
  PyObject *c;
  if (!PyArg_UnpackTuple(args, "uint64s_from_BLSFieldElement", 1, 1, &c) ||
      !PyCapsule_IsValid(c, "BLSFieldElement"))
    return PyErr_Format(PyExc_ValueError, "expected a BLSFieldElement capsule");
  uint64_t u[4];
  uint64s_from_BLSFieldElement(u, PyCapsule_GetPointer(c, PyCapsule_GetName(c)));
  PyObject *out = PyLong_FromUnsignedLong(0);
  PyObject *mult = PyLong_FromUnsignedLong(1);
  PyObject *two64 = PyNumber_Power(PyLong_FromUnsignedLong(2), PyLong_FromUnsignedLong(64), Py_None);
  for (int i = 0; i < 4; i++) {
    out = PyNumber_Add(out, PyNumber_Multiply(mult, PyLong_FromUnsignedLong(u[i])));
    mult = PyNumber_Multiply(mult, two64);
  }
  return out;
}

static PyObject* alloc_polynomial_wrap(PyObject *self, PyObject *args) {
  PyObject *a;
  if (!PyArg_UnpackTuple(args, "alloc_polynomial_wrap", 1, 1, &a) ||
      !PySequence_Check(a))
    return PyErr_Format(PyExc_ValueError, "expected sequence");

  PolynomialEvalForm *p = (PolynomialEvalForm*)malloc(sizeof(PolynomialEvalForm));

  if (p == NULL) return PyErr_NoMemory();

  Py_ssize_t n = PySequence_Length(a);
  p->length = n;

  if (alloc_polynomial(p, n) != C_KZG_OK)
    return PyErr_Format(PyExc_RuntimeError, "error allocating polynomial");

  PyObject *e;
  for (Py_ssize_t i = 0; i < n; i++) {
    e = PySequence_GetItem(a, i);
    if (!PyCapsule_IsValid(e, "BLSFieldElement")) {
      free_polynomial(p);
      free(p);
      return PyErr_Format(PyExc_ValueError, "expected BLSFieldElement capsules");
    }
    p->values[i] = *(BLSFieldElement*)PyCapsule_GetPointer(e, "BLSFieldElement");
  }

  return PyCapsule_New(p, "PolynomialEvalForm", free_PolynomialEvalForm);
}

static PyObject* bytes_from_G1_wrap(PyObject *self, PyObject *args) {
  PyObject *c;
  if (!PyArg_UnpackTuple(args, "bytes_from_G1", 1, 1, &c) ||
      !PyCapsule_IsValid(c, "G1"))
    return PyErr_Format(PyExc_ValueError, "expected G1 capsule");
  uint8_t bytes[48];
  bytes_from_G1(bytes, PyCapsule_GetPointer(c, "G1"));
  return PyBytes_FromStringAndSize((char*)bytes, 48);
}

static PyMethodDef ckzgmethods[] = {
  {"bytes_from_G1",            bytes_from_G1_wrap,          METH_VARARGS, "Convert a group element to 48 bytes"},
  {"int_from_BLSFieldElement", int_from_BLSFieldElement,    METH_VARARGS, "Convert a field element to a 256-bit int"},
  {"bytes_to_bls_field",       bytes_to_bls_field_wrap,     METH_VARARGS, "Convert 32 bytes to a field element"},
  {"alloc_polynomial",         alloc_polynomial_wrap,       METH_VARARGS, "Create a PolynomialEvalForm from a sequence of field elements"},
  // {"load_trusted_setup",       load_trusted_setup_wrap,     METH_VARARGS, "Load trusted setup from file path"},
  // {"blob_to_kzg_commitment",   blob_to_kzg_commitment_wrap, METH_VARARGS, "Create a commitment from a sequence of field elements"},
  // {"compute_powers",           compute_powers_wrap,         METH_VARARGS, "Create a list of powers of a field element"},
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
