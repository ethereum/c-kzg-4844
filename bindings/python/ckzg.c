#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "c_kzg_4844.h"

static void free_G1(PyObject *c) {
  free(PyCapsule_GetPointer(c, "G1"));
}

static void free_KZGSettings(PyObject *c) {
  KZGSettings *s = PyCapsule_GetPointer(c, "KZGSettings");
  free_trusted_setup(s);
  free(s);
}

static PyObject* load_trusted_setup_wrap(PyObject *self, PyObject *args) {
  PyObject *f;

  if (!PyArg_ParseTuple(args, "U", &f))
    return PyErr_Format(PyExc_ValueError, "expected a string");

  KZGSettings *s = (KZGSettings*)malloc(sizeof(KZGSettings));

  if (s == NULL) return PyErr_NoMemory();

  if (load_trusted_setup_file(s, fopen(PyUnicode_AsUTF8(f), "r")) != C_KZG_OK) {
    free(s);
    return PyErr_Format(PyExc_RuntimeError, "error loading trusted setup");
  }

  return PyCapsule_New(s, "KZGSettings", free_KZGSettings);
}

static PyObject* blob_to_kzg_commitment_wrap(PyObject *self, PyObject *args) {
  PyObject *b;
  PyObject *s;

  if (!PyArg_UnpackTuple(args, "blob_to_kzg_commitment_wrap", 2, 2, &b, &s) ||
      !PyBytes_Check(b) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError, "expected bytes and trusted setup");

  if (PyBytes_Size(b) != 32 * FIELD_ELEMENTS_PER_BLOB)
    return PyErr_Format(PyExc_ValueError, "expected 32 * FIELD_ELEMENTS_PER_BLOB bytes");

  Blob *blob = (Blob*)PyBytes_AsString(b);

  KZGCommitment *k = (KZGCommitment*)malloc(sizeof(KZGCommitment));

  if (k == NULL) return PyErr_NoMemory();

  if (blob_to_kzg_commitment(k, blob, PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    free(k);
    return PyErr_Format(PyExc_RuntimeError, "blob_to_kzg_commitment failed");
  }

  return PyCapsule_New(k, "G1", free_G1);
}

static PyObject* compute_aggregate_kzg_proof_wrap(PyObject *self, PyObject *args) {
  PyObject *b, *s;

  if (!PyArg_UnpackTuple(args, "compute_aggregate_kzg_proof", 2, 2, &b, &s) ||
      !PyBytes_Check(b) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError, "expected bytes, trusted setup");

  Py_ssize_t n = PyBytes_Size(b);
  if (n % (32 * FIELD_ELEMENTS_PER_BLOB) != 0)
    return PyErr_Format(PyExc_ValueError, "expected a multiple of 32 * FIELD_ELEMENTS_PER_BLOB bytes");
  n = n / 32 / FIELD_ELEMENTS_PER_BLOB;

  Blob* blobs = (Blob*)PyBytes_AsString(b);

  KZGProof *k = (KZGProof*)malloc(sizeof(KZGProof));

  if (k == NULL) {
    return PyErr_NoMemory();
  }

  if (compute_aggregate_kzg_proof(k, blobs, n,
        PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    free(k);
    return PyErr_Format(PyExc_RuntimeError, "compute_aggregate_kzg_proof failed");
  }

  return PyCapsule_New(k, "G1", free_G1);
}

static PyObject* verify_aggregate_kzg_proof_wrap(PyObject *self, PyObject *args) {
  PyObject *b, *c, *p, *s, *e;

  if (!PyArg_UnpackTuple(args, "verify_aggregate_kzg_proof", 4, 4, &b, &c, &p, &s) ||
      !PyBytes_Check(b) ||
      !PySequence_Check(c) ||
      !PyCapsule_IsValid(p, "G1") ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError,
        "expected bytes, sequence, proof, trusted setup");

  Py_ssize_t n = PyBytes_Size(b);
  if (n % (32 * FIELD_ELEMENTS_PER_BLOB) != 0)
    return PyErr_Format(PyExc_ValueError, "expected a multiple of 32 * FIELD_ELEMENTS_PER_BLOB bytes");
  n = n / 32 / FIELD_ELEMENTS_PER_BLOB;

  if (PySequence_Length(c) != n)
    return PyErr_Format(PyExc_ValueError, "expected same number of commitments as polynomials");

  KZGCommitment* commitments = calloc(n, sizeof(KZGCommitment));

  if (commitments == NULL) {
    return PyErr_NoMemory();
  }

  Blob* blobs = (Blob*)PyBytes_AsString(b);

  for (Py_ssize_t i = 0; i < n; i++) {
    e = PySequence_GetItem(c, i);
    if (!PyCapsule_IsValid(e, "G1")) {
      free(commitments);
      return PyErr_Format(PyExc_ValueError, "expected G1 capsules");
    }
    memcpy(&commitments[i], PyCapsule_GetPointer(e, "G1"), sizeof(KZGCommitment));
  }

  bool out;

  if (verify_aggregate_kzg_proof(&out,
        blobs, commitments, n,
        PyCapsule_GetPointer(p, "G1"),
        PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    free(commitments);
    return PyErr_Format(PyExc_RuntimeError, "verify_aggregate_kzg_proof failed");
  }

  free(commitments);
  if (out) Py_RETURN_TRUE; else Py_RETURN_FALSE;
}

static PyObject* bytes_from_g1_wrap(PyObject *self, PyObject *args) {
  PyObject *c;

  if (!PyArg_UnpackTuple(args, "bytes_from_g1", 1, 1, &c) ||
      !PyCapsule_IsValid(c, "G1"))
    return PyErr_Format(PyExc_ValueError, "expected G1 capsule");

  uint8_t bytes[48];
  bytes_from_g1(bytes, PyCapsule_GetPointer(c, "G1"));

  return PyBytes_FromStringAndSize((char*)bytes, 48);
}

static PyMethodDef ckzgmethods[] = {
  {"load_trusted_setup",          load_trusted_setup_wrap,          METH_VARARGS, "Load trusted setup from file path"},
  {"blob_to_kzg_commitment",      blob_to_kzg_commitment_wrap,      METH_VARARGS, "Create a commitment from a blob"},
  {"compute_aggregate_kzg_proof", compute_aggregate_kzg_proof_wrap, METH_VARARGS, "Compute aggregate KZG proof"},
  {"verify_aggregate_kzg_proof",  verify_aggregate_kzg_proof_wrap,  METH_VARARGS, "Verify aggregate KZG proof"},
  // for tests/debugging
  {"bytes_from_g1",               bytes_from_g1_wrap,               METH_VARARGS, "Convert a group element to 48 bytes"},
  {NULL, NULL, 0, NULL}
};

static struct PyModuleDef ckzg = {
  PyModuleDef_HEAD_INIT,
  "ckzg",
  NULL,
  -1,
  ckzgmethods
};

PyMODINIT_FUNC PyInit_ckzg(void) {
    return PyModule_Create(&ckzg);
}
