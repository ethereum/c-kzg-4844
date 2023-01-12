#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "c_kzg_4844.h"

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

  uint8_t* blob = (uint8_t*)PyBytes_AsString(b);

  KZGCommitment k;
  if (blob_to_kzg_commitment(&k, blob, PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    return PyErr_Format(PyExc_RuntimeError, "blob_to_kzg_commitment failed");
  }

  return PyBytes_FromStringAndSize((char*)(&k), BYTES_PER_COMMITMENT);
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

  KZGProof k;
  if (compute_aggregate_kzg_proof(&k, blobs, n,
        PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    return PyErr_Format(PyExc_RuntimeError, "compute_aggregate_kzg_proof failed");
  }

  return PyBytes_FromStringAndSize((char*)(&k), BYTES_PER_PROOF);
}

static PyObject* verify_aggregate_kzg_proof_wrap(PyObject *self, PyObject *args) {
  PyObject *b, *c, *p, *s, *e;

  if (!PyArg_UnpackTuple(args, "verify_aggregate_kzg_proof", 4, 4, &b, &c, &p, &s) ||
      !PyBytes_Check(b) ||
      !PySequence_Check(c) ||
      !PyBytes_Check(p) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError,
        "expected bytes, sequence, proof, trusted setup");

  if (PyBytes_Size(p) != BYTES_PER_PROOF)
    return PyErr_Format(PyExc_ValueError, "expected proof to be BYTES_PER_PROOF bytes");

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
  KZGProof *proof = (KZGProof*)PyBytes_AsString(p);

  for (Py_ssize_t i = 0; i < n; i++) {
    e = PySequence_GetItem(c, i);
    if (!PyBytes_Check(e)) {
      free(commitments);
      return PyErr_Format(PyExc_ValueError, "expected commitment to be bytes");
    }
    if (PyBytes_Size(e) != BYTES_PER_COMMITMENT) {
      free(commitments);
      return PyErr_Format(PyExc_ValueError, "expected commitment to be BYTES_PER_COMMITMENT bytes");
    }
    memcpy(&commitments[i], PyBytes_AsString(e), sizeof(KZGCommitment));
  }

  bool out;

  if (verify_aggregate_kzg_proof(&out,
        blobs, commitments, n, proof,
        PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    free(commitments);
    return PyErr_Format(PyExc_RuntimeError, "verify_aggregate_kzg_proof failed");
  }

  free(commitments);
  if (out) Py_RETURN_TRUE; else Py_RETURN_FALSE;
}

static PyMethodDef ckzgmethods[] = {
  {"load_trusted_setup",          load_trusted_setup_wrap,          METH_VARARGS, "Load trusted setup from file path"},
  {"blob_to_kzg_commitment",      blob_to_kzg_commitment_wrap,      METH_VARARGS, "Create a commitment from a blob"},
  {"compute_aggregate_kzg_proof", compute_aggregate_kzg_proof_wrap, METH_VARARGS, "Compute aggregate KZG proof"},
  {"verify_aggregate_kzg_proof",  verify_aggregate_kzg_proof_wrap,  METH_VARARGS, "Verify aggregate KZG proof"},
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
