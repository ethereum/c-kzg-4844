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
  FILE *fp;

  if (!PyArg_ParseTuple(args, "U", &f))
    return PyErr_Format(PyExc_ValueError, "expected a string");

  KZGSettings *s = (KZGSettings*)malloc(sizeof(KZGSettings));
  if (s == NULL) return PyErr_NoMemory();

  fp = fopen(PyUnicode_AsUTF8(f), "r");
  if (fp == NULL) {
    free(s);
    return PyErr_Format(PyExc_RuntimeError, "error reading trusted setup");
  }

  C_KZG_RET ret = load_trusted_setup_file(s, fp);
  fclose(fp);

  if (ret != C_KZG_OK) {
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

  if (PyBytes_Size(b) != BYTES_PER_BLOB)
    return PyErr_Format(PyExc_ValueError, "expected blobs to be BYTES_PER_BLOB bytes");

  PyObject *out = PyBytes_FromStringAndSize(NULL, BYTES_PER_COMMITMENT);
  if (out == NULL) return PyErr_NoMemory();

  Blob *blob = (Blob *)PyBytes_AsString(b);
  KZGCommitment *k = (KZGCommitment *)PyBytes_AsString(out);
  if (blob_to_kzg_commitment(k, blob, PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    Py_DECREF(out);
    return PyErr_Format(PyExc_RuntimeError, "blob_to_kzg_commitment failed");
  }

  return out;
}

static PyObject* compute_kzg_proof_wrap(PyObject *self, PyObject *args) {
  PyObject *b, *z, *s;

  if (!PyArg_UnpackTuple(args, "compute_kzg_proof_wrap", 3, 3, &b, &z, &s) ||
      !PyBytes_Check(b) ||
      !PyBytes_Check(z) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError, "expected bytes, bytes, trusted setup");

  if (PyBytes_Size(b) != BYTES_PER_BLOB)
    return PyErr_Format(PyExc_ValueError, "expected blobs to be BYTES_PER_BLOB bytes");
  if (PyBytes_Size(z) != BYTES_PER_FIELD_ELEMENT)
    return PyErr_Format(PyExc_ValueError, "expected blobs to be BYTES_PER_FIELD_ELEMENT bytes");

  PyObject *py_y = PyBytes_FromStringAndSize(NULL, BYTES_PER_FIELD_ELEMENT);
  if (py_y == NULL) return PyErr_NoMemory();
  PyObject *py_proof = PyBytes_FromStringAndSize(NULL, BYTES_PER_PROOF);
  if (py_proof == NULL) return PyErr_NoMemory();

  PyObject *out = PyTuple_Pack(2, py_proof, py_y);
  if (out == NULL) return PyErr_NoMemory();

  Blob *blob = (Blob *)PyBytes_AsString(b);
  Bytes32 *z_bytes = (Bytes32 *)PyBytes_AsString(z);
  KZGProof *proof = (KZGProof *)PyBytes_AsString(py_proof);
  Bytes32 *y_bytes = (Bytes32 *)PyBytes_AsString(py_y);
  if (compute_kzg_proof(proof, y_bytes, blob, z_bytes, PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    Py_DECREF(out);
    return PyErr_Format(PyExc_RuntimeError, "compute_kzg_proof failed");
  }

  return out;
}

static PyObject* compute_blob_kzg_proof_wrap(PyObject *self, PyObject *args) {
  PyObject *b, *c, *s;

  if (!PyArg_UnpackTuple(args, "compute_blob_kzg_proof_wrap", 3, 3, &b, &c, &s) ||
      !PyBytes_Check(b) ||
      !PyBytes_Check(c) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError, "expected bytes, bytes, trusted setup");

  if (PyBytes_Size(b) != BYTES_PER_BLOB)
    return PyErr_Format(PyExc_ValueError, "expected blobs to be BYTES_PER_BLOB bytes");
  if (PyBytes_Size(c) != BYTES_PER_COMMITMENT)
    return PyErr_Format(PyExc_ValueError, "expected commitment to be BYTES_PER_COMMITMENT bytes");

  PyObject *out = PyBytes_FromStringAndSize(NULL, BYTES_PER_PROOF);
  if (out == NULL) return PyErr_NoMemory();

  Blob *blob = (Blob *)PyBytes_AsString(b);
  Bytes48 *commitment_bytes = (Bytes48 *)PyBytes_AsString(c);
  KZGProof *proof = (KZGProof *)PyBytes_AsString(out);
  if (compute_blob_kzg_proof(proof, blob, commitment_bytes, PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    Py_DECREF(out);
    return PyErr_Format(PyExc_RuntimeError, "compute_blob_kzg_proof failed");
  }

  return out;
}

static PyObject* verify_kzg_proof_wrap(PyObject *self, PyObject *args) {
  PyObject *c, *z, *y, *p, *s;

  if (!PyArg_UnpackTuple(args, "verify_kzg_proof", 5, 5, &c, &z, &y, &p, &s) ||
      !PyBytes_Check(c) ||
      !PyBytes_Check(z) ||
      !PyBytes_Check(y) ||
      !PyBytes_Check(p) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError,
        "expected bytes, bytes, bytes, bytes, trusted setup");

  if (PyBytes_Size(c) != BYTES_PER_COMMITMENT)
    return PyErr_Format(PyExc_ValueError, "expected commitment to be BYTES_PER_COMMITMENT bytes");
  if (PyBytes_Size(z) != BYTES_PER_FIELD_ELEMENT)
    return PyErr_Format(PyExc_ValueError, "expected z to be BYTES_PER_FIELD_ELEMENT bytes");
  if (PyBytes_Size(y) != BYTES_PER_FIELD_ELEMENT)
    return PyErr_Format(PyExc_ValueError, "expected y to be BYTES_PER_FIELD_ELEMENT bytes");
  if (PyBytes_Size(p) != BYTES_PER_PROOF)
    return PyErr_Format(PyExc_ValueError, "expected proof to be BYTES_PER_PROOF bytes");

  const Bytes48 *commitment_bytes = (Bytes48 *)PyBytes_AsString(c);
  const Bytes32 *z_bytes = (Bytes32 *)PyBytes_AsString(z);
  const Bytes32 *y_bytes = (Bytes32 *)PyBytes_AsString(y);
  const Bytes48 *proof_bytes = (Bytes48 *)PyBytes_AsString(p);

  bool ok;
  if (verify_kzg_proof(&ok,
        commitment_bytes, z_bytes, y_bytes, proof_bytes,
        PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    return PyErr_Format(PyExc_RuntimeError, "verify_kzg_proof failed");
  }

  if (ok) Py_RETURN_TRUE; else Py_RETURN_FALSE;
}

static PyObject* verify_blob_kzg_proof_wrap(PyObject *self, PyObject *args) {
  PyObject *b, *c, *p, *s;

  if (!PyArg_UnpackTuple(args, "verify_blob_kzg_proof", 4, 4, &b, &c, &p, &s) ||
      !PyBytes_Check(b) ||
      !PyBytes_Check(c) ||
      !PyBytes_Check(p) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError,
        "expected bytes, bytes, bytes, trusted setup");

  if (PyBytes_Size(b) != BYTES_PER_BLOB)
    return PyErr_Format(PyExc_ValueError, "expected blob to be BYTES_PER_BLOB bytes");
  if (PyBytes_Size(c) != BYTES_PER_COMMITMENT)
    return PyErr_Format(PyExc_ValueError, "expected commitment to be BYTES_PER_COMMITMENT bytes");
  if (PyBytes_Size(p) != BYTES_PER_PROOF)
    return PyErr_Format(PyExc_ValueError, "expected proof to be BYTES_PER_PROOF bytes");

  const Blob *blob_bytes = (Blob *)PyBytes_AsString(b);
  const Bytes48 *commitment_bytes = (Bytes48 *)PyBytes_AsString(c);
  const Bytes48 *proof_bytes = (Bytes48 *)PyBytes_AsString(p);

  bool ok;
  if (verify_blob_kzg_proof(&ok,
        blob_bytes, commitment_bytes, proof_bytes,
        PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    return PyErr_Format(PyExc_RuntimeError, "verify_blob_kzg_proof failed");
  }

  if (ok) Py_RETURN_TRUE; else Py_RETURN_FALSE;
}

static PyObject* verify_blob_kzg_proof_batch_wrap(PyObject *self, PyObject *args) {
  PyObject *b, *c, *p, *s;

  if (!PyArg_UnpackTuple(args, "verify_blob_kzg_proof_batch", 4, 4, &b, &c, &p, &s) ||
      !PyBytes_Check(b) ||
      !PyBytes_Check(c) ||
      !PyBytes_Check(p) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError,
        "expected bytes, bytes, bytes, trusted setup");

  Py_ssize_t blobs_count = PyBytes_Size(b);
  if (blobs_count % BYTES_PER_BLOB != 0)
    return PyErr_Format(PyExc_ValueError, "expected blobs to be a multiple of BYTES_PER_BLOB bytes");
  blobs_count = blobs_count / BYTES_PER_BLOB;

  Py_ssize_t commitments_count = PyBytes_Size(c);
  if (commitments_count % BYTES_PER_COMMITMENT != 0)
    return PyErr_Format(PyExc_ValueError, "expected commitments to be a multiple of BYTES_PER_COMMITMENT bytes");
  commitments_count = commitments_count / BYTES_PER_COMMITMENT;

  Py_ssize_t proofs_count = PyBytes_Size(p);
  if (proofs_count % BYTES_PER_PROOF != 0)
    return PyErr_Format(PyExc_ValueError, "expected blobs to be a multiple of BYTES_PER_PROOF bytes");
  proofs_count = proofs_count / BYTES_PER_PROOF;

  if (blobs_count != commitments_count || blobs_count != proofs_count) {
    return PyErr_Format(PyExc_ValueError, "expected same number of blobs/commitments/proofs");
  }

  const Blob *blobs_bytes = (Blob *)PyBytes_AsString(b);
  const Bytes48 *commitments_bytes = (Bytes48 *)PyBytes_AsString(c);
  const Bytes48 *proofs_bytes = (Bytes48 *)PyBytes_AsString(p);

  bool ok;
  if (verify_blob_kzg_proof_batch(&ok,
        blobs_bytes, commitments_bytes, proofs_bytes, blobs_count,
        PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    return PyErr_Format(PyExc_RuntimeError, "verify_blob_kzg_proof_batch failed");
  }

  if (ok) Py_RETURN_TRUE; else Py_RETURN_FALSE;
}

static PyMethodDef ckzgmethods[] = {
  {"load_trusted_setup",          load_trusted_setup_wrap,          METH_VARARGS, "Load trusted setup from file path"},
  {"blob_to_kzg_commitment",      blob_to_kzg_commitment_wrap,      METH_VARARGS, "Create a commitment from a blob"},
  {"compute_kzg_proof",           compute_kzg_proof_wrap,           METH_VARARGS, "Compute a proof for a blob/field"},
  {"compute_blob_kzg_proof",      compute_blob_kzg_proof_wrap,      METH_VARARGS, "Compute a proof for a blob"},
  {"verify_kzg_proof",            verify_kzg_proof_wrap,            METH_VARARGS, "Verify a proof for the given inputs"},
  {"verify_blob_kzg_proof",       verify_blob_kzg_proof_wrap,       METH_VARARGS, "Verify a blob/commitment/proof combo"},
  {"verify_blob_kzg_proof_batch", verify_blob_kzg_proof_batch_wrap, METH_VARARGS, "Verify multiple blob/commitment/proof combos"},
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
