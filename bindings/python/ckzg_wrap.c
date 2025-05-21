#define PY_SSIZE_T_CLEAN
#include "ckzg.h"
#include <Python.h>
#include <stdbool.h>

static void free_KZGSettings(PyObject *c) {
  KZGSettings *s = PyCapsule_GetPointer(c, "KZGSettings");
  free_trusted_setup(s);
  free(s);
}

static PyObject *load_trusted_setup_wrap(PyObject *self, PyObject *args) {
  PyObject *f;
  PyObject *precompute;
  FILE *fp;

  if (!PyArg_UnpackTuple(args, "load_trusted_setup", 2, 2, &f, &precompute) ||
      !PyUnicode_Check(f)) {
    return PyErr_Format(PyExc_ValueError, "expected string and int");
  }

  long precompute_value = PyLong_AsLong(precompute);
  if (precompute_value == -1 && PyErr_Occurred()) {
    return PyErr_Format(PyExc_ValueError, "invalid precompute value");
  }

  KZGSettings *s = (KZGSettings *)malloc(sizeof(KZGSettings));
  if (s == NULL)
    return PyErr_NoMemory();

  fp = fopen(PyUnicode_AsUTF8(f), "r");
  if (fp == NULL) {
    free(s);
    return PyErr_Format(PyExc_RuntimeError, "error reading trusted setup");
  }

  C_KZG_RET ret = load_trusted_setup_file(s, fp, precompute_value);
  fclose(fp);

  if (ret != C_KZG_OK) {
    free(s);
    return PyErr_Format(PyExc_RuntimeError, "error loading trusted setup");
  }

  return PyCapsule_New(s, "KZGSettings", free_KZGSettings);
}

static PyObject *blob_to_kzg_commitment_wrap(PyObject *self, PyObject *args) {
  PyObject *b;
  PyObject *s;

  if (!PyArg_UnpackTuple(args, "blob_to_kzg_commitment_wrap", 2, 2, &b, &s) ||
      !PyBytes_Check(b) || !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError, "expected bytes and trusted setup");

  if (PyBytes_Size(b) != BYTES_PER_BLOB)
    return PyErr_Format(PyExc_ValueError,
                        "expected blobs to be BYTES_PER_BLOB bytes");

  PyObject *out = PyBytes_FromStringAndSize(NULL, BYTES_PER_COMMITMENT);
  if (out == NULL)
    return PyErr_NoMemory();

  Blob *blob = (Blob *)PyBytes_AsString(b);
  KZGCommitment *k = (KZGCommitment *)PyBytes_AsString(out);
  if (blob_to_kzg_commitment(k, blob, PyCapsule_GetPointer(s, "KZGSettings")) !=
      C_KZG_OK) {
    Py_DECREF(out);
    return PyErr_Format(PyExc_RuntimeError, "blob_to_kzg_commitment failed");
  }

  return out;
}

static PyObject *compute_kzg_proof_wrap(PyObject *self, PyObject *args) {
  PyObject *b, *z, *s;

  if (!PyArg_UnpackTuple(args, "compute_kzg_proof_wrap", 3, 3, &b, &z, &s) ||
      !PyBytes_Check(b) || !PyBytes_Check(z) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError,
                        "expected bytes, bytes, trusted setup");

  if (PyBytes_Size(b) != BYTES_PER_BLOB)
    return PyErr_Format(PyExc_ValueError,
                        "expected blobs to be BYTES_PER_BLOB bytes");
  if (PyBytes_Size(z) != BYTES_PER_FIELD_ELEMENT)
    return PyErr_Format(PyExc_ValueError,
                        "expected z to be BYTES_PER_FIELD_ELEMENT bytes");

  PyObject *py_y = PyBytes_FromStringAndSize(NULL, BYTES_PER_FIELD_ELEMENT);
  if (py_y == NULL)
    return PyErr_NoMemory();
  PyObject *py_proof = PyBytes_FromStringAndSize(NULL, BYTES_PER_PROOF);
  if (py_proof == NULL)
    return PyErr_NoMemory();

  PyObject *out = PyTuple_Pack(2, py_proof, py_y);
  if (out == NULL)
    return PyErr_NoMemory();

  Blob *blob = (Blob *)PyBytes_AsString(b);
  Bytes32 *z_bytes = (Bytes32 *)PyBytes_AsString(z);
  KZGProof *proof = (KZGProof *)PyBytes_AsString(py_proof);
  Bytes32 *y_bytes = (Bytes32 *)PyBytes_AsString(py_y);
  if (compute_kzg_proof(proof, y_bytes, blob, z_bytes,
                        PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    Py_DECREF(out);
    return PyErr_Format(PyExc_RuntimeError, "compute_kzg_proof failed");
  }

  return out;
}

static PyObject *compute_blob_kzg_proof_wrap(PyObject *self, PyObject *args) {
  PyObject *b, *c, *s;

  if (!PyArg_UnpackTuple(args, "compute_blob_kzg_proof_wrap", 3, 3, &b, &c,
                         &s) ||
      !PyBytes_Check(b) || !PyBytes_Check(c) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError,
                        "expected bytes, bytes, trusted setup");

  if (PyBytes_Size(b) != BYTES_PER_BLOB)
    return PyErr_Format(PyExc_ValueError,
                        "expected blobs to be BYTES_PER_BLOB bytes");
  if (PyBytes_Size(c) != BYTES_PER_COMMITMENT)
    return PyErr_Format(PyExc_ValueError,
                        "expected commitment to be BYTES_PER_COMMITMENT bytes");

  PyObject *out = PyBytes_FromStringAndSize(NULL, BYTES_PER_PROOF);
  if (out == NULL)
    return PyErr_NoMemory();

  Blob *blob = (Blob *)PyBytes_AsString(b);
  Bytes48 *commitment_bytes = (Bytes48 *)PyBytes_AsString(c);
  KZGProof *proof = (KZGProof *)PyBytes_AsString(out);
  if (compute_blob_kzg_proof(proof, blob, commitment_bytes,
                             PyCapsule_GetPointer(s, "KZGSettings")) !=
      C_KZG_OK) {
    Py_DECREF(out);
    return PyErr_Format(PyExc_RuntimeError, "compute_blob_kzg_proof failed");
  }

  return out;
}

static PyObject *verify_kzg_proof_wrap(PyObject *self, PyObject *args) {
  PyObject *c, *z, *y, *p, *s;

  if (!PyArg_UnpackTuple(args, "verify_kzg_proof", 5, 5, &c, &z, &y, &p, &s) ||
      !PyBytes_Check(c) || !PyBytes_Check(z) || !PyBytes_Check(y) ||
      !PyBytes_Check(p) || !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError,
                        "expected bytes, bytes, bytes, bytes, trusted setup");

  if (PyBytes_Size(c) != BYTES_PER_COMMITMENT)
    return PyErr_Format(PyExc_ValueError,
                        "expected commitment to be BYTES_PER_COMMITMENT bytes");
  if (PyBytes_Size(z) != BYTES_PER_FIELD_ELEMENT)
    return PyErr_Format(PyExc_ValueError,
                        "expected z to be BYTES_PER_FIELD_ELEMENT bytes");
  if (PyBytes_Size(y) != BYTES_PER_FIELD_ELEMENT)
    return PyErr_Format(PyExc_ValueError,
                        "expected y to be BYTES_PER_FIELD_ELEMENT bytes");
  if (PyBytes_Size(p) != BYTES_PER_PROOF)
    return PyErr_Format(PyExc_ValueError,
                        "expected proof to be BYTES_PER_PROOF bytes");

  const Bytes48 *commitment_bytes = (Bytes48 *)PyBytes_AsString(c);
  const Bytes32 *z_bytes = (Bytes32 *)PyBytes_AsString(z);
  const Bytes32 *y_bytes = (Bytes32 *)PyBytes_AsString(y);
  const Bytes48 *proof_bytes = (Bytes48 *)PyBytes_AsString(p);

  bool ok;
  if (verify_kzg_proof(&ok, commitment_bytes, z_bytes, y_bytes, proof_bytes,
                       PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    return PyErr_Format(PyExc_RuntimeError, "verify_kzg_proof failed");
  }

  if (ok)
    Py_RETURN_TRUE;
  else
    Py_RETURN_FALSE;
}

static PyObject *verify_blob_kzg_proof_wrap(PyObject *self, PyObject *args) {
  PyObject *b, *c, *p, *s;

  if (!PyArg_UnpackTuple(args, "verify_blob_kzg_proof", 4, 4, &b, &c, &p, &s) ||
      !PyBytes_Check(b) || !PyBytes_Check(c) || !PyBytes_Check(p) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError,
                        "expected bytes, bytes, bytes, trusted setup");

  if (PyBytes_Size(b) != BYTES_PER_BLOB)
    return PyErr_Format(PyExc_ValueError,
                        "expected blob to be BYTES_PER_BLOB bytes");
  if (PyBytes_Size(c) != BYTES_PER_COMMITMENT)
    return PyErr_Format(PyExc_ValueError,
                        "expected commitment to be BYTES_PER_COMMITMENT bytes");
  if (PyBytes_Size(p) != BYTES_PER_PROOF)
    return PyErr_Format(PyExc_ValueError,
                        "expected proof to be BYTES_PER_PROOF bytes");

  const Blob *blob_bytes = (Blob *)PyBytes_AsString(b);
  const Bytes48 *commitment_bytes = (Bytes48 *)PyBytes_AsString(c);
  const Bytes48 *proof_bytes = (Bytes48 *)PyBytes_AsString(p);

  bool ok;
  if (verify_blob_kzg_proof(&ok, blob_bytes, commitment_bytes, proof_bytes,
                            PyCapsule_GetPointer(s, "KZGSettings")) !=
      C_KZG_OK) {
    return PyErr_Format(PyExc_RuntimeError, "verify_blob_kzg_proof failed");
  }

  if (ok)
    Py_RETURN_TRUE;
  else
    Py_RETURN_FALSE;
}

static PyObject *verify_blob_kzg_proof_batch_wrap(PyObject *self,
                                                  PyObject *args) {
  PyObject *b, *c, *p, *s;

  if (!PyArg_UnpackTuple(args, "verify_blob_kzg_proof_batch", 4, 4, &b, &c, &p,
                         &s) ||
      !PyBytes_Check(b) || !PyBytes_Check(c) || !PyBytes_Check(p) ||
      !PyCapsule_IsValid(s, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError,
                        "expected bytes, bytes, bytes, trusted setup");

  Py_ssize_t blobs_count = PyBytes_Size(b);
  if (blobs_count % BYTES_PER_BLOB != 0)
    return PyErr_Format(
        PyExc_ValueError,
        "expected blobs to be a multiple of BYTES_PER_BLOB bytes");
  blobs_count = blobs_count / BYTES_PER_BLOB;

  Py_ssize_t commitments_count = PyBytes_Size(c);
  if (commitments_count % BYTES_PER_COMMITMENT != 0)
    return PyErr_Format(
        PyExc_ValueError,
        "expected commitments to be a multiple of BYTES_PER_COMMITMENT bytes");
  commitments_count = commitments_count / BYTES_PER_COMMITMENT;

  Py_ssize_t proofs_count = PyBytes_Size(p);
  if (proofs_count % BYTES_PER_PROOF != 0)
    return PyErr_Format(
        PyExc_ValueError,
        "expected proofs to be a multiple of BYTES_PER_PROOF bytes");
  proofs_count = proofs_count / BYTES_PER_PROOF;

  if (blobs_count != commitments_count || blobs_count != proofs_count) {
    return PyErr_Format(PyExc_ValueError,
                        "expected same number of blobs/commitments/proofs");
  }

  const Blob *blobs_bytes = (Blob *)PyBytes_AsString(b);
  const Bytes48 *commitments_bytes = (Bytes48 *)PyBytes_AsString(c);
  const Bytes48 *proofs_bytes = (Bytes48 *)PyBytes_AsString(p);

  bool ok;
  if (verify_blob_kzg_proof_batch(
          &ok, blobs_bytes, commitments_bytes, proofs_bytes, blobs_count,
          PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    return PyErr_Format(PyExc_RuntimeError,
                        "verify_blob_kzg_proof_batch failed");
  }

  if (ok)
    Py_RETURN_TRUE;
  else
    Py_RETURN_FALSE;
}

static PyObject *compute_cells_wrap(PyObject *self, PyObject *args) {
  PyObject *input_blob, *s;
  PyObject *ret = NULL;
  Cell *cells = NULL;

  /* Ensure inputs are the right types */
  if (!PyArg_UnpackTuple(args, "compute_cells", 2, 2, &input_blob, &s) ||
      !PyBytes_Check(input_blob) || !PyCapsule_IsValid(s, "KZGSettings")) {
    ret = PyErr_Format(PyExc_ValueError, "expected bytes and trusted setup");
    goto out;
  }

  /* Ensure blob is the right size */
  if (PyBytes_Size(input_blob) != BYTES_PER_BLOB) {
    ret = PyErr_Format(PyExc_ValueError,
                       "expected blob to be BYTES_PER_BLOB bytes");
    goto out;
  }

  /* Allocate space for the cells */
  cells = calloc(CELLS_PER_EXT_BLOB, BYTES_PER_CELL);
  if (cells == NULL) {
    ret =
        PyErr_Format(PyExc_MemoryError, "Failed to allocate memory for cells");
    goto out;
  }

  /* Call our C function with our inputs */
  const Blob *blob = (Blob *)PyBytes_AsString(input_blob);
  if (compute_cells_and_kzg_proofs(cells, NULL, blob,
                                   PyCapsule_GetPointer(s, "KZGSettings")) !=
      C_KZG_OK) {
    ret = PyErr_Format(PyExc_RuntimeError, "compute_cells failed");
    goto out;
  }

  /* Convert our cells result to a list of bytes objects */
  PyObject *output_cells = PyList_New(CELLS_PER_EXT_BLOB);
  if (output_cells == NULL) {
    ret = PyErr_Format(PyExc_MemoryError,
                       "Failed to allocate memory for output cells");
    goto out;
  }
  for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
    /* Convert cell to a bytes object */
    PyObject *cell_bytes =
        PyBytes_FromStringAndSize((const char *)&cells[i], BYTES_PER_CELL);
    if (cell_bytes == NULL) {
      Py_DECREF(cell_bytes);
      ret = PyErr_Format(PyExc_MemoryError,
                         "Failed to allocate memory for cell bytes");
      goto out;
    }
    /* Add it to our list */
    PyList_SetItem(output_cells, i, cell_bytes);
  }

  /* Success! */
  ret = output_cells;

out:
  free(cells);
  return ret;
}

static PyObject *compute_cells_and_kzg_proofs_wrap(PyObject *self,
                                                   PyObject *args) {
  PyObject *input_blob, *s;
  PyObject *ret = NULL;
  Cell *cells = NULL;
  KZGProof *proofs = NULL;

  /* Ensure inputs are the right types */
  if (!PyArg_UnpackTuple(args, "compute_cells_and_kzg_proofs", 2, 2,
                         &input_blob, &s) ||
      !PyBytes_Check(input_blob) || !PyCapsule_IsValid(s, "KZGSettings")) {
    ret = PyErr_Format(PyExc_ValueError, "expected bytes and trusted setup");
    goto out;
  }

  /* Ensure blob is the right size */
  if (PyBytes_Size(input_blob) != BYTES_PER_BLOB) {
    ret = PyErr_Format(PyExc_ValueError,
                       "expected blob to be BYTES_PER_BLOB bytes");
    goto out;
  }

  /* Allocate space for the cells */
  cells = calloc(CELLS_PER_EXT_BLOB, BYTES_PER_CELL);
  if (cells == NULL) {
    ret =
        PyErr_Format(PyExc_MemoryError, "Failed to allocate memory for cells");
    goto out;
  }

  /* Allocate space for the proofs */
  proofs = calloc(CELLS_PER_EXT_BLOB, BYTES_PER_PROOF);
  if (proofs == NULL) {
    ret =
        PyErr_Format(PyExc_MemoryError, "Failed to allocate memory for proofs");
    goto out;
  }

  /* Call our C function with our inputs */
  const Blob *blob = (Blob *)PyBytes_AsString(input_blob);
  if (compute_cells_and_kzg_proofs(cells, proofs, blob,
                                   PyCapsule_GetPointer(s, "KZGSettings")) !=
      C_KZG_OK) {
    ret =
        PyErr_Format(PyExc_RuntimeError, "compute_cells_and_kzg_proofs failed");
    goto out;
  }

  /* Convert our cells result to a list of bytes objects */
  PyObject *output_cells = PyList_New(CELLS_PER_EXT_BLOB);
  if (output_cells == NULL) {
    ret = PyErr_Format(PyExc_MemoryError,
                       "Failed to allocate memory for output cells");
    goto out;
  }
  for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
    /* Convert cell to a bytes object */
    PyObject *cell_bytes =
        PyBytes_FromStringAndSize((const char *)&cells[i], BYTES_PER_CELL);
    if (cell_bytes == NULL) {
      Py_DECREF(cell_bytes);
      ret = PyErr_Format(PyExc_MemoryError,
                         "Failed to allocate memory for cell bytes");
      goto out;
    }
    /* Add it to our list */
    PyList_SetItem(output_cells, i, cell_bytes);
  }

  /* Convert our proofs result to a list of bytes objects */
  PyObject *output_proofs = PyList_New(CELLS_PER_EXT_BLOB);
  if (output_proofs == NULL) {
    ret = PyErr_Format(PyExc_MemoryError,
                       "Failed to allocate memory for output proofs");
    goto out;
  }
  for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
    /* Convert proof to a bytes object */
    PyObject *proof_bytes =
        PyBytes_FromStringAndSize((const char *)&proofs[i], BYTES_PER_PROOF);
    if (proof_bytes == NULL) {
      Py_DECREF(proof_bytes);
      ret = PyErr_Format(PyExc_MemoryError,
                         "Failed to allocate memory for proof bytes");
      goto out;
    }
    /* Add it to our list */
    PyList_SetItem(output_proofs, i, proof_bytes);
  }

  PyObject *cells_and_proofs = PyTuple_Pack(2, output_cells, output_proofs);
  if (cells_and_proofs == NULL) {
    ret = PyErr_Format(PyExc_RuntimeError,
                       "failed to make tuple of cells and proofs");
    goto out;
  }

  /* Success! */
  ret = cells_and_proofs;

out:
  free(cells);
  free(proofs);
  return ret;
}

static PyObject *recover_cells_and_kzg_proofs_wrap(PyObject *self,
                                                   PyObject *args) {
  PyObject *input_cell_indices, *input_cells, *s;
  PyObject *ret = NULL;
  uint64_t *cell_indices = NULL;
  Cell *cells = NULL;
  Cell *recovered_cells = NULL;
  KZGProof *recovered_proofs = NULL;

  /* Ensure inputs are the right types */
  if (!PyArg_UnpackTuple(args, "recover_cells_and_kzg_proofs", 3, 3,
                         &input_cell_indices, &input_cells, &s) ||
      !PyList_Check(input_cell_indices) || !PyList_Check(input_cells) ||
      !PyCapsule_IsValid(s, "KZGSettings")) {
    ret = PyErr_Format(PyExc_ValueError, "expected list, list, trusted setup");
    goto out;
  }

  /* Ensure cell indices/cells are the same length */
  Py_ssize_t cell_indices_count = PyList_Size(input_cell_indices);
  Py_ssize_t cells_count = PyList_Size(input_cells);
  if (cell_indices_count != cells_count) {
    ret = PyErr_Format(PyExc_ValueError,
                       "expected same number of cell_indices and cells");
    goto out;
  }

  /* Allocate space for the cell indices */
  cell_indices = (uint64_t *)calloc(cells_count, sizeof(uint64_t));
  if (cell_indices == NULL) {
    ret = PyErr_Format(PyExc_MemoryError,
                       "Failed to allocate memory for cell indices");
    goto out;
  }
  for (Py_ssize_t i = 0; i < cell_indices_count; i++) {
    /* Ensure each cell index is an integer */
    PyObject *cell_index = PyList_GetItem(input_cell_indices, i);
    if (!PyLong_Check(cell_index)) {
      ret = PyErr_Format(PyExc_ValueError,
                         "expected cell index to be an integer");
      goto out;
    }
    /* Convert the cell index to a cell index type (uint64_t) */
    uint64_t value = PyLong_AsUnsignedLongLong(cell_index);
    if (PyErr_Occurred()) {
      ret = PyErr_Format(PyExc_ValueError,
                         "failed to convert cell index to uint64_t");
      goto out;
    }
    /* The cell index is good, add it to our array */
    memcpy(&cell_indices[i], &value, sizeof(uint64_t));
  }

  /* Allocate space for the cells */
  cells = (Cell *)calloc(cells_count, BYTES_PER_CELL);
  if (cells == NULL) {
    ret =
        PyErr_Format(PyExc_MemoryError, "Failed to allocate memory for cells");
    goto out;
  }
  for (Py_ssize_t i = 0; i < cells_count; i++) {
    /* Ensure each cell is bytes */
    PyObject *cell = PyList_GetItem(input_cells, i);
    if (!PyBytes_Check(cell)) {
      ret = PyErr_Format(PyExc_ValueError, "expected cell to be bytes");
      goto out;
    }
    /* Ensure each cell is the right size */
    Py_ssize_t cell_size = PyBytes_Size(cell);
    if (cell_size != BYTES_PER_CELL) {
      ret = PyErr_Format(PyExc_ValueError,
                         "expected cell to be BYTES_PER_CELL bytes");
      goto out;
    }
    /* The cell is good, copy it to our array */
    memcpy(&cells[i], PyBytes_AsString(cell), BYTES_PER_CELL);
  }

  /* Allocate space for the recovered cells/proofs */
  recovered_cells = calloc(CELLS_PER_EXT_BLOB, BYTES_PER_CELL);
  if (recovered_cells == NULL) {
    ret = PyErr_Format(PyExc_MemoryError,
                       "Failed to allocate memory for recovered cells");
    goto out;
  }
  recovered_proofs = calloc(CELLS_PER_EXT_BLOB, BYTES_PER_PROOF);
  if (recovered_proofs == NULL) {
    ret = PyErr_Format(PyExc_MemoryError,
                       "Failed to allocate memory for recovered proofs");
    goto out;
  }

  /* Call our C function with our inputs */
  if (recover_cells_and_kzg_proofs(
          recovered_cells, recovered_proofs, cell_indices, cells, cells_count,
          PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    ret =
        PyErr_Format(PyExc_RuntimeError, "recover_cells_and_kzg_proofs failed");
    goto out;
  }

  /* Convert our result to a list of bytes objects */
  PyObject *recovered_cells_list = PyList_New(CELLS_PER_EXT_BLOB);
  if (recovered_cells_list == NULL) {
    ret = PyErr_Format(PyExc_MemoryError,
                       "Failed to allocate memory for return list of cells");
    goto out;
  }
  PyObject *recovered_proofs_list = PyList_New(CELLS_PER_EXT_BLOB);
  if (recovered_proofs_list == NULL) {
    ret = PyErr_Format(PyExc_MemoryError,
                       "Failed to allocate memory for return list of proofs");
    goto out;
  }
  for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
    /* Convert cell to a bytes object */
    PyObject *cell_bytes = PyBytes_FromStringAndSize(
        (const char *)&recovered_cells[i], BYTES_PER_CELL);
    if (cell_bytes == NULL) {
      Py_DECREF(cell_bytes);
      ret = PyErr_Format(PyExc_MemoryError,
                         "Failed to allocate memory for cell bytes");
      goto out;
    }
    PyList_SetItem(recovered_cells_list, i, cell_bytes);

    /* Convert proof to a bytes object */
    PyObject *proof_bytes = PyBytes_FromStringAndSize(
        (const char *)&recovered_proofs[i], BYTES_PER_PROOF);
    if (proof_bytes == NULL) {
      Py_DECREF(proof_bytes);
      ret = PyErr_Format(PyExc_MemoryError,
                         "Failed to allocate memory for proof bytes");
      goto out;
    }
    /* Add it to our list */
    PyList_SetItem(recovered_proofs_list, i, proof_bytes);
  }

  /* Pack recovered cells/proofs into a tuple */
  PyObject *recovered_cells_and_proofs =
      PyTuple_Pack(2, recovered_cells_list, recovered_proofs_list);
  if (recovered_cells_and_proofs == NULL) {
    ret = PyErr_Format(PyExc_RuntimeError,
                       "failed to make tuple of recovered cells and proofs");
    goto out;
  }

  /* Success! */
  ret = recovered_cells_and_proofs;

out:
  free(cell_indices);
  free(cells);
  free(recovered_cells);
  free(recovered_proofs);
  return ret;
}

static PyObject *verify_cell_kzg_proof_batch_wrap(PyObject *self,
                                                  PyObject *args) {
  PyObject *input_commitments, *input_cell_indices, *input_cells, *input_proofs,
      *s;
  PyObject *ret = NULL;
  Bytes48 *commitments = NULL;
  uint64_t *cell_indices = NULL;
  Cell *cells = NULL;
  Bytes48 *proofs = NULL;
  bool ok = false;

  /* Ensure inputs are the right types */
  if (!PyArg_UnpackTuple(args, "verify_cell_kzg_proof_batch", 5, 5,
                         &input_commitments, &input_cell_indices, &input_cells,
                         &input_proofs, &s) ||
      !PyList_Check(input_commitments) || !PyList_Check(input_cell_indices) ||
      !PyList_Check(input_cells) || !PyList_Check(input_proofs) ||
      !PyCapsule_IsValid(s, "KZGSettings")) {
    ret = PyErr_Format(PyExc_ValueError,
                       "expected list, list, list, list, trusted setup");
    goto out;
  }

  /* Ensure input lists are the same length */
  Py_ssize_t commitments_count = PyList_Size(input_commitments);
  Py_ssize_t cell_indices_count = PyList_Size(input_cell_indices);
  Py_ssize_t cells_count = PyList_Size(input_cells);
  Py_ssize_t proofs_count = PyList_Size(input_proofs);
  if (commitments_count != cells_count) {
    ret = PyErr_Format(PyExc_ValueError,
                       "expected same number of commitments and cells");
    goto out;
  }
  if (cell_indices_count != cells_count) {
    ret = PyErr_Format(PyExc_ValueError,
                       "expected same number of column indices and cells");
    goto out;
  }
  if (proofs_count != cells_count) {
    ret = PyErr_Format(PyExc_ValueError,
                       "expected same number of proofs and cells");
    goto out;
  }

  /* Allocate space for the commitments */
  commitments = (Bytes48 *)calloc(commitments_count, BYTES_PER_COMMITMENT);
  if (commitments == NULL) {
    ret = PyErr_Format(PyExc_MemoryError,
                       "Failed to allocate memory for commitments");
    goto out;
  }
  for (Py_ssize_t i = 0; i < commitments_count; i++) {
    /* Ensure each commitment is bytes */
    PyObject *commitment = PyList_GetItem(input_commitments, i);
    if (!PyBytes_Check(commitment)) {
      ret = PyErr_Format(PyExc_ValueError, "expected commitment to be bytes");
      goto out;
    }
    /* Ensure each commitment is the right size */
    Py_ssize_t commitment_size = PyBytes_Size(commitment);
    if (commitment_size != BYTES_PER_COMMITMENT) {
      ret =
          PyErr_Format(PyExc_ValueError,
                       "expected commitment to be BYTES_PER_COMMITMENT bytes");
      goto out;
    }
    /* The commitment is good, copy it to our array */
    memcpy(&commitments[i], PyBytes_AsString(commitment), BYTES_PER_COMMITMENT);
  }

  /* Allocate space for the column indices */
  cell_indices = (uint64_t *)calloc(cell_indices_count, sizeof(uint64_t));
  if (cell_indices == NULL) {
    ret = PyErr_Format(PyExc_MemoryError,
                       "Failed to allocate memory for column indices");
    goto out;
  }
  for (Py_ssize_t i = 0; i < cell_indices_count; i++) {
    /* Ensure each column index is an integer */
    PyObject *cell_index = PyList_GetItem(input_cell_indices, i);
    if (!PyLong_Check(cell_index)) {
      ret = PyErr_Format(PyExc_ValueError,
                         "expected column index to be an integer");
      goto out;
    }
    /* Convert the column index to a uint64_t */
    uint64_t value = PyLong_AsUnsignedLongLong(cell_index);
    if (PyErr_Occurred()) {
      ret = PyErr_Format(PyExc_ValueError,
                         "failed to convert column index to uint64_t");
      goto out;
    }
    /* The column is good, add it to our array */
    memcpy(&cell_indices[i], &value, sizeof(uint64_t));
  }

  /* Allocate space for the cells */
  cells = (Cell *)calloc(cells_count, BYTES_PER_CELL);
  if (cells == NULL) {
    ret =
        PyErr_Format(PyExc_MemoryError, "Failed to allocate memory for cells");
    goto out;
  }
  for (Py_ssize_t i = 0; i < cells_count; i++) {
    /* Ensure each cell is bytes */
    PyObject *cell = PyList_GetItem(input_cells, i);
    if (!PyBytes_Check(cell)) {
      ret = PyErr_Format(PyExc_ValueError, "expected cell to be bytes");
      goto out;
    }
    /* Ensure each cell is the right size */
    Py_ssize_t cell_size = PyBytes_Size(cell);
    if (cell_size != BYTES_PER_CELL) {
      ret = PyErr_Format(PyExc_ValueError,
                         "expected cell to be BYTES_PER_CELL bytes");
      goto out;
    }
    /* The cell is good, copy it to our array */
    memcpy(&cells[i], PyBytes_AsString(cell), BYTES_PER_CELL);
  }

  /* Allocate space for the proofs */
  proofs = (Bytes48 *)calloc(proofs_count, BYTES_PER_PROOF);
  if (proofs == NULL) {
    ret =
        PyErr_Format(PyExc_MemoryError, "Failed to allocate memory for proofs");
    goto out;
  }
  for (Py_ssize_t i = 0; i < proofs_count; i++) {
    /* Ensure each proof is bytes */
    PyObject *proof = PyList_GetItem(input_proofs, i);
    if (!PyBytes_Check(proof)) {
      ret = PyErr_Format(PyExc_ValueError, "expected proof to be bytes");
      goto out;
    }
    /* Ensure each proof is the right size */
    Py_ssize_t proof_size = PyBytes_Size(proof);
    if (proof_size != BYTES_PER_PROOF) {
      ret = PyErr_Format(PyExc_ValueError,
                         "expected proof to be BYTES_PER_PROOF bytes");
      goto out;
    }
    /* The proof is good, copy it to our array */
    memcpy(&proofs[i], PyBytes_AsString(proof), BYTES_PER_PROOF);
  }

  /* Call our C function with our inputs */
  if (verify_cell_kzg_proof_batch(
          &ok, commitments, cell_indices, cells, proofs, cells_count,
          PyCapsule_GetPointer(s, "KZGSettings")) != C_KZG_OK) {
    ret =
        PyErr_Format(PyExc_RuntimeError, "verify_cell_kzg_proof_batch failed");
    goto out;
  }

  /* Success! */
  if (ok) {
    Py_INCREF(Py_True);
    ret = Py_True;
  } else {
    Py_INCREF(Py_False);
    ret = Py_False;
  }

out:
  free(commitments);
  free(cell_indices);
  free(cells);
  free(proofs);
  return ret;
}

static PyMethodDef ckzgmethods[] = {
    {"load_trusted_setup", load_trusted_setup_wrap, METH_VARARGS,
     "Load trusted setup from file path"},
    {"blob_to_kzg_commitment", blob_to_kzg_commitment_wrap, METH_VARARGS,
     "Create a commitment from a blob"},
    {"compute_kzg_proof", compute_kzg_proof_wrap, METH_VARARGS,
     "Compute a proof for a blob/field"},
    {"compute_blob_kzg_proof", compute_blob_kzg_proof_wrap, METH_VARARGS,
     "Compute a proof for a blob"},
    {"verify_kzg_proof", verify_kzg_proof_wrap, METH_VARARGS,
     "Verify a proof for the given inputs"},
    {"verify_blob_kzg_proof", verify_blob_kzg_proof_wrap, METH_VARARGS,
     "Verify a blob/commitment/proof combo"},
    {"verify_blob_kzg_proof_batch", verify_blob_kzg_proof_batch_wrap,
     METH_VARARGS, "Verify multiple blob/commitment/proof combos"},
    {"compute_cells", compute_cells_wrap, METH_VARARGS,
     "Compute cells for a blob"},
    {"compute_cells_and_kzg_proofs", compute_cells_and_kzg_proofs_wrap,
     METH_VARARGS, "Compute cells and proofs for a blob"},
    {"recover_cells_and_kzg_proofs", recover_cells_and_kzg_proofs_wrap,
     METH_VARARGS, "Recover missing cells and proofs"},
    {"verify_cell_kzg_proof_batch", verify_cell_kzg_proof_batch_wrap,
     METH_VARARGS, "Verify multiple cell proofs"},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef ckzg = {PyModuleDef_HEAD_INIT, "ckzg", NULL, -1,
                                  ckzgmethods};

PyMODINIT_FUNC PyInit_ckzg(void) { return PyModule_Create(&ckzg); }
