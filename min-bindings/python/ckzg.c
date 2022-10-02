#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "c_kzg_4844.h"

static void free_BLSFieldElement(PyObject *c) {
  free(PyCapsule_GetPointer(c, "BLSFieldElement"));
}

static void free_G1(PyObject *c) {
  free(PyCapsule_GetPointer(c, "G1"));
}

static void free_PolynomialEvalForm(PyObject *c) {
  PolynomialEvalForm *p = PyCapsule_GetPointer(c, "PolynomialEvalForm");
  free_polynomial(p);
  free(p);
}

static void free_KZGSettings(PyObject *c) {
  KZGSettings *s = PyCapsule_GetPointer(c, "KZGSettings");
  free_trusted_setup(s);
  free(s);
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

static PyObject* int_from_bls_field(PyObject *self, PyObject *args) {
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

static PyObject* bytes_from_g1_wrap(PyObject *self, PyObject *args) {
  PyObject *c;

  if (!PyArg_UnpackTuple(args, "bytes_from_g1", 1, 1, &c) ||
      !PyCapsule_IsValid(c, "G1"))
    return PyErr_Format(PyExc_ValueError, "expected G1 capsule");

  uint8_t bytes[48];
  bytes_from_g1(bytes, PyCapsule_GetPointer(c, "G1"));

  return PyBytes_FromStringAndSize((char*)bytes, 48);
}

static PyObject* compute_powers_wrap(PyObject *self, PyObject *args) {
  PyObject *c;
  PyObject *n;

  if (!PyArg_UnpackTuple(args, "compute_powers", 2, 2, &c, &n) ||
      !PyCapsule_IsValid(c, "BLSFieldElement") ||
      !PyLong_Check(n))
    return PyErr_Format(PyExc_ValueError, "expected a BLSFieldElement capsule and a number");

  Py_ssize_t z = PyLong_AsSsize_t(n);

  PyObject *out = PyList_New(z);

  if (out == NULL) return PyErr_NoMemory();

  BLSFieldElement *a = (BLSFieldElement*)calloc(z, sizeof(BLSFieldElement));

  if (a == NULL) return PyErr_NoMemory();

  compute_powers(a, PyCapsule_GetPointer(c, "BLSFieldElement"), z);

  BLSFieldElement *f;

  for (Py_ssize_t i = 0; i < z; i++) {
    f = (BLSFieldElement*)malloc(sizeof(BLSFieldElement));
    if (f == NULL) {
      free(a);
      return PyErr_NoMemory();
    }
    *f = a[i];
    PyList_SetItem(out, i, PyCapsule_New(f, "BLSFieldElement", free_BLSFieldElement));
  }

  free(a);

  return out;
}

static PyObject* load_trusted_setup_wrap(PyObject *self, PyObject *args) {
  PyObject *f;

  if (!PyArg_ParseTuple(args, "U", &f))
    return PyErr_Format(PyExc_ValueError, "expected a string");

  KZGSettings *s = (KZGSettings*)malloc(sizeof(KZGSettings));

  if (s == NULL) return PyErr_NoMemory();

  if (load_trusted_setup(s, fopen(PyUnicode_AsUTF8(f), "r")) != C_KZG_OK)
    return PyErr_Format(PyExc_RuntimeError, "error loading trusted setup");

  return PyCapsule_New(s, "KZGSettings", free_KZGSettings);
}

static PyObject* blob_to_kzg_commitment_wrap(PyObject *self, PyObject *args) {
  PyObject *a;
  PyObject *c;

  if (!PyArg_UnpackTuple(args, "alloc_polynomial_wrap", 2, 2, &a, &c) ||
      !PySequence_Check(a) ||
      !PyCapsule_IsValid(c, "KZGSettings"))
    return PyErr_Format(PyExc_ValueError, "expected sequence and trusted setup");

  Py_ssize_t n = PySequence_Length(a);

  BLSFieldElement *blob = (BLSFieldElement*)calloc(n, sizeof(BLSFieldElement));

  if (blob == NULL) return PyErr_NoMemory();

  PyObject *e;
  for (Py_ssize_t i = 0; i < n; i++) {
    e = PySequence_GetItem(a, i);
    if (!PyCapsule_IsValid(e, "BLSFieldElement")) {
      free(blob);
      return PyErr_Format(PyExc_ValueError, "expected BLSFieldElement capsules");
    }
    // TODO: could avoid copying if blob_to_kzg_commitment expected pointers instead of an array
    blob[i] = *(BLSFieldElement*)PyCapsule_GetPointer(e, "BLSFieldElement");
  }

  KZGCommitment *k = (KZGCommitment*)malloc(sizeof(KZGCommitment));

  if (k == NULL) return PyErr_NoMemory();

  blob_to_kzg_commitment(k, blob, PyCapsule_GetPointer(c, "KZGSettings"));

  free(blob);

  return PyCapsule_New(k, "G1", free_G1);
}

static PyObject* vector_lincomb_wrap(PyObject *self, PyObject *args) {
  PyObject *vs;
  PyObject *fs;

  if (!PyArg_UnpackTuple(args, "vector_lincomb", 2, 2, &vs, &fs) ||
      !PySequence_Check(vs) ||
      !PySequence_Check(fs))
    return PyErr_Format(PyExc_ValueError, "expected two sequences");

  Py_ssize_t n = PySequence_Length(vs);
  if (PySequence_Length(fs) != n)
    return PyErr_Format(PyExc_ValueError, "expected same-length sequences");

  if (n == 0) { return fs; }

  if (!PySequence_Check(PySequence_GetItem(vs, 0)))
    return PyErr_Format(PyExc_ValueError, "expected sequence of sequences");

  Py_ssize_t i, j, m = PySequence_Length(PySequence_GetItem(vs, 0));

  const BLSFieldElement* *vectors = (const BLSFieldElement**)calloc(n * m, sizeof(BLSFieldElement*));

  if (vectors == NULL) return PyErr_NoMemory();

  PyObject *tmp, *out;

  for (i = 0; i < n; i++) {
    if (!PySequence_Check(PySequence_GetItem(vs, i))) {
      free(vectors);
      return PyErr_Format(PyExc_ValueError, "expected sequence of sequences");
    }
    tmp = PySequence_GetItem(vs, i);
    if (PySequence_Length(tmp) != m) {
      free(vectors);
      return PyErr_Format(PyExc_ValueError, "expected vectors of same length");
    }
    for (j = 0; j < m; j++) {
      out = PySequence_GetItem(tmp, j);
      if (!PyCapsule_IsValid(out, "BLSFieldElement")) {
        free(vectors);
        return PyErr_Format(PyExc_ValueError, "expected vectors of BLSFieldElement capsules");
      }
      vectors[i * m + j] = (BLSFieldElement*)PyCapsule_GetPointer(out, "BLSFieldElement");
    }
  }

  const BLSFieldElement* *scalars = (const BLSFieldElement**)calloc(n, sizeof(BLSFieldElement*));

  if (scalars == NULL) {
    free(vectors);
    return PyErr_NoMemory();
  }

  for (i = 0; i < n; i++) {
    tmp = PySequence_GetItem(fs, i);
    if (!PyCapsule_IsValid(tmp, "BLSFieldElement")) {
      free(scalars);
      free(vectors);
      return PyErr_Format(PyExc_ValueError, "expected a BLSFieldElement capsule");
    }
    scalars[i] = (BLSFieldElement*)PyCapsule_GetPointer(tmp, "BLSFieldElement");
  }

  BLSFieldElement *r = (BLSFieldElement*)calloc(m, sizeof(BLSFieldElement));

  if (r == NULL) {
    free(scalars);
    free(vectors);
    return PyErr_NoMemory();
  }

  vector_lincomb(r, vectors, scalars, n, m);

  free(scalars);
  free(vectors);

  out = PyList_New(m);

  if (out == NULL) {
    free(r);
    return PyErr_NoMemory();
  }

  BLSFieldElement *f;

  for (j = 0; j < m; j++) {
    f = (BLSFieldElement*)malloc(sizeof(BLSFieldElement));
    if (f == NULL) {
      free(r);
      return PyErr_NoMemory();
    }
    *f = r[j];
    PyList_SetItem(out, j, PyCapsule_New(f, "BLSFieldElement", free_BLSFieldElement));
  }

  free(r);

  return out;
}

static PyObject* g1_lincomb_wrap(PyObject *self, PyObject *args) {
  PyObject *gs, *fs;

  if (!PyArg_UnpackTuple(args, "g1_lincomb", 2, 2, &gs, &fs) ||
      !PySequence_Check(gs) ||
      !PySequence_Check(fs) ||
      PySequence_Length(gs) != PySequence_Length(fs))
    return PyErr_Format(PyExc_ValueError, "expected same-length sequences");

  Py_ssize_t i, n = PySequence_Length(gs);

  KZGCommitment *k = (KZGCommitment*)malloc(sizeof(KZGCommitment));

  if (k == NULL) return PyErr_NoMemory();

  KZGCommitment* points = (KZGCommitment*)calloc(n, sizeof(KZGCommitment));

  if (points == NULL) {
    free(k);
    return PyErr_NoMemory();
  }

  BLSFieldElement* scalars = (BLSFieldElement*)calloc(n, sizeof(BLSFieldElement));

  if (scalars == NULL) {
    free(points);
    free(k);
    return PyErr_NoMemory();
  }

  PyObject *tmp;

  // TODO: could avoid copying if g1_lincomb expected pointers

  for (i = 0; i < n; i++) {
    tmp = PySequence_GetItem(gs, i);
    if (!PyCapsule_IsValid(tmp, "G1")) {
      free(scalars); free(points); free(k);
      return PyErr_Format(PyExc_ValueError, "expected group elements");
    }
    points[i] = *(KZGCommitment*)(PyCapsule_GetPointer(tmp, "G1"));

    tmp = PySequence_GetItem(fs, i);
    if (!PyCapsule_IsValid(tmp, "BLSFieldElement")) {
      free(scalars); free(points); free(k);
      return PyErr_Format(PyExc_ValueError, "expected field elements");
    }
    scalars[i] = *(BLSFieldElement*)(PyCapsule_GetPointer(tmp, "BLSFieldElement"));
  }

  g1_lincomb(k, points, scalars, n);

  free(scalars);
  free(points);

  return PyCapsule_New(k, "G1", free_G1);
}

static PyMethodDef ckzgmethods[] = {
  {"bytes_from_g1",            bytes_from_g1_wrap,          METH_VARARGS, "Convert a group element to 48 bytes"},
  {"int_from_bls_field",       int_from_bls_field,          METH_VARARGS, "Convert a field element to a 256-bit int"},
  {"bytes_to_bls_field",       bytes_to_bls_field_wrap,     METH_VARARGS, "Convert 32 bytes to a field element"},
  {"alloc_polynomial",         alloc_polynomial_wrap,       METH_VARARGS, "Create a PolynomialEvalForm from a sequence of field elements"},
  {"load_trusted_setup",       load_trusted_setup_wrap,     METH_VARARGS, "Load trusted setup from file path"},
  {"blob_to_kzg_commitment",   blob_to_kzg_commitment_wrap, METH_VARARGS, "Create a commitment from a sequence of field elements"},
  {"compute_powers",           compute_powers_wrap,         METH_VARARGS, "Create a list of powers of a field element"},
  {"vector_lincomb",           vector_lincomb_wrap,         METH_VARARGS, "Multiply a matrix of field elements with a vector"},
  {"g1_lincomb",               g1_lincomb_wrap,             METH_VARARGS, "Linear combination of group elements with field elements"},
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
