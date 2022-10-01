%module ckzg
%{
#include "c_kzg_4844.h"
%}
%include "stdint.i"
%include "carrays.i"
%include "cpointer.i"

%typemap(in, numinputs=0) OBJECT *OUTPUT($1_basetype tmp) { $1 = &tmp; }
%typemap(argout) OBJECT *OUTPUT {
#if defined(SWIGPYTHON)
  PyObject *obj = SWIG_NewPointerObj(memcpy(malloc(sizeof($1_basetype)),$1,sizeof($1_basetype)),
                                     $descriptor, SWIG_POINTER_NEW);
  $result = ($result == NULL) ? obj : SWIG_Python_AppendOutput($result, obj);
#endif
}
%apply OBJECT *OUTPUT {
  KZGSettings *out, BLSFieldElement *out, PolynomialEvalForm *out,
  KZGCommitment *out, KZGProof *out
}

%typemap(in, numinputs=0) bool *OUTPUT(bool tmp) { $1 = &tmp; }
%typemap(argout) bool *OUTPUT {
#if defined(SWIGPYTHON)
  PyObject *obj = *$1 ? Py_True : Py_False;
  $result = ($result == NULL) ? obj : SWIG_Python_AppendOutput($result, obj);
#endif
}
%apply bool *OUTPUT { bool *out }

%typemap(in, numinputs=0) uint64_t out[4] (uint64_t tmp[4]) { $1 = tmp; }
%typemap(argout) uint64_t out[4] {
#if defined(SWIGPYTHON)
  PyObject *obj = PyTuple_Pack(4,
    PyLong_FromUnsignedLong($1[0]),
    PyLong_FromUnsignedLong($1[1]),
    PyLong_FromUnsignedLong($1[2]),
    PyLong_FromUnsignedLong($1[3]));
  $result = ($result == NULL) ? obj : SWIG_Python_AppendOutput($result, obj);
#endif
}

%typemap(in) const uint64_t[4] (uint64_t tmp[4]) {
#if defined(SWIGPYTHON)
  if (PyTuple_Check($input)) {
    if (!PyArg_ParseTuple($input, "kkkk", tmp, tmp+1, tmp+2, tmp+3)) {
      PyErr_SetString(PyExc_TypeError, "tuple must have 4 elements");
      SWIG_fail;
    }
    $1 = &tmp[0];
  } else {
    PyErr_SetString(PyExc_TypeError, "expected a tuple.");
    SWIG_fail;
  }
#endif
}

#if defined(SWIGPYTHON)
%typemap(in) FILE* {
  if (PyUnicode_Check($input)) {
    $1 = fopen(PyUnicode_AsUTF8($input), "r");
    if ($1 == NULL) {
      PyErr_SetString(PyExc_RuntimeError, "failed to load file");
      SWIG_fail;
    }
  } else {
    PyErr_SetString(PyExc_TypeError, "expected bytes (utf-8 encoded file path)");
    SWIG_fail;
  }
}
#endif

%array_class(uint8_t, bytes)
%array_class(BLSFieldElement, BLSFieldElements)
%pointer_class(PolynomialEvalForm, PolynomialEvalFormPtr)

%include "../min-src/c_kzg_4844.h"
%include "../inc/blst.h"

#if defined(SWIGPYTHON)
%pythoncode %{
# Helper functions

def _fr_from_int(x):
    r = []
    while x > 0:
        r.append(x % 2**64)
        x //= 2**64
    assert len(r) <= 4
    while len(r) < 4:
        r.append(0)
    return BLSFieldElement_from_uint64s(tuple(r))

blst_fr.from_int = _fr_from_int

def _int_from_fr(fr):
    digits = uint64s_from_BLSFieldElement(fr)
    res, mult = 0, 1
    for x in digits:
        res += mult * x
        mult *= 2**64
    return res

blst_fr.__int__ = _int_from_fr

def _poly_from_values(values):
    ret, pptr = alloc_polynomial(len(values))
    assert ret == 0
    p = PolynomialEvalFormPtr_frompointer(pptr).value()
    pvalues = BLSFieldElements_frompointer(p.values)
    for i, c in enumerate(values):
        pvalues[i] = fr_from_int(c)
    return p

PolynomialEvalForm.from_values = _poly_from_values

def _frompybytes(b):
    h = bytes(len(b))
    for i, byte in enumerate(b):
        h[i] = byte
    return h

bytes.frompybytes = _frompybytes
%}
#endif