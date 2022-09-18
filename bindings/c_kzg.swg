%module ckzg
%include "stdint.i"
%include "carrays.i"
%include "cpointer.i"
%{
#include <stdbool.h>
#include "c_kzg.h"
#include "bls12_381.h"
%}
%rename(alloc_poly) new_poly;
%rename(alloc_poly_l) new_poly_l;

%typemap(in, numinputs=0) OBJECT *out ($1_basetype tmp) { $1 = &tmp; }
%typemap(argout) OBJECT *out {
  PyObject *obj = SWIG_NewPointerObj(memcpy(malloc(sizeof($1_basetype)),$1,sizeof($1_basetype)),
                                     $descriptor, SWIG_POINTER_NEW);
  $result = ($result == NULL) ? obj : SWIG_Python_AppendOutput($result, obj);
}
%apply OBJECT *out { fr_t *out, poly *out, poly_l *out }

%typemap(in, numinputs=0) uint64_t out[4] (uint64_t tmp[4]) { $1 = tmp; }
%typemap(argout) uint64_t out[4] {
  PyObject *obj = PyTuple_Pack(4,
    PyLong_FromUnsignedLongLong($1[0]),
    PyLong_FromUnsignedLongLong($1[1]),
    PyLong_FromUnsignedLongLong($1[2]),
    PyLong_FromUnsignedLongLong($1[3]));
  $result = ($result == NULL) ? obj : SWIG_Python_AppendOutput($result, obj);
}

%typemap(in) const uint64_t[4] (uint64_t tmp[4]) {
  int i;
  if (PyTuple_Check($input)) {
    if (!PyArg_ParseTuple($input, "KKKK", tmp, tmp+1, tmp+2, tmp+3)) {
      PyErr_SetString(PyExc_TypeError, "tuple must have 4 elements");
      SWIG_fail;
    }
    $1 = &tmp[0];
  } else {
    PyErr_SetString(PyExc_TypeError, "expected a tuple.");
    SWIG_fail;
  }
}

%array_class(fr_t, frArray)
%pointer_class(poly, polyp)
%pointer_class(poly_l, poly_lp)

%include "../src/c_kzg.h"
%include "../src/bls12_381.h"
