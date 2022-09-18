%module ckzg
%include "stdint.i"
%{
#include <stdbool.h>
#include "c_kzg.h"
%}
%rename(alloc_poly) new_poly;
%rename(alloc_poly_l) new_poly_l;
%include "../src/c_kzg.h"
