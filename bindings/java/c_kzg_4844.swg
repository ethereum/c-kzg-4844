%module CKzg4844

%include "exception.i"
%include "std_string.i"
%include "stdint.i"
%include "enums.swg"
%include "arrays_java.i"
%include "std_vector.i"

%pragma(java) jniclasscode=%{
    static {
        try {
            System.loadLibrary("$module");
        } catch (UnsatisfiedLinkError ex) {
            throw new RuntimeException(ex);
	    }
    }
%}

// copied from blst.swg

// Extensive sorcery to shift memory management to JVM GC. General idea is
// to use Java long[] as opaque storage for blst data. Methods that return
// new objects allocate suitably sized long[] arrays from JVM heap,
// references to which are then assigned to |swigCPtr| on the Java side.
// And when passed back to JNI, |swigCPtr|s are dereferenced with
// GetLongArrayElements... And no destructors!
%nodefaultdtor;
%typemap(javafinalize)  SWIGTYPE ""
%typemap(javadestruct)  SWIGTYPE ""

%typemap(javabody)      SWIGTYPE %{
  private transient long[] swigCPtr;

  protected $javaclassname(long[] cPtr) { swigCPtr = cPtr; }

  protected static long[] getCPtr($javaclassname obj) {
    return obj != null ? obj.swigCPtr : null;
  }

  public $javaclassname dup() { return new $javaclassname(swigCPtr.clone()); }
%}
%ignore dup;
%typemap(javaconstruct) SWIGTYPE { this($imcall); }
%typemap(jni)           SWIGTYPE, SWIGTYPE&, SWIGTYPE* "jlongArray"
%typemap(jtype)         SWIGTYPE, SWIGTYPE&, SWIGTYPE* "long[]"
%typemap(javaout)       SWIGTYPE, SWIGTYPE&, SWIGTYPE* {
    return new $javaclassname($jnicall);
}
%typemap(in)            SWIGTYPE&, SWIGTYPE* %{
    $1 = ($1_ltype)JCALL(GetLongArrayElements, $input, 0);
%}
%typemap(in)      const SWIGTYPE&, const SWIGTYPE* %{
    $1 = $input ? ($1_ltype)JCALL(GetLongArrayElements, $input, 0) : NULL;
%}
%typemap(out)           SWIGTYPE&, SWIGTYPE* %{
    if ($1 != $null) {
        size_t sz = (sizeof($1_basetype) + sizeof(jlong) - 1)/sizeof(jlong);
        $result = JCALL(NewLongArray, sz);
        if ($result != $null)
            JCALL(SetLongArrayRegion, $result, 0, sz, (const jlong *)$1);
    }
%}
%typemap(out)           SWIGTYPE {
    size_t sz = (sizeof($1_basetype) + sizeof(jlong) - 1)/sizeof(jlong);
    $result = JCALL(NewLongArray, sz);
    if ($result != $null)
        JCALL(SetLongArrayRegion, $result, 0, sz, (const jlong *)&$1);
}
%typemap(newfree)       SWIGTYPE* "delete $1;"
%typemap(freearg)       SWIGTYPE&, SWIGTYPE* %{
    JCALL(ReleaseLongArrayElements, $input, (jlong *)$1, 0);
%}
%typemap(freearg) const SWIGTYPE&, const SWIGTYPE* %{
    if ($input) JCALL(ReleaseLongArrayElements, $input, (jlong *)$1, JNI_ABORT);
%}
%typemap(freearg) const std::string& ""

// making the generated java interface prettier and more usable
%template(G1Vector) std::vector<G1>;
%template(G2Vector) std::vector<G2>;
%template(FrVector) std::vector<Fr>;
%template(LongVector) std::vector<long long>;

%begin %{
#include "c_kzg_4844.hpp"
#include "bls12_381.hpp"
#include "setup.hpp"
%}

// remove the _wrap suffix of the functions
%rename("%(regex:/^(.*)(_wrap)$/\\1/)s", %$isfunction) "";

%include "c_kzg_4844.hpp"
%include "bls12_381.hpp"
%include "setup.hpp"