#ifndef ___EXCEPTION_HPP___
#define ___EXCEPTION_HPP___

#include <string>

#include "c_kzg_4844.h"

char *C_KZG_ERRORS[] = {
    "C_KZG_OK",
    "C_KZG_BADARGS",
    "C_KZG_ERROR",
    "C_KZG_MALLOC"};

char *BLST_ERRORS[] = {
    "BLST_SUCCESS",
    "BLST_BAD_ENCODING",
    "BLST_POINT_NOT_ON_CURVE",
    "BLST_POINT_NOT_IN_GROUP",
    "BLST_AGGR_TYPE_MISMATCH",
    "BLST_VERIFY_FAIL",
    "BLST_PK_IS_INFINITY",
    "BLST_BAD_SCALAR"};

class KZGException
{
    std::string message;

public:
    KZGException(const std::string &msg) : message(msg) {}

    std::string message()
    {
        return message;
    }
};

#define CKZG_TRY(result)                                                             \
    {                                                                                \
        C_KZG_RET ___ret = (result);                                                 \
        if (___ret != C_KZG_OK)                                                      \
            throw KZGException(std::string("C-KZG error: ") + C_KZG_ERRORS[___ret]); \
    }

#define BLST_TRY(result)                                                           \
    {                                                                              \
        BLST_ERROR ___ret = (result);                                              \
        if (___ret != BLST_SUCCESS)                                                \
            throw KZGException(std::string("BLST error: ") + BLST_ERRORS[___ret]); \
    }

#endif
