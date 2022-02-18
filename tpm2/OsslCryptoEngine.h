// This file was extracted from the TCG Published
// Trusted Platform Module Library
// Part 4: Supporting Routines
// Family "2.0"
// Level 00 Revision 01.16
// October 30, 2014

#ifndef _OSSL_CRYPTO_ENGINE_H
#define _OSSL_CRYPTO_ENGINE_H
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#define     CRYPTO_ENGINE
#include "CryptoEngine.h"
#include "CpriMisc_fp.h"
#define MAX_ECC_PARAMETER_BYTES 32
#define MAX_2B_BYTES MAX((MAX_RSA_KEY_BYTES * ALG_RSA),                              \
                         MAX((MAX_ECC_PARAMETER_BYTES * ALG_ECC),                   \
                             MAX_DIGEST_SIZE))
#define assert2Bsize(a) pAssert((a).size <= sizeof((a).buffer))
#ifdef TPM_ALG_RSA
#   ifdef   RSA_KEY_SIEVE
#       include     "RsaKeySieve.h"
#       include     "RsaKeySieve_fp.h"
#   endif
#   include    "CpriRSA_fp.h"
#endif
//
//     This is a structure to hold the parameters for the version of KDFa() used by the CryptoEngine(). This
//     structure allows the state to be passed between multiple functions that use the same pseudo-random
//     sequence.
//
typedef struct {
   CPRI_HASH_STATE          iPadCtx;
   CPRI_HASH_STATE          oPadCtx;
   TPM2B                   *extra;
   UINT32                  *outer;
   TPM_ALG_ID               hashAlg;
   UINT16                   keySizeInBits;
} KDFa_CONTEXT;
#endif // _OSSL_CRYPTO_ENGINE_H
