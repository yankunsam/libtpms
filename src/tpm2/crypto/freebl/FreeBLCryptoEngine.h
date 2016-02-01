/********************************************************************************/
/*										*/
/*										*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2012-2015				*/
/*										*/
/********************************************************************************/

#ifndef FREEBL_CRYPTO_ENGINE_H
#define FREEBL_CRYPTO_ENGINE_H

#include <nss3/blapi.h>
#include <nss3/blapit.h>
#include <gmp.h>

#define     CRYPTO_ENGINE
#include "CryptoEngine.h"
#include "mpz_helpers.h"
#include "bn.h"

#define MAX_2B_BYTES MAX((MAX_RSA_KEY_BYTES * ALG_RSA),             \
			 MAX((MAX_ECC_KEY_BYTES * ALG_ECC),	\
			     MAX_DIGEST_SIZE))
#define assert2Bsize(a) pAssert((a).size <= sizeof((a).buffer))


#define FREEBL_HASH_STATE_DATA_SIZE    (MAX_HASH_STATE_SIZE - 8)

// FIXME: BEGIN copied from freebl lib
// we *at least* would need the sizeof(SHA512ContextStr)

typedef PRUint64 SHA_HW_t;

struct SHA1ContextStr {
  union {
    PRUint32 w[16];             /* input buffer */
    PRUint8  b[64];
  } u;
  PRUint64 size;                /* count of hashed bytes. */
  SHA_HW_t H[22];               /* 5 state variables, 16 tmp values, 1 extra */
};

struct SHA256ContextStr {
    union {
        PRUint32 w[64];     /* message schedule, input buffer, plus 48 words */
        PRUint8  b[256];
    } u;
    PRUint32 h[8];              /* 8 state variables */
    PRUint32 sizeHi,sizeLo;     /* 64-bit count of hashed bytes. */
};

struct SHA512ContextStr {
    union {
        PRUint64 w[80];     /* message schedule, input buffer, plus 64 words */
        PRUint32 l[160];
        PRUint8  b[640];
    } u;
    PRUint64 h[8];          /* 8 state variables */
    PRUint64 sizeLo;        /* 64-bit count of hashed bytes. */
};

// FIXME: END

typedef struct SHA256ContextStr SHA256Context;
typedef struct SHA512ContextStr SHA512Context;

typedef struct {
    union
    {
#ifdef TPM_ALG_SHA1
        SHA1Context     sha1_ctxt;
#endif
#ifdef TPM_ALG_SHA224
        SHA224Context   sha224_ctxt;
#endif
#ifdef TPM_ALG_SHA256
        SHA256Context   sha256_ctxt;
#endif
#ifdef TPM_ALG_SHA384
        SHA384Context   sha384_ctxt;
#endif
#ifdef TPM_ALG_SHA512
        SHA512Context   sha512_ctxt;
#endif
    } u;
    TPM_ALG_ID      hashAlg;
} FBLHashContext;

typedef struct {
    union
    {
        FBLHashContext    context;
        BYTE              data[FREEBL_HASH_STATE_DATA_SIZE];
    } u;
    INT16           copySize;
} FREEBL_HASH_STATE;

#endif
