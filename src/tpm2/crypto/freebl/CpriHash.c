/********************************************************************************/
/*										*/
/*										*/
/*			     Written by Stefan Berger				*/
/*			  Derived from openssl/CpriHash.c			*/
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

#include <stdio.h>
#include <blapi.h>

#include "FreeBLCryptoEngine.h"

const HASH_INFO   g_hashData[HASH_COUNT + 1] = {
#if   ALG_SHA1 == YES
    {TPM_ALG_SHA1,    SHA1_DIGEST_SIZE,   SHA1_BLOCK_SIZE,
     SHA1_DER_SIZE,   {SHA1_DER}},
#endif
#if   ALG_SHA256 == YES
    {TPM_ALG_SHA256,    SHA256_DIGEST_SIZE,   SHA256_BLOCK_SIZE,
     SHA256_DER_SIZE,   {SHA256_DER}},
#endif
#if   ALG_SHA384 == YES
    {TPM_ALG_SHA384,    SHA384_DIGEST_SIZE,   SHA384_BLOCK_SIZE,
     SHA384_DER_SIZE,   {SHA384_DER}},
#endif
#if   ALG_SHA512 == YES
    {TPM_ALG_SHA512,    SHA512_DIGEST_SIZE,   SHA512_BLOCK_SIZE,
     SHA512_DER_SIZE,   {SHA512_DER}},
#endif
#if   ALG_WHIRLPOOL512 == YES
    {TPM_ALG_WHIRLPOOL512,    WHIRLPOOL512_DIGEST_SIZE,   WHIRLPOOL512_BLOCK_SIZE,
     WHIRLPOOL512_DER_SIZE,   {WHIRLPOOL512_DER}},
#endif
#if   ALG_SM3_256 == YES
    {TPM_ALG_SM3_256,    SM3_256_DIGEST_SIZE,   SM3_256_BLOCK_SIZE,
     SM3_256_DER_SIZE,   {SM3_256_DER}},
#endif
    {TPM_ALG_NULL,0,0,0,{0}}
};

//#define EVP_sm3_256 EVP_sha256
static const SECHashObject *
GetHashServer(
	      TPM_ALG_ID   hashAlg
)
{
    switch (hashAlg)
    {
#ifdef TPM_ALG_SHA1
    case TPM_ALG_SHA1:
        return HASH_GetRawHashObject(HASH_AlgSHA1);
        break;
#endif
#ifdef TPM_ALG_SHA256
    case TPM_ALG_SHA256:
        return HASH_GetRawHashObject(HASH_AlgSHA256);
        break;
#endif
#ifdef TPM_ALG_SHA384
    case TPM_ALG_SHA384:
        return HASH_GetRawHashObject(HASH_AlgSHA384);
        break;
#endif
#ifdef TPM_ALG_SHA512
    case TPM_ALG_SHA512:
        return HASH_GetRawHashObject(HASH_AlgSHA512);
        break;
#endif
#ifdef TPM_ALG_SM3_256
    case TPM_ALG_SM3_256:
        break;
#endif
    case TPM_ALG_NULL:
        return NULL;
    default:
        FAIL(FATAL_ERROR_INTERNAL);
        return NULL;
    }
}

static UINT16
MarshalHashState(
    FBLHashContext  *ctxt,          // IN: Context to marshal
    BYTE            *buf            // OUT: The buffer that will receive the
                                    //      context. This buffer is at least
                                    //      MAX_HASH_STATE_SIZE bytes
)
{
    unsigned int ctxt_size;

    switch (ctxt->hashAlg) {
    case TPM_ALG_SHA1: //HASH_AlgSHA1:
        ctxt_size = SHA1_FlattenSize((SHA1Context *)ctxt);
        pAssert(ctxt_size <= FREEBL_HASH_STATE_DATA_SIZE);
        // FIXME: This call will not handle endianess conversion
        // to migrate between big and little endian hosts
        SHA1_Flatten((SHA1Context *)ctxt, buf);
        break;
    case TPM_ALG_SHA256: //HASH_AlgSHA256:
        ctxt_size = SHA256_FlattenSize((SHA256Context *)ctxt);
        pAssert(ctxt_size <= FREEBL_HASH_STATE_DATA_SIZE);
        SHA256_Flatten((SHA256Context *)ctxt, buf);
        break;
#ifdef TPM_ALG_SHA384
    case TPM_ALG_SHA384://HASH_AlgSHA384:
        ctxt_size = SHA384_FlattenSize((SHA384Context *)ctxt);
        pAssert(ctxt_size <= FREEBL_HASH_STATE_DATA_SIZE);
        SHA384_Flatten((SHA384Context *)ctxt, buf);
        break;
#endif
#ifdef TPM_ALG_SHA512
    case TPM_ALG_SHA512://HASH_AlgSHA512:
        ctxt_size = SHA512_FlattenSize((SHA512Context *)ctxt);
        pAssert(ctxt_size <= FREEBL_HASH_STATE_DATA_SIZE);
        SHA512_Flatten((SHA512Context *)ctxt, buf);
        break;
#endif
    default:
        abort();
    }

    return ctxt_size;
}
static UINT16
GetHashState(
    FBLHashContext *ctxt,          // OUT: The context structure to receive
                                    //      the result of unmarshaling.
    TPM_ALG_ID       algType,       // IN: The hash algorithm selector
    BYTE            *buf            // IN: Buffer containing marshaled hash data
)
{
    unsigned int          res;

#ifdef TPM_ALG_SHA1
    SHA1Context          *sha1_ctxt;
#endif
#ifdef TPM_ALG_SHA224
    SHA224Context        *sha224_ctxt;
#endif
#ifdef TPM_ALG_SHA256
    SHA256Context        *sha256_ctxt;
#endif
#ifdef TPM_ALG_SHA384
    SHA384Context        *sha384_ctxt;
#endif
#ifdef TPM_ALG_SHA512
    SHA512Context        *sha512_ctxt;
#endif

    pAssert(ctxt != NULL);

    switch (algType)
    {
#ifdef TPM_ALG_SHA1
    case TPM_ALG_SHA1:
        sha1_ctxt = SHA1_Resurrect((unsigned char *)buf, NULL);
        res = SHA1_FlattenSize(sha1_ctxt);
//        pAssert(res < sizeof(HASH_STATE_ARRAY));
        memcpy(&ctxt->u.sha1_ctxt, sha1_ctxt, res);
        PORT_Free(sha1_ctxt);
        break;
#endif
#ifdef TPM_ALG_SHA224
    case TPM_ALG_SHA224:
        sha224_ctxt = SHA224_Resurrect(buf, NULL);
        res = SHA224_FlattenSize(sha224_ctxt);
//        pAssert(res < sizeof(HASH_STATE_ARRAY));
        memcpy(&ctxt->u.sha224_ctxt, sha224_ctxt, res);
        PORT_Free(sha224_ctxt);
        break;
#endif
#ifdef TPM_ALG_SHA256
    case TPM_ALG_SHA256:
        sha256_ctxt = SHA256_Resurrect(buf, NULL);
        res = SHA256_FlattenSize(sha256_ctxt);
//        pAssert(res < sizeof(HASH_STATE_ARRAY));
        memcpy(&ctxt->u.sha256_ctxt, sha256_ctxt, res);
        PORT_Free(sha256_ctxt);
        break;
#endif
#ifdef TPM_ALG_SHA384
    case TPM_ALG_SHA384:
        sha384_ctxt = SHA384_Resurrect(buf, NULL);
        res = SHA384_FlattenSize(sha384_ctxt);
//        pAssert(res < sizeof(HASH_STATE_ARRAY));
        memcpy(&ctxt->u.sha384_ctxt, sha384_ctxt, res);
        PORT_Free(sha384_ctxt);
        break;
#endif
#ifdef TPM_ALG_SHA512
    case TPM_ALG_SHA512:
        sha512_ctxt = SHA512_Resurrect(buf, NULL);
        res = SHA512_FlattenSize(sha512_ctxt);
//        pAssert(res < sizeof(HASH_STATE_ARRAY));
        memcpy(&ctxt->u.sha512_ctxt, sha512_ctxt, res);
        PORT_Free(sha512_ctxt);
        break;
#endif
#ifdef TPM_ALG_SM3_256
#error SM3_256 not supported by freebl
    case TPM_ALG_SM3_256:
        break;
#endif
    default:
        FAIL(FATAL_ERROR_INTERNAL);
        return -1;
    }

    return res;
}

static const HASH_INFO *
GetHashInfoPointer(
    TPM_ALG_ID   hashAlg
)
{
    UINT32 i, tableSize;

    // Get the table size of g_hashData
    tableSize = sizeof(g_hashData) / sizeof(g_hashData[0]);

    for(i = 0; i < tableSize - 1; i++)
    {
        if(g_hashData[i].alg == hashAlg)
            return &g_hashData[i];
    }
    pAssert(hashAlg == TPM_ALG_NULL);
    return &g_hashData[tableSize-1];
}

LIB_EXPORT BOOL
_cpri__HashStartup(
    void
)
{
    // On startup, make sure that the structure sizes are compatible. It would
    // be nice if this could be done at compile time but I couldn't figure it out.
    CPRI_HASH_STATE *cpriState = NULL;
    //    NUMBYTES        evpCtxSize = sizeof(EVP_MD_CTX);
    NUMBYTES        cpriStateSize = sizeof(cpriState->state);
    //    OSSL_HASH_STATE *osslState;
    NUMBYTES        freeblStateSize = sizeof(FREEBL_HASH_STATE);
     //    int             dataSize = sizeof(osslState->u.data);
    fprintf(stderr, "cpriStateSize = %d\n", cpriStateSize);
    fprintf(stderr, "freeblStateSize = %d\n", freeblStateSize);
    pAssert(cpriStateSize >= freeblStateSize);

    return TRUE;
}

TPM_ALG_ID
_cpri__GetHashAlgByIndex(
    UINT32      index       // IN: the index
)
{
    if(index >= HASH_COUNT)
        return TPM_ALG_NULL;
    return g_hashData[index].alg;
}

UINT16
_cpri__GetHashBlockSize(
    TPM_ALG_ID  hashAlg     // IN: hash algorithm to look up
)
{
    return GetHashInfoPointer(hashAlg)->blockSize;
}

UINT16
_cpri__GetHashDER(
    TPM_ALG_ID             hashAlg,    // IN: the algorithm to look up
    const BYTE           **p
)
{
    const HASH_INFO       *q;
    q = GetHashInfoPointer(hashAlg);
    *p = &q->der[0];
    return q->derSize;
}

UINT16
_cpri__GetDigestSize(
    TPM_ALG_ID  hashAlg     // IN: hash algorithm to look up
)
{
    return GetHashInfoPointer(hashAlg)->digestSize;
}

TPM_ALG_ID
_cpri__GetContextAlg(
    CPRI_HASH_STATE         *hashState  // IN: the hash context
)
{
    return hashState->hashAlg;
}

UINT16
_cpri__CopyHashState (
    CPRI_HASH_STATE    *out,       // OUT: destination of the state
    CPRI_HASH_STATE    *in         // IN: source of the state
)
{
    FREEBL_HASH_STATE    *i = (FREEBL_HASH_STATE *)&in->state;
    FREEBL_HASH_STATE    *o = (FREEBL_HASH_STATE *)&out->state;

    //pAssert(sizeof(FREEBL_HASH_STATE) <= sizeof(in->state));

    *o = *i;
    out->hashAlg = in->hashAlg;
    return sizeof(CPRI_HASH_STATE);
}

UINT16
_cpri__StartHash(
    TPM_ALG_ID       hashAlg,       // IN: hash algorithm
    BOOL             sequence,      // IN: TRUE if the state should be saved
    CPRI_HASH_STATE *hashState      // OUT: the state of hash stack.
)
{
    FBLHashContext  localState;
    FREEBL_HASH_STATE *state = (FREEBL_HASH_STATE *)&hashState->state;
    BYTE            *stateData = state->u.data;
    FBLHashContext  *context;
    const SECHashObject *hashServer;
    UINT16           retVal = 0;

    if(sequence)
        context = &localState;
    else
        context = &state->u.context;

    hashState->hashAlg = hashAlg;

    hashServer = GetHashServer(hashAlg);
    if(hashServer == NULL)
        goto Cleanup;

    context->hashAlg = hashAlg;
    hashServer->begin(context);
    retVal = (CRYPT_RESULT)hashServer->length;

Cleanup:
    if(retVal > 0)
    {
        if (sequence)
        {
            if((state->copySize = MarshalHashState(context, stateData)) == 0)
            {
                // If MarshalHashState returns a negative number, it is an error
                // code and not a hash size so copy the error code to be the return
                // from this function and set the actual stateSize to zero.
                retVal = state->copySize;
                state->copySize = 0;
            }
            // Do the cleanup
            hashServer->destroy(context, FALSE);
        }
        else
            state->copySize = -1;
    }
    else
        state->copySize = 0;
    return retVal;
}

void
_cpri__UpdateHash(
    CPRI_HASH_STATE     *hashState,     // IN: the hash context information
    UINT32               dataSize,      // IN: the size of data to be added to
                                        //     the digest
    BYTE                *data           // IN: data to be hashed
)
{
    FBLHashContext  localContext;
    FREEBL_HASH_STATE *state = (FREEBL_HASH_STATE *)&hashState->state;
    BYTE            *stateData = state->u.data;
    FBLHashContext     *context;
    CRYPT_RESULT     retVal = CRYPT_SUCCESS;
    const SECHashObject *hashServer;

    // If there is no context, return
    if(state->copySize == 0)
        return;
    if(state->copySize > 0)
    {
        context = &localContext;
        if((retVal = GetHashState(context, hashState->hashAlg, stateData)) <= 0)
            return;
    }
    else
        context = &state->u.context;

    hashServer = GetHashServer(hashState->hashAlg);
    if(hashServer == NULL)
        goto Cleanup;

    context->hashAlg = hashState->hashAlg;
    hashServer->update(context, data, dataSize);

    if(FALSE)
        FAIL(FATAL_ERROR_INTERNAL);
    else if(   state->copySize > 0
               && (retVal= MarshalHashState(context, stateData)) >= 0)
    {
        // retVal is the size of the marshaled data. Make sure that it is consistent
        // by ensuring that we didn't get more than allowed
        if(retVal < state->copySize)
            FAIL(FATAL_ERROR_INTERNAL);
        else
            hashServer->destroy(context, FALSE);
    }
Cleanup:
    return;
}

LIB_EXPORT UINT16
_cpri__CompleteHash(
    CPRI_HASH_STATE     *hashState,     // IN: the state of hash stack
    UINT32               dOutSize,      // IN: size of digest buffer
    BYTE                *dOut           // OUT: hash digest
)
{
    FBLHashContext   localState;
    FREEBL_HASH_STATE *state = (FREEBL_HASH_STATE *)&hashState->state;
    BYTE            *stateData = state->u.data;
    FBLHashContext  *context;
    UINT16           retVal = 0;
    int              hLen;
    BYTE             temp[MAX_DIGEST_SIZE];
    BYTE            *rBuffer = dOut;
    const SECHashObject *hashServer = NULL;
    unsigned int     digestLen;

    if(state->copySize == 0)
        return 0;
    if(state->copySize > 0)
    {
        context = &localState;
        if((retVal = GetHashState(context, hashState->hashAlg, stateData)) <= 0)
            goto Cleanup;
    }
    else
        context = &state->u.context;

    hashServer = GetHashServer(hashState->hashAlg);
    if(hashServer == NULL)
        goto Cleanup;

    context->hashAlg = hashState->hashAlg;

    hLen = (CRYPT_RESULT)hashServer->length;
    if((unsigned)hLen > dOutSize)
        rBuffer = temp;
    hashServer->end(context, rBuffer, &digestLen, dOutSize);
    if (1)
    {
        if(rBuffer != dOut)
        {
            if(dOut != NULL)
            {
                memcpy(dOut, temp, dOutSize);
            }
            retVal = (UINT16)dOutSize;
        }
        else
        {
            retVal = (UINT16)hLen;
        }
        state->copySize = 0;
    }
    else
    {
        retVal = 0; // Indicate that no data is returned
    }
Cleanup:
    if (hashServer)
        hashServer->destroy(context, FALSE);
    return retVal;
}

// B.8.4.11.	_cpri__ImportExportHashState()

// This function is used to import or export the hash state. This function would be called to export
// state when a sequence object was being prepared for export

LIB_EXPORT void
_cpri__ImportExportHashState(
			     CPRI_HASH_STATE     *osslFmt,       // IN/OUT: the hash state formated for use
			     //     by openSSL
			     EXPORT_HASH_STATE   *externalFmt,   // IN/OUT: the exported hash state
			     IMPORT_EXPORT        direction      //
			     )
{
    NOT_REFERENCED(direction);
    NOT_REFERENCED(externalFmt);
    NOT_REFERENCED(osslFmt);
    return;

#if 0
    if(direction == IMPORT_STATE)
	{
	    // don't have the import export functions yet so just copy
	    _cpri__CopyHashState(osslFmt, (CPRI_HASH_STATE *)externalFmt);
	}
    else
	{
	    _cpri__CopyHashState((CPRI_HASH_STATE *)externalFmt, osslFmt);
	}
#endif
}

UINT16
_cpri__HashBlock(
    TPM_ALG_ID   hashAlg,        // IN: The hash algorithm
    UINT32       dataSize,       // IN: size of buffer to hash
    BYTE        *data,           // IN: the buffer to hash
    UINT32       digestSize,     // IN: size of the digest buffer
    BYTE        *digest          // OUT: hash digest
)
{
    FBLHashContext   hashContext;
    const SECHashObject *hashServer;
    UINT16           retVal = 0;
    BYTE             b[MAX_DIGEST_SIZE]; // temp buffer in case digestSize not
    // a full digest
    unsigned int     dSize = _cpri__GetDigestSize(hashAlg);


    // If there is no digest to compute return
    if(dSize == 0)
        return 0;

    // After the call to EVP_MD_CTX_init(), will need to call EVP_MD_CTX_cleanup()
    hashServer = GetHashServer(hashAlg); // Find the hash server

    // It is an error if the digest size is non-zero but there is no server
    if(   (hashServer == NULL) )
        FAIL(FATAL_ERROR_INTERNAL);
    else
    {
        hashServer->begin(&hashContext);
        hashServer->update(&hashContext, data, dataSize);
        // If the size of the digest produced (dSize) is larger than the available
        // buffer (digestSize), then put the digest in a temp buffer and only copy
        // the most significant part into the available buffer.
        if(dSize > digestSize)
        {
            hashServer->end(&hashContext, b, &dSize, digestSize);
            memcpy(digest, b, digestSize);
            retVal = (UINT16)digestSize;
        }
        else
        {
            hashServer->end(&hashContext, digest, &dSize, digestSize);
            retVal = (UINT16) dSize;
        }
    }
    hashServer->destroy(&hashContext, FALSE);
    return retVal;
}

UINT16
_cpri__StartHMAC(
    TPM_ALG_ID       hashAlg,   // IN: the algorithm to use
    BOOL             sequence,  // IN: indicates if the state should be saved
    CPRI_HASH_STATE *state,     // IN/OUT: the state buffer
    UINT16           keySize,   // IN: the size of the HMAC key
    BYTE            *key,       // IN: the HMAC key
    TPM2B           *oPadKey    // OUT: the key prepared for the oPad round
)
{
    CPRI_HASH_STATE  localState;
    UINT16           blockSize = _cpri__GetHashBlockSize(hashAlg);
    UINT16           digestSize;
    BYTE            *pb;        // temp pointer
    UINT32           i;

    // If the key size is larger than the block size, then the hash of the key
    // is used as the key
    if(keySize > blockSize)
    {
        // large key so digest
        if((digestSize = _cpri__StartHash(hashAlg, FALSE, &localState)) == 0)
            return 0;
        _cpri__UpdateHash(&localState, keySize, key);
        _cpri__CompleteHash(&localState, digestSize, oPadKey->buffer);
        oPadKey->size = digestSize;
    }
    else
    {
        // key size is ok
        memcpy(oPadKey->buffer, key, keySize);
        oPadKey->size = keySize;
    }
    // XOR the key with iPad (0x36)
    pb = oPadKey->buffer;
    for(i = oPadKey->size; i > 0; i--)
        *pb++ ^= 0x36;

    // if the keySize is smaller than a block, fill the rest with 0x36
    for(i = blockSize - oPadKey->size; i >  0; i--)
        *pb++ = 0x36;

    // Increase the oPadSize to a full block
    oPadKey->size = blockSize;

    // Start a new hash with the HMAC key
    // This will go in the caller's state structure and may be a sequence or not

    if((digestSize = _cpri__StartHash(hashAlg, sequence, state)) > 0)
    {

        _cpri__UpdateHash(state, oPadKey->size, oPadKey->buffer);

        // XOR the key block with 0x5c ^ 0x36
        for(pb = oPadKey->buffer, i = blockSize; i > 0; i--)
            *pb++ ^= (0x5c ^ 0x36);
    }

    return digestSize;
}

UINT16
_cpri__CompleteHMAC(
    CPRI_HASH_STATE     *hashState,     // IN: the state of hash stack
    TPM2B               *oPadKey,       // IN: the HMAC key in oPad format
    UINT32               dOutSize,      // IN: size of digest buffer
    BYTE                *dOut           // OUT: hash digest
)
{
    BYTE             digest[MAX_DIGEST_SIZE];
    CPRI_HASH_STATE *state = (CPRI_HASH_STATE *)hashState;
    CPRI_HASH_STATE  localState;
    UINT16           digestSize = _cpri__GetDigestSize(state->hashAlg);


    _cpri__CompleteHash(hashState, digestSize, digest);

    // Using the local hash state, do a hash with the oPad
    if(_cpri__StartHash(state->hashAlg, FALSE, &localState) != digestSize)
        return 0;

    _cpri__UpdateHash(&localState, oPadKey->size, oPadKey->buffer);
    _cpri__UpdateHash(&localState, digestSize, digest);
    return _cpri__CompleteHash(&localState, dOutSize, dOut);
}

CRYPT_RESULT
_cpri__MGF1(
    UINT32      mSize,     // IN: length of the mask to be produced
    BYTE       *mask,      // OUT: buffer to receive the mask
    TPM_ALG_ID  hashAlg,   // IN: hash to use
    UINT32      sSize,     // IN: size of the seed
    BYTE       *seed       // IN: seed size
)
{
    FBLHashContext       hashContext;
    const SECHashObject *hashServer;
    CRYPT_RESULT         retVal = 0;
    BYTE                 b[MAX_DIGEST_SIZE]; // temp buffer in case mask is not an
    // even multiple of a full digest
    CRYPT_RESULT         dSize = _cpri__GetDigestSize(hashAlg);
    unsigned int         digestSize = (UINT32)dSize;
    UINT32               remaining;
    UINT32               counter;
    BYTE                 swappedCounter[4];

    // Parameter check
    if(mSize > (1024*16)) // Semi-arbitrary maximum
        FAIL(FATAL_ERROR_INTERNAL);

    // If there is no digest to compute return
    if(dSize <= 0)
        return 0;

    hashServer = GetHashServer(hashAlg); // Find the hash server
    if(hashServer == NULL)
        // If there is no server, then there is no digest
        return 0;

    // FIXME: remove ?
    hashServer->begin(&hashContext);    // Initialize the local hash context

    for(counter = 0, remaining = mSize; remaining > 0; counter++)
    {
        // Because the system may be either Endian...
        UINT32_TO_BYTE_ARRAY(counter, swappedCounter);

        // Start the hash and include the seed and counter
        // Start the hash and include the seed and counter
        hashServer->begin(&hashContext);
        hashServer->update(&hashContext, seed, sSize);
        hashServer->update(&hashContext, swappedCounter, 4);

        // Handling the completion depends on how much space remains in the mask
        // buffer. If it can hold the entire digest, put it there. If not
        // put the digest in a temp buffer and only copy the amount that
        // will fit into the mask buffer.
        if(remaining < (unsigned)dSize)
        {
            hashServer->end(&hashContext, b, &digestSize, dSize);
            memcpy(mask, b, remaining);
            break;
        }
        else
        {
            hashServer->end(&hashContext, mask, &digestSize, dSize);
            remaining -= dSize;
            mask = &mask[dSize];
        }
        retVal = (CRYPT_RESULT)mSize;
    }

    hashServer->destroy(&hashContext, FALSE);
    return retVal;
}

UINT16
_cpri__KDFa(
    TPM_ALG_ID   hashAlg,       // IN: hash algorithm used in HMAC
    TPM2B       *key,           // IN: HMAC key
    const char  *label,         // IN: a 0-byte terminated label used in KDF
    TPM2B       *contextU,      // IN: context U
    TPM2B       *contextV,      // IN: context V
    UINT32       sizeInBits,    // IN: size of generated key in bits
    BYTE        *keyStream,     // OUT: key buffer
    UINT32      *counterInOut,  // IN/OUT: caller may provide the iteration counter
                                //         for incremental operations to avoid
                                //         large intermediate buffers.
    BOOL         once           // IN: TRUE if only one iteration is performed
                                //     FALSE if iteration count determined by
                                //     "sizeInBits"
)
{
    UINT32                   counter = 0;    // counter value
    INT32                    lLen;           // length of the label
    INT16                    hLen;           // length of the hash
    INT16                    bytes;          // number of bytes to produce
    BYTE                    *stream = keyStream;
    BYTE                     marshaledUint32[4];
    CPRI_HASH_STATE          hashState;
    TPM2B_MAX_HASH_BLOCK     hmacKey;

    pAssert(key != NULL && keyStream != NULL);
    pAssert(once == FALSE || (sizeInBits & 7) == 0);

    if(counterInOut != NULL)
        counter = *counterInOut;

    // Prepare label buffer.  Calculate its size and keep the last 0 byte
    for(lLen = 0; label[lLen++] != 0; );

    // Get the hash size.  If it is less than or 0, either the
    // algorithm is not supported or the hash is TPM_ALG_NULL
    // In either case the digest size is zero.  This is the only return
    // other than the one at the end. All other exits from this function
    // are fatal errors. After we check that the algorithm is supported
    // anything else that goes wrong is an implementation flaw.
    if((hLen = (INT16) _cpri__GetDigestSize(hashAlg)) == 0)
        return 0;

    // If the size of the request is larger than the numbers will handle,
    // it is a fatal error.
    pAssert(((sizeInBits + 7)/ 8) <= INT16_MAX);

    bytes = once ? hLen : (INT16)((sizeInBits + 7) / 8);

    // Generate required bytes
    for (; bytes > 0; stream = &stream[hLen], bytes = bytes - hLen)
    {
        if(bytes < hLen)
            hLen = bytes;

        counter++;
        // Start HMAC
        if(_cpri__StartHMAC(hashAlg,
                            FALSE,
                            &hashState,
                            key->size,
                            &key->buffer[0],
                            &hmacKey.b)         <= 0)
            FAIL(FATAL_ERROR_INTERNAL);

        // Adding counter
        UINT32_TO_BYTE_ARRAY(counter, marshaledUint32);
        _cpri__UpdateHash(&hashState, sizeof(UINT32), marshaledUint32);

        // Adding label
        if(label != NULL)
            _cpri__UpdateHash(&hashState,  lLen, (BYTE *)label);

        // Adding contextU
        if(contextU != NULL)
            _cpri__UpdateHash(&hashState, contextU->size, contextU->buffer);

        // Adding contextV
        if(contextV != NULL)
            _cpri__UpdateHash(&hashState, contextV->size, contextV->buffer);

        // Adding size in bits
        UINT32_TO_BYTE_ARRAY(sizeInBits, marshaledUint32);
        _cpri__UpdateHash(&hashState, sizeof(UINT32), marshaledUint32);

        // Compute HMAC. At the start of each iteration, hLen is set
        // to the smaller of hLen and bytes. This causes bytes to decrement
        // exactly to zero to complete the loop
        _cpri__CompleteHMAC(&hashState, &hmacKey.b, hLen, stream);
    }

    // Mask off bits if the required bits is not a multiple of byte size
    if((sizeInBits % 8) != 0)
        keyStream[0] &= ((1 << (sizeInBits % 8)) - 1);
    if(counterInOut != NULL)
        *counterInOut = counter;
    return (CRYPT_RESULT)((sizeInBits + 7)/8);
}

UINT16
_cpri__KDFe(
    TPM_ALG_ID       hashAlg,           // IN: hash algorithm used in HMAC
    TPM2B           *Z,                 // IN: Z
    const char      *label,             // IN: a 0 terminated label using in KDF
    TPM2B           *partyUInfo,        // IN: PartyUInfo
    TPM2B           *partyVInfo,        // IN: PartyVInfo
    UINT32           sizeInBits,        // IN: size of generated key in bits
    BYTE            *keyStream          // OUT: key buffer
)
{
    UINT32       counter = 0;       // counter value
    UINT32       lSize = 0;
    BYTE        *stream = keyStream;
    CPRI_HASH_STATE         hashState;
    INT16        hLen = (INT16) _cpri__GetDigestSize(hashAlg);
    INT16        bytes;             // number of bytes to generate
    BYTE         marshaledUint32[4];

    pAssert(   keyStream != NULL
               && Z != NULL
               && ((sizeInBits + 7) / 8) < INT16_MAX);

    if(hLen == 0)
        return 0;

    bytes = (INT16)((sizeInBits + 7) / 8);

    // Prepare label buffer.  Calculate its size and keep the last 0 byte
    if(label != NULL)
        for(lSize = 0; label[lSize++] != 0;);

    // Generate required bytes
    //The inner loop of that KDF uses:
    //  Hashi := H(counter | Z | OtherInfo) (5)
    // Where:
    //  Hashi   the hash generated on the i-th iteration of the loop.
    //  H()     an approved hash function
    //  counter a 32-bit counter that is initialized to 1 and incremented
    //          on each iteration
    //  Z       the X coordinate of the product of a public ECC key and a
    //          different private ECC key.
    //  OtherInfo   a collection of qualifying data for the KDF defined below.
    //  In this specification, OtherInfo will be constructed by:
    //      OtherInfo := Use | PartyUInfo  | PartyVInfo
    for (; bytes > 0; stream = &stream[hLen], bytes = bytes - hLen)
    {
        if(bytes < hLen)
            hLen = bytes;

        counter++;
        // Start hash
        if(_cpri__StartHash(hashAlg, FALSE,  &hashState) == 0)
            return 0;

        // Add counter
        UINT32_TO_BYTE_ARRAY(counter, marshaledUint32);
        _cpri__UpdateHash(&hashState, sizeof(UINT32), marshaledUint32);

        // Add Z
        if(Z != NULL)
            _cpri__UpdateHash(&hashState, Z->size, Z->buffer);

        // Add label
        if(label != NULL)
            _cpri__UpdateHash(&hashState, lSize, (BYTE *)label);
        else

            // The SP800-108 specification requires a zero between the label
            // and the context.
            _cpri__UpdateHash(&hashState, 1, (BYTE *)"");

        // Add PartyUInfo
        if(partyUInfo != NULL)
            _cpri__UpdateHash(&hashState, partyUInfo->size, partyUInfo->buffer);

        // Add PartyVInfo
        if(partyVInfo != NULL)
            _cpri__UpdateHash(&hashState, partyVInfo->size, partyVInfo->buffer);

        // Compute Hash. hLen was changed to be the smaller of bytes or hLen
        // at the start of each iteration.
        _cpri__CompleteHash(&hashState, hLen, stream);
    }

    // Mask off bits if the required bits is not a multiple of byte size
    if((sizeInBits % 8) != 0)
        keyStream[0] &= ((1 << (sizeInBits % 8)) - 1);

    return (CRYPT_RESULT)((sizeInBits + 7) / 8);
}

