/********************************************************************************/
/*										*/
/*			  Command and Response Parameter Structures		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Parameters.h 457 2015-12-08 15:29:45Z kgoldman $		*/
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

#include <endian.h>
#include <string.h>

#include "assert.h"
#include "PlatformData.h"
#include "Global.h"
#include "NVMarshal.h"
#include "Marshal_fp.h"
#include "Unmarshal_fp.h"

UINT16 _plat__NvMemoryWriteUINT8(
				unsigned int     startOffset,   // IN: write start
				UINT8		 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(data) <= NV_MEMORY_SIZE);

    return UINT8_Marshal(data, &buffer, &size);
}

TPM_RC _plat__NvMemoryReadUINT8(
				unsigned int     startOffset,   // IN: read start
				UINT8		 *data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return UINT8_Unmarshal(data, &buffer, &size);
}

UINT16 _plat__NvMemoryWriteUINT16(
				unsigned int     startOffset,   // IN: write start
				UINT16		 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(data) <= NV_MEMORY_SIZE);

    return UINT16_Marshal(data, &buffer, &size);
}

TPM_RC _plat__NvMemoryReadUINT16(
				unsigned int     startOffset,   // IN: read start
				UINT16		 *data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return UINT16_Unmarshal(data, &buffer, &size);
}

UINT16 _plat__NvMemoryWriteUINT32(
				unsigned int     startOffset,   // IN: write start
				UINT32		 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(data) <= NV_MEMORY_SIZE);

    return UINT32_Marshal(data, &buffer, &size);
}

TPM_RC _plat__NvMemoryReadUINT32(
				unsigned int     startOffset,   // IN: read start
				UINT32		 *data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return UINT32_Unmarshal(data, &buffer, &size);
}

UINT16 _plat__NvMemoryWriteUINT64(
				unsigned int     startOffset,   // IN: write start
				UINT64		 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(data) <= NV_MEMORY_SIZE);

    return UINT64_Marshal(data, &buffer, &size);
}

TPM_RC _plat__NvMemoryReadUINT64(
				unsigned int     startOffset,   // IN: read start
				UINT64		 *data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return UINT64_Unmarshal(data, &buffer, &size);
}

UINT16 _plat__NvMemoryWriteArray(
				unsigned int     startOffset,   // IN: write start
				unsigned int     dataSize,      // IN: size of the array
				void		 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = dataSize;

    assert(startOffset + size <= NV_MEMORY_SIZE);

    return Array_Marshal(data, size, &buffer, &size);
}

TPM_RC _plat__NvMemoryReadArray(
				unsigned int     startOffset,   // IN: write start
				unsigned int     dataSize,      // IN: size of the array
				void		 *data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = dataSize;

    assert(startOffset + size <= NV_MEMORY_SIZE);

    return Array_Unmarshal(data, size, &buffer, &size);
}

UINT16 _plat__NvMemoryWriteTPM2B(
				unsigned int     startOffset,   // IN: write start
				void		 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    return TPM2B_Marshal(data, &buffer, &size);
}

TPM_RC _plat__NvMemoryReadTPM2B(
				unsigned int     startOffset,   // IN: write start
				void		 *data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    return TPM2B_Marshal(data, &buffer, &size);
}

UINT16 _plat__NvMemoryWriteTPMS_NV_PUBLIC(
				unsigned int     startOffset,   // IN: write start
				TPMS_NV_PUBLIC	 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return TPMS_NV_PUBLIC_Marshal(data, &buffer, &size);
}

TPM_RC _plat__NvMemoryReadTPMS_NV_PUBLIC(
				unsigned int     startOffset,   // IN: write start
				TPMS_NV_PUBLIC	 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return TPMS_NV_PUBLIC_Unmarshal(data, &buffer, &size);
}

UINT16
NV_INDEX_Marshal(NV_INDEX *data, BYTE **buffer, INT32 *size)
{
    UINT16 written;

    written = TPMS_NV_PUBLIC_Marshal(&data->publicArea, buffer, size);
    written += TPM2B_AUTH_Marshal(&data->authValue, buffer, size);

    return written;
}

TPM_RC
NV_INDEX_Unmarshal(NV_INDEX *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
        rc = TPMS_NV_PUBLIC_Unmarshal(&data->publicArea, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_AUTH_Unmarshal(&data->authValue, buffer, size);
    }

    return rc;
}

UINT16 _plat__NvMemoryWriteNV_INDEX(
				unsigned int     startOffset,   // IN: write start
				NV_INDEX	 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return NV_INDEX_Marshal(data, &buffer, &size);
}

TPM_RC _plat__NvMemoryReadNV_INDEX(
				unsigned int     startOffset,   // IN: write start
				NV_INDEX	 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return NV_INDEX_Unmarshal(data, &buffer, &size);
}

UINT16
PCR_POLICY_Marshal(PCR_POLICY *data, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;

#if NUM_POLICY_PCR_GROUP > 0	/* kgold added to prevent zero size array */
    written = UINT16_Marshal(&data->hashAlg, buffer, size);
#endif

    written += TPM2B_DIGEST_Marshal(&data->a, buffer, size);

#if NUM_POLICY_PCR_GROUP > 0	/* kgold added to prevent zero size array */
    written += TPM2B_DIGEST_Marshal(&data->policy, buffer, size);
#endif

    return written;
}

UINT16 _plat__NvMemoryWritePCR_POLICY(
				unsigned int     startOffset,   // IN: write start
				PCR_POLICY	 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return PCR_POLICY_Marshal(data, &buffer, &size);
}

TPM_RC
PCR_POLICY_Unmarshal(PCR_POLICY *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

#if NUM_POLICY_PCR_GROUP > 0	/* kgold added to prevent zero size array */
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT16_Unmarshal(&data->hashAlg, &uffer, size);
    }
#endif

    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_DIGEST_Unmarshal(&data->a, buffer, size);
    }

#if NUM_POLICY_PCR_GROUP > 0	/* kgold added to prevent zero size array */
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_DIGEST_Unmarshal(&data->policy, buffer, size);
    }
#endif

    return rc;
}

TPM_RC _plat__NvMemoryReadPCR_POLICY(
				unsigned int     startOffset,   // IN: write start
				PCR_POLICY	 *data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return PCR_POLICY_Unmarshal(data, &buffer, &size);
}

UINT16
ORDERLY_DATA_Marshal(ORDERLY_DATA *data, BYTE **buffer, INT32 *size)
{
    UINT16 written;

    written = UINT64_Marshal(&data->clock, buffer, size);
    written += UINT8_Marshal(&data->clockSafe, buffer, size);

    return written;
}

UINT16 _plat__NvMemoryWriteORDERLY_DATA(
				unsigned int     startOffset,   // IN: write start
				ORDERLY_DATA	 *data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;
    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return ORDERLY_DATA_Marshal(data, &buffer, &size);
}

TPM_RC
ORDERLY_DATA_Unmarshal(ORDERLY_DATA *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->clock, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal(&data->clockSafe, buffer, size);
    }

    return rc;
}

TPM_RC _plat__NvMemoryReadORDERLY_DATA(
				unsigned int     startOffset,   // IN: write start
				ORDERLY_DATA	 *data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return ORDERLY_DATA_Unmarshal(data, &buffer, &size);
}

UINT16 _plat__NvMemoryWriteTPML_PCR_SELECTION(
				unsigned int     	startOffset,   // IN: write start
				TPML_PCR_SELECTION	*data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    return TPML_PCR_SELECTION_Marshal(data, &buffer, &size);
}

TPM_RC _plat__NvMemoryReadTPML_PCR_SELECTION(
				unsigned int     	startOffset,   // IN: write start
				TPML_PCR_SELECTION	*data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    return TPML_PCR_SELECTION_Unmarshal(data, &buffer, &size);
}

UINT16
PCR_SAVE_Marshal(PCR_SAVE *data, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;

#ifdef TPM_ALG_SHA1
    written = Array_Marshal((BYTE *)&data->sha1, sizeof(data->sha1),
                            buffer, size);
#endif
#ifdef TPM_ALG_SHA256
    written += Array_Marshal((BYTE *)&data->sha256, sizeof(data->sha256),
                              buffer, size);
#endif
#ifdef TPM_ALG_SHA384
    written += Array_Marshal((BYTE *)&data->sha384, sizeof(data->sha384),
                             buffer, size);
#endif
#ifdef TPM_ALG_SHA512
    written += Array_Marshal((BYTE *)&data->sha512, sizeof(data->sha512),
                             buffer, size);
#endif
#ifdef TPM_ALG_SM3_256
    written += Array_Marshal((BYTE *)&data->sm3_256, sizeof(data->sm3_256),
                             buffer, size);
#endif

    return written;
}

UINT16 _plat__NvMemoryWritePCR_SAVE(
				unsigned int    startOffset,   // IN: write start
				PCR_SAVE	*data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return PCR_SAVE_Marshal(data, &buffer, &size);
}

TPM_RC
PCR_SAVE_Unmarshal(PCR_SAVE *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

#ifdef TPM_ALG_SHA1
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha1, sizeof(data->sha1),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SHA256
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha256, sizeof(data->sha256),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SHA384
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha384, sizeof(data->sha384),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SHA512
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha512, sizeof(data->sha512),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SM3_256
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sm3_256, sizeof(data->sm3_256),
                              buffer, size);
    }
#endif

    return rc;
}

TPM_RC _plat__NvMemoryReadPCR_SAVE(
				unsigned int    startOffset,   // IN: write start
				PCR_SAVE	*data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return PCR_SAVE_Unmarshal(data, &buffer, &size);
}

UINT16
STATE_CLEAR_DATA_Marshal(STATE_CLEAR_DATA *data, BYTE **buffer, INT32 *size)
{
    UINT16 written;

    written = UINT8_Marshal((UINT8 *)&data->shEnable, buffer, size);
    written += UINT8_Marshal((UINT8 *)&data->ehEnable, buffer, size);
    written += UINT8_Marshal((UINT8 *)&data->phEnableNV, buffer, size);
    written += UINT16_Marshal(&data->platformAlg, buffer, size);
    written += TPM2B_DIGEST_Marshal(&data->platformPolicy, buffer, size);
    written += TPM2B_AUTH_Marshal(&data->platformAuth, buffer, size);
    written += PCR_SAVE_Marshal(&data->pcrSave, buffer, size);

    return written;
}

UINT16 _plat__NvMemoryWriteSTATE_CLEAR_DATA(
				unsigned int     	startOffset,   // IN: write start
				STATE_CLEAR_DATA	*data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return STATE_CLEAR_DATA_Marshal(data, &buffer, &size);
}

TPM_RC
STATE_CLEAR_DATA_Unmarshal(STATE_CLEAR_DATA *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&data->shEnable, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&data->ehEnable, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&data->phEnableNV, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT16_Unmarshal(&data->platformAlg, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_DIGEST_Unmarshal(&data->platformPolicy, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_AUTH_Unmarshal(&data->platformAuth, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = PCR_SAVE_Unmarshal(&data->pcrSave, buffer, size);
    }

    return rc;
}

TPM_RC _plat__NvMemoryReadSTATE_CLEAR_DATA(
				unsigned int     	startOffset,   // IN: write start
				STATE_CLEAR_DATA	*data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return STATE_CLEAR_DATA_Unmarshal(data, &buffer, &size);
}

TPM_RC
STATE_RESET_DATA_Unmarshal(STATE_RESET_DATA *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_AUTH_Unmarshal(&data->nullProof, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_Unmarshal(&data->nullSeed.b, PRIMARY_SEED_SIZE, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal(&data->clearCount, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->objectContextID, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->contextArray, sizeof(data->contextArray),
                              buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->objectContextID, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->contextCounter, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_DIGEST_Unmarshal(&data->commandAuditDigest,
                              buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal(&data->restartCount, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal(&data->pcrCounter, buffer, size);
    }
#ifdef TPM_ALG_ECC
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->commitCounter, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_AUTH_Unmarshal(&data->commitNonce, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->commitArray,
                              sizeof(data->commitArray),
                              buffer, size);
    }
#endif

    return rc;
}

TPM_RC _plat__NvMemoryReadSTATE_RESET_DATA(
				unsigned int     	startOffset,   // IN: write start
				STATE_RESET_DATA	*data          // OUT: where to write to
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return STATE_RESET_DATA_Unmarshal(data, &buffer, &size);
}

UINT16
OBJECT_Marshal(OBJECT *data, BYTE **buffer, INT32* size)
{
    UINT16 written;
    UINT16 *ptr = (UINT16 *)&data->attributes;

    written = UINT16_Marshal(ptr, buffer, size);
    written += TPMT_PUBLIC_Marshal(&data->publicArea, buffer, size);
    written += TPMT_SENSITIVE_Marshal(&data->sensitive, buffer, size);
#ifdef TPM_ALG_RSA
    written += TPM2B_PUBLIC_KEY_RSA_Marshal(&data->privateExponent,
                                            buffer, size);
#endif
    written += TPM2B_NAME_Marshal(&data->qualifiedName, buffer, size);
    written += TPMI_DH_OBJECT_Marshal(&data->evictHandle, buffer, size);
    written += TPM2B_NAME_Marshal(&data->name, buffer, size);

    return written;
}

TPM_RC
OBJECT_Unmarshal(OBJECT *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 *ptr = (UINT16 *)&data->attributes;

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT16_Unmarshal(ptr, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPMT_PUBLIC_Unmarshal(&data->publicArea, buffer, size, TRUE);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPMT_SENSITIVE_Unmarshal(&data->sensitive, buffer, size);
    }
#ifdef TPM_ALG_RSA
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_PUBLIC_KEY_RSA_Unmarshal(&data->privateExponent,
                                           buffer, size);
    }
#endif
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_NAME_Unmarshal(&data->qualifiedName, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPMI_DH_OBJECT_Unmarshal(&data->evictHandle, buffer, size, TRUE);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_NAME_Unmarshal(&data->name, buffer, size);
    }

    return rc;
}

UINT16 _plat__NvMemoryWriteOBJECT(
				unsigned int   	startOffset,   // IN: write start
				OBJECT		*data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return OBJECT_Marshal(data, &buffer, &size);
}

TPM_RC _plat__NvMemoryReadOBJECT(
				unsigned int   	startOffset,   // IN: write start
				OBJECT		*data          // IN: data to write
				)
{
    BYTE *buffer = &s_NV[startOffset];
    INT32 size = NV_MEMORY_SIZE - startOffset;

    assert(startOffset + sizeof(*data) <= NV_MEMORY_SIZE);

    return OBJECT_Unmarshal(data, &buffer, &size);
}
