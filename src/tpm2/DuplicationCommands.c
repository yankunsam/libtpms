/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: DuplicationCommands.c 471 2015-12-22 19:40:24Z kgoldman $	*/
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

/* rev 124 */

/* 13.1	TPM2_Duplicate */

#include "InternalRoutines.h"
#include "Duplicate_fp.h"
#ifdef TPM_CC_Duplicate  // Conditional expansion of this file
#include "Object_spt_fp.h"

TPM_RC
TPM2_Duplicate(
	       Duplicate_In    *in,            // IN: input parameter list
	       Duplicate_Out   *out            // OUT: output parameter list
	       )
{
    TPM_RC                  result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE          sensitive;

    UINT16                  innerKeySize = 0; // encrypt key size for inner wrap

    OBJECT                  *object;
    TPM2B_DATA              data;

    // Input Validation

    // Get duplicate object pointer
    object = ObjectGet(in->objectHandle);

    // duplicate key must have fixParent bit CLEAR.
    if(object->publicArea.objectAttributes.fixedParent == SET)
	return TPM_RCS_ATTRIBUTES + RC_Duplicate_objectHandle;

    // Do not duplicate object with NULL nameAlg
    if(object->publicArea.nameAlg == TPM_ALG_NULL)
	return TPM_RCS_TYPE + RC_Duplicate_objectHandle;

    // new parent key must be a storage object or TPM_RH_NULL
    if(in->newParentHandle != TPM_RH_NULL
       && !ObjectIsStorage(in->newParentHandle))
	return TPM_RCS_TYPE + RC_Duplicate_newParentHandle;

    // If the duplicated object has encryptedDuplication SET, then there must be
    // an inner wrapper and the new parent may not be TPM_RH_NULL
    if(object->publicArea.objectAttributes.encryptedDuplication == SET)
	{
	    if(in->symmetricAlg.algorithm == TPM_ALG_NULL)
		return TPM_RCS_SYMMETRIC + RC_Duplicate_symmetricAlg;
	    if(in->newParentHandle == TPM_RH_NULL)
		return TPM_RCS_HIERARCHY + RC_Duplicate_newParentHandle;
	}
    if(in->symmetricAlg.algorithm == TPM_ALG_NULL)
	{
	    // if algorithm is TPM_ALG_NULL, input key size must be 0
	    if(in->encryptionKeyIn.t.size != 0)
		return TPM_RCS_SIZE + RC_Duplicate_encryptionKeyIn;
	}
    else
	{
	    // Get inner wrap key size
	    innerKeySize = in->symmetricAlg.keyBits.sym;
	    // If provided the input symmetric key must match the size of the algorithm
	    if(in->encryptionKeyIn.t.size != 0
	       && in->encryptionKeyIn.t.size != (innerKeySize + 7) / 8)
		return TPM_RCS_SIZE + RC_Duplicate_encryptionKeyIn;
	}

    // Command Output

    if(in->newParentHandle != TPM_RH_NULL)
	{

	    // Make encrypt key and its associated secret structure.  A TPM_RC_KEY
	    // error may be returned at this point
	    out->outSymSeed.t.size = sizeof(out->outSymSeed.t.secret);
	    result = CryptSecretEncrypt(in->newParentHandle,
					"DUPLICATE", &data, &out->outSymSeed);
	    pAssert(result != TPM_RC_VALUE);
	    if(result != TPM_RC_SUCCESS)
		return result;
	}
    else
	{
	    // Do not apply outer wrapper
	    data.t.size = 0;
	    out->outSymSeed.t.size = 0;
	}

    // Copy sensitive area
    sensitive = object->sensitive;

    // Prepare output private data from sensitive
    SensitiveToDuplicate(&sensitive, &object->name, in->newParentHandle,
			 object->publicArea.nameAlg, (TPM2B_SEED *) &data,
			 &in->symmetricAlg, &in->encryptionKeyIn,
			 &out->duplicate);

    out->encryptionKeyOut = in->encryptionKeyIn;

    return TPM_RC_SUCCESS;
}
#endif // CC_Duplicate

/* 13.2	TPM2_Rewrap */

#include "InternalRoutines.h"
#include "Rewrap_fp.h"
#ifdef TPM_CC_Rewrap  // Conditional expansion of this file
#include "Object_spt_fp.h"

TPM_RC
TPM2_Rewrap(
	    Rewrap_In       *in,            // IN: input parameter list
	    Rewrap_Out      *out            // OUT: output parameter list
	    )
{
    TPM_RC                  result = TPM_RC_SUCCESS;
    OBJECT                  *oldParent;
    TPM2B_DATA              data;               // symmetric key
    UINT16                  hashSize = 0;
    TPM2B_PRIVATE           privateBlob;        // A temporary private blob
    // to transit between old
    // and new wrappers

    // Input Validation
    
    if((in->inSymSeed.t.size == 0 && in->oldParent != TPM_RH_NULL)
       || (in->inSymSeed.t.size != 0 && in->oldParent == TPM_RH_NULL))
	return TPM_RCS_HANDLE + RC_Rewrap_oldParent;

    if(in->oldParent != TPM_RH_NULL)
	{
	    // Get old parent pointer
	    oldParent = ObjectGet(in->oldParent);

	    // old parent key must be a storage object
	    if(!ObjectIsStorage(in->oldParent))
		return TPM_RCS_TYPE + RC_Rewrap_oldParent;

	    // Decrypt input secret data via asymmetric decryption.  A
	    // TPM_RC_VALUE, TPM_RC_KEY or unmarshal errors may be returned at this
	    // point
	    result = CryptSecretDecrypt(in->oldParent, NULL,
					"DUPLICATE", &in->inSymSeed, &data);
	    if(result != TPM_RC_SUCCESS)
		return TPM_RCS_VALUE + RC_Rewrap_inSymSeed;

	    // Unwrap Outer
	    result = UnwrapOuter(in->oldParent, &in->name,
				 oldParent->publicArea.nameAlg, (TPM2B_SEED *) &data,
				 FALSE,
				 in->inDuplicate.t.size, in->inDuplicate.t.buffer);
	    if(result != TPM_RC_SUCCESS)
		return RcSafeAddToResult(result, RC_Rewrap_inDuplicate);

	    // Copy unwrapped data to temporary variable, remove the integrity field
	    hashSize = sizeof(UINT16) +
		       CryptGetHashDigestSize(oldParent->publicArea.nameAlg);
	    privateBlob.t.size = in->inDuplicate.t.size - hashSize;
	    MemoryCopy(privateBlob.t.buffer, in->inDuplicate.t.buffer + hashSize,
		       privateBlob.t.size, sizeof(privateBlob.t.buffer));
	}
    else
	{
	    // No outer wrap from input blob.  Direct copy.
	    privateBlob = in->inDuplicate;
	}

    if(in->newParent != TPM_RH_NULL)
	{
	    OBJECT          *newParent;
	    newParent = ObjectGet(in->newParent);

	    // New parent must be a storage object
	    if(!ObjectIsStorage(in->newParent))
		return TPM_RCS_TYPE + RC_Rewrap_newParent;

	    // Make new encrypt key and its associated secret structure.  A
	    // TPM_RC_VALUE error may be returned at this point if RSA algorithm is
	    // enabled in TPM
	    out->outSymSeed.t.size = sizeof(out->outSymSeed.t.secret);
	    result = CryptSecretEncrypt(in->newParent,
					"DUPLICATE", &data, &out->outSymSeed);
	    if(result != TPM_RC_SUCCESS)
		return result;

	    // Copy temporary variable to output, reserve the space for integrity
	    hashSize = sizeof(UINT16) +
		       CryptGetHashDigestSize(newParent->publicArea.nameAlg);
	    // Make sure that everything fits into the output buffer
	    // Note: this is mostly only an issue if there was no outer wrapper on
	    // 'inDuplicate'. It could be as large as a TPM2B_PRIVATE buffer. If we add
	    // a digest for an outer wrapper, it won't fit anymore.
	    if((privateBlob.t.size + hashSize) > sizeof(out->outDuplicate.t.buffer))
		return TPM_RCS_VALUE + RC_Rewrap_inDuplicate;

	    // Command output

	    out->outDuplicate.t.size = privateBlob.t.size;
	    MemoryCopy(out->outDuplicate.t.buffer + hashSize,
		       privateBlob.t.buffer,
		       privateBlob.t.size,
		       sizeof(out->outDuplicate.t.buffer) - hashSize);

	    // Produce outer wrapper for output
	    out->outDuplicate.t.size = ProduceOuterWrap(in->newParent, &in->name,
							newParent->publicArea.nameAlg,
							(TPM2B_SEED *) &data,
							FALSE,
							out->outDuplicate.t.size,
							out->outDuplicate.t.buffer);

	}
    else  // New parent is a null key so there is no seed
	{
	    out->outSymSeed.t.size = 0;

	    // Copy privateBlob directly
	    out->outDuplicate = privateBlob;
	}

    return TPM_RC_SUCCESS;
}
#endif // CC_Rewrap

/* 13.3	TPM2_Import1 */

#include "InternalRoutines.h"
#include "Import_fp.h"
#ifdef TPM_CC_Import  // Conditional expansion of this file
#include "Object_spt_fp.h"

TPM_RC
TPM2_Import(
	    Import_In       *in,            // IN: input parameter list
	    Import_Out      *out            // OUT: output parameter list
	    )
{

    TPM_RC                  result = TPM_RC_SUCCESS;
    OBJECT                  *parentObject;
    TPM2B_DATA              data;                   // symmetric key
    TPMT_SENSITIVE          sensitive;
    TPM2B_NAME              name;

    UINT16                  innerKeySize = 0;       // encrypt key size for inner
    // wrapper

    // Input Validation

    // FixedTPM and fixedParent must be CLEAR
    if(   in->objectPublic.t.publicArea.objectAttributes.fixedTPM == SET
	  || in->objectPublic.t.publicArea.objectAttributes.fixedParent == SET)
	return TPM_RCS_ATTRIBUTES + RC_Import_objectPublic;

    // Get parent pointer
    parentObject = ObjectGet(in->parentHandle);

    if(!AreAttributesForParent(parentObject))
	return TPM_RCS_TYPE + RC_Import_parentHandle;

    if(in->symmetricAlg.algorithm != TPM_ALG_NULL)
	{
	    // Get inner wrap key size
	    innerKeySize = in->symmetricAlg.keyBits.sym;
	    // Input symmetric key must match the size of algorithm.
	    if(in->encryptionKey.t.size != (innerKeySize + 7) / 8)
		return TPM_RCS_SIZE + RC_Import_encryptionKey;
	}
    else
	{
	    // If input symmetric algorithm is NULL, input symmetric key size must
	    // be 0 as well
	    if(in->encryptionKey.t.size != 0)
		return TPM_RCS_SIZE + RC_Import_encryptionKey;
	    // If encryptedDuplication is SET, then the object must have an inner
	    // wrapper
	    if(in->objectPublic.t.publicArea.objectAttributes.encryptedDuplication)
		return TPM_RCS_ATTRIBUTES + RC_Import_encryptionKey;
	}

    // See if there is an outer wrapper
    if(in->inSymSeed.t.size != 0)
	{
	    // Decrypt input secret data via asymmetric decryption. TPM_RC_ATTRIBUTES,
	    // TPM_RC_ECC_POINT, TPM_RC_INSUFFICIENT, TPM_RC_KEY, TPM_RC_NO_RESULT,
	    // TPM_RC_SIZE, TPM_RC_VALUE may be returned at this point
	    result = CryptSecretDecrypt(in->parentHandle, NULL, "DUPLICATE",
					&in->inSymSeed, &data);
	    pAssert(result != TPM_RC_BINDING);
	    if(result != TPM_RC_SUCCESS)
		return RcSafeAddToResult(result, RC_Import_inSymSeed);
	}
    else
	{
	    // If encrytpedDuplication is set, then the object must have an outer
	    // wrapper
	    if(in->objectPublic.t.publicArea.objectAttributes.encryptedDuplication)
		return TPM_RCS_ATTRIBUTES + RC_Import_inSymSeed;
	    data.t.size = 0;
	}

    // Compute name of object
    ObjectComputeName(&(in->objectPublic.t.publicArea), &name);

    // Retrieve sensitive from private.
    // TPM_RC_INSUFFICIENT, TPM_RC_INTEGRITY, TPM_RC_SIZE may be returned here.
    result = DuplicateToSensitive(&in->duplicate, &name, in->parentHandle,
				  in->objectPublic.t.publicArea.nameAlg,
				  (TPM2B_SEED *) &data, &in->symmetricAlg,
				  &in->encryptionKey, &sensitive);
    if(result != TPM_RC_SUCCESS)
	return RcSafeAddToResult(result, RC_Import_duplicate);

    // If the parent of this object has fixedTPM SET, then fully validate this
    // object so that validation can be skipped when it is loaded
    if(parentObject->publicArea.objectAttributes.fixedTPM == SET)
	{
	    TPM_HANDLE       objectHandle;

	    // Perform self check on input public area.  A TPM_RC_SIZE, TPM_RC_SCHEME,
	    // TPM_RC_VALUE, TPM_RC_SYMMETRIC, TPM_RC_TYPE, TPM_RC_HASH,
	    // TPM_RC_ASYMMETRIC, TPM_RC_ATTRIBUTES or TPM_RC_KDF error may be returned
	    // at this point
	    result = PublicAttributesValidation(TRUE, in->parentHandle,
						&in->objectPublic.t.publicArea);
	    if(result != TPM_RC_SUCCESS)
		return RcSafeAddToResult(result, RC_Import_objectPublic);

	    // Create internal object.  A TPM_RC_KEY_SIZE, TPM_RC_KEY or
	    // TPM_RC_OBJECT_MEMORY  error may be returned at this point
	    result = ObjectLoad(TPM_RH_NULL, &in->objectPublic.t.publicArea,
				&sensitive, NULL, in->parentHandle, FALSE,
				&objectHandle);
	    if(result != TPM_RC_SUCCESS)
		return result;

	    // Don't need the object, just needed the checks to be performed so
	    // flush the object
	    ObjectFlush(objectHandle);
	}

    // Command output

    // Prepare output private data from sensitive
    SensitiveToPrivate(&sensitive, &name, in->parentHandle,
		       in->objectPublic.t.publicArea.nameAlg,
		       &out->outPrivate);

    return TPM_RC_SUCCESS;
}
#endif // CC_Import
