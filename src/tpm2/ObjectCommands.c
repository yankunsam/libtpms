/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: ObjectCommands.c 458 2015-12-08 17:05:33Z kgoldman $		*/
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

/* rev 119 */

/* 12.1	TPM2_Create */


#include "InternalRoutines.h"
#include "Object_spt_fp.h"
#include "Create_fp.h"
#ifdef TPM_CC_Create  // Conditional expansion of this file

TPM_RC
TPM2_Create(
	    Create_In       *in,            // IN: input parameter list
	    Create_Out      *out            // OUT: output parameter list
	    )
{
    TPM_RC                  result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE          sensitive;
    TPM2B_NAME              name;

    // Input Validation

    OBJECT      *parentObject;

    parentObject = ObjectGet(in->parentHandle);

    // Does parent have the proper attributes?
    if(!AreAttributesForParent(parentObject))
	return TPM_RCS_TYPE + RC_Create_parentHandle;
    // The sensitiveDataOrigin attribute must be consistent with the setting of
    // the size of the data object in inSensitive.
    if(   (in->inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin == SET)
	  != (in->inSensitive.t.sensitive.data.t.size == 0))
	// Mismatch between the object attributes and the parameter.
	return TPM_RCS_ATTRIBUTES + RC_Create_inSensitive;
    // Check attributes in input public area. TPM_RC_ASYMMETRIC, TPM_RC_ATTRIBUTES,
    // TPM_RC_HASH, TPM_RC_KDF, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_SYMMETRIC,
    // or TPM_RC_TYPE error may be returned at this point.
    result = PublicAttributesValidation(FALSE, in->parentHandle,
				&in->inPublic.t.publicArea);
    if(result != TPM_RC_SUCCESS)
	return RcSafeAddToResult(result, RC_Create_inPublic);
    // Validate the sensitive area values
    if(  MemoryRemoveTrailingZeros(&in->inSensitive.t.sensitive.userAuth)
	 > CryptGetHashDigestSize(in->inPublic.t.publicArea.nameAlg))
	return TPM_RCS_SIZE + RC_Create_inSensitive;
    // Command Output
    // Create object crypto data
    result = CryptCreateObject(in->parentHandle, &in->inPublic.t.publicArea,
			       &in->inSensitive.t.sensitive, &sensitive);
    if(result != TPM_RC_SUCCESS)
	return result;
    // Fill in creation data
    FillInCreationData(in->parentHandle, in->inPublic.t.publicArea.nameAlg,
		       &in->creationPCR, &in->outsideInfo,
		       &out->creationData, &out->creationHash);
    // Copy public area from input to output
    out->outPublic.t.publicArea = in->inPublic.t.publicArea;
    // Compute name from public area
    ObjectComputeName(&(out->outPublic.t.publicArea), &name);
    // Compute creation ticket
    TicketComputeCreation(EntityGetHierarchy(in->parentHandle), &name,
			  &out->creationHash, &out->creationTicket);
    // Prepare output private data from sensitive
    SensitiveToPrivate(&sensitive, &name, in->parentHandle,
		       out->outPublic.t.publicArea.nameAlg,
		       &out->outPrivate);
    return TPM_RC_SUCCESS;
}
#endif // CC_Create

/* 12.2	TPM2_Load */

#include "InternalRoutines.h"
#include "Load_fp.h"
#ifdef TPM_CC_Load  // Conditional expansion of this file
#include "Object_spt_fp.h"

TPM_RC
TPM2_Load(
	  Load_In         *in,            // IN: input parameter list
	  Load_Out        *out            // OUT: output parameter list
	  )
{
    TPM_RC                   result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE           sensitive;
    TPMI_RH_HIERARCHY        hierarchy;
    OBJECT                  *parentObject = NULL;
    BOOL                     skipChecks = FALSE;

    // Input Validation
    if(in->inPrivate.t.size == 0)
	return TPM_RCS_SIZE + RC_Load_inPrivate;

    parentObject = ObjectGet(in->parentHandle);
    // Is the object that is being used as the parent actually a parent.
    if(!AreAttributesForParent(parentObject))
	return TPM_RCS_TYPE + RC_Load_parentHandle;

    // If the parent is fixedTPM, then the attributes of the object
    // are either "correct by construction" or were validated
    // when the object was imported.  If they pass the integrity
    // check, then the values are valid
    if(parentObject->publicArea.objectAttributes.fixedTPM)
	skipChecks = TRUE;
    else
	{
	    // If parent doesn't have fixedTPM SET, then this can't have
	    // fixedTPM SET.
	    if(in->inPublic.t.publicArea.objectAttributes.fixedTPM == SET)
		return TPM_RCS_ATTRIBUTES + RC_Load_inPublic;
	    // Perform self check on input public area.  A TPM_RC_SIZE, TPM_RC_SCHEME,
	    // TPM_RC_VALUE, TPM_RC_SYMMETRIC, TPM_RC_TYPE, TPM_RC_HASH,
	    // TPM_RC_ASYMMETRIC, TPM_RC_ATTRIBUTES or TPM_RC_KDF error may be returned
	    // at this point
	    result = PublicAttributesValidation(TRUE, in->parentHandle,
						&in->inPublic.t.publicArea);
	    if(result != TPM_RC_SUCCESS)
		return RcSafeAddToResult(result, RC_Load_inPublic);
	}

    // Compute the name of object
    ObjectComputeName(&in->inPublic.t.publicArea, &out->name);

    // Retrieve sensitive data.  PrivateToSensitive() may return TPM_RC_INTEGRITY or
    // TPM_RC_SENSITIVE
    // errors may be returned at this point
    result = PrivateToSensitive(&in->inPrivate, &out->name, in->parentHandle,
				in->inPublic.t.publicArea.nameAlg,
				&sensitive);
    if(result != TPM_RC_SUCCESS)
	return RcSafeAddToResult(result, RC_Load_inPrivate);

    // Internal Data Update
    
    // Get hierarchy of parent
    hierarchy = ObjectGetHierarchy(in->parentHandle);

    // Create internal object.  A lot of different errors may be returned by this
    // loading operation as it will do several validations, including the public
    // binding check
    result = ObjectLoad(hierarchy, &in->inPublic.t.publicArea, &sensitive,
			&out->name, in->parentHandle, skipChecks,
			&out->objectHandle);

    if(result != TPM_RC_SUCCESS)
	return result;

    return TPM_RC_SUCCESS;
}
#endif // CC_Load

/* 12.3	TPM2_LoadExternal */

#include "InternalRoutines.h"
#include "LoadExternal_fp.h"
#ifdef TPM_CC_LoadExternal  // Conditional expansion of this file
#include "Object_spt_fp.h"

TPM_RC
TPM2_LoadExternal(
		  LoadExternal_In     *in,            // IN: input parameter list
		  LoadExternal_Out    *out            // OUT: output parameter list
		  )
{
    TPM_RC               result;
    TPMT_SENSITIVE      *sensitive;
    BOOL                 skipChecks;

    // Input Validation

    // If the target hierarchy is turned off, the object can not be loaded.
    if(!HierarchyIsEnabled(in->hierarchy))
	return TPM_RCS_HIERARCHY + RC_LoadExternal_hierarchy;

    // the size of authPolicy is either 0 or the digest size of nameAlg
    if(in->inPublic.t.publicArea.authPolicy.t.size != 0
       && in->inPublic.t.publicArea.authPolicy.t.size !=
       CryptGetHashDigestSize(in->inPublic.t.publicArea.nameAlg))
	return TPM_RCS_SIZE + RC_LoadExternal_inPublic;

    // For loading an object with both public and sensitive
    if(in->inPrivate.t.size != 0)
	{
	    // An external object can only be loaded at TPM_RH_NULL hierarchy
	    if(in->hierarchy != TPM_RH_NULL)
		return TPM_RCS_HIERARCHY + RC_LoadExternal_hierarchy;
	    // An external object with a sensitive area must have fixedTPM == CLEAR
	    // fixedParent == CLEAR, and must have restrict CLEAR so that it does not
	    // appear to be a key that was created by this TPM.
	    if(   in->inPublic.t.publicArea.objectAttributes.fixedTPM != CLEAR
		  || in->inPublic.t.publicArea.objectAttributes.fixedParent != CLEAR
		  || in->inPublic.t.publicArea.objectAttributes.restricted != CLEAR
		  )
		return TPM_RCS_ATTRIBUTES + RC_LoadExternal_inPublic;
	}

    // Validate the scheme parameters
    result = SchemeChecks(TRUE, TPM_RH_NULL, &in->inPublic.t.publicArea);
    if(result != TPM_RC_SUCCESS)
	return RcSafeAddToResult(result, RC_LoadExternal_inPublic);

    // Internal Data Update
    // Need the name to compute the qualified name
    ObjectComputeName(&in->inPublic.t.publicArea, &out->name);
    skipChecks = (in->inPublic.t.publicArea.nameAlg == TPM_ALG_NULL);

    // If a sensitive area was provided, load it
    if(in->inPrivate.t.size != 0)
	sensitive = &in->inPrivate.t.sensitiveArea;
    else
	sensitive = NULL;

    // Create external object.  A TPM_RC_BINDING, TPM_RC_KEY, TPM_RC_OBJECT_MEMORY
    // or TPM_RC_TYPE error may be returned by ObjectLoad()
    result = ObjectLoad(in->hierarchy, &in->inPublic.t.publicArea,
			sensitive, &out->name, TPM_RH_NULL, skipChecks,
			&out->objectHandle);
    return result;
}
#endif // CC_LoadExternal

/* 12.4	TPM2_ReadPublic */

#include "InternalRoutines.h"
#include "ReadPublic_fp.h"
#ifdef TPM_CC_ReadPublic  // Conditional expansion of this file

TPM_RC
TPM2_ReadPublic(
		ReadPublic_In   *in,            // IN: input parameter list
		ReadPublic_Out  *out            // OUT: output parameter list
		)
{
    OBJECT                  *object;

    // Input Validation

    // Get loaded object pointer
    object = ObjectGet(in->objectHandle);

    // Can not read public area of a sequence object
    if(ObjectIsSequence(object))
	return TPM_RC_SEQUENCE;

    // Command Output

    // Compute size of public area in canonical form
    out->outPublic.t.size = TPMT_PUBLIC_Marshal(&object->publicArea, NULL, NULL);

    // Copy public area to output
    out->outPublic.t.publicArea = object->publicArea;

    // Copy name to output
    out->name.t.size = ObjectGetName(in->objectHandle, &out->name.t.name);

    // Copy qualified name to output
    ObjectGetQualifiedName(in->objectHandle, &out->qualifiedName);

    return TPM_RC_SUCCESS;
}
#endif // CC_ReadPublic

/* 12.5	TPM2_ActivateCredential */

#include "InternalRoutines.h"
#include "ActivateCredential_fp.h"
#ifdef TPM_CC_ActivateCredential  // Conditional expansion of this file
#include "Object_spt_fp.h"

TPM_RC
TPM2_ActivateCredential(
			ActivateCredential_In   *in,            // IN: input parameter list
			ActivateCredential_Out  *out            // OUT: output parameter list
			)
{
    TPM_RC                       result = TPM_RC_SUCCESS;
    OBJECT                      *object;        // decrypt key
    OBJECT                      *activateObject;// key associated with
    // credential
    TPM2B_DATA                   data;          // credential data
	
    // Input Validation

    // Get decrypt key pointer
    object = ObjectGet(in->keyHandle);

    // Get certificated object pointer
    activateObject = ObjectGet(in->activateHandle);

    // input decrypt key must be an asymmetric, restricted decryption key
    if(   !CryptIsAsymAlgorithm(object->publicArea.type)
	  || object->publicArea.objectAttributes.decrypt == CLEAR
	  || object->publicArea.objectAttributes.restricted == CLEAR)
	return TPM_RCS_TYPE + RC_ActivateCredential_keyHandle;

    // Command output

    // Decrypt input credential data via asymmetric decryption.  A
    // TPM_RC_VALUE, TPM_RC_KEY or unmarshal errors may be returned at this
    // point
    result = CryptSecretDecrypt(in->keyHandle, NULL,
				"IDENTITY", &in->secret, &data);
    if(result != TPM_RC_SUCCESS)
	{
	    if(result == TPM_RC_KEY)
		return TPM_RC_FAILURE;
	    return RcSafeAddToResult(result, RC_ActivateCredential_secret);
	}

    // Retrieve secret data.  A TPM_RC_INTEGRITY error or unmarshal
    // errors may be returned at this point
    result = CredentialToSecret(&in->credentialBlob,
				&activateObject->name,
				(TPM2B_SEED *) &data,
				in->keyHandle,
				&out->certInfo);
    if(result != TPM_RC_SUCCESS)
	return RcSafeAddToResult(result,RC_ActivateCredential_credentialBlob);
    return TPM_RC_SUCCESS;
}
#endif // CC_ActivateCredential

/* 12.6	TPM2_MakeCredential */

#include "InternalRoutines.h"
#include "MakeCredential_fp.h"
#ifdef TPM_CC_MakeCredential  // Conditional expansion of this file
#include "Object_spt_fp.h"

TPM_RC
TPM2_MakeCredential(
		    MakeCredential_In   *in,            // IN: input parameter list
		    MakeCredential_Out  *out            // OUT: output parameter list
		    )
{
    TPM_RC                  result = TPM_RC_SUCCESS;

    OBJECT                  *object;
    TPM2B_DATA              data;

    // Input Validation

    // Get object pointer
    object = ObjectGet(in->handle);

    // input key must be an asymmetric, restricted decryption key
    // NOTE: Needs to be restricted to have a symmetric value.
    if(   !CryptIsAsymAlgorithm(object->publicArea.type)
	  || object->publicArea.objectAttributes.decrypt == CLEAR
	  || object->publicArea.objectAttributes.restricted == CLEAR
	  )
	return TPM_RCS_TYPE + RC_MakeCredential_handle;

    // The credential information may not be larger than the digest size used for
    // the Name of the key associated with handle.
    if(in->credential.t.size > CryptGetHashDigestSize(object->publicArea.nameAlg))
	return TPM_RCS_SIZE + RC_MakeCredential_credential;

    // Command Output

    // Make encrypt key and its associated secret structure.
    // Even though CrypeSecretEncrypt() may return
    out->secret.t.size = sizeof(out->secret.t.secret);
    result = CryptSecretEncrypt(in->handle, "IDENTITY", &data, &out->secret);
    if(result != TPM_RC_SUCCESS)
	return result;

    // Prepare output credential data from secret
    SecretToCredential(&in->credential, &in->objectName, (TPM2B_SEED *) &data,
		       in->handle, &out->credentialBlob);

    return TPM_RC_SUCCESS;
}
#endif // CC_MakeCredential

/* 12.7	TPM2_Unseal */

#include "InternalRoutines.h"
#include "Unseal_fp.h"
#ifdef TPM_CC_Unseal  // Conditional expansion of this file
TPM_RC
TPM2_Unseal(
	    Unseal_In       *in,
	    Unseal_Out      *out
	    )
{
    OBJECT                  *object;

    // Input Validation

    // Get pointer to loaded object
    object = ObjectGet(in->itemHandle);

    // Input handle must be a data object
    if(object->publicArea.type != TPM_ALG_KEYEDHASH)
	return TPM_RCS_TYPE + RC_Unseal_itemHandle;
    if(   object->publicArea.objectAttributes.decrypt == SET
	  || object->publicArea.objectAttributes.sign == SET
	  || object->publicArea.objectAttributes.restricted == SET)
	return TPM_RCS_ATTRIBUTES + RC_Unseal_itemHandle;

    // Command Output

    // Copy data
    MemoryCopy2B(&out->outData.b, &object->sensitive.sensitive.bits.b,
		 sizeof(out->outData.t.buffer));

    return TPM_RC_SUCCESS;
}
#endif // CC_Unseal

/* 12.8	TPM2_ObjectChangeAuth */

#include "InternalRoutines.h"
#include "ObjectChangeAuth_fp.h"
#ifdef TPM_CC_ObjectChangeAuth  // Conditional expansion of this file
#include "Object_spt_fp.h"

TPM_RC
TPM2_ObjectChangeAuth(
		      ObjectChangeAuth_In     *in,            // IN: input parameter list
		      ObjectChangeAuth_Out    *out            // OUT: output parameter list
		      )
{
    TPMT_SENSITIVE           sensitive;
	
    OBJECT                  *object;
    TPM2B_NAME               objectQN, QNCompare;
    TPM2B_NAME               parentQN;

    // Input Validation
    
    // Get object pointer
    object = ObjectGet(in->objectHandle);

    // Can not change auth on sequence object
    if(ObjectIsSequence(object))
	return TPM_RCS_TYPE + RC_ObjectChangeAuth_objectHandle;

    // Make sure that the auth value is consistent with the nameAlg
    if(  MemoryRemoveTrailingZeros(&in->newAuth)
	 > CryptGetHashDigestSize(object->publicArea.nameAlg))
	return TPM_RCS_SIZE + RC_ObjectChangeAuth_newAuth;

    // Check parent for object
    // parent handle must be the parent of object handle.  In this
    // implementation we verify this by checking the QN of object.  Other
    // implementation may choose different method to verify this attribute.
    ObjectGetQualifiedName(in->parentHandle, &parentQN);
    ObjectComputeQualifiedName(&parentQN, object->publicArea.nameAlg,
			       &object->name, &QNCompare);

    ObjectGetQualifiedName(in->objectHandle, &objectQN);
    if(!Memory2BEqual(&objectQN.b, &QNCompare.b))
	return TPM_RCS_TYPE + RC_ObjectChangeAuth_parentHandle;

    // Command Output

    // Copy internal sensitive area
    sensitive = object->sensitive;
    // Copy authValue
    sensitive.authValue = in->newAuth;

    // Prepare output private data from sensitive
    SensitiveToPrivate(&sensitive, &object->name, in->parentHandle,
		       object->publicArea.nameAlg,
		       &out->outPrivate);

    return TPM_RC_SUCCESS;
}
#endif // CC_ObjectChangeAuth
