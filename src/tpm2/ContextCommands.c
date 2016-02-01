/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: ContextCommands.c 484 2015-12-31 02:34:18Z kgoldman $	*/
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

/* 28.2	TPM2_ContextSave */

#include "InternalRoutines.h"
#include "ContextSave_fp.h"
#ifdef TPM_CC_ContextSave  // Conditional expansion of this file
#include "Context_spt_fp.h"

#include "Session_fp.h"	/* kgold */

#include "Unmarshal_fp.h"


TPM_RC
TPM2_ContextSave(
		 ContextSave_In      *in,            // IN: input parameter list
		 ContextSave_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC          result;
    UINT16          fingerprintSize;    // The size of fingerprint in context
    // blob.
    UINT64          contextID = 0;      // session context ID
    TPM2B_SYM_KEY   symKey;
    TPM2B_IV        iv;
    TPM2B_DIGEST    integrity;
    UINT16          integritySize;
    BYTE            *buffer;

    // This command may cause the orderlyState to be cleared due to
    // the update of state reset data.  If this is the case, check if NV is
    // available first
    if(gp.orderlyState != SHUTDOWN_NONE)
	{
	    // The command needs NV update.  Check if NV is available.
	    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
	    // this point
	    result = NvIsAvailable();
	    if(result != TPM_RC_SUCCESS) return result;
	}

    // Internal Data Update

    // Initialize output handle.  At the end of command action, the output
    // handle of an object will be replaced, while the output handle
    // for a session will be the same as input
    out->context.savedHandle = in->saveHandle;

    // Get the size of fingerprint in context blob.  The sequence value in
    // TPMS_CONTEXT structure is used as the fingerprint
    fingerprintSize = sizeof(out->context.sequence);

    // Compute the integrity size at the beginning of context blob
    integritySize = sizeof(integrity.t.size)
		    + CryptGetHashDigestSize(CONTEXT_INTEGRITY_HASH_ALG);

    // Perform object or session specific context save
    switch(HandleGetType(in->saveHandle))
	{
	  case TPM_HT_TRANSIENT:
	      {
		  OBJECT          *object = ObjectGet(in->saveHandle);
		  ANY_OBJECT_BUFFER   *outObject;

		  outObject = (ANY_OBJECT_BUFFER *)(out->context.contextBlob.t.buffer
						    + integritySize + fingerprintSize);

		  // Set size of the context data.  The contents of context blob is vendor
		  // defined.  In this implementation, the size is size of integrity
		  // plus fingerprint plus the whole internal OBJECT structure
		  out->context.contextBlob.t.size = integritySize +
						    fingerprintSize + sizeof(ANY_OBJECT);
		  // Make sure things fit
		  pAssert(out->context.contextBlob.t.size
			  < sizeof(out->context.contextBlob.t.buffer));

		  // Copy the whole internal OBJECT structure to context blob
		  MemoryCopy(outObject, object,
			     sizeof(ANY_OBJECT_BUFFER),
			     sizeof(ANY_OBJECT_BUFFER));

		  // Increment object context ID
		  gr.objectContextID++;
		  // If object context ID overflows, TPM should be put in failure mode
		  if(gr.objectContextID == 0)
		      FAIL(FATAL_ERROR_INTERNAL);

		  // Fill in other return values for an object.
		  out->context.sequence = gr.objectContextID;
		  // For regular object, savedHandle is 0x80000000.  For sequence object,
		  // savedHandle is 0x80000001.  For object with stClear, savedHandle
		  // is 0x80000002
		  if(ObjectIsSequence(object))
		      {
			  out->context.savedHandle = 0x80000001;
			  SequenceDataImportExport((HASH_OBJECT *)object,
						   (HASH_OBJECT_BUFFER *)outObject,
						   EXPORT_STATE);
		      }
		  else if(object->attributes.stClear == SET)
		      {
			  out->context.savedHandle = 0x80000002;
		      }
		  else
		      {
			  out->context.savedHandle = 0x80000000;
		      }

		  // Get object hierarchy
		  out->context.hierarchy = ObjectDataGetHierarchy(object);

		  break;
	      }
	  case TPM_HT_HMAC_SESSION:
	  case TPM_HT_POLICY_SESSION:
	      {
		  SESSION         *session = SessionGet(in->saveHandle);

		  // Set size of the context data.  The contents of context blob is vendor
		  // defined.  In this implementation, the size of context blob is the
		  // size of a internal session structure plus the size of
		  // fingerprint plus the size of integrity
		  out->context.contextBlob.t.size = integritySize +
						    fingerprintSize + sizeof(*session);

		  // Make sure things fit
		  pAssert(out->context.contextBlob.t.size
			  < sizeof(out->context.contextBlob.t.buffer));

		  // Copy the whole internal SESSION structure to context blob.
		  // Save space for fingerprint at the beginning of the buffer
		  // This is done before anything else so that the actual context
		  // can be reclaimed after this call
		  MemoryCopy(out->context.contextBlob.t.buffer
			     + integritySize + fingerprintSize,
			     session, sizeof(*session),
			     sizeof(out->context.contextBlob.t.buffer)
			     - integritySize - fingerprintSize);
		  
		  // Fill in the other return parameters for a session
		  // Get a context ID and set the session tracking values appropriately
		  // TPM_RC_CONTEXT_GAP is a possible error.
		  // SessionContextSave() will flush the in-memory context
		  // so no additional errors may occur after this call.
		  result = SessionContextSave(out->context.savedHandle, &contextID);
		  if(result != TPM_RC_SUCCESS)
		      return result;

		  // sequence number is the current session contextID
		  out->context.sequence = contextID;

		  // use TPM_RH_NULL as hierarchy for session context
		  out->context.hierarchy = TPM_RH_NULL;

		  break;
	      }
	  default:
	    // SaveContext may only take an object handle or a session handle.
	    // All the other handle type should be filtered out at unmarshal
	    pAssert(FALSE);
	    break;
	}

    // Save fingerprint at the beginning of encrypted area of context blob.
    // Reserve the integrity space
    MemoryCopy(out->context.contextBlob.t.buffer + integritySize,
	       &out->context.sequence, sizeof(out->context.sequence),
	       sizeof(out->context.contextBlob.t.buffer) - integritySize);

    // Compute context encryption key
    ComputeContextProtectionKey(&out->context, &symKey, &iv);

    // Encrypt context blob
    CryptSymmetricEncrypt(out->context.contextBlob.t.buffer + integritySize,
			  CONTEXT_ENCRYPT_ALG, CONTEXT_ENCRYPT_KEY_BITS,
			  TPM_ALG_CFB, symKey.t.buffer, &iv,
			  out->context.contextBlob.t.size - integritySize,
			  out->context.contextBlob.t.buffer + integritySize);

    // Compute integrity hash for the object
    // In this implementation, the same routine is used for both sessions
    // and objects.
    ComputeContextIntegrity(&out->context, &integrity);

    // add integrity at the beginning of context blob
    buffer = out->context.contextBlob.t.buffer;
    TPM2B_DIGEST_Marshal(&integrity, &buffer, NULL);

    // orderly state should be cleared because of the update of state reset and
    // state clear data
    g_clearOrderly = TRUE;

    return TPM_RC_SUCCESS;
}
#endif // CC_ContextSave

/* 28.3	TPM2_ContextLoad */

#include "InternalRoutines.h"
#include "ContextLoad_fp.h"
#ifdef TPM_CC_ContextLoad  // Conditional expansion of this file
#include "Context_spt_fp.h"

TPM_RC
TPM2_ContextLoad(
		 ContextLoad_In      *in,            // IN: input parameter list
		 ContextLoad_Out     *out            // OUT: output parameter list
		 )
{
    // Local Variables
    TPM_RC              result = TPM_RC_SUCCESS;

    TPM2B_DIGEST        integrityToCompare;
    TPM2B_DIGEST        integrity;
    BYTE                *buffer;    // defined to save some typing
    UINT32              size;       // defined to save some typing

    TPM_HT              handleType;
    TPM2B_SYM_KEY       symKey;
    TPM2B_IV            iv;

    // Input Validation

    // IF this is a session context, make sure that the sequence number is
    // consistent with the version in the slot

    // Check context blob size
    handleType = HandleGetType(in->context.savedHandle);

    // Get integrity from context blob
    buffer = in->context.contextBlob.t.buffer;
    size = in->context.contextBlob.t.size;
    result = TPM2B_DIGEST_Unmarshal(&integrity, &buffer, (INT32 *)&size);
    if(result != TPM_RC_SUCCESS)
	return result;

    // the size of the integrity value has to match the size of digest produced
    // by the integrity hash
    if(integrity.t.size != CryptGetHashDigestSize(CONTEXT_INTEGRITY_HASH_ALG))
	return TPM_RCS_SIZE + RC_ContextLoad_context;

    // Make sure that the context blob has enough space for the fingerprint. This
    // is elastic pants to go with the belt and suspenders we already have to make
    // sure that the context is complete and untampered.
    if(size < (INT32)sizeof(in->context.sequence))
	return TPM_RCS_SIZE + RC_ContextLoad_context;

    // After unmarshaling the integrity value, 'buffer' is pointing at the first
    // byte of the integrity protected and encrypted buffer and 'size' is the number
    // of integrity protected and encrypted bytes.

    // Compute context integrity
    ComputeContextIntegrity(&in->context, &integrityToCompare);

    // Compare integrity
    if(!Memory2BEqual(&integrity.b, &integrityToCompare.b))
	return TPM_RCS_INTEGRITY + RC_ContextLoad_context;

    // Compute context encryption key
    ComputeContextProtectionKey(&in->context, &symKey, &iv);

    // Decrypt context data in place
    CryptSymmetricDecrypt(buffer,
			  CONTEXT_ENCRYPT_ALG, CONTEXT_ENCRYPT_KEY_BITS,
			  TPM_ALG_CFB, symKey.t.buffer, &iv,
			  size,
			  buffer);

    // See if the fingerprint value matches. If not, it is symptomatic of either
    // a broken TPM or that the TPM is under attack so go into failure mode.
    if(!MemoryEqual(buffer, &in->context.sequence, sizeof(in->context.sequence)))
	FAIL(FATAL_ERROR_INTERNAL);

    // step over fingerprint
    buffer += sizeof(in->context.sequence);

    // set the remaining size of the context
    size -= sizeof(in->context.sequence);

    // Perform object or session specific input check
    switch(handleType)
	{
	  case TPM_HT_TRANSIENT:
	      {
		  OBJECT      *outObject;

		  if(size != sizeof(OBJECT))
		      FAIL(FATAL_ERROR_INTERNAL);

		  // Discard any changes to the handle that the TRM might have made
		  in->context.savedHandle = TRANSIENT_FIRST;

		  // If hierarchy is disabled, no object context can be loaded in this
		  // hierarchy
		  if(!HierarchyIsEnabled(in->context.hierarchy))
		      return TPM_RCS_HIERARCHY + RC_ContextLoad_context;

		  // Restore object.  If there is no empty space, indicate as much
		  outObject = ObjectContextLoad((ANY_OBJECT_BUFFER *)buffer,
						&out->loadedHandle);
		  if(outObject == NULL)
		      return TPM_RC_OBJECT_MEMORY;

		  // If this is a sequence object, the crypto library may need to
		  // reformat the data into an internal format
		  if(ObjectIsSequence(outObject))
		      SequenceDataImportExport((HASH_OBJECT *)outObject,
					       (HASH_OBJECT_BUFFER *)buffer,
					       IMPORT_STATE);

		  break;
	      }
	  case TPM_HT_POLICY_SESSION:
	  case TPM_HT_HMAC_SESSION:
	      {
		  if(size != sizeof(SESSION))
		      FAIL(FATAL_ERROR_INTERNAL);

		  // This command may cause the orderlyState to be cleared due to
		  // the update of state reset data.  If this is the case, check if NV is
		  // available first
		  if(gp.orderlyState != SHUTDOWN_NONE)
		      {
			  // The command needs NV update.  Check if NV is available.
			  // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned
			  // at this point
			  result = NvIsAvailable();
			  if(result != TPM_RC_SUCCESS)
			      return result;
		      }

		  // Check if input handle points to a valid saved session and that the
		  // sequence number makes sense
		  if( !SequenceNumberForSavedContextIsValid(&in->context))
		      return TPM_RCS_HANDLE + RC_ContextLoad_context;

		  // Restore session.  A TPM_RC_SESSION_MEMORY, TPM_RC_CONTEXT_GAP error
		  // may be returned at this point
		  result = SessionContextLoad((TPM_SESSION_BUFFER *)buffer,
					      &in->context.savedHandle);
		  if(result != TPM_RC_SUCCESS)
		      return result;

		  out->loadedHandle = in->context.savedHandle;

		  // orderly state should be cleared because of the update of state
		  // reset and state clear data
		  g_clearOrderly = TRUE;

		  break;
	      }
	  default:
	    // Context blob may only have an object handle or a session handle.
	    // All the other handle type should be filtered out at unmarshal
	    pAssert(FALSE);
	    break;
	}

    return TPM_RC_SUCCESS;
}
#endif // CC_ContextLoad

/* 28.4	TPM2_FlushContext */

#include "InternalRoutines.h"
#include "FlushContext_fp.h"
#ifdef TPM_CC_FlushContext  // Conditional expansion of this file

TPM_RC
TPM2_FlushContext(
		  FlushContext_In     *in             // IN: input parameter list
		  )
{
    // Internal Data Update

    // Call object or session specific routine to flush
    switch(HandleGetType(in->flushHandle))
	{
	  case TPM_HT_TRANSIENT:
	    if(!ObjectIsPresent(in->flushHandle))
		return TPM_RCS_HANDLE + RC_FlushContext_flushHandle;
	    // Flush object
	    ObjectFlush(in->flushHandle);
	    break;
	  case TPM_HT_HMAC_SESSION:
	  case TPM_HT_POLICY_SESSION:
	    if(   !SessionIsLoaded(in->flushHandle)
		  && !SessionIsSaved(in->flushHandle)
		  )
		return TPM_RCS_HANDLE + RC_FlushContext_flushHandle;
	    
	    // If the session to be flushed is the exclusive audit session, then
	    // indicate that there is no exclusive audit session any longer.
	    if(in->flushHandle == g_exclusiveAuditSession)
		g_exclusiveAuditSession = TPM_RH_UNASSIGNED;

	    // Flush session
	    SessionFlush(in->flushHandle);
	    break;
	  default:
	    // This command only takes object or session handle.  Other handles
	    // should be filtered out at handle unmarshal
	    pAssert(FALSE);
	    break;
	}

    return TPM_RC_SUCCESS;
}
#endif // CC_FlushContext

/* 28.5	TPM2_EvictControl */

#include "InternalRoutines.h"
#include "EvictControl_fp.h"
#ifdef TPM_CC_EvictControl  // Conditional expansion of this file

TPM_RC
TPM2_EvictControl(
		  EvictControl_In     *in             // IN: input parameter list
		  )
{
    TPM_RC      result;
    OBJECT      *evictObject;

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

    // Input Validation

    // Get internal object pointer
    evictObject = ObjectGet(in->objectHandle);

    // Temporary, stClear or public only objects can not be made persistent
    if(   evictObject->attributes.temporary == SET
	  || evictObject->attributes.stClear == SET
	  || evictObject->attributes.publicOnly == SET
	  )
	return TPM_RCS_ATTRIBUTES + RC_EvictControl_objectHandle;

    // If objectHandle refers to a persistent object, it should be the same as
    // input persistentHandle
    if(   evictObject->attributes.evict == SET
	  && evictObject->evictHandle != in->persistentHandle
	  )
	return TPM_RCS_HANDLE + RC_EvictControl_objectHandle;

    // Additional auth validation
    if(in->auth ==  TPM_RH_PLATFORM)
	{
	    // To make persistent
	    if(evictObject->attributes.evict == CLEAR)
		{
		    // Platform auth can not set evict object in storage or endorsement
		    // hierarchy
		    if(evictObject->attributes.ppsHierarchy == CLEAR)
			return TPM_RCS_HIERARCHY + RC_EvictControl_objectHandle;
		    // Platform cannot use a handle outside of platform persistent range.
		    if(!NvIsPlatformPersistentHandle(in->persistentHandle))
			return TPM_RCS_RANGE + RC_EvictControl_persistentHandle;
		}
	    // Platform auth can delete any persistent object
	}
    else if(in->auth == TPM_RH_OWNER)
	{
	    // Owner auth can not set or clear evict object in platform hierarchy
	    if(evictObject->attributes.ppsHierarchy == SET)
		return TPM_RCS_HIERARCHY + RC_EvictControl_objectHandle;

	    // Owner cannot use a handle outside of owner persistent range.
	    if(   evictObject->attributes.evict == CLEAR
		  && !NvIsOwnerPersistentHandle(in->persistentHandle)
		  )
		return TPM_RCS_RANGE + RC_EvictControl_persistentHandle;
	}
    else
	{
	    // Other auth is not allowed in this command and should be filtered out
	    // at unmarshal process
	    pAssert(FALSE);
	}

    // Internal Data Update

    // Change evict state
    if(evictObject->attributes.evict == CLEAR)
	{
	    // Make object persistent
	    // A TPM_RC_NV_HANDLE or TPM_RC_NV_SPACE error may be returned at this
	    // point
	    result = NvAddEvictObject(in->persistentHandle, evictObject);
	    if(result != TPM_RC_SUCCESS) return result;
	}
    else
	{
	    // Delete the persistent object in NV
	    NvDeleteEntity(evictObject->evictHandle);
	}

    return TPM_RC_SUCCESS;

}
#endif // CC_EvictControl



























