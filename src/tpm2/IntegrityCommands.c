/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: IntegrityCommands.c 195 2015-03-31 15:39:41Z kgoldman $	*/
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

/* 22.2	TPM2_PCR_Extend */

#include "InternalRoutines.h"
#include "PCR_Extend_fp.h"
#ifdef TPM_CC_PCR_Extend  // Conditional expansion of this file

TPM_RC
TPM2_PCR_Extend(
		PCR_Extend_In   *in             // IN: input parameter list
		)
{
    TPM_RC              result;
    UINT32              i;

    // Input Validation

    // NOTE: This function assumes that the unmarshaling function for 'digests' will
    // have validated that all of the indicated hash algorithms are valid. If the
    // hash algorithms are correct, the unmarshaling code will unmarshal a digest
    // of the size indicated by the hash algorithm. If the overall size is not
    // consistent, the unmarshaling code will run out of input data or have input
    // data left over. In either case, it will cause an unmarshaling error and this
    // function will not be called.

    // For NULL handle, do nothing and return success
    if(in->pcrHandle == TPM_RH_NULL)
	return TPM_RC_SUCCESS;

    // Check if the extend operation is allowed by the current command locality
    if(!PCRIsExtendAllowed(in->pcrHandle))
	return TPM_RC_LOCALITY;

    // If PCR is state saved and we need to update orderlyState, check NV
    // availability
    if(PCRIsStateSaved(in->pcrHandle) && gp.orderlyState != SHUTDOWN_NONE)
	{
	    result = NvIsAvailable();
	    if(result != TPM_RC_SUCCESS) return result;
	    g_clearOrderly = TRUE;
	}

    // Internal Data Update

    // Iterate input digest list to extend
    for(i = 0; i < in->digests.count; i++)
	{
	    PCRExtend(in->pcrHandle, in->digests.digests[i].hashAlg,
		      CryptGetHashDigestSize(in->digests.digests[i].hashAlg),
		      (BYTE *) &in->digests.digests[i].digest);
	}

    return TPM_RC_SUCCESS;
}
#endif // CC_PCR_Extend

/* 22.3	TPM2_PCR_Event */

#include "InternalRoutines.h"
#include "PCR_Event_fp.h"
#ifdef TPM_CC_PCR_Event  // Conditional expansion of this file

TPM_RC
TPM2_PCR_Event(
	       PCR_Event_In    *in,            // IN: input parameter list
	       PCR_Event_Out   *out            // OUT: output parameter list
	       )
{
    TPM_RC              result;
    HASH_STATE          hashState;
    UINT32              i;
    UINT16              size;

    // Input Validation

    // If a PCR extend is required
    if(in->pcrHandle != TPM_RH_NULL)
	{
	    // If the PCR is not allow to extend, return error
	    if(!PCRIsExtendAllowed(in->pcrHandle))
		return TPM_RC_LOCALITY;

	    // If PCR is state saved and we need to update orderlyState, check NV
	    // availability
	    if(PCRIsStateSaved(in->pcrHandle) && gp.orderlyState != SHUTDOWN_NONE)
		{
		    result = NvIsAvailable();
		    if(result != TPM_RC_SUCCESS) return result;
		    g_clearOrderly = TRUE;
		}
	}

    // Internal Data Update

    out->digests.count = HASH_COUNT;

    // Iterate supported PCR bank algorithms to extend
    for(i = 0; i < HASH_COUNT; i++)
	{
	    TPM_ALG_ID  hash = CryptGetHashAlgByIndex(i);
	    out->digests.digests[i].hashAlg = hash;
	    size = CryptStartHash(hash, &hashState);
	    CryptUpdateDigest2B(&hashState, &in->eventData.b);
	    CryptCompleteHash(&hashState, size,
			      (BYTE *) &out->digests.digests[i].digest);
	    if(in->pcrHandle != TPM_RH_NULL)
		PCRExtend(in->pcrHandle, hash, size,
			  (BYTE *) &out->digests.digests[i].digest);
	}

    return TPM_RC_SUCCESS;
}
#endif // CC_PCR_Event

/* 22.4	TPM2_PCR_Read */

#include "InternalRoutines.h"
#include "PCR_Read_fp.h"
#ifdef TPM_CC_PCR_Read  // Conditional expansion of this file

TPM_RC
TPM2_PCR_Read(
	      PCR_Read_In     *in,            // IN: input parameter list
	      PCR_Read_Out    *out            // OUT: output parameter list
	      )
{
    // Command Output

    // Call PCR read function.  input pcrSelectionIn parameter could be changed
    // to reflect the actual PCR being returned
    PCRRead(&in->pcrSelectionIn, &out->pcrValues, &out->pcrUpdateCounter);
    
    out->pcrSelectionOut = in->pcrSelectionIn;

    return TPM_RC_SUCCESS;
}
#endif // CC_PCR_Read

/* 22.5	TPM2_PCR_Allocate */

#include "InternalRoutines.h"
#include "PCR_Allocate_fp.h"
#ifdef TPM_CC_PCR_Allocate  // Conditional expansion of this file

TPM_RC
TPM2_PCR_Allocate(
		  PCR_Allocate_In     *in,            // IN: input parameter list
		  PCR_Allocate_Out    *out            // OUT: output parameter list
		  )
{
    TPM_RC      result;

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point.
    // Note: These codes are not listed in the return values above because it is
    // an implementation choice to check in this routine rather than in a common
    // function that is called before these actions are called. These return values
    // are described in the Response Code section of Part 3.
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS)
	return result;

    // Command Output

    // Call PCR Allocation function.
    result = PCRAllocate(&in->pcrAllocation, &out->maxPCR,
			 &out->sizeNeeded, &out->sizeAvailable);
    if(result == TPM_RC_PCR)
	return result;

    //
    out->allocationSuccess = (result == TPM_RC_SUCCESS);

    // if re-configuration succeeds, set the flag to indicate PCR configuration is
    // going to be changed in next boot
    if(out->allocationSuccess == YES)
	g_pcrReConfig = TRUE;

    return TPM_RC_SUCCESS;
}
#endif // CC_PCR_Allocate

/* 22.6	TPM2_PCR_SetAuthPolicy */

#include "InternalRoutines.h"
#include "PCR_SetAuthPolicy_fp.h"
#ifdef TPM_CC_PCR_SetAuthPolicy  // Conditional expansion of this file

TPM_RC
TPM2_PCR_SetAuthPolicy(
		       PCR_SetAuthPolicy_In    *in             // IN: input parameter list
		       )
{
#if 0
    UINT32      groupIndex;

    TPM_RC      result;

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

    // Input Validation:

    // Check the authPolicy consistent with hash algorithm
    if(in->authPolicy.t.size != CryptGetHashDigestSize(in->hashAlg))
	return TPM_RCS_SIZE + RC_PCR_SetAuthPolicy_authPolicy;

    // If PCR does not belong to a policy group, return TPM_RC_VALUE
    if(!PCRBelongsPolicyGroup(in->pcrNum, &groupIndex))
	return TPM_RCS_VALUE + RC_PCR_SetAuthPolicy_pcrNum;

    // Internal Data Update

    // Set PCR policy
    gp.pcrPolicies.hashAlg[groupIndex] = in->hashAlg;
    gp.pcrPolicies.policy[groupIndex] = in->authPolicy;

    // Save new policy to NV
    NvWriteReserved(NV_PCR_POLICIES, &gp.pcrPolicies);

    return TPM_RC_SUCCESS;
#else	/* kgold, when no PCR policies, this command always fails */
    return TPM_RCS_VALUE + RC_PCR_SetAuthPolicy_pcrNum;
#endif
    
}
#endif // CC_PCR_SetAuthPolicy

/* 22.7	TPM2_PCR_SetAuthValue */

#include "InternalRoutines.h"
#include "PCR_SetAuthValue_fp.h"
#ifdef TPM_CC_PCR_SetAuthValue  // Conditional expansion of this file

TPM_RC
TPM2_PCR_SetAuthValue(
		      PCR_SetAuthValue_In     *in             // IN: input parameter list
		      )
{
    UINT32      groupIndex;
    TPM_RC      result;

    // Input Validation:

    // If PCR does not belong to an auth group, return TPM_RC_VALUE
    if(!PCRBelongsAuthGroup(in->pcrHandle, &groupIndex))
	return TPM_RC_VALUE;

    // The command may cause the orderlyState to be cleared due to the update of
    // state clear data.  If this is the case, Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    if(gp.orderlyState != SHUTDOWN_NONE)
	{
	    result = NvIsAvailable();
	    if(result != TPM_RC_SUCCESS) return result;
	    g_clearOrderly = TRUE;
	}

    // Internal Data Update

    // Set PCR authValue
    gc.pcrAuthValues.auth[groupIndex] = in->auth;

    return TPM_RC_SUCCESS;
}
#endif // CC_PCR_SetAuthValue

/* 22.8	TPM2_PCR_Reset */

#include "InternalRoutines.h"
#include "PCR_Reset_fp.h"
#ifdef TPM_CC_PCR_Reset  // Conditional expansion of this file

TPM_RC
TPM2_PCR_Reset(
	       PCR_Reset_In    *in             // IN: input parameter list
	       )
{
    TPM_RC      result;

    // Input Validation

    // Check if the reset operation is allowed by the current command locality
    if(!PCRIsResetAllowed(in->pcrHandle))
	return TPM_RC_LOCALITY;

    // If PCR is state saved and we need to update orderlyState, check NV
    // availability
    if(PCRIsStateSaved(in->pcrHandle) && gp.orderlyState != SHUTDOWN_NONE)
	{
	    result = NvIsAvailable();
	    if(result != TPM_RC_SUCCESS)
		return result;
	    g_clearOrderly = TRUE;
	}

    // Internal Data Update

    // Reset selected PCR in all banks to 0
    PCRSetValue(in->pcrHandle, 0);

    // Indicate that the PCR changed so that pcrCounter will be incremented if
    // necessary.
    PCRChanged(in->pcrHandle);

    return TPM_RC_SUCCESS;
}
#endif // CC_PCR_Reset

// 22.9	_TPM_Hash_Start

#include "InternalRoutines.h"

// This function is called to process a _TPM_Hash_Start() indication.

void
_TPM_Hash_Start(
		void
		)
{
    TPM_RC              result;
    TPMI_DH_OBJECT      handle;
    // If a DRTM sequence object exists, free it up
    if(g_DRTMHandle != TPM_RH_UNASSIGNED)
	{
	    ObjectFlush(g_DRTMHandle);
	    g_DRTMHandle = TPM_RH_UNASSIGNED;
	}
    // Create an event sequence object and store the handle in global
    // g_DRTMHandle. A TPM_RC_OBJECT_MEMORY error may be returned at this point
    // The null value for the 'auth' parameter will cause the sequence structure to
    // be allocated without being set as present. This keeps the sequence from
    // being left behind if the sequence is terminated early.
    result = ObjectCreateEventSequence(NULL, &g_DRTMHandle);
    // If a free slot was not available, then free up a slot.
    if(result != TPM_RC_SUCCESS)
	{
	    // An implementation does not need to have a fixed relationship between
	    // slot numbers and handle numbers. To handle the general case, scan for
	    // a handle that is assigned and free it for the DRTM sequence.
	    // In the reference implementation, the relationship between handles and
	    // slots is fixed. So, if the call to ObjectCreateEvenSequence()
	    // failed indicating that all slots are occupied, then the first handle we
	    // are going to check (TRANSIENT_FIRST) will be occupied. It will be freed
	    // so that it can be assigned for use as the DRTM sequence object.
	    for(handle = TRANSIENT_FIRST; handle < TRANSIENT_LAST; handle++)
		{
		    // try to flush the first object
		    if(ObjectIsPresent(handle))
			break;
		}
	    // If the first call to find a slot fails but none of the slots is occupied
	    // then there's a big problem
	    pAssert(handle < TRANSIENT_LAST);
	    // Free the slot
	    ObjectFlush(handle);
	    // Try to create an event sequence object again.  This time, we must
	    // succeed.
	    result = ObjectCreateEventSequence(NULL, &g_DRTMHandle);
	    pAssert(result == TPM_RC_SUCCESS);
	}
    return;
}

// 22.10	_TPM_Hash_Data

#include "InternalRoutines.h"
#include "Platform.h"
#include "PCR_fp.h"

// This function is called to process a _TPM_Hash_Data() indication.

void
_TPM_Hash_Data(
	       UINT32           dataSize,      // IN: size of data to be extend
	       BYTE            *data           // IN: data buffer
	       )
{
    UINT32           i;
    HASH_OBJECT     *hashObject;
    TPMI_DH_PCR      pcrHandle = TPMIsStarted()
				 ? PCR_FIRST + DRTM_PCR : PCR_FIRST + HCRTM_PCR;
    // If there is no DRTM sequence object, then _TPM_Hash_Start
    // was not called so this function returns without doing
    // anything.
    if(g_DRTMHandle == TPM_RH_UNASSIGNED)
	return;
    hashObject = (HASH_OBJECT *)ObjectGet(g_DRTMHandle);
    pAssert(hashObject->attributes.eventSeq);
    // For each of the implemented hash algorithms, update the digest with the
    // data provided.
    for(i = 0; i < HASH_COUNT; i++)
	{
	    // make sure that the PCR is implemented for this algorithm
	    if(PcrIsAllocated(pcrHandle,
			      hashObject->state.hashState[i].state.hashAlg))
		// Update sequence object
		CryptUpdateDigest(&hashObject->state.hashState[i], dataSize, data);
	}
    return;
}

// 22.11	_TPM_Hash_End

#include "InternalRoutines.h"

// This function is called to process a _TPM_Hash_End() indication.

void
_TPM_Hash_End(
	      void
	      )
{
    UINT32          i;
    TPM2B_DIGEST    digest;
    HASH_OBJECT    *hashObject;
    TPMI_DH_PCR     pcrHandle;
    // If the DRTM handle is not being used, then either _TPM_Hash_Start has not
    // been called, _TPM_Hash_End was previously called, or some other command
    // was executed and the sequence was aborted.
    if(g_DRTMHandle == TPM_RH_UNASSIGNED)
	return;
    // Get DRTM sequence object
    hashObject = (HASH_OBJECT *)ObjectGet(g_DRTMHandle);
    // Is this _TPM_Hash_End after Startup or before
    if(TPMIsStarted())
	{
	    // After
	    // Reset the DRTM PCR
	    PCRResetDynamics();
	    // Extend the DRTM_PCR.
	    pcrHandle = PCR_FIRST + DRTM_PCR;
	    // DRTM sequence increments restartCount
	    gr.restartCount++;
	}
    else
	{
	    pcrHandle = PCR_FIRST + HCRTM_PCR;
	}
    // Complete hash and extend PCR, or if this is an HCRTM, complete
    // the hash, reset the H-CRTM register (PCR[0]) to 0...04, and then
    // extend the H-CRTM data
    for(i = 0; i < HASH_COUNT; i++)
	{
	    TPMI_ALG_HASH       hash = CryptGetHashAlgByIndex(i);
	    // make sure that the PCR is implemented for this algorithm
	    if(PcrIsAllocated(pcrHandle,
			      hashObject->state.hashState[i].state.hashAlg))
		{
		    // Complete hash
		    digest.t.size = CryptGetHashDigestSize(hash);
		    CryptCompleteHash2B(&hashObject->state.hashState[i], &digest.b);
		    PcrDrtm(pcrHandle, hash, &digest);
		}
	}
    // Flush sequence object.
    ObjectFlush(g_DRTMHandle);
    g_DRTMHandle = TPM_RH_UNASSIGNED;
    g_DrtmPreStartup = TRUE;
    return;
}
