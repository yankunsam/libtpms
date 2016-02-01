/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: HierarchyCommands.c 197 2015-03-31 15:56:34Z kgoldman $	*/
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

/* 24.1	TPM2_CreatePrimary */

#include "InternalRoutines.h"
#include "CreatePrimary_fp.h"
#ifdef TPM_CC_CreatePrimary  // Conditional expansion of this file
#include "Object_spt_fp.h"
#include "Platform.h"

TPM_RC
TPM2_CreatePrimary(
		   CreatePrimary_In    *in,            // IN: input parameter list
		   CreatePrimary_Out   *out            // OUT: output parameter list
		   )
{
    // Local variables
    TPM_RC              result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE      sensitive;

    // Input Validation
    // The sensitiveDataOrigin attribute must be consistent with the setting of
    // the size of the data object in inSensitive.
    if(   (in->inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin == SET)
	  != (in->inSensitive.t.sensitive.data.t.size == 0 ))
	// Mismatch between the object attributes and the parameter.
	return TPM_RCS_ATTRIBUTES + RC_CreatePrimary_inSensitive;

    // Check attributes in input public area. TPM_RC_ATTRIBUTES, TPM_RC_KDF,
    // TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_SYMMETRIC, or TPM_RC_TYPE error may
    // be returned at this point.
    result = PublicAttributesValidation(FALSE, in->primaryHandle,
					&in->inPublic.t.publicArea);
    if(result != TPM_RC_SUCCESS)
	return RcSafeAddToResult(result, RC_CreatePrimary_inPublic);

    // Validate the sensitive area values
    if(  MemoryRemoveTrailingZeros(&in->inSensitive.t.sensitive.userAuth)
	 > CryptGetHashDigestSize(in->inPublic.t.publicArea.nameAlg))
	return TPM_RCS_SIZE + RC_CreatePrimary_inSensitive;

    // Command output

    // Generate Primary Object
    // The primary key generation process uses the Name of the input public
    // template to compute the key. The keys are generated from the template
    // before anything in the template is allowed to be changed.
    // A TPM_RC_KDF, TPM_RC_SIZE error may be returned at this point
    result = CryptCreateObject(in->primaryHandle, &in->inPublic.t.publicArea,
			       &in->inSensitive.t.sensitive,&sensitive);
    if(result != TPM_RC_SUCCESS)
	return result;

    // Fill in creation data
    FillInCreationData(in->primaryHandle, in->inPublic.t.publicArea.nameAlg,
		       &in->creationPCR, &in->outsideInfo, &out->creationData,
		       &out->creationHash);
    
    // Copy public area
    out->outPublic = in->inPublic;

    // Fill in private area for output
    ObjectComputeName(&(out->outPublic.t.publicArea), &out->name);

    // Compute creation ticket
    TicketComputeCreation(EntityGetHierarchy(in->primaryHandle), &out->name,
			  &out->creationHash, &out->creationTicket);

    // Create a internal object.  A TPM_RC_OBJECT_MEMORY error may be returned
    //  at this point.
    result = ObjectLoad(in->primaryHandle, &in->inPublic.t.publicArea, &sensitive,
			&out->name, in->primaryHandle, TRUE, &out->objectHandle);

    return result;
}
#endif // CC_CreatePrimary

/* 24.2	TPM2_HierarchyControl */

#include "InternalRoutines.h"
#include "HierarchyControl_fp.h"
#ifdef TPM_CC_HierarchyControl  // Conditional expansion of this file

TPM_RC
TPM2_HierarchyControl(
		      HierarchyControl_In     *in             // IN: input parameter list
		      )
{
    TPM_RC      result;
    BOOL        select = (in->state == YES);
    BOOL        *selected = NULL;

    // Input Validation
    switch(in->enable)
	{
	    // Platform hierarchy has to be disabled by platform auth
	    // If the platform hierarchy has already been disabled, only a reboot
	    // can enable it again
	  case TPM_RH_PLATFORM:
	  case TPM_RH_PLATFORM_NV:
	    if(in->authHandle != TPM_RH_PLATFORM)
		return TPM_RC_AUTH_TYPE;
	    break;

	    // ShEnable may be disabled if PlatformAuth/PlatformPolicy or
	    // OwnerAuth/OwnerPolicy is provided.  If ShEnable is disabled, then it
	    // may only be enabled if PlatformAuth/PlatformPolicy is provided.
	  case TPM_RH_OWNER:
	    if(   in->authHandle != TPM_RH_PLATFORM
		  && in->authHandle != TPM_RH_OWNER)
		return TPM_RC_AUTH_TYPE;
	    if(   gc.shEnable == FALSE && in->state == YES
		  && in->authHandle != TPM_RH_PLATFORM)
		return TPM_RC_AUTH_TYPE;
	    break;
	    
	    // EhEnable may be disabled if either PlatformAuth/PlatformPolicy or
	    // EndosementAuth/EndorsementPolicy is provided.  If EhEnable is disabled,
	    // then it may only be enabled if PlatformAuth/PlatformPolicy is
	    // provided.
	  case TPM_RH_ENDORSEMENT:
	    if(   in->authHandle != TPM_RH_PLATFORM
		  && in->authHandle != TPM_RH_ENDORSEMENT)
		return TPM_RC_AUTH_TYPE;
	    if(   gc.ehEnable == FALSE && in->state == YES
		  && in->authHandle != TPM_RH_PLATFORM)
		return TPM_RC_AUTH_TYPE;
	    break;
	  default:
	    pAssert(FALSE);
	    break;
	}
    
    // Internal Data Update
    
    // Enable or disable the selected hierarchy
    // Note: the authorization processing for this command may keep these
    // command actions from being executed. For example, if phEnable is
    // CLEAR, then platformAuth cannot be used for authorization. This
    // means that would not be possible to use platformAuth to change the
    // state of phEnable from CLEAR to SET.
    // If it is decided that platformPolicy can still be used when phEnable
    // is CLEAR, then this code could SET phEnable when proper platform
    // policy is provided.
    switch(in->enable)
	{
	  case TPM_RH_OWNER:
	    selected = &gc.shEnable;
	    break;
	  case TPM_RH_ENDORSEMENT:
	    selected = &gc.ehEnable;
	    break;
	  case TPM_RH_PLATFORM:
	    selected = &g_phEnable;
	    break;
	  case TPM_RH_PLATFORM_NV:
	    selected = &gc.phEnableNV;
	    break;
	  default:
	    pAssert(FALSE);
	    break;
	}
    if(selected != NULL && *selected != select)
	{
	    // Before changing the internal state, make sure that NV is available.
	    // Only need to update NV if changing the orderly state
	    if(gp.orderlyState != SHUTDOWN_NONE)
		{
		    // The command needs NV update.  Check if NV is available.
		    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
		    // this point
		    result = NvIsAvailable();
		    if(result != TPM_RC_SUCCESS)
			return result;
		}
	    // state is changing and NV is available so modify
	    *selected = select;
	    // If a hierarchy was just disabled, flush it
	    if(select == CLEAR && in->enable != TPM_RH_PLATFORM_NV)
		// Flush hierarchy
		ObjectFlushHierarchy(in->enable);
	    
	    // orderly state should be cleared because of the update to state clear data
	    // This gets processed in ExecuteCommand() on the way out.
	    g_clearOrderly = TRUE;
	}
    return TPM_RC_SUCCESS;
}
#endif // CC_HierarchyControl

/* 24.3	TPM2_SetPrimaryPolicy */

#include "InternalRoutines.h"
#include "SetPrimaryPolicy_fp.h"
#ifdef TPM_CC_SetPrimaryPolicy  // Conditional expansion of this file

TPM_RC
TPM2_SetPrimaryPolicy(
		      SetPrimaryPolicy_In     *in             // IN: input parameter list
		      )
{
    TPM_RC                   result;

    // Input Validation

    // Check the authPolicy consistent with hash algorithm. If the policy size is
    // zero, then the algorithm is required to be TPM_ALG_NULL
    if(in->authPolicy.t.size != CryptGetHashDigestSize(in->hashAlg))
	return TPM_RCS_SIZE + RC_SetPrimaryPolicy_authPolicy;

    // The command need NV update for OWNER and ENDORSEMENT hierarchy, and
    // might need orderlyState update for PLATFROM hierarchy.
    // Check if NV is available.  A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE
    // error may be returned at this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS)
	return result;

    // Internal Data Update

    // Set hierarchy policy
    switch(in->authHandle)
	{
	  case TPM_RH_OWNER:
	    gp.ownerAlg = in->hashAlg;
	    gp.ownerPolicy = in->authPolicy;
	    NvWriteReserved(NV_OWNER_ALG, &gp.ownerAlg);
	    NvWriteReserved(NV_OWNER_POLICY, &gp.ownerPolicy);
	    break;
	  case TPM_RH_ENDORSEMENT:
	    gp.endorsementAlg = in->hashAlg;
	    gp.endorsementPolicy = in->authPolicy;
	    NvWriteReserved(NV_ENDORSEMENT_ALG, &gp.endorsementAlg);
	    NvWriteReserved(NV_ENDORSEMENT_POLICY, &gp.endorsementPolicy);
	    break;
	  case TPM_RH_PLATFORM:
	    gc.platformAlg = in->hashAlg;
	    gc.platformPolicy = in->authPolicy;
	    // need to update orderly state
	    g_clearOrderly = TRUE;
	    break;
	  case TPM_RH_LOCKOUT:
	    gp.lockoutAlg = in->hashAlg;
	    gp.lockoutPolicy = in->authPolicy;
	    NvWriteReserved(NV_LOCKOUT_ALG, &gp.lockoutAlg);
	    NvWriteReserved(NV_LOCKOUT_POLICY, &gp.lockoutPolicy);
	    break;
	  default:
	    pAssert(FALSE);
	    break;
	}

    return TPM_RC_SUCCESS;
}
#endif // CC_SetPrimaryPolicy

/* 24.4	TPM2_ChangePPS */

#include "InternalRoutines.h"
#include "ChangePPS_fp.h"
#ifdef TPM_CC_ChangePPS  // Conditional expansion of this file

TPM_RC
TPM2_ChangePPS(
	       ChangePPS_In    *in             // IN: input parameter list
	       )
{
    UINT32          i = 0;
    TPM_RC          result;

    i = i;	/* kgold added to prevent compiler warning */

    // Check if NV is available.  A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE
    // error may be returned at this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

    // Input parameter is not reference in command action
    in = NULL;

    // Internal Data Update

    // Reset platform hierarchy seed from RNG
    CryptGenerateRandom(PRIMARY_SEED_SIZE, gp.PPSeed.t.buffer);

    // Create a new phProof value from RNG to prevent the saved platform
    // hierarchy contexts being loaded
    CryptGenerateRandom(PROOF_SIZE, gp.phProof.t.buffer);

    // Set platform authPolicy to null
    gc.platformAlg = TPM_ALG_NULL;
    gc.platformPolicy.t.size = 0;

    // Flush loaded object in platform hierarchy
    ObjectFlushHierarchy(TPM_RH_PLATFORM);

    // Flush platform evict object and index in NV
    NvFlushHierarchy(TPM_RH_PLATFORM);

    // Save hierarchy changes to NV
    NvWriteReserved(NV_PP_SEED, &gp.PPSeed);
    NvWriteReserved(NV_PH_PROOF, &gp.phProof);

    // Re-initialize PCR policies
#if NUM_POLICY_PCR_GROUP > 0	/* kgold added to prevent zero size array */
    for(i = 0; i < NUM_POLICY_PCR_GROUP; i++)
	{
	    gp.pcrPolicies.hashAlg[i] = TPM_ALG_NULL;
	    gp.pcrPolicies.policy[i].t.size = 0;
	}
    NvWriteReserved(NV_PCR_POLICIES, &gp.pcrPolicies);
#endif

    // orderly state should be cleared because of the update to state clear data
    g_clearOrderly = TRUE;

    return TPM_RC_SUCCESS;
}
#endif // CC_ChangePPS

/* 24.5	TPM2_ChangeEPS */

#include "InternalRoutines.h"
#include "ChangeEPS_fp.h"
#ifdef TPM_CC_ChangeEPS  // Conditional expansion of this file

TPM_RC
TPM2_ChangeEPS(
	       ChangeEPS_In    *in             // IN: input parameter list
	       )
{
    TPM_RC          result;

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

    // Input parameter is not reference in command action
    in = NULL;

    // Internal Data Update
    
    // Reset endorsement hierarchy seed from RNG
    CryptGenerateRandom(PRIMARY_SEED_SIZE, gp.EPSeed.t.buffer);

    // Create new ehProof value from RNG
    CryptGenerateRandom(PROOF_SIZE, gp.ehProof.t.buffer);

    // Enable endorsement hierarchy
    gc.ehEnable = TRUE;

    // set authValue buffer to zeros
    MemorySet(gp.endorsementAuth.t.buffer, 0, gp.endorsementAuth.t.size);
    // Set endorsement authValue to null
    gp.endorsementAuth.t.size = 0;

    // Set endorsement authPolicy to null
    gp.endorsementAlg = TPM_ALG_NULL;
    gp.endorsementPolicy.t.size = 0;

    // Flush loaded object in endorsement hierarchy
    ObjectFlushHierarchy(TPM_RH_ENDORSEMENT);

    // Flush evict object of endorsement hierarchy stored in NV
    NvFlushHierarchy(TPM_RH_ENDORSEMENT);

    // Save hierarchy changes to NV
    NvWriteReserved(NV_EP_SEED, &gp.EPSeed);
    NvWriteReserved(NV_EH_PROOF, &gp.ehProof);
    NvWriteReserved(NV_ENDORSEMENT_AUTH, &gp.endorsementAuth);
    NvWriteReserved(NV_ENDORSEMENT_ALG, &gp.endorsementAlg);
    NvWriteReserved(NV_ENDORSEMENT_POLICY, &gp.endorsementPolicy);

    // orderly state should be cleared because of the update to state clear data
    g_clearOrderly = TRUE;

    return TPM_RC_SUCCESS;
}
#endif // CC_ChangeEPS

/* 24.6	TPM2_Clear */

#include "InternalRoutines.h"
#include "Clear_fp.h"
#ifdef TPM_CC_Clear  // Conditional expansion of this file

TPM_RC
TPM2_Clear(
	   Clear_In        *in             // IN: input parameter list
	   )
{
    TPM_RC              result;

    // Input parameter is not reference in command action
    in = NULL;

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

    // Input Validation
    
    // If Clear command is disabled, return an error
    if(gp.disableClear)
	return TPM_RC_DISABLED;

    // Internal Data Update

    // Reset storage hierarchy seed from RNG
    CryptGenerateRandom(PRIMARY_SEED_SIZE, gp.SPSeed.t.buffer);

    // Create new shProof and ehProof value from RNG
    CryptGenerateRandom(PROOF_SIZE, gp.shProof.t.buffer);
    CryptGenerateRandom(PROOF_SIZE, gp.ehProof.t.buffer);

    // Enable storage and endorsement hierarchy
    gc.shEnable = gc.ehEnable = TRUE;

    // set the authValue buffers to zero
    MemorySet(gp.ownerAuth.t.buffer, 0, gp.ownerAuth.t.size);
    MemorySet(gp.endorsementAuth.t.buffer, 0, gp.endorsementAuth.t.size);
    MemorySet(gp.lockoutAuth.t.buffer, 0, gp.lockoutAuth.t.size);
    // Set storage, endorsement and lockout authValue to null
    gp.ownerAuth.t.size = gp.endorsementAuth.t.size = gp.lockoutAuth.t.size = 0;

    // Set storage, endorsement, and lockout authPolicy to null
    gp.ownerAlg = gp.endorsementAlg = gp.lockoutAlg = TPM_ALG_NULL;
    gp.ownerPolicy.t.size = 0;
    gp.endorsementPolicy.t.size = 0;
    gp.lockoutPolicy.t.size = 0;

    // Flush loaded object in storage and endorsement hierarchy
    ObjectFlushHierarchy(TPM_RH_OWNER);
    ObjectFlushHierarchy(TPM_RH_ENDORSEMENT);

    // Flush owner and endorsement object and owner index in NV
    NvFlushHierarchy(TPM_RH_OWNER);
    NvFlushHierarchy(TPM_RH_ENDORSEMENT);

    // Save hierarchy changes to NV
    NvWriteReserved(NV_SP_SEED, &gp.SPSeed);
    NvWriteReserved(NV_SH_PROOF, &gp.shProof);
    NvWriteReserved(NV_EH_PROOF, &gp.ehProof);
    NvWriteReserved(NV_OWNER_AUTH, &gp.ownerAuth);
    NvWriteReserved(NV_ENDORSEMENT_AUTH, &gp.endorsementAuth);
    NvWriteReserved(NV_LOCKOUT_AUTH, &gp.lockoutAuth);
    NvWriteReserved(NV_OWNER_ALG, &gp.ownerAlg);
    NvWriteReserved(NV_ENDORSEMENT_ALG, &gp.endorsementAlg);
    NvWriteReserved(NV_LOCKOUT_ALG, &gp.lockoutAlg);
    NvWriteReserved(NV_OWNER_POLICY, &gp.ownerPolicy);
    NvWriteReserved(NV_ENDORSEMENT_POLICY, &gp.endorsementPolicy);
    NvWriteReserved(NV_LOCKOUT_POLICY, &gp.lockoutPolicy);

    // Initialize dictionary attack parameters
    DAPreInstall_Init();

    // Reset clock
    go.clock = 0;
    go.clockSafe = YES;
    // Update the DRBG state whenever writing orderly state to NV
    CryptDrbgGetPutState(GET_STATE);
    NvWriteReserved(NV_ORDERLY_DATA, &go);

    // Reset counters
    gp.resetCount = gr.restartCount = gr.clearCount = 0;
    gp.auditCounter = 0;
    NvWriteReserved(NV_RESET_COUNT, &gp.resetCount);
    NvWriteReserved(NV_AUDIT_COUNTER, &gp.auditCounter);

    // orderly state should be cleared because of the update to state clear data
    g_clearOrderly = TRUE;

    return TPM_RC_SUCCESS;
}
#endif // CC_Clear

/* 24.7	TPM2_ClearControl */

#include "InternalRoutines.h"
#include "ClearControl_fp.h"
#ifdef TPM_CC_ClearControl  // Conditional expansion of this file

TPM_RC
TPM2_ClearControl(
		  ClearControl_In     *in             // IN: input parameter list
		  )
{
    TPM_RC      result;

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

    // Input Validation

    // LockoutAuth may be used to set disableLockoutClear to TRUE but not to FALSE
    if(in->auth == TPM_RH_LOCKOUT && in->disable == NO)
	return TPM_RC_AUTH_FAIL;

    // Internal Data Update

    if(in->disable == YES)
	gp.disableClear = TRUE;
    else
	gp.disableClear = FALSE;

    // Record the change to NV
    NvWriteReserved(NV_DISABLE_CLEAR, &gp.disableClear);

    return TPM_RC_SUCCESS;
}
#endif // CC_ClearControl

/* 24.8	TPM2_HierarchyChangeAuth */

#include "InternalRoutines.h"
#include "HierarchyChangeAuth_fp.h"
#ifdef TPM_CC_HierarchyChangeAuth  // Conditional expansion of this file
#include "Object_spt_fp.h"

TPM_RC
TPM2_HierarchyChangeAuth(
			 HierarchyChangeAuth_In  *in             // IN: input parameter list
			 )
{
    TPM_RC      result;

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

    // Make sure the the auth value is a reasonable size (not larger than
    // the size of the digest produced by the integrity hash. The integrity
    // hash is assumed to produce the longest digest of any hash implemented
    // on the TPM.
    if(  MemoryRemoveTrailingZeros(&in->newAuth)
	 > CryptGetHashDigestSize(CONTEXT_INTEGRITY_HASH_ALG))
	return TPM_RCS_SIZE + RC_HierarchyChangeAuth_newAuth;

    // Set hierarchy authValue
    switch(in->authHandle)
	{
	  case TPM_RH_OWNER:
	    gp.ownerAuth = in->newAuth;
	    NvWriteReserved(NV_OWNER_AUTH, &gp.ownerAuth);
	    break;
	  case TPM_RH_ENDORSEMENT:
	    gp.endorsementAuth = in->newAuth;
	    NvWriteReserved(NV_ENDORSEMENT_AUTH, &gp.endorsementAuth);
	    break;
	  case TPM_RH_PLATFORM:
	    gc.platformAuth = in->newAuth;
	    // orderly state should be cleared
	    g_clearOrderly = TRUE;
	    break;
	  case TPM_RH_LOCKOUT:
	    gp.lockoutAuth = in->newAuth;
	    NvWriteReserved(NV_LOCKOUT_AUTH, &gp.lockoutAuth);
	    break;
	  default:
	    pAssert(FALSE);
	    break;
	}

    return TPM_RC_SUCCESS;
}
#endif // CC_HierarchyChangeAuth








