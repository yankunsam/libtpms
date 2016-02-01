/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: NVCommands.c 471 2015-12-22 19:40:24Z kgoldman $		*/
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

/* 31.3	TPM2_NV_DefineSpace */

#include "InternalRoutines.h"
#include "NV_DefineSpace_fp.h"
#include "NV.h"
#ifdef TPM_CC_NV_DefineSpace  // Conditional expansion of this file

TPM_RC
TPM2_NV_DefineSpace(
		    NV_DefineSpace_In   *in             // IN: input parameter list
		    )
{
    TPM_RC          result;
    TPMA_NV         attributes;
    UINT16          nameSize;
    
    nameSize = CryptGetHashDigestSize(in->publicInfo.t.nvPublic.nameAlg);
    
    // Check if NV is available. NvIsAvailable may return TPM_RC_NV_UNAVAILABLE
    // TPM_RC_NV_RATE or TPM_RC_SUCCESS.
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS)
	return result;
    
    // Input Validation
    // If an index is being created by the owner and shEnable is
    // clear, then we would not reach this point because ownerAuth
    // can't be given when shEnable is CLEAR. However, if phEnable
    // is SET but phEnableNV is CLEAR, we have to check here
    if(in->authHandle == TPM_RH_PLATFORM && gc.phEnableNV == CLEAR)
	return TPM_RCS_HIERARCHY + RC_NV_DefineSpace_authHandle;
    
    attributes = in->publicInfo.t.nvPublic.attributes;
    
    //TPMS_NV_PUBLIC validation.
    
    // check that the authPolicy consistent with hash algorithm
    if(   in->publicInfo.t.nvPublic.authPolicy.t.size != 0
	  && in->publicInfo.t.nvPublic.authPolicy.t.size != nameSize)
	return TPM_RCS_SIZE + RC_NV_DefineSpace_publicInfo;
    
    // make sure that the authValue is not too large
    MemoryRemoveTrailingZeros(&in->auth);
    if(in->auth.t.size > nameSize)
	return TPM_RCS_SIZE + RC_NV_DefineSpace_auth;
    
    //TPMA_NV validation.
    // Locks may not be SET and written cannot be SET
    if(   attributes.TPMA_NV_WRITTEN == SET
	  || attributes.TPMA_NV_WRITELOCKED == SET
	  || attributes.TPMA_NV_READLOCKED == SET)
	return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_publicInfo;
    
    // There must be a way to read the index
    if(   attributes.TPMA_NV_OWNERREAD == CLEAR
	  && attributes.TPMA_NV_PPREAD == CLEAR
	  && attributes.TPMA_NV_AUTHREAD == CLEAR
	  && attributes.TPMA_NV_POLICYREAD == CLEAR)
	return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_publicInfo;
    
    // There must be a way to write the index
    if(   attributes.TPMA_NV_OWNERWRITE == CLEAR
	  && attributes.TPMA_NV_PPWRITE == CLEAR
	  && attributes.TPMA_NV_AUTHWRITE == CLEAR
	  && attributes.TPMA_NV_POLICYWRITE == CLEAR)
	return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_publicInfo;
    
    //TPMS_NV_PUBLIC validation.
    
    // Check that the attributes and sizes are appropriate for the index and make
    // sure that the Index type supports the command that modifies that type.
    switch(NV_ATTRIBUTES_TO_TYPE(attributes))
	{
	  case TPM_NT_ORDINARY:
	    // Can't exceede the allowed size for the implementation
	    if(in->publicInfo.t.nvPublic.dataSize > MAX_NV_INDEX_SIZE)
		return TPM_RCS_SIZE + RC_NV_DefineSpace_publicInfo;
	    break;
	  case TPM_NT_COUNTER:
#if CC_NV_Increment == NO // no support for counter
	    return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_publicInfo;
#else
	    // Counter has to have a size of 8
	    if(in->publicInfo.t.nvPublic.dataSize != 8)
		return TPM_RCS_SIZE + RC_NV_DefineSpace_publicInfo;
	    // Counter can't have TPMA_NV_CLEAR_STCLEAR SET (don't clear counters)
	    if(attributes.TPMA_NV_CLEAR_STCLEAR == SET)
		return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_publicInfo;
#endif
	    break;
	  case TPM_NT_BITS:
#if CC_NV_SetBits == NO // No bit field support
	    return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_publicInfo;
#else
	    // Must have a size of 8
	    if(in->publicInfo.t.nvPublic.dataSize != 8)
		return TPM_RCS_SIZE + RC_NV_DefineSpace_publicInfo;
#endif
	    break;
	  case TPM_NT_EXTEND:
#if CC_NV_Extend == NO // no support
	    return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_publicInfo;
#else
	    if(in->publicInfo.t.nvPublic.dataSize != nameSize)
		return TPM_RCS_SIZE + RC_NV_DefineSpace_publicInfo;
#endif
	    break;
	    
	  default:
	    // The index type is not supported
	    return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_publicInfo;
	    break;
	}
    
    // If the UndefineSpaceSpecial command is not implemented, then can't have
    // an index that can only be deleted with policy
#if CC_NV_UndefineSpaceSpecial == NO
    if(attributes.TPMA_NV_POLICY_DELETE == SET)
	return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_publicInfo;
#endif
    
    // An index with TPMA_NV_CLEAR_STCLEAR can't have TPMA_NV_WRITEDEFINE SET
    if(     attributes.TPMA_NV_CLEAR_STCLEAR == SET
	    &&  attributes.TPMA_NV_WRITEDEFINE == SET)
	return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_publicInfo;
    
    // Make sure that the creator of the index can delete the index
    if(  (   attributes.TPMA_NV_PLATFORMCREATE == SET
	     && in->authHandle == TPM_RH_OWNER
	     )
	 || (   attributes.TPMA_NV_PLATFORMCREATE == CLEAR
		&& in->authHandle == TPM_RH_PLATFORM
		)
	 )
	return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_authHandle;
    
    // If TPMA_NV_POLICY_DELETE is SET, then the index must be defined by
    // the platform
    if(    attributes.TPMA_NV_POLICY_DELETE == SET
	   && TPM_RH_PLATFORM != in->authHandle
	   )
	return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace_publicInfo;
    
    // See if the index is already defined.
    if(NvIsUndefinedIndex(in->publicInfo.t.nvPublic.nvIndex))
	return TPM_RC_NV_DEFINED;
    
    // Make sure that the TPMA_NV_WRITEALL is not set if the index size is larger
    // than the allowed NV buffer size.
    if(     in->publicInfo.t.size > MAX_NV_BUFFER_SIZE
	    &&  attributes.TPMA_NV_WRITEALL == SET)
	return TPM_RCS_SIZE + RC_NV_DefineSpace_publicInfo;
    
    // Internal Data Update
    // define the space.  A TPM_RC_NV_SPACE error may be returned at this point
    result = NvDefineIndex(&in->publicInfo.t.nvPublic, &in->auth);
    if(result != TPM_RC_SUCCESS)
	return result;
    
    return TPM_RC_SUCCESS;
    
}
#endif // CC_NV_DefineSpace

/* 31.4	TPM2_NV_UndefineSpace */

#include "InternalRoutines.h"
#include "NV_UndefineSpace_fp.h"
#ifdef TPM_CC_NV_UndefineSpace  // Conditional expansion of this file

TPM_RC
TPM2_NV_UndefineSpace(
		      NV_UndefineSpace_In     *in             // IN: input parameter list
		      )
{
    TPM_RC          result;
    NV_INDEX        nvIndex;

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

    // Input Validation

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // This command can't be used to delete an index with TPMA_NV_POLICY_DELETE SET
    if(SET == nvIndex.publicArea.attributes.TPMA_NV_POLICY_DELETE)
	return TPM_RCS_ATTRIBUTES + RC_NV_UndefineSpace_nvIndex;

    // The owner may only delete an index that was defined with ownerAuth. The
    // platform may delete an index that was created with either auth.
    if(   in->authHandle == TPM_RH_OWNER
	  && nvIndex.publicArea.attributes.TPMA_NV_PLATFORMCREATE == SET)
	return TPM_RC_NV_AUTHORIZATION;

    // Internal Data Update

    // Call implementation dependent internal routine to delete NV index
    NvDeleteEntity(in->nvIndex);

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_UndefineSpace

/* 31.5	TPM2_NV_UndefineSpaceSpecial */

#include "InternalRoutines.h"
#include "NV_UndefineSpaceSpecial_fp.h"
#include "SessionProcess_fp.h"
#ifdef TPM_CC_NV_UndefineSpaceSpecial  // Conditional expansion of this file

TPM_RC
TPM2_NV_UndefineSpaceSpecial(
			     NV_UndefineSpaceSpecial_In  *in             // IN: input parameter list
			     )
{
    TPM_RC          result;
    NV_INDEX        nvIndex;

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS)
	return result;

    // Input Validation

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // This operation only applies when the TPMA_NV_POLICY_DELETE attribute is SET
    if(CLEAR == nvIndex.publicArea.attributes.TPMA_NV_POLICY_DELETE)
	return TPM_RCS_ATTRIBUTES + RC_NV_UndefineSpaceSpecial_nvIndex;

    // Internal Data Update

    // Call implementation dependent internal routine to delete NV index
    NvDeleteEntity(in->nvIndex);

    SessionRemoveAssociationToHandle(in->nvIndex);

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_UndefineSpaceSpecial

/* 31.6	TPM2_NV_ReadPublic */

#include "InternalRoutines.h"
#include "NV_ReadPublic_fp.h"
#ifdef TPM_CC_NV_ReadPublic  // Conditional expansion of this file

TPM_RC
TPM2_NV_ReadPublic(
		   NV_ReadPublic_In    *in,            // IN: input parameter list
		   NV_ReadPublic_Out   *out            // OUT: output parameter list
		   )
{
    NV_INDEX        nvIndex;

    // Command Output

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // Copy data to output
    out->nvPublic.t.nvPublic = nvIndex.publicArea;

    // Compute NV name
    out->nvName.t.size = NvGetName(in->nvIndex, &out->nvName.t.name);

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_ReadPublic

/* 31.7	TPM2_NV_Write */

#include "InternalRoutines.h"
#include "NV_Write_fp.h"
#include "NV.h"
#ifdef TPM_CC_NV_Write  // Conditional expansion of this file
#include "NV_spt_fp.h"

TPM_RC
TPM2_NV_Write(
	      NV_Write_In     *in             // IN: input parameter list
	      )
{
    NV_INDEX        nvIndex;
    TPM_RC          result;

    // Input Validation
    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // common access checks. NvWriteAccessChecks() may return
    // TPM_RC_NV_AUTHORIZATION or TPM_RC_NV_LOCKED
    result = NvWriteAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
	return result;

    // Bits index, extend index or counter index may not be updated by
    // TPM2_NV_Write
    if(   IsNvCounterIndex(nvIndex.publicArea.attributes)
	  || IsNvBitsIndex(nvIndex.publicArea.attributes)
	  || IsNvExtendIndex(nvIndex.publicArea.attributes))
	  return TPM_RC_ATTRIBUTES;

    // Make sure that the offeset is not too large
    if(in->offset > nvIndex.publicArea.dataSize)
	return TPM_RCS_VALUE + RC_NV_Write_offset;

    // Make sure that the selection is within the range of the Index
    if(in->data.t.size > (nvIndex.publicArea.dataSize - in->offset))
	return TPM_RC_NV_RANGE;

    // If this index requires a full sized write, make sure that input range is
    // full sized.
    // Note: if the requested size is the same as the Index data size, then offset
    // will have to be zero. Otherwise, the range check above would have failed.
    if(   nvIndex.publicArea.attributes.TPMA_NV_WRITEALL == SET
	  && in->data.t.size < nvIndex.publicArea.dataSize)
	return TPM_RC_NV_RANGE;

    // Internal Data Update

    // Perform the write.  This called routine will SET the TPMA_NV_WRITTEN
    // attribute if it has not already been SET. If NV isn't available, an error
    // will be returned.
    return NvWriteIndexData(in->nvIndex, &nvIndex, in->offset,
			    in->data.t.size, in->data.t.buffer);

}
#endif // CC_NV_Write

/* 31.8	TPM2_NV_Increment */

#include "InternalRoutines.h"
#include "NV_Increment_fp.h"
#include "NV.h"
#ifdef TPM_CC_NV_Increment  // Conditional expansion of this file
#include "NV_spt_fp.h"

TPM_RC
TPM2_NV_Increment(
		  NV_Increment_In     *in             // IN: input parameter list
		  )
{
    TPM_RC          result;
    NV_INDEX        nvIndex;
    UINT64          countValue;

    // Input Validation

    // Common access checks, a TPM_RC_NV_AUTHORIZATION or TPM_RC_NV_LOCKED
    // error may be returned at this point
    result = NvWriteAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
	return result;

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // Make sure that this is a counter
    // Make sure that this is a counter
    if(!IsNvCounterIndex(nvIndex.publicArea.attributes))
	return TPM_RCS_ATTRIBUTES + RC_NV_Increment_nvIndex;

    // Internal Data Update

    // If counter index is not been written, initialize it
    if(nvIndex.publicArea.attributes.TPMA_NV_WRITTEN == CLEAR)
	countValue = NvInitialCounter();
    else
	// Read NV data in native format for TPM CPU.
	NvGetIntIndexData(in->nvIndex, &nvIndex, &countValue);

    // Do the increment
    countValue++;

    // If this is an orderly counter that just rolled over, need to be able to
    // write to NV to proceed. This check is done here, because NvWriteIndexData()
    // does not see if the update is for counter rollover.
    if(    nvIndex.publicArea.attributes.TPMA_NV_ORDERLY == SET
	   && (countValue & MAX_ORDERLY_COUNT) == 0)
	{
	    result = NvIsAvailable();
	    if(result != TPM_RC_SUCCESS)
		return result;

	    // Need to force an NV update
	    g_updateNV = TRUE;
	}

    // NvWriteIndexData does not convert endianess
    countValue = htobe64(countValue);

    // Write NV data back. A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may
    // be returned at this point. If necessary, this function will set the
    // TPMA_NV_WRITTEN attribute
    return NvWriteIndexData(in->nvIndex, &nvIndex, 0, 8, &countValue);

}
#endif // CC_NV_Increment

/* 31.9	TPM2_NV_Extend */

#include "InternalRoutines.h"
#include "NV_Extend_fp.h"
#include "NV.h"
#ifdef TPM_CC_NV_Extend  // Conditional expansion of this file
#include "NV_spt_fp.h"

TPM_RC
TPM2_NV_Extend(
	       NV_Extend_In    *in             // IN: input parameter list
	       )
{
    TPM_RC                  result;
    NV_INDEX                nvIndex;

    TPM2B_DIGEST            oldDigest;
    TPM2B_DIGEST            newDigest;
    HASH_STATE              hashState;

    // Input Validation

    // Common access checks, NvWriteAccessCheck() may return TPM_RC_NV_AUTHORIZATION
    // or TPM_RC_NV_LOCKED
    result = NvWriteAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
	return result;

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // Make sure that this is an extend index
    if(!IsNvExtendIndex(nvIndex.publicArea.attributes))
	return TPM_RCS_ATTRIBUTES + RC_NV_Extend_nvIndex;

    // If the Index is not-orderly, or if this is the first write,  NV will
    // need to be updated.
    if(   nvIndex.publicArea.attributes.TPMA_NV_ORDERLY == CLEAR
	  || nvIndex.publicArea.attributes.TPMA_NV_WRITTEN == CLEAR)
	{
	    // Check if NV is available. NvIsAvailable may return TPM_RC_NV_UNAVAILABLE
	    // TPM_RC_NV_RATE or TPM_RC_SUCCESS.
	    result = NvIsAvailable();
	    if(result != TPM_RC_SUCCESS)
		return result;
	}

    // Internal Data Update

    // Perform the write.
    oldDigest.t.size = CryptGetHashDigestSize(nvIndex.publicArea.nameAlg);
    pAssert(oldDigest.t.size <= sizeof(oldDigest.t.buffer));
    if(nvIndex.publicArea.attributes.TPMA_NV_WRITTEN == SET)
	{
	    NvGetIndexData(in->nvIndex, &nvIndex, 0,
			   oldDigest.t.size, oldDigest.t.buffer);
	}
    else
	{
	    MemorySet(oldDigest.t.buffer, 0, oldDigest.t.size);
	}

    // Start hash
    newDigest.t.size = CryptStartHash(nvIndex.publicArea.nameAlg, &hashState);

    // Adding old digest
    CryptUpdateDigest2B(&hashState, &oldDigest.b);

    // Adding new data
    CryptUpdateDigest2B(&hashState, &in->data.b);

    // Complete hash
    CryptCompleteHash2B(&hashState, &newDigest.b);

    // Write extended hash back.
    // Note, this routine will SET the TPMA_NV_WRITTEN attribute if necessary
    return NvWriteIndexData(in->nvIndex, &nvIndex, 0,
			    newDigest.t.size, newDigest.t.buffer);
}
#endif // CC_NV_Extend

/* 31.10	TPM2_NV_SetBits */

#include "InternalRoutines.h"
#include "NV_SetBits_fp.h"
#include "NV.h"
#ifdef TPM_CC_NV_SetBits  // Conditional expansion of this file
#include "NV_spt_fp.h"

TPM_RC
TPM2_NV_SetBits(
		NV_SetBits_In   *in             // IN: input parameter list
		)
{
    TPM_RC          result;
    NV_INDEX        nvIndex;
    UINT64          oldValue;
    UINT64          newValue;

    // Input Validation

    // Common access checks, NvWriteAccessCheck() may return TPM_RC_NV_AUTHORIZATION
    // or TPM_RC_NV_LOCKED
    // error may be returned at this point
    result = NvWriteAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
	return result;

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // Make sure that this is a bit field
    if(!IsNvBitsIndex(nvIndex.publicArea.attributes))
	return TPM_RCS_ATTRIBUTES + RC_NV_SetBits_nvIndex;

    // If index is not been written, initialize it
    if(nvIndex.publicArea.attributes.TPMA_NV_WRITTEN == CLEAR)
	oldValue = 0;
    else
	// Read index data
	NvGetIntIndexData(in->nvIndex, &nvIndex, &oldValue);

    // Figure out what the new value is going to be
    newValue = oldValue | in->bits;

    // If the Index is not-orderly and it has changed, or if this is the first
    // write,  NV will need to be updated.
    if(    (    nvIndex.publicArea.attributes.TPMA_NV_ORDERLY == CLEAR
		&&  newValue != oldValue)
	   || nvIndex.publicArea.attributes.TPMA_NV_WRITTEN == CLEAR)
	{

	    // Internal Data Update
	    // Check if NV is available. NvIsAvailable may return TPM_RC_NV_UNAVAILABLE
	    // TPM_RC_NV_RATE or TPM_RC_SUCCESS.
	    result = NvIsAvailable();
	    if(result != TPM_RC_SUCCESS)
		return result;

            // NvWriteIndexData does not convert endianess
            newValue = htobe64(newValue);

	    // Write index data back. If necessary, this function will SET
	    // TPMA_NV_WRITTEN.
	    result = NvWriteIndexData(in->nvIndex, &nvIndex, 0, 8, &newValue);
	}
    return result;

}
#endif // CC_NV_SetBits

/* 31.11	TPM2_NV_WriteLock */

#include "InternalRoutines.h"
#include "NV_WriteLock_fp.h"
#ifdef TPM_CC_NV_WriteLock  // Conditional expansion of this file
#include "NV_spt_fp.h"

TPM_RC
TPM2_NV_WriteLock(
		  NV_WriteLock_In     *in             // IN: input parameter list
		  )
{
    TPM_RC          result;
    NV_INDEX        nvIndex;

    // Input Validation:

    // Common write access checks, a TPM_RC_NV_AUTHORIZATION or TPM_RC_NV_LOCKED
    // error may be returned at this point
    result = NvWriteAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
	{
	    if(result == TPM_RC_NV_AUTHORIZATION)
		return TPM_RC_NV_AUTHORIZATION;
	    // If write access failed because the index is already locked, then it is
	    // no error.
	    return TPM_RC_SUCCESS;
	}

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // if neither TPMA_NV_WRITEDEFINE nor TPMA_NV_WRITE_STCLEAR is set, the index
    // can not be write-locked
    if(   nvIndex.publicArea.attributes.TPMA_NV_WRITEDEFINE == CLEAR
	  && nvIndex.publicArea.attributes.TPMA_NV_WRITE_STCLEAR == CLEAR)
	return TPM_RCS_ATTRIBUTES + RC_NV_WriteLock_nvIndex;

    // Internal Data Update

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS)
	return result;

    // Set the WRITELOCK attribute.
    // Note: if TPMA_NV_WRITELOCKED were already SET, then the write access check
    // above would have failed and this code isn't executed.
    nvIndex.publicArea.attributes.TPMA_NV_WRITELOCKED = SET;

    // Write index info back
    NvWriteIndexInfo(in->nvIndex, &nvIndex);

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_WriteLock

/* 31.12	TPM2_NV_GlobalWriteLock */

#include "InternalRoutines.h"
#include "NV_GlobalWriteLock_fp.h"
#ifdef TPM_CC_NV_GlobalWriteLock  // Conditional expansion of this file

TPM_RC
TPM2_NV_GlobalWriteLock(
			NV_GlobalWriteLock_In   *in             // IN: input parameter list
			)
{
    TPM_RC          result;

    // Input parameter is not reference in command action
    in = NULL;  // to silence compiler warnings.

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS)
	return result;

    // Internal Data Update

    // Implementation dependent method of setting the global lock
    NvSetGlobalLock();

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_GlobalWriteLock

/* 31.13	TPM2_NV_Read */

#include "InternalRoutines.h"
#include "NV_Read_fp.h"
#ifdef TPM_CC_NV_Read  // Conditional expansion of this file
#include "NV_spt_fp.h"

TPM_RC
TPM2_NV_Read(
	     NV_Read_In      *in,            // IN: input parameter list
	     NV_Read_Out     *out            // OUT: output parameter list
	     )
{
    NV_INDEX        nvIndex;
    TPM_RC          result;

    // Input Validation

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // Common read access checks. NvReadAccessChecks() returns
    // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
    // error may be returned at this point
    result = NvReadAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
	return result;

    // Make sure the data will fit the return buffer
    if( in->size > MAX_NV_BUFFER_SIZE)
	return TPM_RCS_VALUE + RC_NV_Read_size;

    // Verify that the offset is not too large
    if( in->offset > nvIndex.publicArea.dataSize)
	return TPM_RCS_VALUE + RC_NV_Read_offset;

    // Make sure that the selection is within the range of the Index
    if( in->size > (nvIndex.publicArea.dataSize - in->offset))
	return TPM_RC_NV_RANGE;

    // Command Output

    // Set the return size
    out->data.t.size = in->size;
    // Perform the read
    NvGetIndexData(in->nvIndex, &nvIndex, in->offset, in->size, out->data.t.buffer);

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_Read

/* 31.14	TPM2_NV_ReadLock */

#include "InternalRoutines.h"
#include "NV_ReadLock_fp.h"
#ifdef TPM_CC_NV_ReadLock  // Conditional expansion of this file
#include "NV_spt_fp.h"

TPM_RC
TPM2_NV_ReadLock(
		 NV_ReadLock_In  *in             // IN: input parameter list
		 )
{
    TPM_RC          result;
    NV_INDEX        nvIndex;

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

    // Input Validation

    // Common read access checks. NvReadAccessChecks() returns
    // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
    // error may be returned at this point
    result = NvReadAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
	{
	    if(result == TPM_RC_NV_AUTHORIZATION)
		return TPM_RC_NV_AUTHORIZATION;
	    // Index is already locked for write
	    else if(result == TPM_RC_NV_LOCKED)
		return TPM_RC_SUCCESS;

	    // If NvReadAccessChecks return TPM_RC_NV_UNINITALIZED, then continue.
	    // It is not an error to read lock an uninitialized Index.
	}

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // if TPMA_NV_READ_STCLEAR is not set, the index can not be read-locked
    if(nvIndex.publicArea.attributes.TPMA_NV_READ_STCLEAR == CLEAR)
	return TPM_RCS_ATTRIBUTES + RC_NV_ReadLock_nvIndex;

    // Internal Data Update

    // Set the READLOCK attribute
    nvIndex.publicArea.attributes.TPMA_NV_READLOCKED = SET;
    // Write NV info back
    NvWriteIndexInfo(in->nvIndex, &nvIndex);

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_ReadLock

/* 31.15	TPM2_NV_ChangeAuth */

#include "InternalRoutines.h"
#include "NV_ChangeAuth_fp.h"
#ifdef TPM_CC_NV_ChangeAuth  // Conditional expansion of this file

TPM_RC
TPM2_NV_ChangeAuth(
		   NV_ChangeAuth_In    *in             // IN: input parameter list
		   )
{
    TPM_RC          result;
    NV_INDEX        nvIndex;

    // Input Validation
    // Check if NV is available. NvIsAvailable may return TPM_RC_NV_UNAVAILABLE
    // TPM_RC_NV_RATE or TPM_RC_SUCCESS.
    result = NvIsAvailable();
    if(result != TPM_RC_SUCCESS) return result;

    // Read index info from NV
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // Remove any trailing zeros that might have been added by the caller
    // to obfuscate the size.
    MemoryRemoveTrailingZeros(&(in->newAuth));

    // Make sure that the authValue is no larger than the nameAlg of the Index
    if(in->newAuth.t.size > CryptGetHashDigestSize(nvIndex.publicArea.nameAlg))
	return TPM_RCS_SIZE + RC_NV_ChangeAuth_newAuth;

    // Internal Data Update
    // Change auth
    nvIndex.authValue = in->newAuth;
    // Write index info back to NV
    NvWriteIndexInfo(in->nvIndex, &nvIndex);

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_ChangeAuth

/* 31.16	TPM2_NV_Certify */

#include "InternalRoutines.h"
#include "Attest_spt_fp.h"
#include "NV_spt_fp.h"
#include "NV_Certify_fp.h"
#ifdef TPM_CC_NV_Certify  // Conditional expansion of this file

TPM_RC
TPM2_NV_Certify(
		NV_Certify_In   *in,            // IN: input parameter list
		NV_Certify_Out  *out            // OUT: output parameter list
		)
{
    TPM_RC                  result;
    NV_INDEX                nvIndex;
    TPMS_ATTEST             certifyInfo;

    // Attestation command may cause the orderlyState to be cleared due to
    // the reporting of clock info.  If this is the case, check if NV is
    // available first
    if(gp.orderlyState != SHUTDOWN_NONE)
	{
	    // The command needs NV update.  Check if NV is available.
	    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
	    // this point
	    result = NvIsAvailable();
	    if(result != TPM_RC_SUCCESS)
		return result;
	}

    // Input Validation

    // Get NV index info
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // Common access checks.  A TPM_RC_NV_AUTHORIZATION or TPM_RC_NV_LOCKED
    // error may be returned at this point
    result = NvReadAccessChecks(in->authHandle, in->nvIndex);
    if(result != TPM_RC_SUCCESS)
	return result;

    // Validate that the size is not too large
    if(in->size > MAX_NV_BUFFER_SIZE)
	return TPM_RCS_VALUE + RC_NV_Certify_size;

    // Verify that the initial offset is within the bounds of the index
    if(in->offset > nvIndex.publicArea.dataSize)
	return TPM_RCS_VALUE + RC_NV_Certify_offset;

    // Make sure that the selection is within the range of the Index
    if( in->size > (nvIndex.publicArea.dataSize - in->offset))
	return TPM_RC_NV_RANGE;

    // Command Output

    // Filling in attest information
    // Common fields
    //  FillInAttestInfo can return TPM_RC_SCHEME or TPM_RC_KEY
    result = FillInAttestInfo(in->signHandle,
			      &in->inScheme,
			      &in->qualifyingData,
			      &certifyInfo);
    if(result != TPM_RC_SUCCESS)
	{
	    if(result == TPM_RC_KEY)
		return TPM_RCS_KEY + RC_NV_Certify_signHandle;
	    else
		return RcSafeAddToResult(result, RC_NV_Certify_inScheme);
	}
    // NV certify specific fields
    // Attestation type
    certifyInfo.type = TPM_ST_ATTEST_NV;

    // Get the name of the index
    certifyInfo.attested.nv.indexName.t.size =
	NvGetName(in->nvIndex, &certifyInfo.attested.nv.indexName.t.name);

    // Set the return size
    certifyInfo.attested.nv.nvContents.t.size = in->size;

    // Set the offset
    certifyInfo.attested.nv.offset = in->offset;

    // Perform the read
    NvGetIndexData(in->nvIndex, &nvIndex,
		   in->offset, in->size,
		   certifyInfo.attested.nv.nvContents.t.buffer);
    // Sign attestation structure.  A NULL signature will be returned if
    // signHandle is TPM_RH_NULL.  SignAttestInfo() may return TPM_RC_VALUE,
    // TPM_RC_SCHEME or TPM_RC_ATTRUBUTES.
    // Note: SignAttestInfo may return TPM_RC_ATTRIBUTES if the key is not a
    // signing key but that was checked above. TPM_RC_VALUE would mean that the
    // data to sign is too large but the data to sign is a digest
    result = SignAttestInfo(in->signHandle,
			    &in->inScheme,
			    &certifyInfo,
			    &in->qualifyingData,
			    &out->certifyInfo,
			    &out->signature);
    if(result != TPM_RC_SUCCESS)
	return result;

    // orderly state should be cleared because of the reporting of clock info
    // if signing happens
    if(in->signHandle != TPM_RH_NULL)
	g_clearOrderly = TRUE;

    return TPM_RC_SUCCESS;
}
#endif // CC_NV_Certify











