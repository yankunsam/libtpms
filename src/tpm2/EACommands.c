/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: EACommands.c 471 2015-12-22 19:40:24Z kgoldman $		*/
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

/* 23.3	TPM2_PolicySigned */

#include "InternalRoutines.h"
#include "Policy_spt_fp.h"
#include "PolicySigned_fp.h"

#include "Unmarshal_fp.h"

#ifdef TPM_CC_PolicySigned  // Conditional expansion of this file

TPM_RC
TPM2_PolicySigned(
		  PolicySigned_In     *in,            // IN: input parameter list
		  PolicySigned_Out    *out            // OUT: output parameter list
		  )
{
    TPM_RC                   result = TPM_RC_SUCCESS;
    SESSION                 *session;
    TPM2B_NAME               entityName;
    TPM2B_DIGEST             authHash;
    HASH_STATE               hashState;
    UINT32                   expiration = (in->expiration < 0)
					  ? -(in->expiration) : in->expiration;
    UINT64                   authTimeout = 0;

    // Input Validation
    
    // Set up local pointers
    session = SessionGet(in->policySession);    // the session structure

    // Only do input validation if this is not a trial policy session
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    if(expiration != 0)
		authTimeout = expiration * 1000 + session->startTime;
	    
	    result = PolicyParameterChecks(session, authTimeout,
					   &in->cpHashA, &in->nonceTPM,
					   RC_PolicySigned_nonceTPM,
					   RC_PolicySigned_cpHashA,
					   RC_PolicySigned_expiration);
	    if(result != TPM_RC_SUCCESS)
		return result;

	    // Re-compute the digest being signed
	    /*(See part 3 specification)
	    // The digest is computed as:
	    //     aHash := hash ( nonceTPM | expiration | cpHashA | policyRef)
	    //  where:
	    //      hash()      the hash associated with the signed auth
	    //      nonceTPM    the nonceTPM value from the TPM2_StartAuthSession .
	    //                  response If the authorization is not limited to this
	    //                  session, the size of this value is zero.
	    //      expiration  time limit on authorization set by authorizing object.
	    //                  This 32-bit value is set to zero if the expiration
	    //                  time is not being set.
	    //      cpHashA     hash of the command parameters for the command being
	    //                  approved using the hash algorithm of the PSAP session.
	    //                  Set to NULLauth if the authorization is not limited
	    //                  to a specific command.
	    //      policyRef   hash of an opaque value determined by the authorizing
	    //                  object.  Set to the NULLdigest if no hash is present.
	    */
	    // Start hash
	    authHash.t.size = CryptStartHash(CryptGetSignHashAlg(&in->auth),
					     &hashState);
	    // If there is no digest size, then we don't have a verification function
	    // for this algorithm (e.g. TPM_ALG_ECDAA) so indicate that it is a
	    // bad scheme.
	    if(authHash.t.size == 0)
		return TPM_RCS_SCHEME + RC_PolicySigned_auth;

	    //  add nonceTPM
	    CryptUpdateDigest2B(&hashState, &in->nonceTPM.b);

	    //  add expiration
	    CryptUpdateDigestInt(&hashState, sizeof(UINT32), (BYTE*) &in->expiration);

	    //  add cpHashA
	    CryptUpdateDigest2B(&hashState, &in->cpHashA.b);

	    //  add policyRef
	    CryptUpdateDigest2B(&hashState, &in->policyRef.b);

	    //  Complete digest
	    CryptCompleteHash2B(&hashState, &authHash.b);

	    // Validate Signature.  A TPM_RC_SCHEME, TPM_RC_HANDLE or TPM_RC_SIGNATURE
	    // error may be returned at this point
	    result = CryptVerifySignature(in->authObject, &authHash, &in->auth);
	    if(result != TPM_RC_SUCCESS)
		return RcSafeAddToResult(result, RC_PolicySigned_auth);
	}
    // Internal Data Update
    // Need the Name of the signing entity
    entityName.t.size = EntityGetName(in->authObject, &entityName.t.name);

    // Update policy with input policyRef and name of auth key
    // These values are updated even if the session is a trial session
    PolicyContextUpdate(TPM_CC_PolicySigned, &entityName, &in->policyRef,
			&in->cpHashA, authTimeout, session);

    // Command Output

    // Create ticket and timeout buffer if in->expiration < 0 and this is not
    // a trial session.
    // NOTE: PolicyParameterChecks() makes sure that nonceTPM is present
    // when expiration is non-zero.
    if(   in->expiration < 0
	  && session->attributes.isTrialPolicy == CLEAR
	  )
	{
	    // Generate timeout buffer.  The format of output timeout buffer is
	    // TPM-specific.
	    // Note: can't do a direct copy because the output buffer is a byte
	    // array and it may not be aligned to accept a 64-bit value.  The method
	    // used has the side-effect of making the returned value a big-endian,
	    // 64-bit value that is byte aligned.
	    out->timeout.t.size = sizeof(UINT64);
	    UINT64_TO_BYTE_ARRAY(authTimeout, out->timeout.t.buffer);

	    // Compute policy ticket
	    TicketComputeAuth(TPM_ST_AUTH_SIGNED, EntityGetHierarchy(in->authObject),
			      authTimeout, &in->cpHashA, &in->policyRef, &entityName,
			      &out->policyTicket);
	}
    else
	{
	    // Generate a null ticket.
	    // timeout buffer is null
	    out->timeout.t.size = 0;
	    // auth ticket is null
	    out->policyTicket.tag = TPM_ST_AUTH_SIGNED;
	    out->policyTicket.hierarchy = TPM_RH_NULL;
	    out->policyTicket.digest.t.size = 0;
	}
    return TPM_RC_SUCCESS;
}
#endif // CC_PolicySigned

/* 23.4	TPM2_PolicySecret */

#include "InternalRoutines.h"
#include "PolicySecret_fp.h"
#ifdef TPM_CC_PolicySecret  // Conditional expansion of this file
#include "Policy_spt_fp.h"

TPM_RC
TPM2_PolicySecret(
		  PolicySecret_In     *in,            // IN: input parameter list
		  PolicySecret_Out    *out            // OUT: output parameter list
		  )
{
    TPM_RC                   result;
    SESSION                 *session;
    TPM2B_NAME               entityName;
    INT64                    expiration = (in->expiration < 0)
					  ? -((INT64)in->expiration) : in->expiration;
    UINT64                   authTimeout = 0;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    //Only do input validation if this is not a trial policy session
    if(session->attributes.isTrialPolicy == CLEAR)
	{

	    if(expiration != 0)
		authTimeout = expiration * 1000 + session->startTime;
	    result = PolicyParameterChecks(session, authTimeout,
					   &in->cpHashA, &in->nonceTPM,
					   RC_PolicySecret_nonceTPM,
					   RC_PolicySecret_cpHashA,
					   RC_PolicySecret_expiration);
	    if(result != TPM_RC_SUCCESS)
		return result;
	}

    // Internal Data Update
    // Need the name of the authorizing entity
    entityName.t.size = EntityGetName(in->authHandle, &entityName.t.name);

    // Update policy context with input policyRef and name of auth key
    // This value is computed even for trial sessions. Possibly update the cpHash
    PolicyContextUpdate(TPM_CC_PolicySecret, &entityName, &in->policyRef,
			&in->cpHashA, authTimeout, session);

    // Command Output

    // Create ticket and timeout buffer if in->expiration < 0 and this is not
    // a trial session.
    // NOTE: PolicyParameterChecks() makes sure that nonceTPM is present
    // when expiration is non-zero.
    if(   in->expiration < 0
	  && session->attributes.isTrialPolicy == CLEAR
	  )
	{
	    // Generate timeout buffer.  The format of output timeout buffer is
	    // TPM-specific.
	    // Note: can't do a direct copy because the output buffer is a byte
	    // array and it may not be aligned to accept a 64-bit value.  The method
	    // used has the side-effect of making the returned value a big-endian,
	    // 64-bit value that is byte aligned.
	    out->timeout.t.size = sizeof(UINT64);
	    UINT64_TO_BYTE_ARRAY(authTimeout, out->timeout.t.buffer);

	    // Compute policy ticket
	    TicketComputeAuth(TPM_ST_AUTH_SECRET, EntityGetHierarchy(in->authHandle),
			      authTimeout, &in->cpHashA, &in->policyRef,
			      &entityName, &out->policyTicket);
	}
    else
	{
	    // timeout buffer is null
	    out->timeout.t.size = 0;
	    // auth ticket is null
	    out->policyTicket.tag = TPM_ST_AUTH_SECRET;
	    out->policyTicket.hierarchy = TPM_RH_NULL;
	    out->policyTicket.digest.t.size = 0;
	}

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicySecret

/* 23.5	TPM2_PolicyTicket */

#include "InternalRoutines.h"
#include "PolicyTicket_fp.h"
#ifdef TPM_CC_PolicyTicket  // Conditional expansion of this file
#include "Policy_spt_fp.h"

TPM_RC
TPM2_PolicyTicket(
		  PolicyTicket_In     *in             // IN: input parameter list
		  )
{
    TPM_RC                   result;
    SESSION                 *session;
    UINT64                   timeout;
    TPMT_TK_AUTH             ticketToCompare;
    TPM_CC                   commandCode = TPM_CC_PolicySecret;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // NOTE: A trial policy session is not allowed to use this command.
    // A ticket is used in place of a previously given authorization. Since
    // a trial policy doesn't actually authenticate, the validated
    // ticket is not necessary and, in place of using a ticket, one
    // should use the intended authorization for which the ticket
    // would be a substitute.
    if(session->attributes.isTrialPolicy)
	return TPM_RCS_ATTRIBUTES + RC_PolicyTicket_policySession;

    // Restore timeout data.  The format of timeout buffer is TPM-specific.
    // In this implementation, we simply copy the value of timeout to the
    // buffer.
    if(in->timeout.t.size != sizeof(UINT64))
	return TPM_RCS_SIZE + RC_PolicyTicket_timeout;
    timeout = BYTE_ARRAY_TO_UINT64(in->timeout.t.buffer);

    // Do the normal checks on the cpHashA and timeout values
    result = PolicyParameterChecks(session, timeout,
				   &in->cpHashA, NULL,
				   0,                       // no bad nonce return
				   RC_PolicyTicket_cpHashA,
				   RC_PolicyTicket_timeout);
    if(result != TPM_RC_SUCCESS)
	return result;

    // Validate Ticket
    // Re-generate policy ticket by input parameters
    TicketComputeAuth(in->ticket.tag, in->ticket.hierarchy, timeout, &in->cpHashA,
		      &in->policyRef, &in->authName, &ticketToCompare);

    // Compare generated digest with input ticket digest
    if(!Memory2BEqual(&in->ticket.digest.b, &ticketToCompare.digest.b))
	return TPM_RCS_TICKET + RC_PolicyTicket_ticket;

    // Internal Data Update

    // Is this ticket to take the place of a TPM2_PolicySigned() or
    // a TPM2_PolicySecret()?
    if(in->ticket.tag == TPM_ST_AUTH_SIGNED)
	commandCode = TPM_CC_PolicySigned;
    else if(in->ticket.tag == TPM_ST_AUTH_SECRET)
	commandCode = TPM_CC_PolicySecret;
    else
	// There could only be two possible tag values.  Any other value should
	// be caught by the ticket validation process.
	pAssert(FALSE);

    // Update policy context
    PolicyContextUpdate(commandCode, &in->authName, &in->policyRef,
			&in->cpHashA, timeout, session);

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyTicket

/* 23.6	TPM2_PolicyOR */

#include "InternalRoutines.h"
#include "PolicyOR_fp.h"
#ifdef TPM_CC_PolicyOR  // Conditional expansion of this file
#include "Policy_spt_fp.h"

TPM_RC
TPM2_PolicyOR(
	      PolicyOR_In     *in             // IN: input parameter list
	      )
{
    SESSION     *session;
    UINT32       i;

    // Input Validation and Update
    
    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Compare and Update Internal Session policy if match
    for(i = 0; i < in->pHashList.count; i++)
	{
	    if(   session->attributes.isTrialPolicy == SET
		  || (Memory2BEqual(&session->u2.policyDigest.b,
				    &in->pHashList.digests[i].b))
		  )
		{
		    // Found a match
		    HASH_STATE      hashState;
		    TPM_CC          commandCode = TPM_CC_PolicyOR;

		    // Start hash
		    session->u2.policyDigest.t.size = CryptStartHash(session->authHashAlg,
								     &hashState);
		    // Set policyDigest to 0 string and add it to hash
		    MemorySet(session->u2.policyDigest.t.buffer, 0,
			      session->u2.policyDigest.t.size);
		    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

		    // add command code
		    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

		    // Add each of the hashes in the list
		    for(i = 0; i < in->pHashList.count; i++)
			{
			    // Extend policyDigest
			    CryptUpdateDigest2B(&hashState, &in->pHashList.digests[i].b);
			}
		    // Complete digest
		    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

		    return TPM_RC_SUCCESS;
		}
	}
    // None of the values in the list matched the current policyDigest
    return TPM_RCS_VALUE + RC_PolicyOR_pHashList;
}
#endif // CC_PolicyOR

/* 23.7	TPM2_PolicyPCR */

#include "InternalRoutines.h"
#include "PolicyPCR_fp.h"
#ifdef TPM_CC_PolicyPCR  // Conditional expansion of this file

TPM_RC
TPM2_PolicyPCR(
	       PolicyPCR_In    *in             // IN: input parameter list
	       )
{
    SESSION         *session;
    TPM2B_DIGEST     pcrDigest;
    BYTE             pcrs[sizeof(TPML_PCR_SELECTION)];
    UINT32           pcrSize;
    BYTE            *buffer;
    TPM_CC           commandCode = TPM_CC_PolicyPCR;
    HASH_STATE       hashState;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Do validation for non trial session
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    // Make sure that this is not going to invalidate a previous PCR check
	    if(session->pcrCounter != 0 && session->pcrCounter != gr.pcrCounter)
		return TPM_RC_PCR_CHANGED;

	    // Compute current PCR digest
	    PCRComputeCurrentDigest(session->authHashAlg, &in->pcrs, &pcrDigest);

	    // If the caller specified the PCR digest and it does not
	    // match the current PCR settings, return an error..
	    if(in->pcrDigest.t.size != 0)
		{
		    if(!Memory2BEqual(&in->pcrDigest.b, &pcrDigest.b))
			return TPM_RCS_VALUE + RC_PolicyPCR_pcrDigest;
		}
	}
    else
	{
	    // For trial session, just use the input PCR digest
	    pcrDigest = in->pcrDigest;
	}
    // Internal Data Update

    // Update policy hash
    // policyDigestnew = hash(   policyDigestold || TPM_CC_PolicyPCR
    //                      || pcrs || pcrDigest)
    //  Start hash
    CryptStartHash(session->authHashAlg, &hashState);

    //  add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  add PCRS
    buffer = pcrs;
    pcrSize = TPML_PCR_SELECTION_Marshal(&in->pcrs, &buffer, NULL);
    CryptUpdateDigest(&hashState, pcrSize, pcrs);

    //  add PCR digest
    CryptUpdateDigest2B(&hashState, &pcrDigest.b);

    //  complete the hash and get the results
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    //  update pcrCounter in session context for non trial session
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    session->pcrCounter = gr.pcrCounter;
	}

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyPCR

/* 23.8	TPM2_PolicyLocality */

#include "InternalRoutines.h"
#include "PolicyLocality_fp.h"
#ifdef TPM_CC_PolicyLocality  // Conditional expansion of this file

TPM_RC
TPM2_PolicyLocality(
		    PolicyLocality_In   *in             // IN: input parameter list
		    )
{
    SESSION     *session;
    BYTE         marshalBuffer[sizeof(TPMA_LOCALITY)];
    BYTE         prevSetting[sizeof(TPMA_LOCALITY)];
    UINT32       marshalSize;
    BYTE        *buffer;
    TPM_CC       commandCode = TPM_CC_PolicyLocality;
    HASH_STATE   hashState;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Get new locality setting in canonical form
    buffer = marshalBuffer;
    marshalSize = TPMA_LOCALITY_Marshal(&in->locality, &buffer, NULL);

    // Its an error if the locality parameter is zero
    if(marshalBuffer[0] == 0)
	return TPM_RCS_RANGE + RC_PolicyLocality_locality;

    // Get existing locality setting in canonical form
    buffer = prevSetting;
    TPMA_LOCALITY_Marshal(&session->commandLocality, &buffer, NULL);

    // If the locality has previously been set
    if(    prevSetting[0] != 0
	   // then the current locality setting and the requested have to be the same
	   // type (that is, either both normal or both extended
	   && ((prevSetting[0] < 32) != (marshalBuffer[0] < 32)))
	return TPM_RCS_RANGE + RC_PolicyLocality_locality;

    // See if the input is a regular or extended locality
    if(marshalBuffer[0] < 32)
	{
	    // if there was no previous setting, start with all normal localities
	    // enabled
	    if(prevSetting[0] == 0)
		prevSetting[0] = 0x1F;

	    // AND the new setting with the previous setting and store it in prevSetting
	    prevSetting[0] &= marshalBuffer[0];

	    // The result setting can not be 0
	    if(prevSetting[0] == 0)
		return TPM_RCS_RANGE + RC_PolicyLocality_locality;
	}
    else
	{
	    // for extended locality
	    // if the locality has already been set, then it must match the
	    if(prevSetting[0] != 0 && prevSetting[0] != marshalBuffer[0])
		return TPM_RCS_RANGE + RC_PolicyLocality_locality;

	    // Setting is OK
	    prevSetting[0] = marshalBuffer[0];

	}

    // Internal Data Update

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyLocality || locality)
    // Start hash
    CryptStartHash(session->authHashAlg, &hashState);

    // add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    // add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    // add input locality
    CryptUpdateDigest(&hashState, marshalSize, marshalBuffer);

    // complete the digest
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    // update session locality by unmarshal function.  The function must succeed
    // because both input and existing locality setting have been validated.
    buffer = prevSetting;
    TPMA_LOCALITY_Unmarshal(&session->commandLocality, &buffer,
			    (INT32 *) &marshalSize);

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyLocality

/* 23.9	TPM2_PolicyNV */

#include "InternalRoutines.h"
#include "PolicyNV_fp.h"
#ifdef TPM_CC_PolicyNV  // Conditional expansion of this file
#include "Policy_spt_fp.h"
#include "NV_spt_fp.h"          // Include NV support routine for read access check

TPM_RC
TPM2_PolicyNV(
	      PolicyNV_In     *in             // IN: input parameter list
	      )
{
    TPM_RC               result;
    SESSION             *session;
    NV_INDEX             nvIndex;
    BYTE		 nvBuffer[sizeof(in->operandB.t.buffer)];
    TPM2B_NAME           nvName;
    TPM_CC               commandCode = TPM_CC_PolicyNV;
    HASH_STATE           hashState;
    TPM2B_DIGEST         argHash;

    // Input Validation

    // Get NV index information
    NvGetIndexInfo(in->nvIndex, &nvIndex);

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    //If this is a trial policy, skip all validations and the operation
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    // NV Read access check.  NV index should be allowed for read.  A
	    // TPM_RC_AUTH_TYPE or TPM_RC_NV_LOCKED error may be return at this
	    // point
	    result = NvReadAccessChecks(in->authHandle, in->nvIndex);
	    if(result != TPM_RC_SUCCESS)
		return result;

	    // Make sure that offset is withing range
	    if(in->offset > nvIndex.publicArea.dataSize)
		return TPM_RCS_VALUE + RC_PolicyNV_offset;

	    // Valid NV data size should not be smaller than input operandB size
	    if((nvIndex.publicArea.dataSize - in->offset) < in->operandB.t.size)
		return TPM_RCS_SIZE + RC_PolicyNV_operandB;

	    // Arithmetic Comparison

	    // Get NV data.  The size of NV data equals the input operand B size
	    NvGetIndexData(in->nvIndex, &nvIndex, in->offset,
			   in->operandB.t.size, nvBuffer);

	    switch(in->operation)
		{
		  case TPM_EO_EQ:
		    // compare A = B
		    if(CryptCompare(in->operandB.t.size, nvBuffer,
				    in->operandB.t.size, in->operandB.t.buffer) != 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_NEQ:
		    // compare A != B
		    if(CryptCompare(in->operandB.t.size, nvBuffer,
				    in->operandB.t.size, in->operandB.t.buffer) == 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_SIGNED_GT:
		    // compare A > B signed
		    if(CryptCompareSigned(in->operandB.t.size, nvBuffer,
					  in->operandB.t.size, in->operandB.t.buffer) <= 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_UNSIGNED_GT:
		    // compare A > B unsigned
		    if(CryptCompare(in->operandB.t.size, nvBuffer,
				    in->operandB.t.size, in->operandB.t.buffer) <= 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_SIGNED_LT:
		    // compare A < B signed
		    if(CryptCompareSigned(in->operandB.t.size, nvBuffer,
					  in->operandB.t.size, in->operandB.t.buffer) >= 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_UNSIGNED_LT:
		    // compare A < B unsigned
		    if(CryptCompare(in->operandB.t.size, nvBuffer,
				    in->operandB.t.size, in->operandB.t.buffer) >= 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_SIGNED_GE:
		    // compare A >= B signed
		    if(CryptCompareSigned(in->operandB.t.size, nvBuffer,
					  in->operandB.t.size, in->operandB.t.buffer) < 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_UNSIGNED_GE:
		    // compare A >= B unsigned
		    if(CryptCompare(in->operandB.t.size, nvBuffer,
				    in->operandB.t.size, in->operandB.t.buffer) < 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_SIGNED_LE:
		    // compare A <= B signed
		    if(CryptCompareSigned(in->operandB.t.size, nvBuffer,
					  in->operandB.t.size, in->operandB.t.buffer) > 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_UNSIGNED_LE:
		    // compare A <= B unsigned
		    if(CryptCompare(in->operandB.t.size, nvBuffer,
				    in->operandB.t.size, in->operandB.t.buffer) > 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_BITSET:
		    // All bits SET in B are SET in A. ((A&B)=B)
		      {
			  UINT32 i;
			  for (i = 0; i < in->operandB.t.size; i++)
			      if((nvBuffer[i] & in->operandB.t.buffer[i])
				 != in->operandB.t.buffer[i])
				  return TPM_RC_POLICY;
		      }
		      break;
		  case TPM_EO_BITCLEAR:
		    // All bits SET in B are CLEAR in A. ((A&B)=0)
		      {
			  UINT32 i;
			  for (i = 0; i < in->operandB.t.size; i++)
			      if((nvBuffer[i] & in->operandB.t.buffer[i]) != 0)
				  return TPM_RC_POLICY;
		      }
		      break;
		  default:
		    pAssert(FALSE);
		    break;
		}
	}

    // Internal Data Update

    // Start argument hash
    argHash.t.size = CryptStartHash(session->authHashAlg, &hashState);

    //  add operandB
    CryptUpdateDigest2B(&hashState, &in->operandB.b);

    //  add offset
    CryptUpdateDigestInt(&hashState, sizeof(UINT16), &in->offset);

    //  add operation
    CryptUpdateDigestInt(&hashState, sizeof(TPM_EO), &in->operation);

    //  complete argument digest
    CryptCompleteHash2B(&hashState, &argHash.b);

    // Update policyDigest
    //  Start digest
    CryptStartHash(session->authHashAlg, &hashState);

    //  add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  add argument digest
    CryptUpdateDigest2B(&hashState, &argHash.b);

    // Adding nvName
    nvName.t.size = EntityGetName(in->nvIndex, &nvName.t.name);
    CryptUpdateDigest2B(&hashState, &nvName.b);

    // complete the digest
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyNV

/* 23.10	TPM2_PolicyCounterTimer */

#include "InternalRoutines.h"
#include "PolicyCounterTimer_fp.h"
#ifdef TPM_CC_PolicyCounterTimer  // Conditional expansion of this file
#include "Policy_spt_fp.h"

TPM_RC
TPM2_PolicyCounterTimer(
			PolicyCounterTimer_In   *in             // IN: input parameter list
			)
{
    TPM_RC               result;
    SESSION             *session;
    TIME_INFO            infoData;      // data buffer of  TPMS_TIME_INFO
    TPM_CC               commandCode = TPM_CC_PolicyCounterTimer;
    HASH_STATE           hashState;
    TPM2B_DIGEST         argHash;

    // Input Validation

    // If the command is going to use any part of the counter or timer, need
    // to verify that time is advancing.
    // The time and clock vales are the first two 64-bit values in the clock
    if(in->offset < sizeof(UINT64) + sizeof(UINT64))
	{
	    // Using Clock or Time so see if clock is running. Clock doesn't run while
	    // NV is unavailable.
	    // TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned here.
	    result = NvIsAvailable();
	    if(result != TPM_RC_SUCCESS)
		return result;
	}
    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    //If this is a trial policy, skip all validations and the operation
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    // Get time data info.  The size of time info data equals the input
	    // operand B size.  A TPM_RC_RANGE or TPM_RC_VALUE error may be returned.
	    // NOTE: The reaons that there is no check in this function that the offset
	    // is within the allowed range is because the allowed range depends on the
	    // marshaled sise of the TPMS_TIME_INFO structure. The size for that is
	    // not known in this function so the offset check is deferred to
	    // TimeGetRange().
	    result = TimeGetRange(in->offset, in->operandB.t.size, &infoData);
	    if(result != TPM_RC_SUCCESS)
		{
		    // handle offset out of range
		    if(result == TPM_RC_VALUE)
			return TPM_RCS_VALUE + RC_PolicyCounterTimer_offset;
		    return result;
		}

	    // Arithmetic Comparison
	    switch(in->operation)
		{
		  case TPM_EO_EQ:
		    // compare A = B
		    if(CryptCompare(in->operandB.t.size, infoData,
				    in->operandB.t.size, in->operandB.t.buffer) != 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_NEQ:
		    // compare A != B
		    if(CryptCompare(in->operandB.t.size, infoData,
				    in->operandB.t.size, in->operandB.t.buffer) == 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_SIGNED_GT:
		    // compare A > B signed
		    if(CryptCompareSigned(in->operandB.t.size, infoData,
					  in->operandB.t.size, in->operandB.t.buffer) <= 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_UNSIGNED_GT:
		    // compare A > B unsigned
		    if(CryptCompare(in->operandB.t.size, infoData,
				    in->operandB.t.size, in->operandB.t.buffer) <= 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_SIGNED_LT:
		    // compare A < B signed
		    if(CryptCompareSigned(in->operandB.t.size, infoData,
					  in->operandB.t.size, in->operandB.t.buffer) >= 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_UNSIGNED_LT:
		    // compare A < B unsigned
		    if(CryptCompare(in->operandB.t.size, infoData,
				    in->operandB.t.size, in->operandB.t.buffer) >= 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_SIGNED_GE:
		    // compare A >= B signed
		    if(CryptCompareSigned(in->operandB.t.size, infoData,
					  in->operandB.t.size, in->operandB.t.buffer) < 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_UNSIGNED_GE:
		    // compare A >= B unsigned
		    if(CryptCompare(in->operandB.t.size, infoData,
				    in->operandB.t.size, in->operandB.t.buffer) < 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_SIGNED_LE:
		    // compare A <= B signed
		    if(CryptCompareSigned(in->operandB.t.size, infoData,
					  in->operandB.t.size, in->operandB.t.buffer) > 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_UNSIGNED_LE:
		    // compare A <= B unsigned
		    if(CryptCompare(in->operandB.t.size, infoData,
				    in->operandB.t.size, in->operandB.t.buffer) > 0)
			return TPM_RC_POLICY;
		    break;
		  case TPM_EO_BITSET:
		    // All bits SET in B are SET in A. ((A&B)=B)
		      {
			  UINT32 i;
			  for (i = 0; i < in->operandB.t.size; i++)
			      if(   (infoData[i] & in->operandB.t.buffer[i])
				    != in->operandB.t.buffer[i])
				  return TPM_RC_POLICY;
		      }
		      break;
		  case TPM_EO_BITCLEAR:
		    // All bits SET in B are CLEAR in A. ((A&B)=0)
		      {
			  UINT32 i;
			  for (i = 0; i < in->operandB.t.size; i++)
			      if((infoData[i] & in->operandB.t.buffer[i]) != 0)
				  return TPM_RC_POLICY;
		      }
		      break;
		  default:
		    pAssert(FALSE);
		    break;
		}
	}

    // Internal Data Update

    // Start argument list hash
    argHash.t.size = CryptStartHash(session->authHashAlg, &hashState);
    //  add operandB
    CryptUpdateDigest2B(&hashState, &in->operandB.b);
    //  add offset
    CryptUpdateDigestInt(&hashState, sizeof(UINT16), &in->offset);
    //  add operation
    CryptUpdateDigestInt(&hashState, sizeof(TPM_EO), &in->operation);
    //  complete argument hash
    CryptCompleteHash2B(&hashState, &argHash.b);

    // update policyDigest
    //  start hash
    CryptStartHash(session->authHashAlg, &hashState);

    //  add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  add argument digest
    CryptUpdateDigest2B(&hashState, &argHash.b);

    // complete the digest
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyCounterTimer

/* 23.11	TPM2_PolicyCommandCode */

#include "InternalRoutines.h"
#include "PolicyCommandCode_fp.h"
#ifdef TPM_CC_PolicyCommandCode  // Conditional expansion of this file

TPM_RC
TPM2_PolicyCommandCode(
		       PolicyCommandCode_In    *in             // IN: input parameter list
		       )
{
    SESSION     *session;
    TPM_CC      commandCode = TPM_CC_PolicyCommandCode;
    HASH_STATE  hashState;

    // Input validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    if(session->commandCode != 0 && session->commandCode != in->code)
	return TPM_RCS_VALUE + RC_PolicyCommandCode_code;

    if(CommandCodeToCommandIndex(in->code) == UNIMPLEMENTED_COMMAND_INDEX)
	return TPM_RCS_POLICY_CC + RC_PolicyCommandCode_code;

    // Internal Data Update
    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyCommandCode || code)
    //  Start hash
    CryptStartHash(session->authHashAlg, &hashState);

    //  add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  add input commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &in->code);

    //  complete the hash and get the results
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    // update commandCode value in session context
    session->commandCode = in->code;

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyCommandCode

/* 23.12	TPM2_PolicyPhysicalPresence */

#include "InternalRoutines.h"
#include "PolicyPhysicalPresence_fp.h"
#ifdef TPM_CC_PolicyPhysicalPresence  // Conditional expansion of this file

TPM_RC
TPM2_PolicyPhysicalPresence(
			    PolicyPhysicalPresence_In   *in             // IN: input parameter list
			    )
{
    SESSION     *session;
    TPM_CC      commandCode = TPM_CC_PolicyPhysicalPresence;
    HASH_STATE  hashState;

    // Internal Data Update

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyPhysicalPresence)
    //  Start hash
    CryptStartHash(session->authHashAlg, &hashState);

    //  add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  complete the digest
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    // update session attribute
    session->attributes.isPPRequired = SET;

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyPhysicalPresence

/* 23.13	TPM2_PolicyCpHash */

#include "InternalRoutines.h"
#include "PolicyCpHash_fp.h"
#ifdef TPM_CC_PolicyCpHash  // Conditional expansion of this file

TPM_RC
TPM2_PolicyCpHash(
		  PolicyCpHash_In     *in             // IN: input parameter list
		  )
{
    SESSION     *session;
    TPM_CC      commandCode = TPM_CC_PolicyCpHash;
    HASH_STATE  hashState;

    // Input Validation
    
    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // A new cpHash is given in input parameter, but cpHash in session context
    // is not empty, or is not the same as the new cpHash
    if(    in->cpHashA.t.size != 0
	   && session->u1.cpHash.t.size != 0
	   && !Memory2BEqual(&in->cpHashA.b, &session->u1.cpHash.b)
	   )
	return TPM_RC_CPHASH;

    // A valid cpHash must have the same size as session hash digest
    if(in->cpHashA.t.size != CryptGetHashDigestSize(session->authHashAlg))
	return TPM_RCS_SIZE + RC_PolicyCpHash_cpHashA;

    // Internal Data Update

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyCpHash || cpHashA)
    //  Start hash
    CryptStartHash(session->authHashAlg, &hashState);

    //  add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  add cpHashA
    CryptUpdateDigest2B(&hashState, &in->cpHashA.b);

    //  complete the digest and get the results
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    // update cpHash in session context
    session->u1.cpHash = in->cpHashA;
    session->attributes.iscpHashDefined = SET;

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyCpHash

/* 23.14	TPM2_PolicyNameHash */

#include "InternalRoutines.h"
#include "PolicyNameHash_fp.h"
#ifdef TPM_CC_PolicyNameHash  // Conditional expansion of this file

TPM_RC
TPM2_PolicyNameHash(
		    PolicyNameHash_In   *in             // IN: input parameter list
		    )
{
    SESSION             *session;
    TPM_CC               commandCode = TPM_CC_PolicyNameHash;
    HASH_STATE           hashState;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // A new nameHash is given in input parameter, but cpHash in session context
    // is not empty
    if(in->nameHash.t.size != 0 && session->u1.cpHash.t.size != 0)
	return TPM_RC_CPHASH;

    // A valid nameHash must have the same size as session hash digest
    if(in->nameHash.t.size != CryptGetHashDigestSize(session->authHashAlg))
	return TPM_RCS_SIZE + RC_PolicyNameHash_nameHash;

    // Internal Data Update

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyNameHash || nameHash)
    //  Start hash
    CryptStartHash(session->authHashAlg, &hashState);

    //  add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  add nameHash
    CryptUpdateDigest2B(&hashState, &in->nameHash.b);

    //  complete the digest
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    //  clear iscpHashDefined bit to indicate now this field contains a nameHash
    session->attributes.iscpHashDefined = CLEAR;

    // update nameHash in session context
    session->u1.cpHash = in->nameHash;

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyNameHash

/* 23.15	TPM2_PolicyDuplicationSelect */

#include "InternalRoutines.h"
#include "PolicyDuplicationSelect_fp.h"
#ifdef TPM_CC_PolicyDuplicationSelect  // Conditional expansion of this file

TPM_RC
TPM2_PolicyDuplicationSelect(
			     PolicyDuplicationSelect_In  *in             // IN: input parameter list
			     )
{
    SESSION         *session;
    HASH_STATE      hashState;
    TPM_CC          commandCode = TPM_CC_PolicyDuplicationSelect;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // cpHash in session context must be empty
    if(session->u1.cpHash.t.size != 0)
	return TPM_RC_CPHASH;

    // commandCode in session context must be empty
    if(session->commandCode != 0)
	return TPM_RC_COMMAND_CODE;

    // Internal Data Update

    // Update name hash
    session->u1.cpHash.t.size = CryptStartHash(session->authHashAlg, &hashState);

    //  add objectName
    CryptUpdateDigest2B(&hashState, &in->objectName.b);

    //  add new parent name
    CryptUpdateDigest2B(&hashState, &in->newParentName.b);

    //  complete hash
    CryptCompleteHash2B(&hashState, &session->u1.cpHash.b);

    // update policy hash
    // Old policyDigest size should be the same as the new policyDigest size since
    // they are using the same hash algorithm
    session->u2.policyDigest.t.size
	= CryptStartHash(session->authHashAlg, &hashState);

    //  add old policy
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    //  add command code
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  add objectName
    if(in->includeObject == YES)
	CryptUpdateDigest2B(&hashState, &in->objectName.b);

    //  add new parent name
    CryptUpdateDigest2B(&hashState, &in->newParentName.b);

    //  add includeObject
    CryptUpdateDigestInt(&hashState, sizeof(TPMI_YES_NO), &in->includeObject);

    //  complete digest
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    // clear iscpHashDefined bit to indicate now this field contains a nameHash
    session->attributes.iscpHashDefined = CLEAR;

    // set commandCode in session context
    session->commandCode = TPM_CC_Duplicate;

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyDuplicationSelect

/* 23.16	TPM2_PolicyAuthorize */

#include "InternalRoutines.h"
#include "PolicyAuthorize_fp.h"
#ifdef TPM_CC_PolicyAuthorize  // Conditional expansion of this file
#include "Policy_spt_fp.h"

TPM_RC
TPM2_PolicyAuthorize(
		     PolicyAuthorize_In  *in             // IN: input parameter list
		     )
{
    SESSION                 *session;
    TPM2B_DIGEST             authHash;
    HASH_STATE               hashState;
    TPMT_TK_VERIFIED         ticket;
    TPM_ALG_ID               hashAlg;
    UINT16                   digestSize;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Extract from the Name of the key, the algorithm used to compute it's Name
    hashAlg = BYTE_ARRAY_TO_UINT16(in->keySign.t.name);

    // 'keySign' parameter needs to use a supported hash algorithm, otherwise
    // can't tell how large the digest should be
    digestSize = CryptGetHashDigestSize(hashAlg);
    if(digestSize == 0)
	return TPM_RCS_HASH + RC_PolicyAuthorize_keySign;

    if(digestSize != (in->keySign.t.size - 2))
	return TPM_RCS_SIZE + RC_PolicyAuthorize_keySign;

    //If this is a trial policy, skip all validations
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    // Check that "approvedPolicy" matches the current value of the
	    // policyDigest in policy session
	    if(!Memory2BEqual(&session->u2.policyDigest.b,
			      &in->approvedPolicy.b))
		return TPM_RCS_VALUE + RC_PolicyAuthorize_approvedPolicy;
	    
	    // Validate ticket TPMT_TK_VERIFIED
	    // Compute aHash.  The authorizing object sign a digest
	    //  aHash := hash(approvedPolicy || policyRef).
	    // Start hash
	    authHash.t.size = CryptStartHash(hashAlg, &hashState);

	    // add approvedPolicy
	    CryptUpdateDigest2B(&hashState, &in->approvedPolicy.b);

	    // add policyRef
	    CryptUpdateDigest2B(&hashState, &in->policyRef.b);

	    // complete hash
	    CryptCompleteHash2B(&hashState, &authHash.b);

	    // re-compute TPMT_TK_VERIFIED
	    TicketComputeVerified(in->checkTicket.hierarchy, &authHash,
				  &in->keySign, &ticket);

	    // Compare ticket digest.  If not match, return error
	    if(!Memory2BEqual(&in->checkTicket.digest.b, &ticket.digest.b))
		return TPM_RCS_VALUE+ RC_PolicyAuthorize_checkTicket;
	}

    // Internal Data Update

    // Set policyDigest to zero digest
    MemorySet(session->u2.policyDigest.t.buffer, 0,
	      session->u2.policyDigest.t.size);

    // Update policyDigest
    PolicyContextUpdate(TPM_CC_PolicyAuthorize, &in->keySign, &in->policyRef,
			NULL, 0, session);

    return TPM_RC_SUCCESS;

}
#endif // CC_PolicyAuthorize

/* 23.17	TPM2_PolicyAuthValue */


#include "InternalRoutines.h"
#include "PolicyAuthValue_fp.h"
#ifdef TPM_CC_PolicyAuthValue  // Conditional expansion of this file
#include "Policy_spt_fp.h"

TPM_RC
TPM2_PolicyAuthValue(
		     PolicyAuthValue_In  *in             // IN: input parameter list
		     )
{
    SESSION             *session;
    TPM_CC               commandCode = TPM_CC_PolicyAuthValue;
    HASH_STATE           hashState;

    // Internal Data Update

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyAuthValue)
    //   Start hash
    CryptStartHash(session->authHashAlg, &hashState);

    //  add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  complete the hash and get the results
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    // update isAuthValueNeeded bit in the session context
    session->attributes.isAuthValueNeeded = SET;
    session->attributes.isPasswordNeeded = CLEAR;

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyAuthValue

/* 23.18	TPM2_PolicyPassword */

#include "InternalRoutines.h"
#include "PolicyPassword_fp.h"
#ifdef TPM_CC_PolicyPassword  // Conditional expansion of this file
#include "Policy_spt_fp.h"

TPM_RC
TPM2_PolicyPassword(
		    PolicyPassword_In   *in             // IN: input parameter list
		    )
{
    SESSION             *session;
    TPM_CC               commandCode = TPM_CC_PolicyAuthValue;
    HASH_STATE           hashState;

    // Internal Data Update

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyAuthValue)
    //  Start hash
    CryptStartHash(session->authHashAlg, &hashState);

    //  add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  complete the digest
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    //  Update isPasswordNeeded bit
    session->attributes.isPasswordNeeded = SET;
    session->attributes.isAuthValueNeeded = CLEAR;

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyPassword

/* 23.19	TPM2_PolicyGetDigest */

#include "InternalRoutines.h"
#include "PolicyGetDigest_fp.h"
#ifdef TPM_CC_PolicyGetDigest  // Conditional expansion of this file

TPM_RC
TPM2_PolicyGetDigest(
		     PolicyGetDigest_In      *in,            // IN: input parameter list
		     PolicyGetDigest_Out     *out            // OUT: output parameter list
		     )
{
    SESSION     *session;

    // Command Output

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    out->policyDigest = session->u2.policyDigest;

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyGetDigest

/* 23.20	TPM2_PolicyNvWritten */

#include "InternalRoutines.h"
#include "PolicyNvWritten_fp.h"
#ifdef TPM_CC_PolicyNvWritten  // Conditional expansion of this file

TPM_RC
TPM2_PolicyNvWritten(
		     PolicyNvWritten_In  *in             // IN: input parameter list
		     )
{
    SESSION     *session;
    TPM_CC       commandCode = TPM_CC_PolicyNvWritten;
    HASH_STATE   hashState;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // If already set is this a duplicate (the same setting)? If it
    // is a conflicting setting, it is an error
    if(session->attributes.checkNvWritten == SET)
	{
	    if((    (session->attributes.nvWrittenState == SET)
		    !=  (in->writtenSet == YES)))
		return TPM_RCS_VALUE + RC_PolicyNvWritten_writtenSet;
	}

    // Internal Data Update

    // Set session attributes so that the NV Index needs to be checked
    session->attributes.checkNvWritten = SET;
    session->attributes.nvWrittenState = (in->writtenSet == YES);

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyNvWritten
    //                          || writtenSet)
    // Start hash
    CryptStartHash(session->authHashAlg, &hashState);

    // add old digest
    CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

    // add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    // add the byte of writtenState
    CryptUpdateDigestInt(&hashState, sizeof(TPMI_YES_NO), &in->writtenSet);

    // complete the digest
    CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyNvWritten
