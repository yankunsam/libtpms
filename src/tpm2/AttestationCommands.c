/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: AttestationCommands.c 55 2015-02-05 22:03:16Z kgoldman $	*/
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

/* 18.2	TPM2_Certify */

#include "InternalRoutines.h"
#include "Attest_spt_fp.h"
#include "Certify_fp.h"
#ifdef TPM_CC_Certify  // Conditional expansion of this file

TPM_RC
TPM2_Certify(
	     Certify_In      *in,            // IN: input parameter list
	     Certify_Out     *out            // OUT: output parameter list
	     )
{
    TPM_RC                  result;
    TPMS_ATTEST             certifyInfo;

    // Command Output

    // Filling in attest information
    // Common fields
    result = FillInAttestInfo(in->signHandle,
			      &in->inScheme,
			      &in->qualifyingData,
			      &certifyInfo);
    if(result != TPM_RC_SUCCESS)
	{
	    if(result == TPM_RC_KEY)
		return TPM_RCS_KEY + RC_Certify_signHandle;
	    else
		return RcSafeAddToResult(result, RC_Certify_inScheme);
	}
    // Certify specific fields
    // Attestation type
    certifyInfo.type = TPM_ST_ATTEST_CERTIFY;
    // Certified object name
    certifyInfo.attested.certify.name.t.size =
	ObjectGetName(in->objectHandle,
		      &certifyInfo.attested.certify.name.t.name);
    // Certified object qualified name
    ObjectGetQualifiedName(in->objectHandle,
			   &certifyInfo.attested.certify.qualifiedName);

    // Sign attestation structure.  A NULL signature will be returned if
    // signHandle is TPM_RH_NULL.  A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned
    // by SignAttestInfo()
    result = SignAttestInfo(in->signHandle,
			    &in->inScheme,
			    &certifyInfo,
			    &in->qualifyingData,
			    &out->certifyInfo,
			    &out->signature);

    // TPM_RC_ATTRIBUTES cannot be returned here as FillInAttestInfo would already
    // have returned TPM_RC_KEY
    pAssert(result != TPM_RC_ATTRIBUTES);

    if(result != TPM_RC_SUCCESS)
	return result;

    // orderly state should be cleared because of the reporting of clock info
    // if signing happens
    if(in->signHandle != TPM_RH_NULL)
	g_clearOrderly = TRUE;

    return TPM_RC_SUCCESS;
}
#endif // CC_Certify

/* 18.3	TPM2_CertifyCreation */

#include "InternalRoutines.h"
#include "Attest_spt_fp.h"
#include "CertifyCreation_fp.h"
#ifdef TPM_CC_CertifyCreation  // Conditional expansion of this file

TPM_RC
TPM2_CertifyCreation(
		     CertifyCreation_In      *in,            // IN: input parameter list
		     CertifyCreation_Out     *out            // OUT: output parameter list
		     )
{
    TPM_RC                  result;
    TPM2B_NAME              name;
    TPMT_TK_CREATION        ticket;
    TPMS_ATTEST             certifyInfo;

    // Input Validation

    // CertifyCreation specific input validation
    // Get certified object name
    name.t.size = ObjectGetName(in->objectHandle, &name.t.name);
    // Re-compute ticket
    TicketComputeCreation(in->creationTicket.hierarchy, &name,
			  &in->creationHash, &ticket);
    // Compare ticket
    if(!Memory2BEqual(&ticket.digest.b, &in->creationTicket.digest.b))
	return TPM_RCS_TICKET + RC_CertifyCreation_creationTicket;

    // Command Output
    // Common fields
    result = FillInAttestInfo(in->signHandle,  &in->inScheme, &in->qualifyingData,
			      &certifyInfo);
    if(result != TPM_RC_SUCCESS)
	{
	    if(result == TPM_RC_KEY)
		return TPM_RCS_KEY + RC_CertifyCreation_signHandle;
	    else
		return RcSafeAddToResult(result, RC_CertifyCreation_inScheme);
	}

    // CertifyCreation specific fields
    // Attestation type
    certifyInfo.type = TPM_ST_ATTEST_CREATION;
    certifyInfo.attested.creation.objectName = name;

    // Copy the creationHash
    certifyInfo.attested.creation.creationHash = in->creationHash;

    // Sign attestation structure.  A NULL signature will be returned if
    // signHandle is TPM_RH_NULL.  A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned at
    // this point
    result = SignAttestInfo(in->signHandle,
			    &in->inScheme,
			    &certifyInfo,
			    &in->qualifyingData,
			    &out->certifyInfo,
			    &out->signature);

    // TPM_RC_ATTRIBUTES cannot be returned here as FillInAttestInfo would already
    // have returned TPM_RC_KEY
    pAssert(result != TPM_RC_ATTRIBUTES);

    if(result != TPM_RC_SUCCESS)
	return result;

    // orderly state should be cleared because of the reporting of clock info
    // if signing happens
    if(in->signHandle != TPM_RH_NULL)
	g_clearOrderly = TRUE;
    return TPM_RC_SUCCESS;
}
#endif // CC_CertifyCreation

/* 18.4	TPM2_Quote */

#include "InternalRoutines.h"
#include "Attest_spt_fp.h"
#include "Quote_fp.h"
#ifdef TPM_CC_Quote  // Conditional expansion of this file

TPM_RC
TPM2_Quote(
	   Quote_In        *in,            // IN: input parameter list
	   Quote_Out       *out            // OUT: output parameter list
	   )
{
    TPM_RC                   result;
    TPMI_ALG_HASH            hashAlg;
    TPMS_ATTEST              quoted;

    // Command Output

    // Filling in attest information
    // Common fields
    // FillInAttestInfo may return TPM_RC_SCHEME or TPM_RC_KEY
    result = FillInAttestInfo(in->signHandle,
			      &in->inScheme,
			      &in->qualifyingData,
			      &quoted);
    if(result != TPM_RC_SUCCESS)
	{
	    if(result == TPM_RC_KEY)
		return TPM_RCS_KEY + RC_Quote_signHandle;
	    else
		return RcSafeAddToResult(result, RC_Quote_inScheme);
	}

    // Quote specific fields
    // Attestation type
    quoted.type = TPM_ST_ATTEST_QUOTE;

    // Get hash algorithm in sign scheme.  This hash algorithm is used to
    // compute PCR digest. If there is no algorithm, then the PCR cannot
    // be digested and this command returns TPM_RC_SCHEME
    hashAlg = in->inScheme.details.any.hashAlg;

    if(hashAlg == TPM_ALG_NULL)
	return TPM_RCS_SCHEME + RC_Quote_inScheme;

    // Compute PCR digest
    PCRComputeCurrentDigest(hashAlg,
			    &in->PCRselect,
			    &quoted.attested.quote.pcrDigest);

    // Copy PCR select.  "PCRselect" is modified in PCRComputeCurrentDigest
    // function
    quoted.attested.quote.pcrSelect = in->PCRselect;

    // Sign attestation structure.  A NULL signature will be returned if
    // signHandle is TPM_RH_NULL.  TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES
    // error may be returned by SignAttestInfo.
    // NOTE: TPM_RC_ATTRIBUTES means that the key is not a signing key but that
    // was checked above and TPM_RC_KEY was returned. TPM_RC_VALUE means that the
    // value to sign is too large but that means that the digest is too big and
    // that can't happen.
    result = SignAttestInfo(in->signHandle,
			    &in->inScheme,
			    &quoted,
			    &in->qualifyingData,
			    &out->quoted,
			    &out->signature);
    if(result != TPM_RC_SUCCESS)
	return result;

    // orderly state should be cleared because of the reporting of clock info
    // if signing happens
    if(in->signHandle != TPM_RH_NULL)
	g_clearOrderly = TRUE;

    return TPM_RC_SUCCESS;
}
#endif // CC_Quote

/* 18.5	TPM2_GetSessionAuditDigest */

#include "InternalRoutines.h"
#include "Attest_spt_fp.h"
#include "GetSessionAuditDigest_fp.h"
#ifdef TPM_CC_GetSessionAuditDigest  // Conditional expansion of this file

TPM_RC
TPM2_GetSessionAuditDigest(
			   GetSessionAuditDigest_In    *in,            // IN: input parameter list
			   GetSessionAuditDigest_Out   *out            // OUT: output parameter list
			   )
{
    TPM_RC                   result;
    SESSION                 *session;
    TPMS_ATTEST              auditInfo;

    // Input Validation

    // SessionAuditDigest specific input validation
    // Get session pointer
    session = SessionGet(in->sessionHandle);

    // session must be an audit session
    if(session->attributes.isAudit == CLEAR)
	return TPM_RCS_TYPE + RC_GetSessionAuditDigest_sessionHandle;

    // Command Output

    // Filling in attest information
    // Common fields
    result = FillInAttestInfo(in->signHandle,
			      &in->inScheme,
			      &in->qualifyingData,
			      &auditInfo);
    if(result != TPM_RC_SUCCESS)
	{
	    if(result == TPM_RC_KEY)
		return TPM_RCS_KEY + RC_GetSessionAuditDigest_signHandle;
	    else
		return RcSafeAddToResult(result, RC_GetSessionAuditDigest_inScheme);
	}

    // SessionAuditDigest specific fields
    // Attestation type
    auditInfo.type = TPM_ST_ATTEST_SESSION_AUDIT;

    // Copy digest
    auditInfo.attested.sessionAudit.sessionDigest = session->u2.auditDigest;

    // Exclusive audit session
    if(g_exclusiveAuditSession == in->sessionHandle)
	auditInfo.attested.sessionAudit.exclusiveSession = TRUE;
    else
	auditInfo.attested.sessionAudit.exclusiveSession = FALSE;

    // Sign attestation structure.  A NULL signature will be returned if
    // signHandle is TPM_RH_NULL.  A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned at
    // this point
    result = SignAttestInfo(in->signHandle,
			    &in->inScheme,
			    &auditInfo,
			    &in->qualifyingData,
			    &out->auditInfo,
			    &out->signature);
    if(result != TPM_RC_SUCCESS)
	return result;

    // orderly state should be cleared because of the reporting of clock info
    // if signing happens
    if(in->signHandle != TPM_RH_NULL)
	g_clearOrderly = TRUE;

    return TPM_RC_SUCCESS;
}
#endif // CC_GetSessionAuditDigest

/* 18.6	TPM2_GetCommandAuditDigest */

#include "InternalRoutines.h"
#include "Attest_spt_fp.h"
#include "GetCommandAuditDigest_fp.h"
#ifdef TPM_CC_GetCommandAuditDigest  // Conditional expansion of this file

TPM_RC
TPM2_GetCommandAuditDigest(
			   GetCommandAuditDigest_In    *in,            // IN: input parameter list
			   GetCommandAuditDigest_Out   *out            // OUT: output parameter list
			   )
{
    TPM_RC                  result;
    TPMS_ATTEST             auditInfo;

    // Command Output

    // Filling in attest information
    // Common fields
    result = FillInAttestInfo(in->signHandle,
			      &in->inScheme,
			      &in->qualifyingData,
			      &auditInfo);
    if(result != TPM_RC_SUCCESS)
	{
	    if(result == TPM_RC_KEY)
		return TPM_RCS_KEY + RC_GetCommandAuditDigest_signHandle;
	    else
		return RcSafeAddToResult(result, RC_GetCommandAuditDigest_inScheme);
	}

    // CommandAuditDigest specific fields
    // Attestation type
    auditInfo.type = TPM_ST_ATTEST_COMMAND_AUDIT;

    // Copy audit hash algorithm
    auditInfo.attested.commandAudit.digestAlg = gp.auditHashAlg;

    // Copy counter value
    auditInfo.attested.commandAudit.auditCounter = gp.auditCounter;

    // Copy command audit log
    auditInfo.attested.commandAudit.auditDigest = gr.commandAuditDigest;
    CommandAuditGetDigest(&auditInfo.attested.commandAudit.commandDigest);

    // Sign attestation structure.  A NULL signature will be returned if
    // signHandle is TPM_RH_NULL.  A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned at
    // this point
    result = SignAttestInfo(in->signHandle,
			    &in->inScheme,
			    &auditInfo,
			    &in->qualifyingData,
			    &out->auditInfo,
			    &out->signature);

    if(result != TPM_RC_SUCCESS)
	return result;

    // Internal Data Update

    if(in->signHandle != TPM_RH_NULL)
	{
	    // Reset log
	    gr.commandAuditDigest.t.size = 0;
	    // orderly state should be cleared because of the update in
	    // commandAuditDigest, as well as the reporting of clock info
	    g_clearOrderly = TRUE;
	}

    return TPM_RC_SUCCESS;
}
#endif // CC_GetCommandAuditDigest

/* 18.7	TPM2_GetTime */

#include "InternalRoutines.h"
#include "Attest_spt_fp.h"
#include "GetTime_fp.h"
#ifdef TPM_CC_GetTime  // Conditional expansion of this file

TPM_RC
TPM2_GetTime(
	     GetTime_In      *in,            // IN: input parameter list
	     GetTime_Out     *out            // OUT: output parameter list
	     )
{
    TPM_RC                  result;
    TPMS_ATTEST             timeInfo;

    // Command Output

    // Filling in attest information
    // Common fields
    result = FillInAttestInfo(in->signHandle,
			      &in->inScheme,
			      &in->qualifyingData,
			      &timeInfo);
    if(result != TPM_RC_SUCCESS)
	{
	    if(result == TPM_RC_KEY)
		return TPM_RCS_KEY + RC_GetTime_signHandle;
	    else
		return RcSafeAddToResult(result, RC_GetTime_inScheme);
	}

    // GetClock specific fields
    // Attestation type
    timeInfo.type = TPM_ST_ATTEST_TIME;

    // current clock in plain text
    timeInfo.attested.time.time.time = g_time;
    TimeFillInfo(&timeInfo.attested.time.time.clockInfo);

    // Firmware version in plain text
    timeInfo.attested.time.firmwareVersion
	= ((UINT64) gp.firmwareV1) << 32;
    timeInfo.attested.time.firmwareVersion += gp.firmwareV2;
    // Sign attestation structure.  A NULL signature will be returned if
    // signHandle is TPM_RH_NULL.  A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned at
    // this point
    result = SignAttestInfo(in->signHandle,
			    &in->inScheme,
			    &timeInfo,
			    &in->qualifyingData,
			    &out->timeInfo,
			    &out->signature);
    if(result != TPM_RC_SUCCESS)
	return result;

    // orderly state should be cleared because of the reporting of clock info
    // if signing happens
    if(in->signHandle != TPM_RH_NULL)
	g_clearOrderly = TRUE;

    return TPM_RC_SUCCESS;
}
#endif // CC_GetTime
