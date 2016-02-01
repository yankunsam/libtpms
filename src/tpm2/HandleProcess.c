/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: HandleProcess.c 199 2015-03-31 20:06:52Z kgoldman $		*/
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

#include "TPM_Types.h"
#include "Global.h"
#include "Unmarshal_fp.h"
#include "CommandCodeAttributes_fp.h"
#include "HandleProcess_fp.h"

/* Handle unmarshal table */

typedef TPM_RC (*UnmarshalFunction_t)(TPM_HANDLE *target, BYTE **buffer, INT32 *size, BOOL allowNull);

typedef struct {
    TPM_CC 			commandCode;
    UnmarshalFunction_t 	unmarshalFunction0;
    BOOL			allowNull0;
    UnmarshalFunction_t 	unmarshalFunction1;
    BOOL			allowNull1;
    UnmarshalFunction_t 	unmarshalFunction2;
    BOOL			allowNull2;
} HANDLE_UNMARSHAL_TABLE;

static const HANDLE_UNMARSHAL_TABLE handleUnmarshalTable [] = {
				 
    {TPM_CC_Startup, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_Shutdown, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_SelfTest, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_IncrementalSelfTest, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_GetTestResult, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_StartAuthSession, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, YES, (UnmarshalFunction_t)TPMI_DH_ENTITY_Unmarshal, YES, NULL, NO},
    {TPM_CC_PolicyRestart, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_Create, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_Load, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_LoadExternal, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_ReadPublic, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_ActivateCredential, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO},
    {TPM_CC_MakeCredential, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_Unseal, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_ObjectChangeAuth, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO},
    {TPM_CC_Duplicate, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, YES, NULL, NO},
    {TPM_CC_Rewrap, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, YES, TPMI_DH_OBJECT_Unmarshal, YES, NULL, NO},
    {TPM_CC_Import, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_RSA_Encrypt, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_RSA_Decrypt, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_ECDH_KeyGen, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_ECDH_ZGen, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_ECC_Parameters, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_ZGen_2Phase, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_EncryptDecrypt, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_Hash, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_HMAC, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_GetRandom, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_StirRandom, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_HMAC_Start, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_HashSequenceStart, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_SequenceUpdate, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_SequenceComplete, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_EventSequenceComplete, (UnmarshalFunction_t)TPMI_DH_PCR_Unmarshal, YES, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO},
    {TPM_CC_Certify, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, YES, NULL, NO},
    {TPM_CC_CertifyCreation, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, YES, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO},
    {TPM_CC_Quote, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, YES, NULL, NO, NULL, NO},
    {TPM_CC_GetSessionAuditDigest, (UnmarshalFunction_t)TPMI_RH_ENDORSEMENT_Unmarshal, NO, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, YES, (UnmarshalFunction_t)TPMI_SH_HMAC_Unmarshal, NO},
    {TPM_CC_GetCommandAuditDigest, (UnmarshalFunction_t)TPMI_RH_ENDORSEMENT_Unmarshal, NO, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, YES, NULL, NO},
    {TPM_CC_GetTime, (UnmarshalFunction_t)TPMI_RH_ENDORSEMENT_Unmarshal, NO, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, YES, NULL, NO},
    {TPM_CC_Commit, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_EC_Ephemeral, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_VerifySignature, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_Sign, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_SetCommandCodeAuditStatus, (UnmarshalFunction_t)TPMI_RH_PROVISION_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PCR_Extend, (UnmarshalFunction_t)TPMI_DH_PCR_Unmarshal, YES, NULL, NO, NULL, NO},
    {TPM_CC_PCR_Event, (UnmarshalFunction_t)TPMI_DH_PCR_Unmarshal, YES, NULL, NO, NULL, NO},
    {TPM_CC_PCR_Read, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_PCR_Allocate, (UnmarshalFunction_t)TPMI_RH_PLATFORM_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PCR_SetAuthPolicy, (UnmarshalFunction_t)TPMI_RH_PLATFORM_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PCR_SetAuthValue, (UnmarshalFunction_t)TPMI_DH_PCR_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PCR_Reset, (UnmarshalFunction_t)TPMI_DH_PCR_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicySigned, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, NO, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO},
    {TPM_CC_PolicySecret, (UnmarshalFunction_t)TPMI_DH_ENTITY_Unmarshal, NO, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO},
    {TPM_CC_PolicyTicket, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyOR, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyPCR, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyLocality, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyNV, (UnmarshalFunction_t)TPMI_RH_NV_AUTH_Unmarshal, NO, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO},
    {TPM_CC_PolicyCounterTimer, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyCommandCode, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyPhysicalPresence, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyCpHash, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyNameHash, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyDuplicationSelect, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyAuthorize, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyAuthValue, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyPassword, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyGetDigest, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PolicyNvWritten, (UnmarshalFunction_t)TPMI_SH_POLICY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_CreatePrimary, (UnmarshalFunction_t)TPMI_RH_HIERARCHY_Unmarshal, YES, NULL, NO, NULL, NO},
    {TPM_CC_HierarchyControl, (UnmarshalFunction_t)TPMI_RH_HIERARCHY_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_SetPrimaryPolicy, (UnmarshalFunction_t)TPMI_RH_HIERARCHY_AUTH_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_ChangePPS, (UnmarshalFunction_t)TPMI_RH_PLATFORM_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_ChangeEPS, (UnmarshalFunction_t)TPMI_RH_PLATFORM_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_Clear, (UnmarshalFunction_t)TPMI_RH_CLEAR_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_ClearControl, (UnmarshalFunction_t)TPMI_RH_CLEAR_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_HierarchyChangeAuth, (UnmarshalFunction_t)TPMI_RH_HIERARCHY_AUTH_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_DictionaryAttackLockReset, (UnmarshalFunction_t)TPMI_RH_LOCKOUT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_DictionaryAttackParameters, (UnmarshalFunction_t)TPMI_RH_LOCKOUT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_PP_Commands, (UnmarshalFunction_t)TPMI_RH_PLATFORM_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_SetAlgorithmSet, (UnmarshalFunction_t)TPMI_RH_PLATFORM_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_ContextSave, (UnmarshalFunction_t)TPMI_DH_CONTEXT_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_ContextLoad, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_FlushContext, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_EvictControl, (UnmarshalFunction_t)TPMI_RH_PROVISION_Unmarshal, NO,(UnmarshalFunction_t) TPMI_DH_OBJECT_Unmarshal, NO, NULL, NO},
    {TPM_CC_ReadClock, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_ClockSet, (UnmarshalFunction_t)TPMI_RH_PROVISION_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_ClockRateAdjust, (UnmarshalFunction_t)TPMI_RH_PROVISION_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_GetCapability, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_TestParms, NULL, NO, NULL, NO, NULL, NO},
    {TPM_CC_NV_DefineSpace, (UnmarshalFunction_t)TPMI_RH_PROVISION_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_NV_UndefineSpace, (UnmarshalFunction_t)TPMI_RH_PROVISION_Unmarshal, NO, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, NULL, NO},
    {TPM_CC_NV_UndefineSpaceSpecial, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, (UnmarshalFunction_t)TPMI_RH_PLATFORM_Unmarshal, NO, NULL, NO},
    {TPM_CC_NV_ReadPublic, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_NV_Write, (UnmarshalFunction_t)TPMI_RH_NV_AUTH_Unmarshal, NO, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, NULL, NO},
    {TPM_CC_NV_Increment, (UnmarshalFunction_t)TPMI_RH_NV_AUTH_Unmarshal, NO, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, NULL, NO},
    {TPM_CC_NV_Extend, (UnmarshalFunction_t)TPMI_RH_NV_AUTH_Unmarshal, NO, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, NULL, NO},
    {TPM_CC_NV_SetBits, (UnmarshalFunction_t)TPMI_RH_NV_AUTH_Unmarshal, NO, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, NULL, NO},
    {TPM_CC_NV_WriteLock, (UnmarshalFunction_t)TPMI_RH_NV_AUTH_Unmarshal, NO, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, NULL, NO},
    {TPM_CC_NV_GlobalWriteLock, (UnmarshalFunction_t)TPMI_RH_PROVISION_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_NV_Read, (UnmarshalFunction_t)TPMI_RH_NV_AUTH_Unmarshal, NO, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, NULL, NO},
    {TPM_CC_NV_ReadLock, (UnmarshalFunction_t)TPMI_RH_NV_AUTH_Unmarshal, NO, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, NULL, NO},
    {TPM_CC_NV_ChangeAuth, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO, NULL, NO, NULL, NO},
    {TPM_CC_NV_Certify, (UnmarshalFunction_t)TPMI_DH_OBJECT_Unmarshal, YES, (UnmarshalFunction_t)TPMI_RH_NV_AUTH_Unmarshal, NO, (UnmarshalFunction_t)TPMI_RH_NV_INDEX_Unmarshal, NO},
};

static COMMAND_INDEX 
GetUnmarshalTableIndex(COMMAND_INDEX commandIndex)
{
    COMMAND_INDEX index;

    /* map from the incoming MS table command index to the command code */
    TPM_CC commandCode = GetCommandCode(commandIndex);
    /* get the command index in the dispatch table */
    for (index = 0 ; index < (sizeof(handleUnmarshalTable)/ sizeof(HANDLE_UNMARSHAL_TABLE)) ; index++) {
	if (handleUnmarshalTable[index].commandCode == commandCode) {
	    return index;
	}
    }
    /* command code must be in the dispatch table */
    pAssert(FALSE);
    return 0;
}

TPM_RC
ParseHandleBuffer(
		  COMMAND_INDEX    commandIndex,          // IN: Command being processed
		  BYTE           **handleBufferStart,     // IN/OUT: command buffer where handles
		                                          //   are located. Updated as handles
		                                          //   are unmarshaled
		  INT32           *bufferRemainingSize,   // IN/OUT: indicates the amount of data
		                                          //   left in the command buffer.
		                                          //   Updated as handles are unmarshaled
		  TPM_HANDLE       handles[],             // OUT: Array that receives the handles
		  UINT32          *handleCount            // OUT: Receives the count of handles
		  )
{
    TPM_RC 		rc = TPM_RC_SUCCESS;
    UINT32     		tableHandleCount = 0;
    COMMAND_INDEX 	index;
    
    /* get number of command handles from table */
    if (rc == TPM_RC_SUCCESS) {
	*handleCount = s_ccAttr[commandIndex].cHandles;
	/* Number of handles retrieved from handle area should be less than MAX_HANDLE_NUM */
	pAssert(*handleCount <= MAX_HANDLE_NUM);
	index = GetUnmarshalTableIndex(commandIndex);
    }
    /* unmarshal the handles if the unmarshal function is not null */
    if (rc == TPM_RC_SUCCESS) {
	if (handleUnmarshalTable[index].unmarshalFunction0 != NULL) {
	    rc = handleUnmarshalTable[index].unmarshalFunction0(&handles[0],
								handleBufferStart, bufferRemainingSize,
								handleUnmarshalTable[index].allowNull0);
	    if (rc == TPM_RC_SUCCESS) {
		tableHandleCount++;
	    }
	    else {
		rc += TPM_RC_H + TPM_RC_1;
	    }
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	if (handleUnmarshalTable[index].unmarshalFunction1 != NULL) {
	    rc = handleUnmarshalTable[index].unmarshalFunction1(&handles[1],
								handleBufferStart, bufferRemainingSize,
								handleUnmarshalTable[index].allowNull1);
	    if (rc == TPM_RC_SUCCESS) {
		tableHandleCount++;
	    }
	    else {
		rc += TPM_RC_H + TPM_RC_2;
	    }
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	if (handleUnmarshalTable[index].unmarshalFunction2 != NULL) {
	    rc = handleUnmarshalTable[index].unmarshalFunction2(&handles[2],
								handleBufferStart, bufferRemainingSize,
								handleUnmarshalTable[index].allowNull2);
	    if (rc == TPM_RC_SUCCESS) {
		tableHandleCount++;
	    }
	    else {
		rc += TPM_RC_H + TPM_RC_3;
	    }
	}
    }
    /* sanity check the two tables */
    if (rc == TPM_RC_SUCCESS) {
	pAssert(*handleCount == tableHandleCount);
    }
    return rc;
}
