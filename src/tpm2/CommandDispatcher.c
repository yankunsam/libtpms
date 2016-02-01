/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CommandDispatcher.c 457 2015-12-08 15:29:45Z kgoldman $	*/
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

#include <string.h>

#include "CommandDispatcher_fp.h"
#include "Commands_fp.h"
#include "Parameters.h"
#include "CommandCodeAttributes_fp.h"
#include "MemoryLib_fp.h"
#include "Marshal_fp.h"

// 6.1	CommandDispatcher()
/* rev 119 */

// In the reference implementation, a program that uses TPM 2.0 Part 3 as input automatically
// generates the command dispatch code. The function prototype header file (CommandDispatcher_fp.h)
// is shown here.

// CommandDispatcher() performs the following operations:

//	unmarshals command parameters from the input buffer;

//	invokes the function that performs the command actions;

//	marshals the returned handles, if any; and

//	marshals the returned parameters, if any, into the output buffer putting in the
//	parameterSize field if authorization sessions are present.

typedef TPM_RC (*UnmarshalFunction_t)(COMMAND_PARAMETERS *target, BYTE **buffer, INT32 *size, TPM_HANDLE handles[]);
typedef UINT16 (*MarshalFunction_t)(RESPONSE_PARAMETERS *source, TPMI_ST_COMMAND_TAG  tag, BYTE **buffer, INT32 *size);

typedef TPM_RC (*ExecuteFunction_t)();

typedef struct {
    TPM_CC 			commandCode;
    UnmarshalFunction_t 	unmarshalFunction;
    ExecuteFunction_t 		executeFunction;
    MarshalFunction_t 		marshalFunction;
} DISPATCH_TABLE;
				 
static const DISPATCH_TABLE dispatchTable [] = {
				 
    {TPM_CC_Startup, (UnmarshalFunction_t)Startup_In_Unmarshal, TPM2_Startup, NULL},
    {TPM_CC_Shutdown, (UnmarshalFunction_t)Shutdown_In_Unmarshal, TPM2_Shutdown, NULL},
    {TPM_CC_SelfTest, (UnmarshalFunction_t)SelfTest_In_Unmarshal, TPM2_SelfTest, NULL},
    {TPM_CC_IncrementalSelfTest, (UnmarshalFunction_t)IncrementalSelfTest_In_Unmarshal, TPM2_IncrementalSelfTest, (MarshalFunction_t)IncrementalSelfTest_Out_Marshal},
    {TPM_CC_GetTestResult, NULL, TPM2_GetTestResult, (MarshalFunction_t)GetTestResult_Out_Marshal},
    {TPM_CC_StartAuthSession, (UnmarshalFunction_t)StartAuthSession_In_Unmarshal, TPM2_StartAuthSession, (MarshalFunction_t)StartAuthSession_Out_Marshal},
    {TPM_CC_PolicyRestart, (UnmarshalFunction_t)PolicyRestart_In_Unmarshal, TPM2_PolicyRestart, NULL},
    {TPM_CC_Create, (UnmarshalFunction_t)Create_In_Unmarshal, TPM2_Create, (MarshalFunction_t)Create_Out_Marshal},
    {TPM_CC_Load, (UnmarshalFunction_t)Load_In_Unmarshal, TPM2_Load, (MarshalFunction_t)Load_Out_Marshal},
    {TPM_CC_LoadExternal, (UnmarshalFunction_t)LoadExternal_In_Unmarshal, TPM2_LoadExternal, (MarshalFunction_t)LoadExternal_Out_Marshal},
    {TPM_CC_ReadPublic, (UnmarshalFunction_t)ReadPublic_In_Unmarshal, TPM2_ReadPublic, (MarshalFunction_t)ReadPublic_Out_Marshal},
    {TPM_CC_ActivateCredential, (UnmarshalFunction_t)ActivateCredential_In_Unmarshal, TPM2_ActivateCredential, (MarshalFunction_t)ActivateCredential_Out_Marshal},
    {TPM_CC_MakeCredential, (UnmarshalFunction_t)MakeCredential_In_Unmarshal, TPM2_MakeCredential, (MarshalFunction_t)MakeCredential_Out_Marshal},
    {TPM_CC_Unseal, (UnmarshalFunction_t)Unseal_In_Unmarshal, TPM2_Unseal, (MarshalFunction_t)Unseal_Out_Marshal},
    {TPM_CC_ObjectChangeAuth, (UnmarshalFunction_t)ObjectChangeAuth_In_Unmarshal, TPM2_ObjectChangeAuth, (MarshalFunction_t)ObjectChangeAuth_Out_Marshal},
    {TPM_CC_Duplicate, (UnmarshalFunction_t)Duplicate_In_Unmarshal, TPM2_Duplicate, (MarshalFunction_t)Duplicate_Out_Marshal},
    {TPM_CC_Rewrap, (UnmarshalFunction_t)Rewrap_In_Unmarshal, TPM2_Rewrap, (MarshalFunction_t)Rewrap_Out_Marshal},
    {TPM_CC_Import, (UnmarshalFunction_t)Import_In_Unmarshal, TPM2_Import, (MarshalFunction_t)Import_Out_Marshal},
    {TPM_CC_RSA_Encrypt, (UnmarshalFunction_t)RSA_Encrypt_In_Unmarshal, TPM2_RSA_Encrypt, (MarshalFunction_t)RSA_Encrypt_Out_Marshal},
    {TPM_CC_RSA_Decrypt, (UnmarshalFunction_t)RSA_Decrypt_In_Unmarshal, TPM2_RSA_Decrypt, (MarshalFunction_t)RSA_Decrypt_Out_Marshal},
    {TPM_CC_ECDH_KeyGen, (UnmarshalFunction_t)ECDH_KeyGen_In_Unmarshal, TPM2_ECDH_KeyGen, (MarshalFunction_t)ECDH_KeyGen_Out_Marshal},
    {TPM_CC_ECDH_ZGen, (UnmarshalFunction_t)ECDH_ZGen_In_Unmarshal, TPM2_ECDH_ZGen, (MarshalFunction_t)ECDH_ZGen_Out_Marshal},
    {TPM_CC_ECC_Parameters, (UnmarshalFunction_t)ECC_Parameters_In_Unmarshal, TPM2_ECC_Parameters, (MarshalFunction_t)ECC_Parameters_Out_Marshal},
    {TPM_CC_ZGen_2Phase, (UnmarshalFunction_t)ZGen_2Phase_In_Unmarshal, TPM2_ZGen_2Phase, (MarshalFunction_t)ZGen_2Phase_Out_Marshal},
    {TPM_CC_EncryptDecrypt, (UnmarshalFunction_t)EncryptDecrypt_In_Unmarshal, TPM2_EncryptDecrypt, (MarshalFunction_t)EncryptDecrypt_Out_Marshal},
    {TPM_CC_Hash, (UnmarshalFunction_t)Hash_In_Unmarshal, TPM2_Hash, (MarshalFunction_t)Hash_Out_Marshal},
    {TPM_CC_HMAC, (UnmarshalFunction_t)HMAC_In_Unmarshal, TPM2_HMAC, (MarshalFunction_t)HMAC_Out_Marshal},
    {TPM_CC_GetRandom, (UnmarshalFunction_t)GetRandom_In_Unmarshal, TPM2_GetRandom, (MarshalFunction_t)GetRandom_Out_Marshal},
    {TPM_CC_StirRandom, (UnmarshalFunction_t)StirRandom_In_Unmarshal, TPM2_StirRandom, NULL},
    {TPM_CC_HMAC_Start, (UnmarshalFunction_t)HMAC_Start_In_Unmarshal, TPM2_HMAC_Start, (MarshalFunction_t)HMAC_Start_Out_Marshal},
    {TPM_CC_HashSequenceStart, (UnmarshalFunction_t)HashSequenceStart_In_Unmarshal, TPM2_HashSequenceStart, (MarshalFunction_t)HashSequenceStart_Out_Marshal},
    {TPM_CC_SequenceUpdate, (UnmarshalFunction_t)SequenceUpdate_In_Unmarshal, TPM2_SequenceUpdate, NULL},
    {TPM_CC_SequenceComplete, (UnmarshalFunction_t)SequenceComplete_In_Unmarshal, TPM2_SequenceComplete, (MarshalFunction_t)SequenceComplete_Out_Marshal},
    {TPM_CC_EventSequenceComplete, (UnmarshalFunction_t)EventSequenceComplete_In_Unmarshal, TPM2_EventSequenceComplete, (MarshalFunction_t)EventSequenceComplete_Out_Marshal},
    {TPM_CC_Certify, (UnmarshalFunction_t)Certify_In_Unmarshal, TPM2_Certify, (MarshalFunction_t)Certify_Out_Marshal},
    {TPM_CC_CertifyCreation, (UnmarshalFunction_t)CertifyCreation_In_Unmarshal, TPM2_CertifyCreation, (MarshalFunction_t)CertifyCreation_Out_Marshal},
    {TPM_CC_Quote, (UnmarshalFunction_t)Quote_In_Unmarshal, TPM2_Quote, (MarshalFunction_t)Quote_Out_Marshal},
    {TPM_CC_GetSessionAuditDigest, (UnmarshalFunction_t)GetSessionAuditDigest_In_Unmarshal, TPM2_GetSessionAuditDigest, (MarshalFunction_t)GetSessionAuditDigest_Out_Marshal},
    {TPM_CC_GetCommandAuditDigest, (UnmarshalFunction_t)GetCommandAuditDigest_In_Unmarshal, TPM2_GetCommandAuditDigest, (MarshalFunction_t)GetCommandAuditDigest_Out_Marshal},
    {TPM_CC_GetTime, (UnmarshalFunction_t)GetTime_In_Unmarshal, TPM2_GetTime, (MarshalFunction_t)GetTime_Out_Marshal},
    {TPM_CC_Commit, (UnmarshalFunction_t)Commit_In_Unmarshal, TPM2_Commit, (MarshalFunction_t)Commit_Out_Marshal},
    {TPM_CC_EC_Ephemeral, (UnmarshalFunction_t)EC_Ephemeral_In_Unmarshal, TPM2_EC_Ephemeral, (MarshalFunction_t)EC_Ephemeral_Out_Marshal},
    {TPM_CC_VerifySignature, (UnmarshalFunction_t)VerifySignature_In_Unmarshal, TPM2_VerifySignature, (MarshalFunction_t)VerifySignature_Out_Marshal},
    {TPM_CC_Sign, (UnmarshalFunction_t)Sign_In_Unmarshal, TPM2_Sign, (MarshalFunction_t)Sign_Out_Marshal},
    {TPM_CC_SetCommandCodeAuditStatus, (UnmarshalFunction_t)SetCommandCodeAuditStatus_In_Unmarshal, TPM2_SetCommandCodeAuditStatus, NULL},
    {TPM_CC_PCR_Extend, (UnmarshalFunction_t)PCR_Extend_In_Unmarshal, TPM2_PCR_Extend, NULL},
    {TPM_CC_PCR_Event, (UnmarshalFunction_t)PCR_Event_In_Unmarshal, TPM2_PCR_Event, (MarshalFunction_t)PCR_Event_Out_Marshal},
    {TPM_CC_PCR_Read, (UnmarshalFunction_t)PCR_Read_In_Unmarshal, TPM2_PCR_Read, (MarshalFunction_t)PCR_Read_Out_Marshal},
    {TPM_CC_PCR_Allocate, (UnmarshalFunction_t)PCR_Allocate_In_Unmarshal, TPM2_PCR_Allocate, (MarshalFunction_t)PCR_Allocate_Out_Marshal},
    {TPM_CC_PCR_SetAuthPolicy, (UnmarshalFunction_t)PCR_SetAuthPolicy_In_Unmarshal, TPM2_PCR_SetAuthPolicy, NULL},
    {TPM_CC_PCR_SetAuthValue, (UnmarshalFunction_t)PCR_SetAuthValue_In_Unmarshal, TPM2_PCR_SetAuthValue, NULL},
    {TPM_CC_PCR_Reset, (UnmarshalFunction_t)PCR_Reset_In_Unmarshal, TPM2_PCR_Reset, NULL},
    {TPM_CC_PolicySigned, (UnmarshalFunction_t)PolicySigned_In_Unmarshal, TPM2_PolicySigned, (MarshalFunction_t)PolicySigned_Out_Marshal},
    {TPM_CC_PolicySecret, (UnmarshalFunction_t)PolicySecret_In_Unmarshal, TPM2_PolicySecret, (MarshalFunction_t)PolicySecret_Out_Marshal},
    {TPM_CC_PolicyTicket, (UnmarshalFunction_t)PolicyTicket_In_Unmarshal, TPM2_PolicyTicket, NULL},
    {TPM_CC_PolicyOR, (UnmarshalFunction_t)PolicyOR_In_Unmarshal, TPM2_PolicyOR, NULL},
    {TPM_CC_PolicyPCR, (UnmarshalFunction_t)PolicyPCR_In_Unmarshal, TPM2_PolicyPCR, NULL},
    {TPM_CC_PolicyLocality, (UnmarshalFunction_t)PolicyLocality_In_Unmarshal, TPM2_PolicyLocality, NULL},
    {TPM_CC_PolicyNV, (UnmarshalFunction_t)PolicyNV_In_Unmarshal, TPM2_PolicyNV, NULL},
    {TPM_CC_PolicyCounterTimer, (UnmarshalFunction_t)PolicyCounterTimer_In_Unmarshal, TPM2_PolicyCounterTimer, NULL},
    {TPM_CC_PolicyCommandCode, (UnmarshalFunction_t)PolicyCommandCode_In_Unmarshal, TPM2_PolicyCommandCode, NULL},
    {TPM_CC_PolicyPhysicalPresence, (UnmarshalFunction_t)PolicyPhysicalPresence_In_Unmarshal, TPM2_PolicyPhysicalPresence, NULL},
    {TPM_CC_PolicyCpHash, (UnmarshalFunction_t)PolicyCpHash_In_Unmarshal, TPM2_PolicyCpHash, NULL},
    {TPM_CC_PolicyNameHash, (UnmarshalFunction_t)PolicyNameHash_In_Unmarshal, TPM2_PolicyNameHash, NULL},
    {TPM_CC_PolicyDuplicationSelect, (UnmarshalFunction_t)PolicyDuplicationSelect_In_Unmarshal, TPM2_PolicyDuplicationSelect, NULL},
    {TPM_CC_PolicyAuthorize, (UnmarshalFunction_t)PolicyAuthorize_In_Unmarshal, TPM2_PolicyAuthorize, NULL},
    {TPM_CC_PolicyAuthValue, (UnmarshalFunction_t)PolicyAuthValue_In_Unmarshal, TPM2_PolicyAuthValue, NULL},
    {TPM_CC_PolicyPassword, (UnmarshalFunction_t)PolicyPassword_In_Unmarshal, TPM2_PolicyPassword, NULL},
    {TPM_CC_PolicyGetDigest, (UnmarshalFunction_t)PolicyGetDigest_In_Unmarshal, TPM2_PolicyGetDigest, (MarshalFunction_t)PolicyGetDigest_Out_Marshal},
    {TPM_CC_PolicyNvWritten, (UnmarshalFunction_t)PolicyNvWritten_In_Unmarshal, TPM2_PolicyNvWritten, NULL},
    {TPM_CC_CreatePrimary, (UnmarshalFunction_t)CreatePrimary_In_Unmarshal, TPM2_CreatePrimary, (MarshalFunction_t)CreatePrimary_Out_Marshal},
    {TPM_CC_HierarchyControl, (UnmarshalFunction_t)HierarchyControl_In_Unmarshal, TPM2_HierarchyControl, NULL},
    {TPM_CC_SetPrimaryPolicy, (UnmarshalFunction_t)SetPrimaryPolicy_In_Unmarshal, TPM2_SetPrimaryPolicy, NULL},
    {TPM_CC_ChangePPS, (UnmarshalFunction_t)ChangePPS_In_Unmarshal, TPM2_ChangePPS, NULL},
    {TPM_CC_ChangeEPS, (UnmarshalFunction_t)ChangeEPS_In_Unmarshal, TPM2_ChangeEPS, NULL},
    {TPM_CC_Clear, (UnmarshalFunction_t)Clear_In_Unmarshal, TPM2_Clear, NULL},
    {TPM_CC_ClearControl, (UnmarshalFunction_t)ClearControl_In_Unmarshal, TPM2_ClearControl, NULL},
    {TPM_CC_HierarchyChangeAuth, (UnmarshalFunction_t)HierarchyChangeAuth_In_Unmarshal, TPM2_HierarchyChangeAuth, NULL},
    {TPM_CC_DictionaryAttackLockReset, (UnmarshalFunction_t)DictionaryAttackLockReset_In_Unmarshal, TPM2_DictionaryAttackLockReset, NULL},
    {TPM_CC_DictionaryAttackParameters, (UnmarshalFunction_t)DictionaryAttackParameters_In_Unmarshal, TPM2_DictionaryAttackParameters, NULL},
    {TPM_CC_PP_Commands, (UnmarshalFunction_t)PP_Commands_In_Unmarshal, TPM2_PP_Commands, NULL},
    {TPM_CC_SetAlgorithmSet, (UnmarshalFunction_t)SetAlgorithmSet_In_Unmarshal, TPM2_SetAlgorithmSet, NULL},
    {TPM_CC_ContextSave, (UnmarshalFunction_t)ContextSave_In_Unmarshal, TPM2_ContextSave, (MarshalFunction_t)ContextSave_Out_Marshal},
    {TPM_CC_ContextLoad, (UnmarshalFunction_t)ContextLoad_In_Unmarshal, TPM2_ContextLoad, (MarshalFunction_t)ContextLoad_Out_Marshal},
    {TPM_CC_FlushContext, (UnmarshalFunction_t)FlushContext_In_Unmarshal, TPM2_FlushContext, NULL},
    {TPM_CC_EvictControl, (UnmarshalFunction_t)EvictControl_In_Unmarshal, TPM2_EvictControl, NULL},
    {TPM_CC_ReadClock, NULL, TPM2_ReadClock, (MarshalFunction_t)ReadClock_Out_Marshal},
    {TPM_CC_ClockSet, (UnmarshalFunction_t)ClockSet_In_Unmarshal, TPM2_ClockSet, NULL},
    {TPM_CC_ClockRateAdjust, (UnmarshalFunction_t)ClockRateAdjust_In_Unmarshal, TPM2_ClockRateAdjust, NULL},
    {TPM_CC_GetCapability, (UnmarshalFunction_t)GetCapability_In_Unmarshal, TPM2_GetCapability, (MarshalFunction_t)GetCapability_Out_Marshal},
    {TPM_CC_TestParms, (UnmarshalFunction_t)TestParms_In_Unmarshal, TPM2_TestParms, NULL},
    {TPM_CC_NV_DefineSpace, (UnmarshalFunction_t)NV_DefineSpace_In_Unmarshal, TPM2_NV_DefineSpace, NULL},
    {TPM_CC_NV_UndefineSpace, (UnmarshalFunction_t)NV_UndefineSpace_In_Unmarshal, TPM2_NV_UndefineSpace, NULL},
    {TPM_CC_NV_UndefineSpaceSpecial, (UnmarshalFunction_t)NV_UndefineSpaceSpecial_In_Unmarshal, TPM2_NV_UndefineSpaceSpecial, NULL},
    {TPM_CC_NV_ReadPublic, (UnmarshalFunction_t)NV_ReadPublic_In_Unmarshal, TPM2_NV_ReadPublic, (MarshalFunction_t)NV_ReadPublic_Out_Marshal},
    {TPM_CC_NV_Write, (UnmarshalFunction_t)NV_Write_In_Unmarshal, TPM2_NV_Write, NULL},
    {TPM_CC_NV_Increment, (UnmarshalFunction_t)NV_Increment_In_Unmarshal, TPM2_NV_Increment, NULL},
    {TPM_CC_NV_Extend, (UnmarshalFunction_t)NV_Extend_In_Unmarshal, TPM2_NV_Extend, NULL},
    {TPM_CC_NV_SetBits, (UnmarshalFunction_t)NV_SetBits_In_Unmarshal, TPM2_NV_SetBits, NULL},
    {TPM_CC_NV_WriteLock, (UnmarshalFunction_t)NV_WriteLock_In_Unmarshal, TPM2_NV_WriteLock, NULL},
    {TPM_CC_NV_GlobalWriteLock, (UnmarshalFunction_t)NV_GlobalWriteLock_In_Unmarshal, TPM2_NV_GlobalWriteLock, NULL},
    {TPM_CC_NV_Read, (UnmarshalFunction_t)NV_Read_In_Unmarshal, TPM2_NV_Read, (MarshalFunction_t)NV_Read_Out_Marshal},
    {TPM_CC_NV_ReadLock, (UnmarshalFunction_t)NV_ReadLock_In_Unmarshal, TPM2_NV_ReadLock, NULL},
    {TPM_CC_NV_ChangeAuth, (UnmarshalFunction_t)NV_ChangeAuth_In_Unmarshal, TPM2_NV_ChangeAuth, NULL},
    {TPM_CC_NV_Certify, (UnmarshalFunction_t)NV_Certify_In_Unmarshal, TPM2_NV_Certify, (MarshalFunction_t)NV_Certify_Out_Marshal}

};

static COMMAND_INDEX 
GetDispatchTableIndex(COMMAND_INDEX commandIndex)
{
    COMMAND_INDEX index;

    /* map from the incoming MS table command index to the command code */
    TPM_CC commandCode = GetCommandCode(commandIndex);
    /* get the command index in the dispatch table */
    for (index = 0 ; index < (sizeof(dispatchTable) / sizeof(DISPATCH_TABLE)) ; index++) {
	if (dispatchTable[index].commandCode == commandCode) {
	    return index;
	}
    }
    /* command code must be in the dispatch table */
    pAssert(FALSE);
    return 0;
}

TPM_RC
CommandDispatcher(
		  TPMI_ST_COMMAND_TAG  tag,               // IN: Input command tag
		  COMMAND_INDEX        commandIndex,      // IN: Command index
		  INT32               *parmBufferSize,    // IN: size of parameter buffer
		  BYTE                *parmBufferStart,   // IN: pointer to start of parameter
		                                          //     buffer
		  TPM_HANDLE           handles[],         // IN: handle array
		  UINT32              *responseHandleSize,// OUT: size of handle buffer in
		                                          //      response
		  UINT32              *respParmSize       // OUT: size of parameter buffer in
		                                          //      response
		  )
{
    TPM_RC 		rc = TPM_RC_SUCCESS;
    COMMAND_INDEX 	index;
    BYTE        	*responseBuffer = NULL;		/* buffer pointer for marshaling */
    
    /* the TPM code assumes all unused areas of a structure are zero so that unions can be compared
       using memcmp rather that comparing each element */
    if (rc == TPM_RC_SUCCESS) {
	memset(&in, 0, sizeof(COMMAND_PARAMETERS));
	memset(&out, 0, sizeof(RESPONSE_PARAMETERS));
    }
    if (rc == TPM_RC_SUCCESS) {
	/* get index into the dispatch table */
	index = GetDispatchTableIndex(commandIndex);
	/* if there are input parameters, unmarshal them */
	if (dispatchTable[index].unmarshalFunction != NULL) {
	    /* caller's parmBufferStart does not advance, parmBufferSize is reduced */
	    rc = dispatchTable[index].unmarshalFunction(&in, &parmBufferStart, parmBufferSize, handles);
	}
    }
    /* check for extra bytes after unmarshaling */
    if (rc == TPM_RC_SUCCESS) {
	if (*parmBufferSize != 0) {
	    rc = TPM_RC_SIZE;
	}
    }
    /* dispatch the command */
    if (rc == TPM_RC_SUCCESS) {
	if (dispatchTable[index].unmarshalFunction != NULL) {		/* if input parameters */
	    if (dispatchTable[index].marshalFunction != NULL) {		/* if output parameters */

		rc = dispatchTable[index].executeFunction(&in, &out);
	    }
	    else {							/* no output parameters */
		rc = dispatchTable[index].executeFunction(&in);
  
	    }
	}
	else {								/* if no input parameters */
	    if (dispatchTable[index].marshalFunction != NULL) {		/* if output parameters */

		rc = dispatchTable[index].executeFunction(&out);
	    }
	    else {							/* no output parameters */
		pAssert(FALSE);						/* currently never occurs */
	    }
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	uint8_t *parameterSizeBuffer = NULL;
	
	/* so far, commands can only have one handle in response */
	if (IsHandleInResponse(commandIndex)) {
	    *responseHandleSize = sizeof(TPM_HANDLE);
	}
	else {
	    *responseHandleSize = 0;
	}
	/* response buffer is a static */
	responseBuffer = MemoryGetResponseBuffer(commandIndex);
	/* advance past the header to the handle area or parameters */
	responseBuffer += sizeof(TPM_ST) + sizeof(UINT32) + sizeof(TPM_RC);
	/* the response parameterSize is marshaled after the response handles */
	parameterSizeBuffer = responseBuffer + *responseHandleSize;

	/* marshal the response parameters

	   This includes the handle, if any, and a placeholder for the parameterSize if the command tag is TPM_ST_SESSIONS */
	*respParmSize = 0;	/* initialize, marshalFunction sets final value, final value includes handles */
	if (dispatchTable[index].marshalFunction != NULL) {
	    /* maximum allowed size of response parameters */
	    INT32 responseSize = sizeof(RESPONSE_PARAMETERS) - sizeof(TPM_ST) + sizeof(UINT32) + sizeof(TPM_RC);
	    *respParmSize = dispatchTable[index].marshalFunction(&out, tag, &responseBuffer, &responseSize);
	    /* since marshalFunction includes the handles, subtract it out */
	    *respParmSize -= *responseHandleSize;
	}
	/* if the tag is TPM_ST_SESSIONS, back fill response parameterSize.  unmarshalFunction added a zero placeholder */
	if (tag == TPM_ST_SESSIONS) {
	    UINT32_Marshal(respParmSize, &parameterSizeBuffer, NULL);
	}
    }
    return rc;
}
