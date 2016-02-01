/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Manufacture.c 476 2015-12-23 18:25:05Z kgoldman $		*/
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

// 9.10	Manufacture.c
// 9.10.1	Description

// This file contains the function that performs the manufacturing of the TPM in a simulated
// environment. These functions should not be used outside of a manufacturing or simulation
// environment.

// 9.10.2	Includes and Data Definitions

#define MANUFACTURE_C
#include "InternalRoutines.h"
#include "Global.h"

// 9.10.3	Functions
// 9.10.3.1	TPM_Manufacture()

// This function initializes the TPM values in preparation for the TPM's first use. This function
// will fail if previously called. The TPM can be re-manufactured by calling TPM_Teardown() first
// and then calling this function again.

// Return Value	Meaning
// 0	success
// 1	manufacturing process previously performed

LIB_EXPORT int
TPM_Manufacture(
		BOOL             firstTime      // IN: indicates if this is the first call from main()
		)
{
    TPM_SU          orderlyShutdown;
    UINT64          totalResetCount = 0;
    
    // If TPM has been manufactured, return indication.
    if(!firstTime && g_manufactured)
	return 1;
    
    // initialize crypto units
    //CryptInitUnits();
    
    // Initialize the DA timers (not sure this is really needed, but ...
    DAInit();

    s_DAPendingOnNV = FALSE;
    
    // initialize NV
    NvInit();
    
#ifdef _DRBG_STATE_SAVE
    // Initialize the drbg. This needs to come before the install
    // of the hierarchies
    if(!_cpri__Startup())               // Have to start the crypto units first
	FAIL(FATAL_ERROR_INTERNAL);
    _cpri__DrbgGetPutState(PUT_STATE, 0, NULL);
#endif
    
    // default configuration for PCR
    PCRSimStart();
    
    // initialize pre-installed hierarchy data
    // This should happen after NV is initialized because hierarchy data is
    // stored in NV.
    HierarchyPreInstall_Init();
    
    // initialize dictionary attack parameters
    DAPreInstall_Init();
    
    // initialize PP list
    PhysicalPresencePreInstall_Init();
    
    // initialize command audit list
    CommandAuditPreInstall_Init();
    
    // first start up is required to be Startup(CLEAR)
    orderlyShutdown = TPM_SU_CLEAR;
    NvWriteReserved(NV_ORDERLY, &orderlyShutdown);
    
    // initialize the firmware version
    gp.firmwareV1 = FIRMWARE_V1;
#ifdef FIRMWARE_V2
    gp.firmwareV2 = FIRMWARE_V2;
#else
    gp.firmwareV2 = 0;
#endif
    NvWriteReserved(NV_FIRMWARE_V1, &gp.firmwareV1);
    NvWriteReserved(NV_FIRMWARE_V2, &gp.firmwareV2);
    
    // initialize the total reset counter to 0
    NvWriteReserved(NV_TOTAL_RESET_COUNT, &totalResetCount);
    
    // initialize the clock stuff
    go.clock = 0;
    go.clockSafe = YES;
    
#ifdef _DRBG_STATE_SAVE
    // initialize the current DRBG state in NV
    
    _cpri__DrbgGetPutState(GET_STATE, sizeof(go.drbgState), (BYTE *)&go.drbgState);
#endif
    
    NvWriteReserved(NV_ORDERLY_DATA, &go);
    
    // Commit NV writes.  Manufacture process is an artificial process existing
    // only in simulator environment and it is not defined in the specification
    // that what should be the expected behavior if the NV write fails at this
    // point.  Therefore, it is assumed the NV write here is always success and
    // no return code of this function is checked.
    NvCommit();
    
    g_manufactured = TRUE;
    
    return 0;
}

// 9.10.3.2	TPM_TearDown()

// This function prepares the TPM for re-manufacture. It should not be implemented in anything other
// than a simulated TPM.
// In this implementation, all that is needs is to stop the cryptographic units and set a flag to
// indicate that the TPM can be re-manufactured. This should be all that is necessary to start the
// manufacturing process again.
// Return Value	Meaning
// 0	success
// 1	TPM not previously manufactured

LIB_EXPORT int
TPM_TearDown(
	     void
	     )
{
    // stop crypt units
    CryptStopUnits();
    
    g_manufactured = FALSE;
    return 0;
}
