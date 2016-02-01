/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CpriRNG.c 474 2015-12-23 16:18:21Z kgoldman $		*/
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

/* rev 122 */

#include <string.h>

// B.7	CpriRNG.c

// B.7.1.	Introduction
// This file contains the interface to the OpenSSL() random number functions.
// B.7.2.	Includes

#include "OsslCryptoEngine.h"

// State of crypto engine's RNG. Ideally it should be part of the TPM state, but there's no way to put it there

DRBG_STATE           g_drbgState;

// Indicates failure of the entropy source

int         s_entropyFailure;

#define DRBG_MAGIC  ((UINT32) 0x47425244) // "DRBG"

#ifdef TPM_RNG_FOR_DEBUG
TPM2B_TYPE(B64, 64);
TPM2B_B64       randomSeed = {
    .t.size = 64,
    .t.buffer = "Special version of the RNG to be used only during TPM debug!!!!"
};
static UINT32   rngCounter = 923;
#endif

// B.7.3.	Functions
// B.7.3.1.	_cpri__RngStartup()

// This function is called to initialize the random number generator. It collects entropy from the
// platform to seed the OpenSSL() random number generator.

LIB_EXPORT BOOL
_cpri__RngStartup(void)
{
#ifndef TPM_RNG_FOR_DEBUG
    UINT32       entropySize;
    BYTE         entropy[MAX_RNG_ENTROPY_SIZE];
    INT32        returnedSize = 0;
    
    // Initialize the entropy source
    s_entropyFailure = FALSE;
    _plat__GetEntropy(NULL, 0);
    
    // Collect entropy until we have enough
    for(entropySize  = 0;
	entropySize < MAX_RNG_ENTROPY_SIZE && returnedSize >= 0;
	entropySize += returnedSize)
	{
	    returnedSize = _plat__GetEntropy(&entropy[entropySize],
					     MAX_RNG_ENTROPY_SIZE - entropySize);
	}
    // Got some entropy on the last call and did not get an error
    if(returnedSize > 0)
	{
	    // Seed OpenSSL with entropy
	    RAND_seed(entropy, entropySize);
	}
    else
	{
	    s_entropyFailure = TRUE;
	}
    return s_entropyFailure == FALSE;
#else
    memcpy(randomSeed.t.buffer,
	   "Special version of the RNG to be used only during TPM debug!!!!",
	   64);
    randomSeed.t.size = 64;
    // rngCounter = 923;
    return TRUE;
#endif
}

// B.7.3.2.	_cpri__GenerateRandom()

// This function is called to get a string of random bytes from the OpenSSL() random number
// generator. The return value is the number of bytes placed in the buffer. If the number of bytes
// returned is not equal to the number of bytes requested (randomSize) it is indicative of a failure
// of the OpenSSL() random number generator and is probably fatal.

LIB_EXPORT UINT16
_cpri__GenerateRandom(
		      INT32            randomSize,
		      BYTE            *buffer
		      )
{
    //
    // We don't do negative sizes or ones that are too large
    if (randomSize < 0 || randomSize > UINT16_MAX)
	return 0;
    
#ifndef TPM_RNG_FOR_DEBUG
    // RAND_bytes uses 1 for success and we use 0
    if(RAND_bytes(buffer, randomSize) == 1)
	return (UINT16)randomSize;
    else
	return 0;
#else
    _cpri__KDFa(TPM_ALG_SHA256,
		&randomSeed.b,
		"Not really random numbers",
		NULL,
		NULL,
		randomSize * 8,
		buffer,
		&rngCounter,
		FALSE);
    
    return (UINT16)randomSize;
#endif
}

// B.7.3.3.	_cpri__GenerateSeededRandom()

// This function is used to generate a pseudo-random number from some seed values. This function
// returns the same result each time it is called with the same parameters

LIB_EXPORT UINT16
_cpri__GenerateSeededRandom(
			    INT32            randomSize,    // IN: the size of the request
			    BYTE            *random,        // OUT: receives the data
			    TPM_ALG_ID       hashAlg,       // IN: used by KDF version but not here
			    TPM2B           *seed,          // IN: the seed value
			    const char      *label,         // IN: a label string (optional)
			    TPM2B           *partyU,        // IN: other data (oprtional)
			    TPM2B           *partyV         // IN: still more (optional)
			    )
{
    
    return (_cpri__KDFa(hashAlg, seed, label, partyU, partyV,
			randomSize * 8, random, NULL, FALSE));
}

// B.7.3.4.	_cpri__DrbgGetPutState()

// This function is used to set the state of the RNG (direction == PUT_STATE) or to recover the state of the RNG (direction == GET_STATE).

//NOTE:	This not currently supported on OpenSSL() version.

LIB_EXPORT CRYPT_RESULT
_cpri__DrbgGetPutState(
		       GET_PUT          direction,
		       size_t		bufferSize,
		       BYTE            *buffer
		       )
{
    // This function is a stub providing minimal DRBG state management
    // for crypto engines that completely delegate RNG functionality
    // to the underlying crypto library and do not have access its RNG state.
    
    if(direction == PUT_STATE)
	{
	    // If no buffer is specified, this is the call from manufacturing
	    if(buffer == NULL)
		{
		    // Default-initialize the global DRBG state.
		    memset(&g_drbgState, 0, sizeof(DRBG_STATE));
		    g_drbgState.magic = DRBG_MAGIC;
		}
	    else
		{
		    // Store the DRBG state
		    memcpy(&g_drbgState, buffer, sizeof(g_drbgState));
		}
	}
    else
	{
	    // Output buffer has to be big enough to hold the state
	    pAssert(buffer != NULL && bufferSize >= (int)sizeof(g_drbgState));
	    
	    // Return the current state of the DRBG
	    memcpy(buffer, &g_drbgState, sizeof(g_drbgState));
	}
    
    return CRYPT_SUCCESS;       // Function is not implemented
}

// B.7.3.5.	_cpri__StirRandom()

// This function is called to add external entropy to the OpenSSL() random number generator.

LIB_EXPORT CRYPT_RESULT
_cpri__StirRandom(
		  INT32            entropySize,
		  BYTE            *entropy
		  )
{
    if (entropySize >= 0)
	{
#ifndef TPM_RGN_FOR_DEBUG
	    RAND_add((const void *)entropy, (int) entropySize, 0.0);
#else
	    randomSeed.t.size = (UINT16)((entropySize > 64) ? 64 : entropySize);
	    memcpy(randomSeed.t.buffer, entropy, randomSeed.t.size);
	    rngCounter = 0;
#endif
	}
    return CRYPT_SUCCESS;
}

