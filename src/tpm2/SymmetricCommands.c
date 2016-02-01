/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: SymmetricCommands.c 472 2015-12-22 22:43:40Z kgoldman $	*/
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

/* 15.2	TPM2_EncryptDecrypt */

#include "InternalRoutines.h"
#include "EncryptDecrypt_fp.h"
#ifdef TPM_CC_EncryptDecrypt  // Conditional expansion of this file

TPM_RC
TPM2_EncryptDecrypt(
		    EncryptDecrypt_In   *in,            // IN: input parameter list
		    EncryptDecrypt_Out  *out            // OUT: output parameter list
		    )
{
    OBJECT              *symKey;
    UINT16              keySize;
    UINT16              blockSize;
    BYTE                *key;
    TPM_ALG_ID          alg;
    TPM_ALG_ID          mode;
    
    // Input Validation
    symKey = ObjectGet(in->keyHandle);
    mode = symKey->publicArea.parameters.symDetail.sym.mode.sym;
    
    // The input key should be a symmetric decrypt key.
    if(    symKey->publicArea.type != TPM_ALG_SYMCIPHER
	   || symKey->attributes.publicOnly == SET)
	return TPM_RCS_KEY + RC_EncryptDecrypt_keyHandle;
    
    // The key must be unrestricted and allow the selected operation
    if(     (symKey->publicArea.objectAttributes.restricted == SET)
	    ||  (in->decrypt == SET && symKey->publicArea.objectAttributes.decrypt != SET)
	    ||  (in->decrypt == CLEAR && symKey->publicArea.objectAttributes.sign != SET))
	return TPM_RCS_ATTRIBUTES + RC_EncryptDecrypt_keyHandle;
    
    // If the key mode is not TPM_ALG_NULL...
    // or TPM_ALG_NULL
    if(mode != TPM_ALG_NULL)
	{
	    // then the input mode has to be the same
	    if(in->mode != TPM_ALG_NULL && in->mode != mode)
		return TPM_RCS_MODE + RC_EncryptDecrypt_mode;
	}
    else
	{
	    // if the key mode is null, then the input can't be null
	    if(in->mode == TPM_ALG_NULL)
		return TPM_RCS_MODE + RC_EncryptDecrypt_mode;
	    mode = in->mode;
	}
    
    // The input iv for ECB mode should be null.  All the other modes should
    // have an iv size same as encryption block size
    
    keySize = symKey->publicArea.parameters.symDetail.sym.keyBits.sym;
    alg = symKey->publicArea.parameters.symDetail.sym.algorithm;
    blockSize = CryptGetSymmetricBlockSize(alg, keySize);
    if(   (mode == TPM_ALG_ECB && in->ivIn.t.size != 0)
	  || (mode != TPM_ALG_ECB && in->ivIn.t.size != blockSize))
	return TPM_RCS_SIZE + RC_EncryptDecrypt_ivIn;
    
    // The input data size of CBC mode or ECB mode must be an even multiple of
    // the symmetric algorithm's block size
    if(   (mode == TPM_ALG_CBC || mode == TPM_ALG_ECB)
	  && (in->inData.t.size % blockSize) != 0)
	return TPM_RCS_SIZE + RC_EncryptDecrypt_inData;
    
    // Copy IV
    // Note: This is copied here so that the calls to the encrypt/decrypt functions
    // will modify the output buffer, not the input buffer
    out->ivOut = in->ivIn;
    
    // Command Output
    
    key = symKey->sensitive.sensitive.sym.t.buffer;
    // For symmetric encryption, the cipher data size is the same as plain data
    // size.
    out->outData.t.size = in->inData.t.size;
    if(in->decrypt == YES)
	{
	    // Decrypt data to output
	    CryptSymmetricDecrypt(out->outData.t.buffer,
				  alg,
				  keySize,
				  mode,
				  key,
				  &(out->ivOut),
				  in->inData.t.size,
				  in->inData.t.buffer);
	}
    else
	{
	    // Encrypt data to output
	    CryptSymmetricEncrypt(out->outData.t.buffer,
				  alg,
				  keySize,
				  mode,
				  key,
				  &(out->ivOut),
				  in->inData.t.size,
				  in->inData.t.buffer);
	}
    return TPM_RC_SUCCESS;
}
#endif // CC_EncryptDecrypt

/* 15.3	TPM2_Hash */

#include "InternalRoutines.h"
#include "Hash_fp.h"
#ifdef TPM_CC_Hash  // Conditional expansion of this file

TPM_RC
TPM2_Hash(
	  Hash_In         *in,            // IN: input parameter list
	  Hash_Out        *out            // OUT: output parameter list
	  )
{
    HASH_STATE          hashState;

    // Command Output

    // Output hash
    // Start hash stack
    out->outHash.t.size = CryptStartHash(in->hashAlg, &hashState);
    // Adding hash data
    CryptUpdateDigest2B(&hashState, &in->data.b);
    // Complete hash
    CryptCompleteHash2B(&hashState, &out->outHash.b);
    // Output ticket
    out->validation.tag = TPM_ST_HASHCHECK;
    out->validation.hierarchy = in->hierarchy;
    if(in->hierarchy == TPM_RH_NULL)
	{
	    // Ticket is not required
	    out->validation.hierarchy = TPM_RH_NULL;
	    out->validation.digest.t.size = 0;
	}
    else if(  in->data.t.size >= sizeof(TPM_GENERATED)
	      && !TicketIsSafe(&in->data.b))
	{
	    // Ticket is not safe
	    out->validation.hierarchy = TPM_RH_NULL;
	    out->validation.digest.t.size = 0;
	}
    else
	{
	    // Compute ticket
	    TicketComputeHashCheck(in->hierarchy, in->hashAlg,
				   &out->outHash, &out->validation);
	}
    return TPM_RC_SUCCESS;
}
#endif // CC_Hash

/* 15.4	TPM2_HMAC */

#include "InternalRoutines.h"
#include "HMAC_fp.h"
#ifdef TPM_CC_HMAC  // Conditional expansion of this file

TPM_RC
TPM2_HMAC(
	  HMAC_In         *in,            // IN: input parameter list
	  HMAC_Out        *out            // OUT: output parameter list
	  )
{
    HMAC_STATE               hmacState;
    OBJECT                  *hmacObject;
    TPMI_ALG_HASH            hashAlg;
    TPMT_PUBLIC             *publicArea;

    // Input Validation

    // Get HMAC key object and public area pointers
    hmacObject = ObjectGet(in->handle);
    publicArea = &hmacObject->publicArea;

    // Make sure that the key is an HMAC key
    if(publicArea->type != TPM_ALG_KEYEDHASH)
	return TPM_RCS_TYPE + RC_HMAC_handle;

    // and that it is unrestricted
    if(publicArea->objectAttributes.restricted == SET)
	return TPM_RCS_ATTRIBUTES + RC_HMAC_handle;

    // and that it is a signing key
    if(publicArea->objectAttributes.sign != SET)
	return TPM_RCS_KEY + RC_HMAC_handle;

    // See if the key has a default
    if(publicArea->parameters.keyedHashDetail.scheme.scheme == TPM_ALG_NULL)
	// it doesn't so use the input value
	hashAlg = in->hashAlg;
    else
	{
	    // key has a default so use it
	    hashAlg
		= publicArea->parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
	    // and verify that the input was either the  TPM_ALG_NULL or the default
	    if(in->hashAlg != TPM_ALG_NULL && in->hashAlg != hashAlg)
		hashAlg = TPM_ALG_NULL;
	}
    // if we ended up without a hash algorith then return an error
    if(hashAlg == TPM_ALG_NULL)
	return TPM_RCS_VALUE + RC_HMAC_hashAlg;

    // Command Output

    // Start HMAC stack
    out->outHMAC.t.size = CryptStartHMAC2B(hashAlg,
					   &hmacObject->sensitive.sensitive.bits.b,
					   &hmacState);
    // Adding HMAC data
	CryptUpdateDigest2B(&hmacState, &in->buffer.b);
    
	// Complete HMAC
	CryptCompleteHMAC2B(&hmacState, &out->outHMAC.b);

	return TPM_RC_SUCCESS;
}
#endif // CC_HMAC
