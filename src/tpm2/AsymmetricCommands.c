/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: AsymmetricCommands.c 471 2015-12-22 19:40:24Z kgoldman $	*/
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

/* 14.2	TPM2_RSA_Encrypt */
#include "InternalRoutines.h"
#include "RSA_Encrypt_fp.h"
#ifdef TPM_CC_RSA_Encrypt  // Conditional expansion of this file
#ifdef TPM_ALG_RSA

TPM_RC
TPM2_RSA_Encrypt(
		 RSA_Encrypt_In      *in,            // IN: input parameter list
		 RSA_Encrypt_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC                  result;
    OBJECT                  *rsaKey;
    TPMT_RSA_DECRYPT        *scheme;
    char                    *label = NULL;

    // Input Validation
    
    rsaKey = ObjectGet(in->keyHandle);

    // selected key must be an RSA key
    if(rsaKey->publicArea.type != TPM_ALG_RSA)
	return TPM_RCS_KEY + RC_RSA_Encrypt_keyHandle;

    // selected key must have the decryption attribute
    if(rsaKey->publicArea.objectAttributes.decrypt != SET)
	return TPM_RCS_ATTRIBUTES + RC_RSA_Encrypt_keyHandle;

    // Is there a label?
    if(in->label.t.size > 0)
	{
	    // label is present, so make sure that is it NULL-terminated
	    if(in->label.t.buffer[in->label.t.size - 1] != 0)
		return TPM_RCS_VALUE + RC_RSA_Encrypt_label;
	    label = (char *)in->label.t.buffer;
	}

    // Command Output

    // Select a scheme for encryption
    scheme = CryptSelectRSAScheme(in->keyHandle, &in->inScheme);
    if(scheme == NULL)
	return TPM_RCS_SCHEME + RC_RSA_Encrypt_inScheme;

    // Encryption.  TPM_RC_VALUE, or TPM_RC_SCHEME errors my be returned buy
    // CryptEncyptRSA. Note: It can also return TPM_RC_ATTRIBUTES if the key does
    // not have the decrypt attribute but that was checked above.
    out->outData.t.size = sizeof(out->outData.t.buffer);
    result = CryptEncryptRSA(&out->outData.t.size, out->outData.t.buffer, rsaKey,
			     scheme, in->message.t.size, in->message.t.buffer,
			     label);
    return result;
}
#endif
#endif // CC_RSA_Encrypt

/* 14.3	TPM2_RSA_Decrypt */

#include "InternalRoutines.h"
#include "RSA_Decrypt_fp.h"
#ifdef TPM_CC_RSA_Decrypt  // Conditional expansion of this file
#ifdef TPM_ALG_RSA
TPM_RC
TPM2_RSA_Decrypt(
		 RSA_Decrypt_In      *in,            // IN: input parameter list
		 RSA_Decrypt_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC                       result;
    OBJECT                      *rsaKey;
    TPMT_RSA_DECRYPT            *scheme;
    char                        *label = NULL;

    // Input Validation

    rsaKey = ObjectGet(in->keyHandle);

    // The selected key must be an RSA key
    if(rsaKey->publicArea.type != TPM_ALG_RSA)
	return TPM_RCS_KEY + RC_RSA_Decrypt_keyHandle;

    // The selected key must be an unrestricted decryption key
    if(   rsaKey->publicArea.objectAttributes.restricted == SET
	  || rsaKey->publicArea.objectAttributes.decrypt == CLEAR)
	return TPM_RCS_ATTRIBUTES + RC_RSA_Decrypt_keyHandle;

    // NOTE: Proper operation of this command requires that the sensitive area
    // of the key is loaded. This is assured because authorization is required
    // to use the sensitive area of the key. In order to check the authorization,
    // the sensitive area has to be loaded, even if authorization is with policy.

    // If label is present, make sure that it is a NULL-terminated string
    if(in->label.t.size > 0)
	{
	    // Present, so make sure that it is NULL-terminated
	    if(in->label.t.buffer[in->label.t.size - 1] != 0)
		return TPM_RCS_VALUE + RC_RSA_Decrypt_label;
	    label = (char *)in->label.t.buffer;
	}

    // Command Output

    // Select a scheme for decrypt.
    scheme = CryptSelectRSAScheme(in->keyHandle, &in->inScheme);
    if(scheme == NULL)
	return TPM_RCS_SCHEME + RC_RSA_Decrypt_inScheme;

    // Decryption.  TPM_RC_VALUE, TPM_RC_SIZE, and TPM_RC_KEY error may be
    // returned by CryptDecryptRSA.
    // NOTE: CryptDecryptRSA can also return TPM_RC_ATTRIBUTES or TPM_RC_BINDING
    // when the key is not a decryption key but that was checked above.
    out->message.t.size = sizeof(out->message.t.buffer);
    result = CryptDecryptRSA(&out->message.t.size, out->message.t.buffer, rsaKey,
			     scheme, in->cipherText.t.size,
			     in->cipherText.t.buffer,
			     label);

    return result;
}
#endif
#endif // CC_RSA_Decrypt

/* 14.4	TPM2_ECDH_KeyGen */

#include "InternalRoutines.h"
#include "ECDH_KeyGen_fp.h"
#ifdef TPM_CC_ECDH_KeyGen  // Conditional expansion of this file
#ifdef TPM_ALG_ECC

TPM_RC
TPM2_ECDH_KeyGen(
		 ECDH_KeyGen_In      *in,            // IN: input parameter list
		 ECDH_KeyGen_Out     *out            // OUT: output parameter list
		 )
{
    OBJECT                  *eccKey;
    TPM2B_ECC_PARAMETER      sensitive;
    TPM_RC                   result;

    // Input Validation

    eccKey = ObjectGet(in->keyHandle);

    // Input key must be a non-restricted, decrypt ECC key
    if(   eccKey->publicArea.type != TPM_ALG_ECC)
	return TPM_RCS_KEY + RC_ECDH_KeyGen_keyHandle;

    if(     eccKey->publicArea.objectAttributes.restricted == SET
	    ||   eccKey->publicArea.objectAttributes.decrypt != SET )
	return TPM_RCS_KEY + RC_ECDH_KeyGen_keyHandle;

    // Command Output
    do
	{
	    // Create ephemeral ECC key
	    result = CryptNewEccKey(eccKey->publicArea.parameters.eccDetail.curveID,
				    &out->pubPoint.t.point, &sensitive);
	    if(result == TPM_RC_SUCCESS)
		{
		    out->pubPoint.t.size = TPMS_ECC_POINT_Marshal(&out->pubPoint.t.point,
								  NULL, NULL);
		    // Compute Z
		    result = CryptEccPointMultiply(&out->zPoint.t.point,
						   eccKey->publicArea.parameters.eccDetail.curveID,
						   &sensitive, &eccKey->publicArea.unique.ecc);
		    // The point in the key is not on the curve. Indicate
		    // that the key is bad.
		    if(result == TPM_RC_ECC_POINT)
			result = TPM_RC_KEY;

		    // The other possible error from CryptEccPointMultiply is
		    // TPM_RC_NO_RESULT indicating that the multiplication resulted in
		    // the point at infinity, so get a new random key and start over
		    // BTW, this never happens.
		}
	}
    while(result == TPM_RC_NO_RESULT);

    if(result == TPM_RC_SUCCESS)
	// Marshal the values to generate the point.
	out->zPoint.t.size = TPMS_ECC_POINT_Marshal(&out->zPoint.t.point,
						    NULL, NULL);

    return result;
}
#endif // ALG_ECC
#endif // CC_ECDH_KeyGen

/* 14.5	TPM2_ECDH_ZGen */

#include "InternalRoutines.h"
#include "ECDH_ZGen_fp.h"
#ifdef TPM_CC_ECDH_ZGen  // Conditional expansion of this file
#ifdef TPM_ALG_ECC

TPM_RC
TPM2_ECDH_ZGen(
	       ECDH_ZGen_In    *in,            // IN: input parameter list
	       ECDH_ZGen_Out   *out            // OUT: output parameter list
	       )
{
    TPM_RC                   result;
    OBJECT                  *eccKey;

    // Input Validation

    eccKey = ObjectGet(in->keyHandle);

    // Input key must be a non-restricted, decrypt ECC key
    if(   eccKey->publicArea.type != TPM_ALG_ECC)
	return TPM_RCS_KEY + RC_ECDH_ZGen_keyHandle;

    if(     eccKey->publicArea.objectAttributes.restricted == SET
	    ||   eccKey->publicArea.objectAttributes.decrypt != SET
	    )
	return TPM_RCS_KEY + RC_ECDH_ZGen_keyHandle;
    
    // Make sure the scheme allows this use
    if(     eccKey->publicArea.parameters.eccDetail.scheme.scheme != TPM_ALG_ECDH
	    &&  eccKey->publicArea.parameters.eccDetail.scheme.scheme != TPM_ALG_NULL)
	return TPM_RCS_SCHEME + RC_ECDH_ZGen_keyHandle;

    // Command Output

    // Compute Z. TPM_RC_ECC_POINT or TPM_RC_NO_RESULT may be returned here.
    result = CryptEccPointMultiply(&out->outPoint.t.point,
				   eccKey->publicArea.parameters.eccDetail.curveID,
				   &eccKey->sensitive.sensitive.ecc,
				   &in->inPoint.t.point);
    if(result != TPM_RC_SUCCESS)
	return RcSafeAddToResult(result, RC_ECDH_ZGen_inPoint);

    out->outPoint.t.size = TPMS_ECC_POINT_Marshal(&out->outPoint.t.point,
						  NULL, NULL);

    return TPM_RC_SUCCESS;
}
#endif
#endif // CC_ECDH_ZGen

/* 14.6	TPM2_ECC_Parameters */

#include "InternalRoutines.h"
#include "ECC_Parameters_fp.h"
#ifdef TPM_CC_ECC_Parameters  // Conditional expansion of this file
#ifdef TPM_ALG_ECC

TPM_RC
TPM2_ECC_Parameters(
		    ECC_Parameters_In   *in,            // IN: input parameter list
		    ECC_Parameters_Out  *out            // OUT: output parameter list
		    )
{
    // Command Output
	
    // Get ECC curve parameters
    if(CryptEccGetParameters(in->curveID, &out->parameters))
	return TPM_RC_SUCCESS;
    else
	return TPM_RCS_VALUE + RC_ECC_Parameters_curveID;
}
#endif
#endif // CC_ECC_Parameters

/* 14.7	TPM2_ZGen_2Phase */

#include "InternalRoutines.h"
#include "ZGen_2Phase_fp.h"
#ifdef TPM_CC_ZGen_2Phase  // Conditional expansion of this file
TPM_RC
TPM2_ZGen_2Phase(
		 ZGen_2Phase_In      *in,            // IN: input parameter list
		 ZGen_2Phase_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC                   result;
    OBJECT                  *eccKey;
    TPM2B_ECC_PARAMETER      r;
    TPM_ALG_ID               scheme;

    // Input Validation

    eccKey = ObjectGet(in->keyA);

    // keyA must be an ECC key
    if(eccKey->publicArea.type != TPM_ALG_ECC)
	return TPM_RCS_KEY + RC_ZGen_2Phase_keyA;

    // keyA must not be restricted and must be a decrypt key
    if(   eccKey->publicArea.objectAttributes.restricted == SET
	  || eccKey->publicArea.objectAttributes.decrypt != SET
	  )
	return TPM_RCS_ATTRIBUTES + RC_ZGen_2Phase_keyA;

    // if the scheme of keyA is TPM_ALG_NULL, then use the input scheme; otherwise
    // the input scheme must be the same as the scheme of keyA
    scheme = eccKey->publicArea.parameters.asymDetail.scheme.scheme;
    if(scheme != TPM_ALG_NULL)
	{
	    if(scheme != in->inScheme)
		return TPM_RCS_SCHEME + RC_ZGen_2Phase_inScheme;
	}
    else
	scheme = in->inScheme;
    if(scheme == TPM_ALG_NULL)
	return TPM_RCS_SCHEME + RC_ZGen_2Phase_inScheme;

    // Input points must be on the curve of keyA
    if(!CryptEccIsPointOnCurve(eccKey->publicArea.parameters.eccDetail.curveID,
			       &in->inQsB.t.point))
	return TPM_RCS_ECC_POINT + RC_ZGen_2Phase_inQsB;

    if(!CryptEccIsPointOnCurve(eccKey->publicArea.parameters.eccDetail.curveID,
			       &in->inQeB.t.point))
	return TPM_RCS_ECC_POINT + RC_ZGen_2Phase_inQeB;

    if(!CryptGenerateR(&r, &in->counter,
		       eccKey->publicArea.parameters.eccDetail.curveID,
		       NULL))
	return TPM_RCS_VALUE + RC_ZGen_2Phase_counter;

    // Command Output

    result = CryptEcc2PhaseKeyExchange(&out->outZ1.t.point,
				       &out->outZ2.t.point,
				       eccKey->publicArea.parameters.eccDetail.curveID,
				       scheme,
				       &eccKey->sensitive.sensitive.ecc,
				       &r,
				       &in->inQsB.t.point,
				       &in->inQeB.t.point);
    if(result == TPM_RC_SCHEME)
	return TPM_RCS_SCHEME + RC_ZGen_2Phase_inScheme;
    if(result == TPM_RC_SUCCESS)
	CryptEndCommit(in->counter);

    return result;
}
#endif
